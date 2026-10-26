// front.c — TLS 1.3 0-RTT early-data terminating proxy for a CTF lab.
//
// This is an INTENTIONALLY VULNERABLE educational artifact. Two deliberate
// weaknesses live in this file; each is marked with a `VULN` banner so a CTF
// author can audit the design:
//
//   VULN #1 (request desync): when a 0-RTT early-data buffer contains more than
//           one pipelined HTTP/1.1 request, we tag ONLY the first request with
//           `Early-Data: 1` and splice the rest of the raw buffer to the
//           backend untouched. A smuggled second request therefore reaches the
//           backend WITHOUT the early-data tag.
//
//   VULN #2 (replay-cache partition): the 0-RTT anti-replay cache is a plain
//           in-process table, local to THIS instance and never shared with its
//           sibling. An identical early-data flight replayed through the load
//           balancer lands on the other instance, whose cache is empty.
//
// Everything else aims to be a correct, minimal TLS-terminating HTTP/1.1 proxy.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#define MAX_EARLY   32768
#define READ_CHUNK  4096

static const char *g_instance   = "X";
static const char *g_backend_h  = "backend";
static const char *g_backend_p  = "8080";

// --- shared session-ticket key (STEK) ---------------------------------------
// Both front instances load the SAME 80-byte key file so that a ticket issued
// by one instance resumes (and does 0-RTT) on the other. This is the realistic
// "identical instances behind a load balancer" setup — NOT the vuln. The vuln
// is that the *replay cache* below is not shared, even though the ticket key is.
static unsigned char tk_name[16], tk_aes[32], tk_hmac[32];

static int ticket_key_cb(SSL *s, unsigned char key_name[16], unsigned char *iv,
                         EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc) {
    (void)s;
    if (enc) {
        if (RAND_bytes(iv, 16) <= 0) return -1;
        memcpy(key_name, tk_name, 16);
        EVP_EncryptInit_ex(ectx, EVP_aes_256_cbc(), NULL, tk_aes, iv);
        HMAC_Init_ex(hctx, tk_hmac, sizeof tk_hmac, EVP_sha256(), NULL);
        return 1;
    } else {
        if (memcmp(key_name, tk_name, 16) != 0) return 0; // not our key
        HMAC_Init_ex(hctx, tk_hmac, sizeof tk_hmac, EVP_sha256(), NULL);
        EVP_DecryptInit_ex(ectx, EVP_aes_256_cbc(), NULL, tk_aes, iv);
        return 1;
    }
}

// --------------------------------------------------------------------------
// VULN #2: per-instance, in-memory 0-RTT replay cache keyed by a hash of the
// early-data flight. In a hardened deployment this would be a SHARED store
// (e.g. Redis) consulted by every front instance so a replayed flight is
// rejected fleet-wide. Here it is a local linked list, so the sibling instance
// never learns that this flight was already seen.
// --------------------------------------------------------------------------
struct replay_node { char hex[65]; struct replay_node *next; };
static struct replay_node *replay_head = NULL;
static pthread_mutex_t replay_mu = PTHREAD_MUTEX_INITIALIZER;

static int replay_seen_or_record(const char *hex) {
    int seen = 0;
    pthread_mutex_lock(&replay_mu);
    for (struct replay_node *n = replay_head; n; n = n->next)
        if (strcmp(n->hex, hex) == 0) { seen = 1; break; }
    if (!seen) {
        struct replay_node *n = calloc(1, sizeof *n);
        memcpy(n->hex, hex, 65);
        n->next = replay_head;
        replay_head = n;
    }
    pthread_mutex_unlock(&replay_mu);
    return seen;
}

static void sha256_hex(const unsigned char *buf, size_t len, char out[65]) {
    unsigned char md[32]; unsigned int mdlen = 0;
    EVP_Digest(buf, len, md, &mdlen, EVP_sha256(), NULL);
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[i*2] = h[md[i] >> 4]; out[i*2+1] = h[md[i] & 0xf]; }
    out[64] = 0;
}

// --- small I/O helpers ------------------------------------------------------
static int writeall(int fd, const unsigned char *b, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, b + off, n - off, 0);
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static int ssl_writeall(SSL *ssl, const unsigned char *b, size_t n) {
    size_t off = 0;
    while (off < n) {
        int w = SSL_write(ssl, b + off, (int)(n - off));
        if (w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

static int connect_backend(void) {
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(g_backend_h, g_backend_p, &hints, &res) != 0) return -1;
    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) {
        // bound relay reads so we return after a backend response batch
        struct timeval tv = { .tv_sec = 0, .tv_usec = 500000 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    }
    return fd;
}

// Relay one backend response batch (one or more pipelined responses) to the
// TLS client, stopping on the first idle gap (the SO_RCVTIMEO above).
static void relay_backend(int bfd, SSL *ssl) {
    unsigned char b[8192];
    for (;;) {
        ssize_t n = recv(bfd, b, sizeof b, 0);
        if (n > 0) { if (ssl_writeall(ssl, b, (size_t)n) < 0) return; continue; }
        return; // backend closed, or recv timed out -> batch done
    }
}

// Drop every `Early-Data:` header line from a buffer (client-supplied values
// must never be trusted). Used on the NORMAL (non-early) path so a client
// cannot forge the tag by pipelining it themselves. Returns new length.
static size_t strip_early_data(unsigned char *buf, size_t len) {
    unsigned char *out = malloc(len + 1);
    size_t o = 0, i = 0;
    while (i < len) {
        size_t j = i;
        while (j + 1 < len && !(buf[j] == '\r' && buf[j+1] == '\n')) j++;
        int hasCRLF = (j + 1 < len);
        size_t ll = hasCRLF ? (j - i) : (len - i);
        if (!(ll >= 11 && strncasecmp((char*)buf + i, "early-data:", 11) == 0)) {
            memcpy(out + o, buf + i, ll); o += ll;
            if (hasCRLF) { out[o++] = '\r'; out[o++] = '\n'; }
        }
        if (!hasCRLF) break;
        i = j + 2;
    }
    memcpy(buf, out, o);
    free(out);
    return o;
}

// ==========================================================================
// VULN #1 (request desync). Tag ONLY the first request of an early-data buffer
// with `Early-Data: 1`, then splice the remainder of the raw buffer verbatim.
// Any pipelined/smuggled request after the first is forwarded with NO tag.
// A correct proxy would re-frame and tag every request carried in early data.
// ==========================================================================
static unsigned char *tag_first_request(const unsigned char *buf, size_t len, size_t *outlen) {
    unsigned char *sep = memmem(buf, len, "\r\n\r\n", 4);
    if (!sep) { // no complete header block; forward unchanged
        unsigned char *c = malloc(len ? len : 1);
        memcpy(c, buf, len); *outlen = len; return c;
    }
    size_t hlen = (size_t)(sep - buf);          // request-line + headers (no CRLFCRLF)
    const unsigned char *rest = sep + 4;         // first body + ALL pipelined bytes (raw)
    size_t restlen = len - (hlen + 4);

    unsigned char *out = malloc(hlen + restlen + 64);
    size_t o = 0, i = 0;
    while (i < hlen) {                            // copy first block, dropping any Early-Data
        size_t j = i;
        while (j + 1 < hlen && !(buf[j] == '\r' && buf[j+1] == '\n')) j++;
        int hasCRLF = (j + 1 < hlen);
        size_t ll = hasCRLF ? (j - i) : (hlen - i);
        if (!(ll >= 11 && strncasecmp((char*)buf + i, "early-data:", 11) == 0)) {
            memcpy(out + o, buf + i, ll); o += ll;
            out[o++] = '\r'; out[o++] = '\n';
        }
        if (!hasCRLF) break;
        i = j + 2;
    }
    const char *tag = "Early-Data: 1\r\n";       // <-- tag applied to the FIRST request only
    memcpy(out + o, tag, strlen(tag)); o += strlen(tag);
    out[o++] = '\r'; out[o++] = '\n';            // terminate first request's headers
    memcpy(out + o, rest, restlen); o += restlen; // <-- smuggled request rides along UNTAGGED
    *outlen = o;
    return out;
}

static void handle(SSL *ssl, int clientfd) {
    (void)clientfd;
    SSL_set_accept_state(ssl);

    // Drain TLS 1.3 early data into a single contiguous buffer.
    unsigned char early[MAX_EARLY];
    size_t earlylen = 0;
    for (;;) {
        unsigned char tmp[READ_CHUNK];
        size_t nread = 0;
        int rc = SSL_read_early_data(ssl, tmp, sizeof tmp, &nread);
        if (rc == SSL_READ_EARLY_DATA_SUCCESS) {
            if (earlylen + nread > MAX_EARLY) nread = MAX_EARLY - earlylen;
            memcpy(early + earlylen, tmp, nread);
            earlylen += nread;
            if (earlylen >= MAX_EARLY) break;
            continue;
        }
        if (rc == SSL_READ_EARLY_DATA_FINISH) break;
        // ERROR
        int e = SSL_get_error(ssl, rc);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) continue;
        return;
    }
    if (SSL_accept(ssl) <= 0) return;            // complete the handshake

    int early_ok = (SSL_get_early_data_status(ssl) == SSL_EARLY_DATA_ACCEPTED) && earlylen > 0;

    int bfd = connect_backend();
    if (bfd < 0) {
        const char *msg = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        ssl_writeall(ssl, (const unsigned char*)msg, strlen(msg));
        return;
    }

    if (early_ok) {
        char hex[65];
        sha256_hex(early, earlylen, hex);        // replay key = hash of the flight
        if (replay_seen_or_record(hex)) {
            // VULN #2 in action: THIS instance has already seen this exact
            // flight. We reject the replay — but the sibling instance would
            // happily accept it, because the cache is not shared.
            char resp[160];
            int n = snprintf(resp, sizeof resp,
                "HTTP/1.1 425 Too Early\r\nContent-Length: %zu\r\nConnection: close\r\n\r\nreplay: blocked by instance %s\n",
                strlen("replay: blocked by instance ") + strlen(g_instance) + 1, g_instance);
            ssl_writeall(ssl, (unsigned char*)resp, n);
            close(bfd);
            return;
        }
        size_t taglen = 0;
        unsigned char *tagged = tag_first_request(early, earlylen, &taglen);
        writeall(bfd, tagged, taglen);           // forward tagged-first + smuggled-rest
        free(tagged);
        relay_backend(bfd, ssl);
    }

    // Normal (1-RTT) request loop on the same TLS connection / backend keep-alive.
    for (;;) {
        unsigned char req[16384];
        int n = SSL_read(ssl, req, sizeof req);
        if (n <= 0) break;
        size_t m = strip_early_data(req, (size_t)n); // never trust a client Early-Data header
        if (writeall(bfd, req, m) < 0) break;
        relay_backend(bfd, ssl);
    }
    close(bfd);
}

struct conn { SSL_CTX *ctx; int fd; };

static void *conn_thread(void *arg) {
    struct conn *c = arg;
    int one = 1;
    setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    SSL *ssl = SSL_new(c->ctx);
    if (ssl) {
        SSL_set_fd(ssl, c->fd);
        handle(ssl, c->fd);
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(c->fd);
    free(c);
    return NULL;
}

static SSL_CTX *make_ctx(const char *cert, const char *key) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { ERR_print_errors_fp(stderr); exit(1); }
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(1);
    }
    // Enable 0-RTT early data (advertised in issued tickets).
    SSL_CTX_set_max_early_data(ctx, MAX_EARLY);
    // Disable OpenSSL's built-in single-use anti-replay so replay handling is
    // governed solely by our (intentionally partitioned) cache above.
    SSL_CTX_set_options(ctx, SSL_OP_NO_ANTI_REPLAY);
    // Shared, static STEK -> tickets from either instance resume on both.
    SSL_CTX_set_tlsext_ticket_key_cb(ctx, ticket_key_cb);
    return ctx;
}

static void load_ticket_key(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("ticket key"); exit(1); }
    unsigned char buf[80];
    if (fread(buf, 1, sizeof buf, f) != sizeof buf) { fprintf(stderr, "ticket key must be 80 bytes\n"); exit(1); }
    fclose(f);
    memcpy(tk_name, buf, 16);
    memcpy(tk_aes, buf + 16, 32);
    memcpy(tk_hmac, buf + 48, 32);
}

int main(void) {
    const char *port   = getenv("LISTEN_PORT")  ? getenv("LISTEN_PORT")  : "8443";
    const char *cert   = getenv("CERT")         ? getenv("CERT")         : "/certs/server.crt";
    const char *key    = getenv("KEY")          ? getenv("KEY")          : "/certs/server.key";
    const char *tkpath = getenv("TICKET_KEY")   ? getenv("TICKET_KEY")   : "/certs/ticket.key";
    if (getenv("INSTANCE"))    g_instance  = getenv("INSTANCE");
    if (getenv("BACKEND_HOST")) g_backend_h = getenv("BACKEND_HOST");
    if (getenv("BACKEND_PORT")) g_backend_p = getenv("BACKEND_PORT");

    load_ticket_key(tkpath);
    SSL_CTX *ctx = make_ctx(cert, key);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(atoi(port));
    if (bind(ls, (struct sockaddr*)&a, sizeof a) < 0) { perror("bind"); exit(1); }
    if (listen(ls, 64) < 0) { perror("listen"); exit(1); }
    fprintf(stderr, "[front %s] listening on :%s -> %s:%s\n", g_instance, port, g_backend_h, g_backend_p);

    for (;;) {
        int fd = accept(ls, NULL, NULL);
        if (fd < 0) continue;
        struct conn *c = malloc(sizeof *c);
        c->ctx = ctx; c->fd = fd;
        pthread_t t;
        if (pthread_create(&t, NULL, conn_thread, c) == 0) pthread_detach(t);
        else { close(fd); free(c); }
    }
}
