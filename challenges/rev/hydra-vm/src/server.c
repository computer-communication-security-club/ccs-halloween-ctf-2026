#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "fw_crypto.h"
#include "hydra_vm.h"

#define BANNER "HYDRA-SVC/1.0 AUTH-REQUIRED"
#define LINE_MAX_LEN 128

static uint8_t *g_fw;
static size_t g_fw_len;
static char g_flag[512];
static char g_activity_path[512];
static int g_timeout_sec = 30;
static uint64_t g_max_steps = 1000000;
static int g_max_conn = 64;
static int g_active = 0;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static void log_line(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
}

static void touch_activity(void)
{
    if (!g_activity_path[0])
        return;
    int fd = open(g_activity_path, O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) {
        char buf[32];
        int n = snprintf(buf, sizeof(buf), "%ld\n", (long)time(NULL));
        if (write(fd, buf, (size_t)n) < 0) { /* best effort */ }
        close(fd);
    }
}

static int read_line(int fd, char *buf, size_t cap)
{
    size_t len = 0;
    while (len + 1 < cap) {
        char ch;
        ssize_t n = recv(fd, &ch, 1, 0);
        if (n <= 0)
            return -1;
        if (ch == '\n')
            break;
        buf[len++] = ch;
    }
    while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n' || buf[len - 1] == ' '))
        len--;
    buf[len] = '\0';
    return (int)len;
}

static int hex_val(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static int parse_hex16(const char *s, uint8_t out[16])
{
    if (strlen(s) != 32)
        return -1;
    for (int i = 0; i < 16; i++) {
        int hi = hex_val(s[2 * i]), lo = hex_val(s[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void format_hex16(const uint8_t in[16], char out[33])
{
    static const char *d = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out[2 * i] = d[in[i] >> 4];
        out[2 * i + 1] = d[in[i] & 0xF];
    }
    out[32] = '\0';
}

/* Verify a candidate proof by running the decrypted firmware in the VM.
 * The VM only reports accept/reject; it never returns a proof. */
static int verify_proof(const uint8_t nonce[16], const uint8_t proof[16])
{
    hydra_vm vm;
    hydra_vm_init(&vm);
    if (hydra_vm_load(&vm, g_fw, g_fw_len) != 0)
        return -1;
    memcpy(vm.mem + HYDRA_NONCE_ADDR, nonce, 16);
    memcpy(vm.mem + HYDRA_PROOF_ADDR, proof, 16);
    if (hydra_vm_run(&vm, g_max_steps) != 0)
        return -1;
    return vm.mem[HYDRA_RESULT_ADDR] == 1 ? 1 : 0;
}

static int random_bytes(uint8_t *out, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, out + got, n - got);
        if (r <= 0) {
            close(fd);
            return -1;
        }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}

struct conn_arg {
    int fd;
    struct sockaddr_in addr;
};

static void *client_thread(void *p)
{
    struct conn_arg *arg = (struct conn_arg *)p;
    int fd = arg->fd;
    char peer[64];
    char line[LINE_MAX_LEN];
    char hexbuf[33];
    uint8_t nonce[16], proof[16];
    const char *result = "FAIL";

    snprintf(peer, sizeof(peer), "%s:%d",
             inet_ntoa(arg->addr.sin_addr), ntohs(arg->addr.sin_port));
    free(arg);

    struct timeval tv = { .tv_sec = g_timeout_sec, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (random_bytes(nonce, sizeof(nonce)) != 0) {
        dprintf(fd, "ERR INTERNAL\n");
        log_line("[hydra] peer=%s result=INTERNAL", peer);
        goto out;
    }

    format_hex16(nonce, hexbuf);
    dprintf(fd, "%s\nNONCE %s\n", BANNER, hexbuf);

    if (read_line(fd, line, sizeof(line)) < 0) {
        log_line("[hydra] peer=%s result=TIMEOUT", peer);
        goto out;
    }
    /* Count real client interaction as activity, not health-check probes. */
    touch_activity();

    if (strncmp(line, "AUTH ", 5) != 0) {
        dprintf(fd, "ERR BAD-REQUEST\n");
        log_line("[hydra] peer=%s result=BAD-REQUEST", peer);
        goto out;
    }
    if (parse_hex16(line + 5, proof) != 0) {
        dprintf(fd, "ERR BAD-REQUEST\n");
        log_line("[hydra] peer=%s result=BAD-REQUEST", peer);
        goto out;
    }

    int verdict = verify_proof(nonce, proof);
    if (verdict < 0) {
        dprintf(fd, "ERR INTERNAL\n");
        log_line("[hydra] peer=%s result=INTERNAL", peer);
        goto out;
    }
    if (verdict == 1) {
        result = "OK";
        dprintf(fd, "AUTH-OK\nFLAG %s\n", g_flag);
    } else {
        dprintf(fd, "AUTH-FAIL\n");
    }
    log_line("[hydra] peer=%s result=%s", peer, result);

out:
    close(fd);
    pthread_mutex_lock(&g_mu);
    g_active--;
    pthread_mutex_unlock(&g_mu);
    return NULL;
}

static char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len < 0) {
        fclose(f);
        return NULL;
    }
    char *buf = malloc((size_t)len + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    buf[len] = '\0';
    *out_len = (size_t)len;
    return buf;
}

static void load_flag(void)
{
    const char *env = getenv("HYDRA_FLAG");
    if (env && env[0]) {
        snprintf(g_flag, sizeof(g_flag), "%s", env);
    } else {
        const char *path = getenv("HYDRA_FLAG_FILE");
        if (!path || !path[0])
            path = "flag.txt";
        size_t len = 0;
        char *buf = read_file(path, &len);
        if (!buf) {
            fprintf(stderr, "[hydra] cannot read flag file: %s\n", path);
            exit(1);
        }
        snprintf(g_flag, sizeof(g_flag), "%s", buf);
        free(buf);
    }
    size_t n = strlen(g_flag);
    while (n > 0 && (g_flag[n - 1] == '\n' || g_flag[n - 1] == '\r' || g_flag[n - 1] == ' '))
        g_flag[--n] = '\0';
    if (!g_flag[0]) {
        fprintf(stderr, "[hydra] empty flag\n");
        exit(1);
    }
}

static void load_firmware(void)
{
    const char *path = getenv("HYDRA_FW_FILE");
    if (!path || !path[0])
        path = "firmware.enc";
    size_t blob_len = 0;
    char *blob = read_file(path, &blob_len);
    if (!blob) {
        fprintf(stderr, "[hydra] cannot read firmware: %s\n", path);
        exit(1);
    }
    g_fw = hydra_fw_decrypt((const uint8_t *)blob, blob_len, &g_fw_len);
    free(blob);
    if (!g_fw) {
        fprintf(stderr, "[hydra] firmware decryption failed: %s\n", path);
        exit(1);
    }
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    const char *env;
    int port = 31337;
    const char *bind_addr = "0.0.0.0";

    if ((env = getenv("HYDRA_PORT")) && env[0])
        port = atoi(env);
    if ((env = getenv("HYDRA_BIND")) && env[0])
        bind_addr = env;
    if ((env = getenv("HYDRA_TIMEOUT")) && env[0])
        g_timeout_sec = atoi(env);
    if ((env = getenv("HYDRA_MAX_STEPS")) && env[0])
        g_max_steps = strtoull(env, NULL, 10);
    if ((env = getenv("HYDRA_MAX_CONN")) && env[0])
        g_max_conn = atoi(env);
    if ((env = getenv("HYDRA_ACTIVITY_FILE")) && env[0])
        snprintf(g_activity_path, sizeof(g_activity_path), "%s", env);

    load_firmware();
    load_flag();

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        perror("socket");
        return 1;
    }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_addr, &sa.sin_addr) != 1) {
        fprintf(stderr, "[hydra] bad bind address: %s\n", bind_addr);
        return 1;
    }
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(srv, 128) < 0) {
        perror("listen");
        return 1;
    }

    log_line("[hydra] firmware loaded (%zu bytes), listening on %s:%d",
             g_fw_len, bind_addr, port);

    for (;;) {
        struct sockaddr_in ca;
        socklen_t clen = sizeof(ca);
        int fd = accept(srv, (struct sockaddr *)&ca, &clen);
        if (fd < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            break;
        }

        pthread_mutex_lock(&g_mu);
        int busy = (g_active >= g_max_conn);
        if (!busy)
            g_active++;
        pthread_mutex_unlock(&g_mu);

        if (busy) {
            dprintf(fd, "ERR BUSY\n");
            close(fd);
            continue;
        }

        struct conn_arg *arg = malloc(sizeof(*arg));
        if (!arg) {
            close(fd);
            pthread_mutex_lock(&g_mu);
            g_active--;
            pthread_mutex_unlock(&g_mu);
            continue;
        }
        arg->fd = fd;
        arg->addr = ca;

        pthread_t th;
        if (pthread_create(&th, NULL, client_thread, arg) != 0) {
            close(fd);
            free(arg);
            pthread_mutex_lock(&g_mu);
            g_active--;
            pthread_mutex_unlock(&g_mu);
            continue;
        }
        pthread_detach(th);
    }

    close(srv);
    return 0;
}
