/*
 * ============================================================================
 *  Poltergeist  --  the Séance runtime, a cursed little web language.
 * ============================================================================
 *
 *  Séance is a tiny PHP-flavoured scripting language with its OWN persistent
 *  web worker.  Like classic mod_php / php-fpm, ONE long-lived process answers
 *  many HTTP requests in a loop:
 *
 *      * ENGINE state   lives for the whole worker process (across requests);
 *      * REQUEST state   is carved from a per-request "arena" that is reset
 *                        ("freed") when the request ends.
 *
 *  You POST a Séance program to /seance and the worker compiles and runs it,
 *  returning whatever the program `whisper`s.  The language is a normal little
 *  interpreter: 64-bit integers, byte strings, arrays, variables (`$x`),
 *  `rite` functions, `when/otherwise`, `chant` loops, the usual operators and a
 *  handful of builtins.
 *
 *  ONE convenience feature crosses the request boundary: a séance may `leave`
 *  an "echo" for the next page in the same séance to `recall`.  The echo is an
 *  engine global that points at a value living in the request arena, and it is
 *  dismissed (cleared) at the end of every request.
 *
 *     Build:  a hardened C compile (PIE/ASLR, Full RELRO, NX, stack canaries),
 *             then fully stripped.  (The deployed binary carries no symbols.)
 *     Run:    ./run -S 0.0.0.0:8080 -m 262144      (POW_BITS=24 in the env)
 *
 *  The door is WARDED.  In front of /seance sit two things that are NOT part of
 *  the language and do NOT change the vulnerability -- they only make the door
 *  costlier to knock on:  a small signature WAF, and a proof-of-work gate
 *  (GET /pow issues a challenge; send the solved nonce back in an X-Pow header).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <setjmp.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* ==========================================================================
 * SHA-256 (compact, public-domain style).  Used ONLY by the front-door
 * proof-of-work gate near the bottom of this file -- it is not part of the
 * Seance language or the vulnerability.
 * ========================================================================== */

typedef struct { uint32_t s[8]; uint64_t nbits; unsigned char buf[64]; size_t n; } Sha256;

static uint32_t sha_ror(uint32_t x, int r) { return (x >> r) | (x << (32 - r)); }

static const uint32_t SHA_K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha_block(Sha256 *c, const unsigned char *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i*4]<<24 | (uint32_t)p[i*4+1]<<16 | (uint32_t)p[i*4+2]<<8 | p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = sha_ror(w[i-15],7) ^ sha_ror(w[i-15],18) ^ (w[i-15]>>3);
        uint32_t s1 = sha_ror(w[i-2],17) ^ sha_ror(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c->s[0],b=c->s[1],cc=c->s[2],d=c->s[3],e=c->s[4],f=c->s[5],g=c->s[6],h=c->s[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = sha_ror(e,6) ^ sha_ror(e,11) ^ sha_ror(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + SHA_K[i] + w[i];
        uint32_t S0 = sha_ror(a,2) ^ sha_ror(a,13) ^ sha_ror(a,22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->s[0]+=a;c->s[1]+=b;c->s[2]+=cc;c->s[3]+=d;c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;
}

static void sha_init(Sha256 *c) {
    c->s[0]=0x6a09e667;c->s[1]=0xbb67ae85;c->s[2]=0x3c6ef372;c->s[3]=0xa54ff53a;
    c->s[4]=0x510e527f;c->s[5]=0x9b05688c;c->s[6]=0x1f83d9ab;c->s[7]=0x5be0cd19;
    c->nbits=0;c->n=0;
}

static void sha_update(Sha256 *c, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char*)data;
    c->nbits += (uint64_t)len * 8;
    while (len) {
        size_t take = 64 - c->n; if (take > len) take = len;
        memcpy(c->buf + c->n, p, take); c->n += take; p += take; len -= take;
        if (c->n == 64) { sha_block(c, c->buf); c->n = 0; }
    }
}

static void sha_final(Sha256 *c, unsigned char out[32]) {
    uint64_t bits = c->nbits;
    unsigned char one = 0x80; sha_update(c, &one, 1);
    unsigned char zero = 0; while (c->n != 56) sha_update(c, &zero, 1);
    unsigned char len8[8];
    for (int i = 0; i < 8; i++) len8[i] = (unsigned char)(bits >> (56 - 8*i));
    sha_update(c, len8, 8);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (unsigned char)(c->s[i] >> 24);
        out[i*4+1] = (unsigned char)(c->s[i] >> 16);
        out[i*4+2] = (unsigned char)(c->s[i] >> 8);
        out[i*4+3] = (unsigned char)(c->s[i]);
    }
}

static void sha256_bytes(const void *data, size_t len, unsigned char out[32]) {
    Sha256 c; sha_init(&c); sha_update(&c, data, len); sha_final(&c, out);
}

/* ==========================================================================
 * Values.  A Séance value is a tagged 24-byte record (like a PHP zval).
 * ========================================================================== */

enum { T_NULL = 0, T_INT = 1, T_STR = 2, T_ARR = 3 };

typedef struct Val {
    int64_t type;
    int64_t len;          /* bytes for T_STR, element count for T_ARR */
    union {
        int64_t    i;     /* T_INT                      */
        char      *s;     /* T_STR: pointer to bytes    */
        struct Val *a;    /* T_ARR: pointer to elements */
    } u;
} Val;                    /* sizeof == 24 */

static Val VNULL = { T_NULL, 0, { 0 } };
static Val vint(int64_t n)  { Val v; v.type = T_INT; v.len = 0; v.u.i = n; return v; }

/* ==========================================================================
 * The REQUEST arena.  A single fixed buffer, reused for every request;
 * "freeing" request memory is just resetting the offset to 0.  `memory_limit`
 * caps how much one request may carve out of it (cf. PHP's memory_limit).
 * ========================================================================== */

#define ARENA_SIZE   (8 * 1024 * 1024)
static char    arena[ARENA_SIZE];
static size_t  arena_off;
static size_t  memory_limit = 256 * 1024;        /* per-request cap (cf. PHP memory_limit) */

static jmp_buf oom_bailout;      /* FATAL landing pad (cf. PHP bailout)      */
static jmp_buf script_fault;     /* non-fatal script error landing pad       */
static char    fault_msg[256];   /* message for the non-fatal fault path     */

static size_t align8(size_t n) { return (n + 7) & ~(size_t)7; }

/*
 * The request allocator.  A memory_limit (or arena) overflow is a fatal error:
 * it longjmps to oom_bailout in the accept loop, which abandons the request.
 */
static void *ralloc(size_t n) {
    size_t need = align8(n ? n : 1);
    if (need > memory_limit || arena_off + need > memory_limit ||
        arena_off + need > ARENA_SIZE) {
        longjmp(oom_bailout, 1);           /* FATAL: out of memory */
    }
    void *p = arena + arena_off;
    arena_off += need;
    return p;
}

static void arena_reset(void) { arena_off = 0; }

/* A non-fatal script error: report it and unwind to process_request, which
 * STILL runs the normal cleanup.  Ordinary mistakes never leak anything. */
static void fault(const char *fmt, const char *arg) {
    snprintf(fault_msg, sizeof fault_msg, fmt, arg ? arg : "");
    longjmp(script_fault, 1);
}

/* ==========================================================================
 * ENGINE globals -- persist for the whole worker, across requests.
 * ========================================================================== */

/* The cross-page "echo": a value a program may `leave` for the next page in the
 * same séance to `recall`.  It points at a value in the request arena and is
 * cleared at the end of each request. */
static Val *g_echo;

/* ==========================================================================
 * The "echo" wire format: a tiny PHP-serialize-alike used by `unserialize`.
 *     i:<n>;                      integer
 *     s:<len>:<len bytes>;        string
 *     a:<n>:{ <elem> <elem> ... } array of n values
 *
 * The top-level value is allocated first and published as the current echo,
 * then its contents are filled in.
 * ========================================================================== */

static const char *up;   /* cursor */

static void un_value(Val *out);

static int64_t un_int_raw(void) {
    int neg = 0;
    if (*up == '-') { neg = 1; up++; }
    int64_t v = 0;
    while (*up >= '0' && *up <= '9') v = v * 10 + (*up++ - '0');
    return neg ? -v : v;
}

static void un_value(Val *out) {
    char tag = *up;
    if (tag == 'i') {                 /* i:<n>; */
        up += 2;
        out->type = T_INT; out->len = 0; out->u.i = un_int_raw();
        if (*up == ';') up++;
    } else if (tag == 's') {          /* s:<len>:<bytes>; */
        up += 2;
        int64_t len = un_int_raw();
        if (*up == ':') up++;
        out->type = T_STR; out->len = len;
        out->u.s = ralloc((size_t)len + 1);
        for (int64_t k = 0; k < len && *up; k++) out->u.s[k] = *up++;
        out->u.s[len < 0 ? 0 : len] = 0;
        if (*up == ';') up++;
    } else if (tag == 'a') {          /* a:<n>:{...} */
        up += 2;
        int64_t n = un_int_raw();
        if (*up == ':') up++;
        if (*up == '{') up++;
        out->type = T_ARR; out->len = n;
        out->u.a = ralloc((size_t)n * sizeof(Val));
        for (int64_t k = 0; k < n; k++) un_value(&out->u.a[k]);
        if (*up == '}') up++;
    } else {
        out->type = T_NULL; out->len = 0; out->u.i = 0;
    }
}

/* Decode an echo blob and publish it to the engine global. */
static Val *do_unserialize(const char *blob) {
    up = blob;
    Val *v = ralloc(sizeof(Val));   /* top-level value */
    g_echo = v;                     /* publish as the current echo */
    un_value(v);                    /* fill in its contents */
    return v;
}

/* ==========================================================================
 * Parse/eval POOL.  AST nodes, tokens and scopes are allocated here, NOT in
 * the value arena -- so the value arena's offsets stay deterministic.  The
 * whole pool is freed after each request.
 * ========================================================================== */

typedef struct Chunk { struct Chunk *next; size_t off; size_t cap; char *buf; } Chunk;
static Chunk *pool_head;

static void *pool_alloc(size_t n) {
    n = align8(n ? n : 1);
    if (!pool_head || pool_head->off + n > pool_head->cap) {
        size_t cap = n > (1 << 20) ? n : (1 << 20);
        Chunk *c = (Chunk *)malloc(sizeof(Chunk));
        c->buf = (char *)malloc(cap);
        c->cap = cap; c->off = 0; c->next = pool_head;
        pool_head = c;
    }
    void *p = pool_head->buf + pool_head->off;
    pool_head->off += n;
    return p;
}

static void pool_reset(void) {
    Chunk *c = pool_head;
    while (c) { Chunk *n = c->next; free(c->buf); free(c); c = n; }
    pool_head = NULL;
}

static char *pool_strndup(const char *s, int n) {
    char *d = (char *)pool_alloc(n + 1);
    memcpy(d, s, n); d[n] = 0; return d;
}

/* ==========================================================================
 * Lexer
 * ========================================================================== */

enum { TK_EOF, TK_INT, TK_STR, TK_IDENT, TK_VAR, TK_KW, TK_OP };

typedef struct { int kind; int64_t ival; char *sval; int slen; int line; } Tok;

static Tok  *toks;
static int   ntoks, tcap;

static const char *KW[] = {
    "summon","whisper","rite","return","when","otherwise","chant",
    "true","false","null", NULL
};

static int is_kw(const char *s, int n) {
    for (int i = 0; KW[i]; i++)
        if ((int)strlen(KW[i]) == n && !strncmp(KW[i], s, n)) return 1;
    return 0;
}

static void push_tok(Tok t) {
    if (ntoks == tcap) {
        tcap = tcap ? tcap * 2 : 256;
        Tok *nt = (Tok *)pool_alloc(sizeof(Tok) * tcap);
        if (toks) memcpy(nt, toks, sizeof(Tok) * ntoks);
        toks = nt;
    }
    toks[ntoks++] = t;
}

static void lex(const char *src) {
    toks = NULL; ntoks = tcap = 0;
    int i = 0, line = 1, n = (int)strlen(src);
    while (i < n) {
        char c = src[i];
        if (c == '\n') { line++; i++; continue; }
        if (c == ' ' || c == '\t' || c == '\r') { i++; continue; }
        if (c == '#') { while (i < n && src[i] != '\n') i++; continue; }

        if (isdigit((unsigned char)c)) {       /* integer (dec or 0x) */
            int j = i; int64_t v = 0;
            if (src[j] == '0' && (src[j+1] == 'x' || src[j+1] == 'X')) {
                j += 2;
                while (j < n && isxdigit((unsigned char)src[j])) {
                    int d = isdigit((unsigned char)src[j]) ? src[j]-'0'
                          : (tolower(src[j])-'a'+10);
                    v = v * 16 + d; j++;
                }
            } else {
                while (j < n && isdigit((unsigned char)src[j])) v = v*10 + (src[j++]-'0');
            }
            Tok t = {0}; t.kind = TK_INT; t.ival = v; t.line = line;
            push_tok(t); i = j; continue;
        }

        if (c == '"') {                         /* string with escapes */
            int j = i + 1;
            char *buf = (char *)pool_alloc(n - i + 1);
            int bi = 0;
            while (j < n && src[j] != '"') {
                if (src[j] == '\\' && j + 1 < n) {
                    char e = src[j+1];
                    if (e == 'n') { buf[bi++] = '\n'; j += 2; }
                    else if (e == 't') { buf[bi++] = '\t'; j += 2; }
                    else if (e == 'r') { buf[bi++] = '\r'; j += 2; }
                    else if (e == '0') { buf[bi++] = '\0'; j += 2; }
                    else if (e == 'x' && j + 3 < n) {
                        int hi = src[j+2], lo = src[j+3];
                        int h = isdigit(hi)?hi-'0':(tolower(hi)-'a'+10);
                        int l = isdigit(lo)?lo-'0':(tolower(lo)-'a'+10);
                        buf[bi++] = (char)((h<<4)|l); j += 4;
                    } else { buf[bi++] = e; j += 2; }
                } else { buf[bi++] = src[j++]; }
            }
            if (j >= n) fault("unterminated string literal", NULL);
            Tok t = {0}; t.kind = TK_STR; t.sval = buf; t.slen = bi; t.line = line;
            push_tok(t); i = j + 1; continue;
        }

        if (c == '$') {                          /* variable */
            int j = i + 1;
            while (j < n && (isalnum((unsigned char)src[j]) || src[j] == '_')) j++;
            Tok t = {0}; t.kind = TK_VAR; t.sval = pool_strndup(src+i+1, j-i-1);
            t.line = line; push_tok(t); i = j; continue;
        }

        if (isalpha((unsigned char)c) || c == '_') {     /* ident / keyword */
            int j = i;
            while (j < n && (isalnum((unsigned char)src[j]) || src[j] == '_')) j++;
            Tok t = {0}; t.line = line;
            t.sval = pool_strndup(src+i, j-i); t.slen = j-i;
            t.kind = is_kw(src+i, j-i) ? TK_KW : TK_IDENT;
            push_tok(t); i = j; continue;
        }

        /* operators: two-char first */
        static const char *two[] = {"==","!=","<=",">=","&&","||",NULL};
        int matched = 0;
        for (int k = 0; two[k]; k++) {
            if (src[i] == two[k][0] && src[i+1] == two[k][1]) {
                Tok t = {0}; t.kind = TK_OP; t.sval = pool_strndup(two[k],2);
                t.slen = 2; t.line = line; push_tok(t); i += 2; matched = 1; break;
            }
        }
        if (matched) continue;

        if (strchr("+-*/%().[]{},;=<>!.", c)) {
            Tok t = {0}; t.kind = TK_OP; t.sval = pool_strndup(src+i,1);
            t.slen = 1; t.line = line; push_tok(t); i++; continue;
        }
        fault("unexpected character in spell near '%s'", pool_strndup(src+i,1));
    }
    Tok t = {0}; t.kind = TK_EOF; t.line = line; push_tok(t);
}

/* ==========================================================================
 * AST
 * ========================================================================== */

enum {
    N_INT, N_STR, N_BOOL, N_NULL, N_VAR, N_LIST,
    N_ASSIGN, N_IDXSET, N_UNARY, N_BINARY, N_CALL, N_INDEX,
    N_BLOCK, N_LET, N_WHISPER, N_RITE, N_IF, N_WHILE, N_RETURN, N_EXPRSTMT
};

typedef struct Node {
    int kind;
    int64_t ival; int bval;
    char *sval; int slen;          /* string literal bytes / name */
    char *name;                    /* var / call / rite name       */
    struct Node *a, *b, *c, *d;    /* generic children             */
    struct Node **list; int nlist; /* list items / args / stmts    */
    char **params; int nparams;    /* rite params                  */
} Node;

static Node *nnew(int kind) {
    Node *n = (Node *)pool_alloc(sizeof(Node));
    memset(n, 0, sizeof *n); n->kind = kind; return n;
}

/* ==========================================================================
 * Parser (recursive descent + precedence climbing)
 * ========================================================================== */

static int tp;   /* token pointer */

static Tok *cur(void) { return &toks[tp]; }
static int  is_op(const char *o) { return cur()->kind==TK_OP && !strcmp(cur()->sval,o); }
static int  is_kwv(const char *k){ return cur()->kind==TK_KW && !strcmp(cur()->sval,k); }

static void eat_op(const char *o) {
    if (!is_op(o)) fault("expected '%s'", (char*)o);
    tp++;
}

static Node *expression(void);
static Node *statement(void);

static Node **parse_args(int *count) {
    eat_op("(");
    Node **a = NULL; int n = 0, cap = 0;
    if (!is_op(")")) {
        for (;;) {
            if (n == cap) { cap = cap?cap*2:4; Node**na=(Node**)pool_alloc(sizeof(Node*)*cap);
                            if(a) memcpy(na,a,sizeof(Node*)*n); a=na; }
            a[n++] = expression();
            if (is_op(",")) { tp++; continue; }
            break;
        }
    }
    eat_op(")");
    *count = n; return a;
}

static Node *primary(void) {
    Tok *t = cur();
    if (t->kind == TK_INT)  { tp++; Node*n=nnew(N_INT);  n->ival=t->ival; return n; }
    if (t->kind == TK_STR)  { tp++; Node*n=nnew(N_STR);  n->sval=t->sval; n->slen=t->slen; return n; }
    if (is_kwv("true"))  { tp++; Node*n=nnew(N_BOOL); n->bval=1; return n; }
    if (is_kwv("false")) { tp++; Node*n=nnew(N_BOOL); n->bval=0; return n; }
    if (is_kwv("null"))  { tp++; return nnew(N_NULL); }
    if (t->kind == TK_VAR)  { tp++; Node*n=nnew(N_VAR); n->name=t->sval; return n; }
    if (t->kind == TK_IDENT) {                         /* a call: name(args) */
        tp++; Node *n = nnew(N_CALL); n->name = t->sval;
        if (!is_op("(")) fault("'%s' is not a variable; use $ for variables", n->name);
        n->list = parse_args(&n->nlist);
        return n;
    }
    if (is_op("(")) { tp++; Node *e = expression(); eat_op(")"); return e; }
    if (is_op("[")) {                                  /* array literal */
        tp++; Node *n = nnew(N_LIST);
        int cap = 0;
        if (!is_op("]")) {
            for (;;) {
                if (n->nlist==cap){cap=cap?cap*2:4;Node**na=(Node**)pool_alloc(sizeof(Node*)*cap);
                    if(n->list)memcpy(na,n->list,sizeof(Node*)*n->nlist);n->list=na;}
                n->list[n->nlist++] = expression();
                if (is_op(",")) { tp++; if (is_op("]")) break; continue; }
                break;
            }
        }
        eat_op("]"); return n;
    }
    fault("unexpected token '%s' in spell", cur()->sval ? cur()->sval : "<eof>");
    return NULL;
}

static Node *postfix(void) {
    Node *e = primary();
    while (is_op("[")) {                               /* indexing */
        tp++; Node *key = expression(); eat_op("]");
        Node *n = nnew(N_INDEX); n->a = e; n->b = key; e = n;
    }
    return e;
}

static Node *unary(void) {
    if (is_op("!") || is_op("-")) {
        char *op = cur()->sval; tp++;
        Node *n = nnew(N_UNARY); n->name = op; n->a = unary(); return n;
    }
    return postfix();
}

static Node *bin_level(Node *(*sub)(void), const char **ops) {
    Node *left = sub();
    for (;;) {
        int hit = -1;
        for (int k = 0; ops[k]; k++) if (is_op(ops[k])) { hit = k; break; }
        if (hit < 0) break;
        char *op = cur()->sval; tp++;
        Node *right = sub();
        Node *n = nnew(N_BINARY); n->name = op; n->a = left; n->b = right; left = n;
    }
    return left;
}

static Node *factor(void)    { const char *o[]={"*","/","%",NULL}; return bin_level(unary,o); }
static Node *term(void)      { const char *o[]={"+","-",".",NULL}; return bin_level(factor,o); }
static Node *compare(void)   { const char *o[]={"<",">","<=",">=",NULL}; return bin_level(term,o); }
static Node *equality(void)  { const char *o[]={"==","!=",NULL}; return bin_level(compare,o); }
static Node *logic_and(void) { const char *o[]={"&&",NULL}; return bin_level(equality,o); }
static Node *logic_or(void)  { const char *o[]={"||",NULL}; return bin_level(logic_and,o); }

static Node *expression(void) {
    Node *left = logic_or();
    if (is_op("=")) {                                 /* assignment */
        tp++; Node *val = expression();
        if (left->kind == N_VAR) {
            Node *n = nnew(N_ASSIGN); n->name = left->name; n->a = val; return n;
        }
        if (left->kind == N_INDEX) {
            Node *n = nnew(N_IDXSET); n->a = left->a; n->b = left->b; n->c = val; return n;
        }
        fault("invalid assignment target", NULL);
    }
    return left;
}

static Node *block(void) {
    eat_op("{");
    Node *n = nnew(N_BLOCK); int cap = 0;
    while (!is_op("}") && cur()->kind != TK_EOF) {
        if (n->nlist==cap){cap=cap?cap*2:8;Node**na=(Node**)pool_alloc(sizeof(Node*)*cap);
            if(n->list)memcpy(na,n->list,sizeof(Node*)*n->nlist);n->list=na;}
        n->list[n->nlist++] = statement();
    }
    eat_op("}"); return n;
}

static Node *statement(void) {
    if (is_kwv("summon")) {
        tp++; if (cur()->kind != TK_VAR) fault("summon expects a $variable", NULL);
        Node *n = nnew(N_LET); n->name = cur()->sval; tp++;
        eat_op("="); n->a = expression(); eat_op(";"); return n;
    }
    if (is_kwv("whisper")) { tp++; Node*n=nnew(N_WHISPER); n->a=expression(); eat_op(";"); return n; }
    if (is_kwv("return"))  { tp++; Node*n=nnew(N_RETURN);
        if (!is_op(";")) n->a = expression(); eat_op(";"); return n; }
    if (is_kwv("when")) {
        tp++; eat_op("("); Node*n=nnew(N_IF); n->a=expression(); eat_op(")");
        n->b = block();
        if (is_kwv("otherwise")) { tp++; n->c = block(); }
        return n;
    }
    if (is_kwv("chant")) {
        tp++; eat_op("("); Node*n=nnew(N_WHILE); n->a=expression(); eat_op(")");
        n->b = block(); return n;
    }
    if (is_kwv("rite")) {
        tp++; if (cur()->kind != TK_IDENT) fault("rite needs a name", NULL);
        Node *n = nnew(N_RITE); n->name = cur()->sval; tp++;
        eat_op("("); int cap = 0;
        if (!is_op(")")) {
            for (;;) {
                if (cur()->kind != TK_VAR) fault("rite params must be $variables", NULL);
                if (n->nparams==cap){cap=cap?cap*2:4;char**np=(char**)pool_alloc(sizeof(char*)*cap);
                    if(n->params)memcpy(np,n->params,sizeof(char*)*n->nparams);n->params=np;}
                n->params[n->nparams++] = cur()->sval; tp++;
                if (is_op(",")) { tp++; continue; }
                break;
            }
        }
        eat_op(")"); n->a = block(); return n;
    }
    if (is_op("{")) { return block(); }
    Node *e = expression(); eat_op(";");
    Node *n = nnew(N_EXPRSTMT); n->a = e; return n;
}

static Node *parse_program(void) {
    tp = 0;
    Node *n = nnew(N_BLOCK); int cap = 0;
    while (cur()->kind != TK_EOF) {
        if (n->nlist==cap){cap=cap?cap*2:16;Node**na=(Node**)pool_alloc(sizeof(Node*)*cap);
            if(n->list)memcpy(na,n->list,sizeof(Node*)*n->nlist);n->list=na;}
        n->list[n->nlist++] = statement();
    }
    return n;
}

/* ==========================================================================
 * Environment (scopes)
 * ========================================================================== */

#define MAX_VARS 512
typedef struct Scope {
    char *names[MAX_VARS];
    Val   vals[MAX_VARS];
    int   n;
    struct Scope *parent;
} Scope;

static Scope *scope_new(Scope *parent) {
    Scope *s = (Scope *)pool_alloc(sizeof(Scope));
    s->n = 0; s->parent = parent; return s;
}
static Val *scope_find(Scope *s, const char *name) {
    for (; s; s = s->parent)
        for (int i = 0; i < s->n; i++)
            if (!strcmp(s->names[i], name)) return &s->vals[i];
    return NULL;
}
static void scope_set_local(Scope *s, const char *name, Val v) {
    for (int i = 0; i < s->n; i++) if (!strcmp(s->names[i], name)) { s->vals[i] = v; return; }
    if (s->n >= MAX_VARS) fault("too many variables in one scope", NULL);
    s->names[s->n] = (char *)name; s->vals[s->n] = v; s->n++;
}

/* rite (function) registry */
#define MAX_RITES 256
static struct { char *name; Node *rite; } rites[MAX_RITES];
static int nrites;

static Node *rite_find(const char *name) {
    for (int i = 0; i < nrites; i++) if (!strcmp(rites[i].name, name)) return rites[i].rite;
    return NULL;
}

/* ==========================================================================
 * Output buffer (the HTTP response body built by `whisper`)
 * ========================================================================== */

#define OUT_MAX (128 * 1024)
static char out_buf[OUT_MAX];
static int  out_len;

static void out_write(const char *s, int n) {
    if (n < 0) n = 0;
    if (out_len + n > OUT_MAX) n = OUT_MAX - out_len;
    if (n > 0) { memcpy(out_buf + out_len, s, n); out_len += n; }
}
static void out_cstr(const char *s) { out_write(s, (int)strlen(s)); }

/* ==========================================================================
 * Evaluator
 * ========================================================================== */

static long  step_budget;
static int   call_depth;
#define MAX_STEPS   5000000
#define MAX_DEPTH   200

typedef struct { int is_return; Val val; } Flow;  /* control-flow carrier */

static Val eval(Node *n, Scope *sc);
static Flow exec_block(Node *blk, Scope *sc);

static int truthy(Val v) {
    switch (v.type) {
        case T_NULL: return 0;
        case T_INT:  return v.u.i != 0;
        case T_STR:  return v.len != 0;
        case T_ARR:  return v.len != 0;
    }
    return 0;
}

static char *int_to_str(int64_t n, int *outlen) {
    char tmp[32]; int t = snprintf(tmp, sizeof tmp, "%lld", (long long)n);
    char *s = (char *)ralloc(t + 1); memcpy(s, tmp, t); s[t] = 0;
    if (outlen) *outlen = t; return s;
}

static Val str_val(const char *s, int64_t len) {
    Val v; v.type = T_STR; v.len = len;
    v.u.s = (char *)ralloc((size_t)len + 1);
    memcpy(v.u.s, s, (size_t)len); v.u.s[len] = 0; return v;
}

/* value -> displayable string bytes (into arena) */
static Val stringify(Val v) {
    if (v.type == T_STR) return v;
    if (v.type == T_INT) { int l; char *s = int_to_str(v.u.i, &l); return (Val){T_STR,l,{.s=s}}; }
    if (v.type == T_NULL) return str_val("null", 4);
    if (v.type == T_ARR) {
        /* [a, b, c] */
        char *buf = (char*)ralloc(2); buf[0]='['; int bl=1;
        for (int64_t i=0;i<v.len;i++){
            Val e = stringify(v.u.a[i]);
            char *nb=(char*)ralloc(bl+e.len+2); memcpy(nb,buf,bl); buf=nb;
            if(i){buf[bl++]=',';buf[bl++]=' ';}
            memcpy(buf+bl,e.u.s,e.len); bl+=e.len;
        }
        char *nb=(char*)ralloc(bl+2);memcpy(nb,buf,bl);buf=nb;buf[bl++]=']';buf[bl]=0;
        return (Val){T_STR,bl,{.s=buf}};
    }
    return str_val("", 0);
}

static int64_t as_int(Val v, const char *ctx) {
    if (v.type == T_INT) return v.u.i;
    if (v.type == T_STR) return strtoll(v.u.s, NULL, 0);
    if (v.type == T_NULL) return 0;
    fault("expected a number in %s", (char*)ctx); return 0;
}

static int val_eq(Val a, Val b) {
    if (a.type != b.type) return 0;
    switch (a.type) {
        case T_NULL: return 1;
        case T_INT:  return a.u.i == b.u.i;
        case T_STR:  return a.len == b.len && !memcmp(a.u.s, b.u.s, a.len);
        case T_ARR:  return a.u.a == b.u.a;
    }
    return 0;
}

/* ---- builtins ---------------------------------------------------------- */

static Val call_builtin(const char *name, Val *args, int nargs, int *handled) {
    *handled = 1;

    if (!strcmp(name, "len")) {
        if (nargs!=1) fault("len() takes 1 argument", NULL);
        if (args[0].type==T_STR || args[0].type==T_ARR) return vint(args[0].len);
        fault("len() wants a string or array", NULL);
    }
    if (!strcmp(name, "str"))  { if(nargs!=1)fault("str() takes 1 argument",NULL);  return stringify(args[0]); }
    if (!strcmp(name, "int"))  { if(nargs!=1)fault("int() takes 1 argument",NULL);  return vint(as_int(args[0],"int()")); }
    if (!strcmp(name, "type")) {
        if(nargs!=1)fault("type() takes 1 argument",NULL);
        const char *t = args[0].type==T_NULL?"null":args[0].type==T_INT?"int":
                        args[0].type==T_STR?"str":"array";
        return str_val(t,(int)strlen(t));
    }
    if (!strcmp(name, "chr")) {
        if(nargs!=1)fault("chr() takes 1 argument",NULL);
        char c=(char)as_int(args[0],"chr()"); return str_val(&c,1);
    }
    if (!strcmp(name, "ord")) {
        if(nargs!=1||args[0].type!=T_STR||args[0].len<1)fault("ord() wants a non-empty string",NULL);
        return vint((unsigned char)args[0].u.s[0]);
    }
    if (!strcmp(name, "repeat")) {
        if(nargs!=2||args[0].type!=T_STR)fault("repeat(string,count)",NULL);
        int64_t cnt=as_int(args[1],"repeat()"); if(cnt<0)cnt=0;
        int64_t sl=args[0].len, total=sl*cnt;
        char *buf=(char*)ralloc((size_t)total+1);    /* huge count -> OOM */
        for(int64_t k=0;k<cnt;k++) memcpy(buf+k*sl,args[0].u.s,sl);
        buf[total]=0; return (Val){T_STR,total,{.s=buf}};
    }
    if (!strcmp(name, "range")) {
        if(nargs!=1)fault("range(n)",NULL);
        int64_t cnt=as_int(args[0],"range()"); if(cnt<0)cnt=0;
        Val *a=(Val*)ralloc((size_t)cnt*sizeof(Val));  /* huge n -> OOM */
        for(int64_t k=0;k<cnt;k++)a[k]=vint(k);
        return (Val){T_ARR,cnt,{.a=a}};
    }
    if (!strcmp(name, "concat")) {
        int64_t tot=0; for(int i=0;i<nargs;i++){Val s=stringify(args[i]);args[i]=s;tot+=s.len;}
        char *buf=(char*)ralloc((size_t)tot+1); int64_t o=0;
        for(int i=0;i<nargs;i++){memcpy(buf+o,args[i].u.s,args[i].len);o+=args[i].len;}
        buf[tot]=0; return (Val){T_STR,tot,{.s=buf}};
    }

    /* ---- the cross-séance "echo" feature ------------------------------ */

    if (!strcmp(name, "leave")) {           /* publish a value for the next page */
        if(nargs!=1)fault("leave(value)",NULL);
        Val *p=(Val*)ralloc(sizeof(Val));   /* copy into the request arena */
        *p=args[0]; g_echo=p;               /* engine global -> arena value */
        return VNULL;
    }
    if (!strcmp(name, "recall")) {          /* read back the echo */
        if(nargs!=0)fault("recall() takes no arguments",NULL);
        if(!g_echo) return VNULL;
        return *g_echo;
    }
    if (!strcmp(name, "echo_poke")) {       /* overwrite the echo string's first 8 bytes */
        if(nargs!=1)fault("echo_poke(value)",NULL);
        if(g_echo && g_echo->type==T_STR) { *(int64_t*)(g_echo->u.s)=as_int(args[0],"echo_poke()"); }
        return VNULL;
    }
    if (!strcmp(name, "echo_write")) {      /* copy bytes into the echo string's buffer */
        if(nargs!=1||args[0].type!=T_STR)fault("echo_write(string)",NULL);
        if(g_echo && g_echo->type==T_STR) {
            int64_t n = args[0].len;
            if(n > g_echo->len) n = g_echo->len;   /* bounded by the echo's own length */
            if(n > 0) memcpy(g_echo->u.s, args[0].u.s, (size_t)n);
        }
        return VNULL;
    }
    if (!strcmp(name, "unserialize")) {     /* decode an echo blob */
        if(nargs!=1||args[0].type!=T_STR)fault("unserialize(string)",NULL);
        return *do_unserialize(args[0].u.s);
    }
    if (!strcmp(name, "knell")) {           /* ring the bell: write a line to the worker log */
        if(nargs!=1)fault("knell(string)",NULL);
        Val s=stringify(args[0]); puts(s.u.s); return VNULL;
    }

    *handled = 0; return VNULL;
}

static Val call_rite(Node *rite, Val *args, int nargs) {
    if (nargs != rite->nparams)
        fault("rite '%s' called with the wrong number of arguments", rite->name);
    if (++call_depth > MAX_DEPTH) fault("spell recursion too deep", NULL);
    Scope *local = scope_new(NULL);               /* rites get a fresh scope */
    for (int i = 0; i < rite->nparams; i++)
        scope_set_local(local, rite->params[i], args[i]);
    Flow f = exec_block(rite->a, local);
    call_depth--;
    return f.is_return ? f.val : VNULL;
}

static Val eval(Node *n, Scope *sc) {
    if (--step_budget < 0) fault("spell exceeded its step budget", NULL);
    switch (n->kind) {
        case N_INT:  return vint(n->ival);
        case N_STR:  return str_val(n->sval, n->slen);
        case N_BOOL: return vint(n->bval ? 1 : 0);
        case N_NULL: return VNULL;
        case N_VAR: {
            Val *p = scope_find(sc, n->name);
            if (!p) fault("unknown variable $%s", n->name);
            return *p;
        }
        case N_ASSIGN: {
            Val v = eval(n->a, sc);
            Val *p = scope_find(sc, n->name);
            if (p) *p = v; else scope_set_local(sc, n->name, v);
            return v;
        }
        case N_IDXSET: {
            Val base = eval(n->a, sc);
            Val key  = eval(n->b, sc);
            Val v    = eval(n->c, sc);
            if (base.type != T_ARR) fault("cannot index-assign a non-array", NULL);
            int64_t k = as_int(key, "index");
            if (k < 0 || k >= base.len) fault("array index out of range", NULL);
            base.u.a[k] = v; return v;
        }
        case N_LIST: {
            Val *a = (Val*)ralloc((size_t)n->nlist * sizeof(Val));
            for (int i = 0; i < n->nlist; i++) a[i] = eval(n->list[i], sc);
            return (Val){T_ARR, n->nlist, {.a = a}};
        }
        case N_INDEX: {
            Val base = eval(n->a, sc);
            Val key  = eval(n->b, sc);
            int64_t k = as_int(key, "index");
            if (base.type == T_ARR) {
                if (k < 0 || k >= base.len) fault("array index out of range", NULL);
                return base.u.a[k];
            }
            if (base.type == T_STR) {
                if (k < 0 || k >= base.len) fault("string index out of range", NULL);
                return str_val(&base.u.s[k], 1);
            }
            fault("cannot index this value", NULL);
        }
        case N_UNARY: {
            Val v = eval(n->a, sc);
            if (!strcmp(n->name, "-")) return vint(-as_int(v, "negation"));
            if (!strcmp(n->name, "!")) return vint(!truthy(v));
            fault("bad unary operator", NULL);
        }
        case N_BINARY: {
            const char *op = n->name;
            if (!strcmp(op, "&&")) { Val l=eval(n->a,sc); return truthy(l)?eval(n->b,sc):l; }
            if (!strcmp(op, "||")) { Val l=eval(n->a,sc); return truthy(l)?l:eval(n->b,sc); }
            Val a = eval(n->a, sc), b = eval(n->b, sc);
            if (!strcmp(op, ".")) {                      /* string concat */
                Val sa = stringify(a), sb = stringify(b);
                int64_t t = sa.len + sb.len;
                char *buf = (char*)ralloc((size_t)t + 1);
                memcpy(buf, sa.u.s, sa.len); memcpy(buf+sa.len, sb.u.s, sb.len);
                buf[t]=0; return (Val){T_STR,t,{.s=buf}};
            }
            if (!strcmp(op, "==")) return vint(val_eq(a,b));
            if (!strcmp(op, "!=")) return vint(!val_eq(a,b));
            int64_t x=as_int(a,"arithmetic"), y=as_int(b,"arithmetic");
            if (!strcmp(op,"+")) return vint(x+y);
            if (!strcmp(op,"-")) return vint(x-y);
            if (!strcmp(op,"*")) return vint(x*y);
            if (!strcmp(op,"/")) { if(!y)fault("division by zero",NULL); return vint(x/y); }
            if (!strcmp(op,"%")) { if(!y)fault("modulo by zero",NULL);   return vint(x%y); }
            if (!strcmp(op,"<"))  return vint(x<y);
            if (!strcmp(op,">"))  return vint(x>y);
            if (!strcmp(op,"<=")) return vint(x<=y);
            if (!strcmp(op,">=")) return vint(x>=y);
            fault("bad operator", NULL);
        }
        case N_CALL: {
            Val args[64]; int na = n->nlist;
            if (na > 64) fault("too many arguments", NULL);
            for (int i = 0; i < na; i++) args[i] = eval(n->list[i], sc);
            int handled; Val r = call_builtin(n->name, args, na, &handled);
            if (handled) return r;
            Node *rite = rite_find(n->name);
            if (rite) return call_rite(rite, args, na);
            fault("unknown rite '%s'", n->name);
        }
        default: fault("cannot evaluate this node", NULL);
    }
    return VNULL;
}

static Flow exec_block(Node *blk, Scope *sc) {
    Flow none = {0, VNULL};
    for (int i = 0; i < blk->nlist; i++) {
        Node *s = blk->list[i];
        if (--step_budget < 0) fault("spell exceeded its step budget", NULL);
        switch (s->kind) {
            case N_LET:     scope_set_local(sc, s->name, eval(s->a, sc)); break;
            case N_ASSIGN:  eval(s, sc); break;
            case N_EXPRSTMT:eval(s->a, sc); break;
            case N_WHISPER: { Val v = stringify(eval(s->a, sc)); out_write(v.u.s, (int)v.len);
                              out_cstr("\n"); break; }
            case N_RETURN:  { Flow f; f.is_return=1; f.val = s->a?eval(s->a,sc):VNULL; return f; }
            case N_IF: {
                if (truthy(eval(s->a, sc))) { Flow f=exec_block(s->b,sc); if(f.is_return)return f; }
                else if (s->c) { Flow f=exec_block(s->c,sc); if(f.is_return)return f; }
                break;
            }
            case N_WHILE: {
                while (truthy(eval(s->a, sc))) {
                    if (--step_budget < 0) fault("spell exceeded its step budget", NULL);
                    Flow f = exec_block(s->b, sc); if (f.is_return) return f;
                }
                break;
            }
            case N_BLOCK:   { Flow f=exec_block(s,sc); if(f.is_return)return f; break; }
            case N_RITE:    break;   /* hoisted before execution */
            default:        eval(s, sc); break;
        }
    }
    return none;
}

/* Register all top-level rites (so forward references work), then run. */
static void run_program(Node *prog, Scope *global) {
    nrites = 0;
    for (int i = 0; i < prog->nlist; i++) {
        Node *s = prog->list[i];
        if (s->kind == N_RITE) {
            if (nrites >= MAX_RITES) fault("too many rites", NULL);
            rites[nrites].name = s->name; rites[nrites].rite = s; nrites++;
        }
    }
    exec_block(prog, global);
}

/* ==========================================================================
 * Minimal HTTP/1.1 worker (single process; requests handled sequentially so
 * engine globals persist across them, exactly like a reused PHP worker).
 * ========================================================================== */

typedef struct {
    char  method[8];
    char  path[1024];
    char  echo[8192];      /* X-Seance-Echo header value */
    int   have_echo;
    char  powh[160];       /* X-Pow header value           */
    int   have_pow;
    char *body; int body_len;
} Req;

static int clientfd = -1;

static void http_write(const char *buf, int len) {
    int off = 0;
    while (off < len) { int w = write(clientfd, buf + off, len - off); if (w <= 0) break; off += w; }
}
static void respond(int code, const char *ctype, const char *body, int blen) {
    const char *reason = code==200?"OK":code==400?"Bad Request":
                         code==403?"Forbidden":code==404?"Not Found":
                         code==500?"Internal Server Error":"OK";
    char hdr[256];
    int n = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n"
        "Connection: close\r\n\r\n", code, reason, ctype, blen);
    http_write(hdr, n);                /* headers via write(), never puts() */
    if (blen) http_write(body, blen);
}

/* ==========================================================================
 * Front-door wards: a signature WAF and a proof-of-work gate in front of
 * /seance.  These sit OUTSIDE the interpreter; they do not change the language
 * or the use-after-free -- they only make the door costlier to knock on.  None
 * of the intended solution's traffic trips the WAF.
 * ========================================================================== */

static unsigned char pow_secret[16];
static int  pow_bits = 24;            /* leading zero bits required; 0 disables */
#define POW_WINDOW 120                /* seconds a challenge stays valid         */

/* The challenge for a time window: first 12 bytes of sha256(secret || ":" || w),
 * hex-encoded (24 chars).  Stateless -- no per-challenge storage. */
static void pow_challenge_for(long w, char out[25]) {
    unsigned char m[40]; size_t ml = sizeof pow_secret;
    memcpy(m, pow_secret, sizeof pow_secret);
    m[ml++] = ':';
    ml += (size_t)snprintf((char*)m + ml, sizeof m - ml, "%ld", w);
    unsigned char d[32]; sha256_bytes(m, ml, d);
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 12; i++) { out[2*i] = hx[d[i] >> 4]; out[2*i+1] = hx[d[i] & 15]; }
    out[24] = 0;
}

static int pow_leading_zero_bits(const unsigned char d[32]) {
    int n = 0;
    for (int i = 0; i < 32; i++) {
        if (d[i] == 0) { n += 8; continue; }
        unsigned char b = d[i];
        while (!(b & 0x80)) { n++; b <<= 1; }
        break;
    }
    return n;
}

/* Validate an "X-Pow: <challenge>.<nonce>" header. */
static int pow_ok(const char *hdr) {
    if (pow_bits <= 0) return 1;                      /* gate disabled */
    if (!hdr || !*hdr) return 0;
    const char *dot = strchr(hdr, '.');
    if (!dot) return 0;
    if ((size_t)(dot - hdr) != 24) return 0;          /* 24 hex challenge chars */
    char chal[25]; memcpy(chal, hdr, 24); chal[24] = 0;
    const char *nonce = dot + 1;
    if (!*nonce || strlen(nonce) > 128) return 0;
    long w = (long)(time(NULL) / POW_WINDOW);
    char c0[25], c1[25];
    pow_challenge_for(w, c0); pow_challenge_for(w - 1, c1);
    if (strcmp(chal, c0) && strcmp(chal, c1)) return 0;   /* stale / forged */
    char m[200]; int ml = snprintf(m, sizeof m, "%s%s", chal, nonce);
    unsigned char d[32]; sha256_bytes(m, (size_t)ml, d);
    return pow_leading_zero_bits(d) >= pow_bits;
}

/* Emit the proof-of-work instructions (200 for GET /pow; 403 for a /seance
 * request that arrives without a valid proof). */
static void pow_respond(int code) {
    char c0[25]; pow_challenge_for((long)(time(NULL) / POW_WINDOW), c0);
    char body[512];
    int n = snprintf(body, sizeof body,
        "%sproof-of-work required to commune with the worker.\n"
        "pow %s %d\n"
        "find a nonce so sha256(\"%s\" + nonce) begins with %d zero bits,\n"
        "then resend POST /seance with header:  X-Pow: %s.<nonce>\n"
        "(a solved proof is valid for ~%d seconds and may be reused.)\n",
        code == 403 ? "warded: " : "", c0, pow_bits, c0, pow_bits, c0, POW_WINDOW);
    respond(code, "text/plain", body, n);
}

/* Case-insensitive substring over a (possibly non-terminated) buffer. */
static int ci_contains(const char *hay, int hl, const char *needle) {
    int nl = (int)strlen(needle);
    if (nl == 0 || hl < nl) return 0;
    for (int i = 0; i + nl <= hl; i++) {
        int k = 0;
        while (k < nl && tolower((unsigned char)hay[i+k]) == tolower((unsigned char)needle[k])) k++;
        if (k == nl) return 1;
    }
    return 0;
}

/* The WAF.  Returns a refusal reason, or NULL to allow.  It blocks the naive,
 * obvious shapes (a giant literal OOM count; generic scanner/traversal probes)
 * -- so a player must shape the exploit with intent -- while leaving every
 * primitive the intended chain needs untouched. */
static const char *waf_check(Req *r) {
    const char *body = r->body ? r->body : "";
    int bl = r->body_len;
    if (bl > 4096) return "payload too large";
    const char *echo = r->have_echo ? r->echo : "";
    int el = (int)strlen(echo);

    /* (1) no 7+ digit decimal literals: the naive OOM uses a huge count, but the
     *     real memory_limit is far smaller -- shape the OOM to fit under it. */
    for (int pass = 0; pass < 2; pass++) {
        const char *s = pass ? echo : body;
        int sl = pass ? el : bl, run = 0;
        for (int i = 0; i < sl; i++) {
            if (s[i] >= '0' && s[i] <= '9') { if (++run >= 7) return "oversized numeric literal"; }
            else run = 0;
        }
    }
    /* (2) generic scanner / traversal / RCE signatures. */
    static const char *sig[] = {
        "/etc/passwd", "../", "..\\", "%2e%2e", "/proc/self", "union select",
        "<script", "/bin/sh", "/bin/bash", "wget ", "curl ", "${jndi", NULL
    };
    int pl = (int)strlen(r->path);
    for (int k = 0; sig[k]; k++)
        if (ci_contains(body, bl, sig[k]) || ci_contains(echo, el, sig[k]) ||
            ci_contains(r->path, pl, sig[k]))
            return "forbidden pattern";
    return NULL;
}

/* The per-request handler. */
static void process_request(Req *r) {
    arena_reset();
    out_len = 0;

    if (r->have_echo) do_unserialize(r->echo);   /* resume an echo from the header */

    /* Non-fatal (script) errors land HERE and STILL run the cleanup. */
    if (setjmp(script_fault)) {
        respond(400, "text/plain", fault_msg, (int)strlen(fault_msg));
        g_echo = NULL;
        return;
    }

    step_budget = MAX_STEPS; call_depth = 0;
    const char *src = r->body ? r->body : "";
    lex(src);
    Node *prog = parse_program();
    Scope *global = scope_new(NULL);
    run_program(prog, global);

    respond(200, "text/plain", out_buf, out_len);

    g_echo = NULL;                 /* clear the echo at the end of the request */
}

static const char *LANDING =
"<!doctype html><html><head><meta charset=utf-8>"
"<meta name=viewport content='width=device-width,initial-scale=1'>"
"<title>The Séance</title><style>"
"body{background:#0b0410;color:#e6d8f0;font-family:ui-monospace,Menlo,monospace;"
"max-width:760px;margin:2rem auto;padding:0 1rem;line-height:1.5}"
"h1{color:#c77dff;font-weight:600}a{color:#ff9e64}"
"textarea{width:100%;height:12rem;background:#160a22;color:#e6d8f0;border:1px solid #3a2050;"
"border-radius:8px;padding:.6rem;font:inherit}"
"button{background:#7b2cbf;color:#fff;border:0;border-radius:8px;padding:.5rem 1rem;cursor:pointer}"
"pre{background:#160a22;border:1px solid #3a2050;border-radius:8px;padding:.6rem;white-space:pre-wrap}"
"code{color:#ffd6a5}.muted{color:#9a86ad}</style></head><body>"
"<h1>&#128123; The S&eacute;ance</h1>"
"<p class=muted>One worker. Many s&eacute;ances. Mind the spirits that linger between them.</p>"
"<p class=muted>The door is warded: <code>/seance</code> wants a proof-of-work "
"(see <code>GET /pow</code>) sent back in an <code>X-Pow</code> header, and a filter "
"turns away the obvious probes.</p>"
"<p>Write a <b>Séance</b> program and the worker will brew it. The language has "
"<code>summon $x = ...;</code>, <code>whisper ...;</code>, <code>rite f($a){...}</code>, "
"<code>when/otherwise</code>, <code>chant</code> loops, arrays and the usual builtins "
"(<code>len str int chr ord repeat range concat</code>). Full source is handed out.</p>"
"<textarea id=src>whisper \"boo, mortal!\";\n"
"summon $n = 3;\nchant ($n > 0) { whisper \"toll: \" . str($n); $n = $n - 1; }\n</textarea>"
"<p><button onclick=cast()>brew</button></p><pre id=out>...</pre>"
"<script>async function cast(){let r=await fetch('/seance',{method:'POST',"
"headers:{'Content-Type':'text/plain'},body:document.getElementById('src').value});"
"document.getElementById('out').textContent=await r.text();}</script>"
"</body></html>";

static void route(Req *r) {
    if (!strcmp(r->method, "GET") && !strcmp(r->path, "/healthz")) {
        respond(200, "text/plain", "ok", 2); return;
    }
    if (!strcmp(r->method, "GET") && !strcmp(r->path, "/pow")) {
        pow_respond(200); return;
    }
    if (!strcmp(r->method, "GET") && !strcmp(r->path, "/")) {
        respond(200, "text/html", LANDING, (int)strlen(LANDING)); return;
    }
    if (!strcmp(r->method, "POST") && !strcmp(r->path, "/seance")) {
        const char *bad = waf_check(r);              /* WAF first */
        if (bad) {
            char m[128]; int n = snprintf(m, sizeof m, "warded: %s\n", bad);
            respond(403, "text/plain", m, n); return;
        }
        if (!pow_ok(r->have_pow ? r->powh : NULL)) { /* then proof-of-work */
            pow_respond(403); return;
        }
        process_request(r); return;
    }
    respond(404, "text/plain", "no such page\n", 13);
}

static char reqbuf[1 << 20];
static int read_request(Req *r) {
    memset(r, 0, sizeof *r);
    int total = 0, hdr_end = -1;
    while (total < (int)sizeof(reqbuf) - 1) {
        int n = read(clientfd, reqbuf + total, sizeof(reqbuf) - 1 - total);
        if (n <= 0) { if (total == 0) return 0; break; }
        total += n; reqbuf[total] = 0;
        char *p = strstr(reqbuf, "\r\n\r\n");
        if (p) { hdr_end = (int)(p - reqbuf) + 4; break; }
    }
    if (hdr_end < 0) return 1;

    sscanf(reqbuf, "%7s %1023s", r->method, r->path);
    char *q = strchr(r->path, '?'); if (q) *q = 0;

    int content_len = 0;
    char *line = strstr(reqbuf, "\r\n");
    while (line && line < reqbuf + hdr_end) {
        line += 2;
        if (line >= reqbuf + hdr_end - 2) break;
        if (!strncasecmp(line, "Content-Length:", 15)) content_len = atoi(line + 15);
        else if (!strncasecmp(line, "X-Seance-Echo:", 14)) {
            const char *v = line + 14; while (*v==' ') v++;
            const char *e = strstr(v, "\r\n"); int vl = e?(int)(e-v):0;
            if (vl > (int)sizeof(r->echo)-1) vl = sizeof(r->echo)-1;
            memcpy(r->echo, v, vl); r->echo[vl]=0; r->have_echo=1;
        }
        else if (!strncasecmp(line, "X-Pow:", 6)) {
            const char *v = line + 6; while (*v==' ') v++;
            const char *e = strstr(v, "\r\n"); int vl = e?(int)(e-v):0;
            if (vl > (int)sizeof(r->powh)-1) vl = sizeof(r->powh)-1;
            memcpy(r->powh, v, vl); r->powh[vl]=0; r->have_pow=1;
        }
        line = strstr(line, "\r\n");
    }

    int have_body = total - hdr_end;
    if (content_len > 0) {
        if (content_len > (int)sizeof(reqbuf) - hdr_end - 1)
            content_len = sizeof(reqbuf) - hdr_end - 1;
        while (have_body < content_len) {
            int n = read(clientfd, reqbuf + hdr_end + have_body, content_len - have_body);
            if (n <= 0) break; have_body += n;
        }
        reqbuf[hdr_end + content_len] = 0;
        r->body = reqbuf + hdr_end; r->body_len = content_len;
    }
    return 1;
}

static int make_listen(const char *host, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET; addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);
    if (bind(s, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); exit(1); }
    if (listen(s, 64) < 0) { perror("listen"); exit(1); }
    return s;
}

/* One worker: a single long-lived process that answers request after request
 * with persistent engine state (the cross-request UAF lives here).  The parent
 * watchdog in main() re-spawns this if it ever dies (e.g. an exploit), so one
 * player's RCE never takes the service down for everyone. */
static void serve_loop(int s) {
    puts("Poltergeist worker online -- one spirit, many seances.");
    fflush(stdout);

    for (;;) {
        struct sockaddr_in c; socklen_t cl = sizeof c;
        clientfd = accept(s, (struct sockaddr *)&c, &cl);
        if (clientfd < 0) continue;

        /* A stalled client must not wedge the single sequential worker. */
        struct timeval tv = { 15, 0 };
        setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(clientfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

        Req r;
        if (read_request(&r)) {
            pool_reset();
            if (setjmp(oom_bailout)) {
                /* fatal out-of-memory: tidy the request arena and report 500. */
                arena_reset();
                respond(500, "text/plain", "fatal: out of memory\n", 21);
            } else {
                route(&r);
            }
            pool_reset();
        }
        close(clientfd); clientfd = -1;
    }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGPIPE, SIG_IGN);

    /* Seed the proof-of-work secret (random per worker lifetime) and read the
     * difficulty from the environment (POW_BITS; 0 disables the gate). */
    {
        FILE *rf = fopen("/dev/urandom", "rb");
        if (!rf || fread(pow_secret, 1, sizeof pow_secret, rf) != sizeof pow_secret) {
            uint64_t seed = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 20);
            for (size_t i = 0; i < sizeof pow_secret; i++) {
                seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
                pow_secret[i] = (unsigned char)(seed >> 33);
            }
        }
        if (rf) fclose(rf);
        const char *pb = getenv("POW_BITS");
        if (pb && *pb) pow_bits = atoi(pb);
    }

    const char *host = "0.0.0.0"; int port = 8080;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-S") && i + 1 < argc) {
            char *hp = argv[++i]; char *colon = strchr(hp, ':');
            if (colon) { *colon = 0; host = hp; port = atoi(colon + 1); } else port = atoi(hp);
        } else if (!strcmp(argv[i], "-m") && i + 1 < argc) {
            memory_limit = (size_t)strtoull(argv[++i], NULL, 0);
        }
    }

    /* The listening socket lives in the watchdog parent; each worker inherits it.
     * If a worker dies (a solved exploit ends with _exit, or crashes), the parent
     * simply forks a fresh one -- the port never drops and the container is never
     * restarted. */
    signal(SIGCHLD, SIG_DFL);
    int s = make_listen(host, port);
    for (;;) {
        time_t t0 = time(NULL);
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); sleep(1); continue; }
        if (pid == 0) { serve_loop(s); _exit(0); }   /* worker */
        int status; waitpid(pid, &status, 0);        /* worker ended -> respawn */
        if (time(NULL) - t0 < 1) usleep(200000);     /* never a tight crash-loop */
    }
    return 0;
}
