/*
 * DEAD SIGNAL -- satellite recovery authentication terminal
 * ---------------------------------------------------------
 * Presents a recovery terminal and asks for the 24-character
 * authentication token from the satellite's final transmission.
 *
 * The token is validated by a five-stage transform (see organizer/writeup.md):
 *
 *   stage_permute   -- nontrivial byte permutation of the 24 token bytes
 *   stage_index_mix -- index-dependent XOR and 8-bit rotations
 *   stage_roll      -- rolling 32-bit state: each byte influences the next
 *   stage_block_arx -- 32-bit affine mix plus a cross-dword ARX chain
 *   stage_verify    -- final comparison against embedded target data
 *
 * The flag is stored only as ciphertext.  Its key is derived from the
 * supplied token via ARX_HASH, so patching the acceptance branch with a
 * wrong token decrypts to noise, never to the flag.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dsig_consts.h"
#include "generated_constants.h"

/* ---------------------------------------------------------------- */
/* primitives                                                        */
/* ---------------------------------------------------------------- */

static inline uint8_t rol8(uint8_t x, unsigned n) {
    n &= 7u;
    return (uint8_t)((x << n) | (x >> (8u - n)));
}

static inline uint8_t ror8(uint8_t x, unsigned n) {
    n &= 7u;
    return (uint8_t)((x >> n) | (x << (8u - n)));
}

static inline uint32_t rol32(uint32_t x, unsigned n) {
    n &= 31u;
    /* (32 - n) & 31 keeps the shift amount < 32 even for n == 0 (UB-free) */
    return (x << n) | (x >> ((32u - n) & 31u));
}

/* fold the 32-bit rolling state down to one byte */
static inline uint8_t fold8(uint32_t s) {
    return (uint8_t)(s ^ (s >> 8) ^ (s >> 16) ^ (s >> 24));
}

/* ---------------------------------------------------------------- */
/* validation stages                                                 */
/* ---------------------------------------------------------------- */

/* Stage A: nontrivial permutation of the token bytes. */
__attribute__((noinline))
static void stage_permute(const uint8_t *tok, uint8_t *out) {
    for (unsigned i = 0; i < DSIG_TOKEN_LEN; i++)
        out[i] = tok[G_CONST.perm[i]];
}

/* Stage B: index-dependent XOR keystream and bit rotations. */
__attribute__((noinline))
static void stage_index_mix(const uint8_t *in, uint8_t *out) {
    for (unsigned i = 0; i < DSIG_TOKEN_LEN; i++)
        out[i] = rol8((uint8_t)(in[i] ^ G_CONST.xkey[i]), G_CONST.rots[i]);
}

/* Stage C: rolling internal state; byte i perturbs every later byte. */
__attribute__((noinline))
static void stage_roll(const uint8_t *in, uint8_t *out) {
    uint32_t state = G_CONST.roll_seed;
    for (unsigned i = 0; i < DSIG_TOKEN_LEN; i++) {
        out[i] = (uint8_t)(in[i] ^ fold8(state));
        state = state * G_CONST.roll_mul + G_CONST.roll_add + in[i];
    }
}

/* Stage D: 32-bit affine mix per dword, then a cross-dword ARX chain. */
__attribute__((noinline))
static void stage_block_arx(const uint8_t *in, uint8_t *out) {
    uint32_t d[DSIG_BLK_COUNT];
    for (unsigned j = 0; j < DSIG_BLK_COUNT; j++) {
        uint32_t x = (uint32_t)in[4 * j]
                   | ((uint32_t)in[4 * j + 1] << 8)
                   | ((uint32_t)in[4 * j + 2] << 16)
                   | ((uint32_t)in[4 * j + 3] << 24);
        x = x * G_CONST.blk_mul[j] + G_CONST.blk_add[j];
        d[j] = x;
    }
    for (unsigned j = 1; j < DSIG_BLK_COUNT; j++)
        d[j] ^= rol32(d[j - 1], G_CONST.blk_rol[j]);
    for (unsigned j = 0; j < DSIG_BLK_COUNT; j++) {
        out[4 * j + 0] = (uint8_t)(d[j]);
        out[4 * j + 1] = (uint8_t)(d[j] >> 8);
        out[4 * j + 2] = (uint8_t)(d[j] >> 16);
        out[4 * j + 3] = (uint8_t)(d[j] >> 24);
    }
}

/* Stage E: final comparison against embedded transformed target data. */
__attribute__((noinline))
static int stage_verify(const uint8_t *state) {
    uint8_t diff = 0;
    for (unsigned i = 0; i < DSIG_TOKEN_LEN; i++)
        diff |= (uint8_t)(state[i] ^ G_CONST.target[i]);
    return diff == 0;
}

/* ---------------------------------------------------------------- */
/* ARX_HASH key derivation                                           */
/* ---------------------------------------------------------------- */

__attribute__((noinline))
static void arx_hash(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint32_t h[8];
    for (unsigned j = 0; j < 8; j++)
        h[j] = 0x9E3779B9u * (uint32_t)(j + 1u) ^ 0xC2B2AE35u;

    for (size_t i = 0; i < len; i++) {
        unsigned a = (unsigned)(i & 7u);
        unsigned b = (unsigned)((i + 3u) & 7u);
        unsigned c = (unsigned)((i + 5u) & 7u);
        h[a] += data[i];
        h[a] = rol32(h[a], (unsigned)((i * 5u) & 7u) + 1u);
        h[b] ^= h[a];
        h[c] += rol32(h[a], 9u);
    }
    h[0] ^= (uint32_t)len * 0x85EBCA6Bu;

    for (unsigned r = 0; r < 8; r++) {
        for (unsigned j = 0; j < 8; j++) {
            h[j] += h[(j + 1u) & 7u];
            h[j] = rol32(h[j], 7u);
            h[j] ^= h[(j + 3u) & 7u];
            h[j] *= 0x27D4EB2Du;
        }
    }
    for (unsigned j = 0; j < 8; j++) {
        out[4 * j + 0] = (uint8_t)(h[j]);
        out[4 * j + 1] = (uint8_t)(h[j] >> 8);
        out[4 * j + 2] = (uint8_t)(h[j] >> 16);
        out[4 * j + 3] = (uint8_t)(h[j] >> 24);
    }
}

/* Derive the flag key from the SUPPLIED token. */
__attribute__((noinline))
static void derive_key(const uint8_t *tok, uint8_t key[32]) {
    arx_hash(tok, DSIG_TOKEN_LEN, key);
}

/* ---------------------------------------------------------------- */
/* flag release                                                      */
/* ---------------------------------------------------------------- */

static void decrypt_and_release(const uint8_t *tok) {
    uint8_t key[32];
    uint8_t flag[DSIG_FLAG_MAX];
    uint8_t block[32];
    uint8_t kb[36];

    if (G_CONST.flag_len == 0 || G_CONST.flag_len > DSIG_FLAG_MAX) {
        fputs("[ERR] PAYLOAD CORRUPTED\n", stderr);
        return;
    }

    derive_key(tok, key);
    memcpy(kb, key, 32);

    for (uint32_t j = 0; j * 32 < G_CONST.flag_len; j++) {
        kb[32] = (uint8_t)(j);
        kb[33] = (uint8_t)(j >> 8);
        kb[34] = (uint8_t)(j >> 16);
        kb[35] = (uint8_t)(j >> 24);
        arx_hash(kb, sizeof(kb), block);
        for (uint32_t i = 0; i < 32 && j * 32 + i < G_CONST.flag_len; i++)
            flag[j * 32 + i] = (uint8_t)(G_CONST.flag_ct[j * 32 + i] ^ block[i]);
    }

    fputs("[LNK] AUTH SEQUENCE ACCEPTED\n", stdout);
    fputs("[LNK] RECOVERY CHANNEL OPEN -- PAYLOAD FOLLOWS\n\n", stdout);
    fwrite(flag, 1, G_CONST.flag_len, stdout);
    fputc('\n', stdout);
}

/* ---------------------------------------------------------------- */
/* terminal                                                          */
/* ---------------------------------------------------------------- */

static int token_char_ok(uint8_t ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
}

static void banner(void) {
    fputs(
        "============================================================\n"
        "   DDD   EEE   A   DDD      SSS  III  GGG  N   N  AAA  L\n"
        "   D  D  E    A A  D  D    S      I  G     NN  N A   A L\n"
        "   D  D  EEE AAAA  D  D     SSS   I  G  GG N N N AAAAA L\n"
        "   D  D  E   A  A  D  D       S  I  G   G N  NN A   A L\n"
        "   DDD   EEE A  A  DDD     SSS  III  GGG  N   N A   A LLLL\n"
        "============================================================\n"
        " ORBITAL RECOVERY TERMINAL v2.7   //   LINK STATUS: SEVERED\n"
        " Last carrier: SAT-9 \"MERIDIAN\"  //  frame loss: total\n"
        "============================================================\n", stdout);
}

int main(void) {
    char line[256];
    uint8_t tok[DSIG_TOKEN_LEN];
    uint8_t st_a[DSIG_TOKEN_LEN];
    uint8_t st_b[DSIG_TOKEN_LEN];
    uint8_t st_c[DSIG_TOKEN_LEN];
    uint8_t st_d[DSIG_TOKEN_LEN];
    int ok;

    setvbuf(stdout, NULL, _IONBF, 0);
    banner();
    fputs("[SYS] awaiting 24-char authentication token [A-Z0-9]: ", stdout);

    if (!fgets(line, sizeof(line), stdin)) {
        fputs("\n[ERR] INPUT LOST -- NO CARRIER\n", stderr);
        return 2;
    }

    line[strcspn(line, "\r\n")] = '\0';
    size_t n = strlen(line);
    if (n != DSIG_TOKEN_LEN) {
        fprintf(stderr, "[ERR] MALFORMED TOKEN -- LENGTH %zu REJECTED (EXPECTED 24)\n", n);
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        if (!token_char_ok((uint8_t)line[i])) {
            fprintf(stderr, "[ERR] MALFORMED TOKEN -- BAD CHARACTER AT OFFSET %zu\n", i);
            return 1;
        }
        tok[i] = (uint8_t)line[i];
    }

    stage_permute(tok, st_a);
    stage_index_mix(st_a, st_b);
    stage_roll(st_b, st_c);
    stage_block_arx(st_c, st_d);
    ok = stage_verify(st_d);

#ifdef DSIG_BYPASS
    /* test-only: simulates a patched acceptance branch */
    ok = 1;
#endif

    if (!ok) {
        fputs("[ERR] AUTH SEQUENCE MISMATCH -- SIGNAL LOST\n", stderr);
        return 1;
    }

    decrypt_and_release(tok);
    return 0;
}
