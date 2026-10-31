#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdalign.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <randombytes.h>
#include <mayo.h>
#include <fips202.h>
#include <arithmetic.h>
#include <simple_arithmetic.h>

#define MAYO_MIN(x, y) (((x) < (y)) ? (x) : (y))
#define PK_PRF AES_128_CTR

static void decode(const unsigned char *m, unsigned char *mdec, int mdeclen) {
    int i;
    for (i = 0; i < mdeclen / 2; ++i) {
        *mdec++ = m[i] & 0xf;
        *mdec++ = m[i] >> 4;
    }

    if (mdeclen % 2 == 1) {
        *mdec++ = m[i] & 0x0f;
    }
}

static void encode(const unsigned char *m, unsigned char *menc, int mlen) {
    int i;
    for (i = 0; i < mlen / 2; ++i, m += 2) {
        menc[i] = (*m) | (*(m + 1) << 4);
    }

    if (mlen % 2 == 1) {
        menc[i] = (*m);
    }
}

static void compute_rhs(const mayo_params_t *p, uint64_t *vPv, const unsigned char *t, unsigned char *y){
    #ifndef ENABLE_PARAMS_DYNAMIC
    (void) p;
    #endif

    const size_t top_pos = ((PARAM_m(p) - 1) % 16) * 4;
    const size_t m_vec_limbs = PARAM_m_vec_limbs(p);


    if(PARAM_m(p) % 16 != 0){
        uint64_t mask = 1;
        mask <<= ((PARAM_m(p) % 16)*4);
        mask -= 1;
        for (int i = 0; i < PARAM_k(p)*PARAM_k(p); i++)
        {
            vPv[i*m_vec_limbs + m_vec_limbs - 1] &= mask;
        }
    }

    uint64_t temp[M_VEC_LIMBS_MAX] = {0};
    unsigned char *temp_bytes = (unsigned char *) temp;
    for (int i = PARAM_k(p) - 1; i >= 0 ; i--) {
        for (int j = i; j < PARAM_k(p); j++) {

            unsigned char top = (temp[m_vec_limbs-1] >> top_pos) % 16;
            temp[m_vec_limbs-1] <<= 4;
            for(int k = m_vec_limbs - 2; k>=0; k--){
                temp[k+1] ^= temp[k] >> 60;
                temp[k] <<= 4;
            }

            for (int jj = 0; jj < F_TAIL_LEN; jj++) {
                if(jj%2 == 0){
#ifdef TARGET_BIG_ENDIAN
                    temp_bytes[(((jj/2 + 8) / 8) * 8) - 1 - (jj/2)%8] ^= mul_f(top, PARAM_f_tail(p)[jj]);
#else
                    temp_bytes[jj/2] ^= mul_f(top, PARAM_f_tail(p)[jj]);
#endif
                }
                else {
#ifdef TARGET_BIG_ENDIAN
                    temp_bytes[(((jj/2 + 8) / 8) * 8) - 1 - (jj/2)%8] ^= mul_f(top, PARAM_f_tail(p)[jj]) << 4;
#else
                    temp_bytes[jj/2] ^= mul_f(top, PARAM_f_tail(p)[jj]) << 4;
#endif
                }
            }


            for(size_t k=0; k < m_vec_limbs; k ++){
                temp[k] ^= vPv[( i * PARAM_k(p) + j )* m_vec_limbs + k] ^ ((i!=j)*vPv[( j * PARAM_k(p) + i )* m_vec_limbs + k]);
            }
        }
    }


    for (int i = 0; i < PARAM_m(p); i+=2)
    {
#ifdef TARGET_BIG_ENDIAN
        y[i]   = t[i]   ^ (temp_bytes[(((i/2 + 8) / 8) * 8) - 1 - (i/2)%8] & 0xF);
        y[i+1] = t[i+1] ^ (temp_bytes[(((i/2 + 8) / 8) * 8) - 1 - (i/2)%8] >> 4);
#else
        y[i]   = t[i]   ^ (temp_bytes[i/2] & 0xF);
        y[i+1] = t[i+1] ^ (temp_bytes[i/2] >> 4);
#endif
    }
}

static void transpose_16x16_nibbles(uint64_t *M){
    static const uint64_t even_nibbles = 0x0f0f0f0f0f0f0f0f;
    static const uint64_t even_bytes   = 0x00ff00ff00ff00ff;
    static const uint64_t even_2bytes  = 0x0000ffff0000ffff;
    static const uint64_t even_half    = 0x00000000ffffffff;

    for (size_t i = 0; i < 16; i+=2)
    {
        uint64_t t = ((M[i] >> 4 ) ^ M[i+1]) & even_nibbles;
        M[i  ] ^= t << 4;
        M[i+1] ^= t;
    }

    for (size_t i = 0; i < 16; i+=4)
    {
        uint64_t t0 = ((M[i  ] >> 8) ^ M[i+2]) & even_bytes;
        uint64_t t1 = ((M[i+1] >> 8) ^ M[i+3]) & even_bytes;
        M[i  ] ^= (t0 << 8);
        M[i+1] ^= (t1 << 8);
        M[i+2] ^= t0;
        M[i+3] ^= t1;
    }

    for (size_t i = 0; i < 4; i++)
    {
        uint64_t t0 = ((M[i  ] >> 16) ^ M[i+ 4]) & even_2bytes;
        uint64_t t1 = ((M[i+8] >> 16) ^ M[i+12]) & even_2bytes;

        M[i   ] ^= t0 << 16;
        M[i+ 8] ^= t1 << 16;
        M[i+ 4] ^= t0;
        M[i+12] ^= t1;
    }

    for (size_t i = 0; i < 8; i++)
    {
        uint64_t t = ((M[i]>>32) ^ M[i+8]) & even_half;
        M[i  ] ^= t << 32;
        M[i+8] ^= t;
    }
}

#define MAYO_M_OVER_8 ((M_MAX + 7) / 8)
static void compute_A(const mayo_params_t *p, uint64_t *VtL, unsigned char *A_out) {
    #ifndef ENABLE_PARAMS_DYNAMIC
    (void) p;
    #endif

    int bits_to_shift = 0;
    int words_to_shift = 0;
    const int m_vec_limbs = PARAM_m_vec_limbs(p);
    uint64_t A[(((O_MAX*K_MAX+15)/16)*16)*MAYO_M_OVER_8] = {0};
    size_t A_width = ((PARAM_o(p)*PARAM_k(p) + 15)/16)*16;
    const uint64_t *Mi, *Mj;


    if(PARAM_m(p) % 16 != 0){
        uint64_t mask = 1;
        mask <<= (PARAM_m(p) % 16)*4;
        mask -= 1;
        for (int i = 0; i < PARAM_o(p)*PARAM_k(p); i++)
        {
            VtL[i*m_vec_limbs + m_vec_limbs - 1] &= mask;
        }
    }

    for (int i = 0; i <= PARAM_k(p) - 1; ++i) {
        for (int j = PARAM_k(p) - 1; j >= i; --j) {

            Mj = VtL + j * m_vec_limbs * PARAM_o(p);
            for (int c = 0; c < PARAM_o(p); c++) {
                for (int k = 0; k < m_vec_limbs; k++)
                {
                    A[ PARAM_o(p) * i + c + (k + words_to_shift)*A_width] ^= Mj[k + c*m_vec_limbs] << bits_to_shift;
                    if(bits_to_shift > 0){
                        A[ PARAM_o(p) * i + c + (k + words_to_shift + 1)*A_width] ^= Mj[k + c*m_vec_limbs] >> (64-bits_to_shift);
                    }
                }
            }

            if (i != j) {
                Mi = VtL + i * m_vec_limbs * PARAM_o(p);
                for (int c = 0; c < PARAM_o(p); c++) {
                    for (int k = 0; k < m_vec_limbs; k++)
                    {
                        A[PARAM_o(p) * j + c + (k + words_to_shift)*A_width] ^= Mi[k + c*m_vec_limbs] << bits_to_shift;
                        if(bits_to_shift > 0){
                            A[PARAM_o(p) * j + c + (k + words_to_shift + 1)*A_width] ^= Mi[k + c*m_vec_limbs] >> (64-bits_to_shift);
                        }
                    }
                }
            }

            bits_to_shift += 4;
            if(bits_to_shift == 64){
                words_to_shift ++;
                bits_to_shift = 0;
            }
        }
    }

    for (size_t c = 0; c < A_width*((PARAM_m(p) + (PARAM_k(p)+1)*PARAM_k(p)/2 +15)/16) ; c+= 16)
    {
        transpose_16x16_nibbles(A + c);
    }

    unsigned char tab[F_TAIL_LEN*4] = {0};
    for (size_t i = 0; i < F_TAIL_LEN; i++)
    {
        tab[4*i]   = mul_f(PARAM_f_tail(p)[i],1);
        tab[4*i+1] = mul_f(PARAM_f_tail(p)[i],2);
        tab[4*i+2] = mul_f(PARAM_f_tail(p)[i],4);
        tab[4*i+3] = mul_f(PARAM_f_tail(p)[i],8);
    }

    uint64_t low_bit_in_nibble = 0x1111111111111111;

    for (size_t c = 0; c < A_width; c+= 16)
    {
        for (int r = PARAM_m(p); r < PARAM_m(p) + (PARAM_k(p)+1)*PARAM_k(p)/2 ; r++)
        {
            size_t pos = (r/16)*A_width + c + (r%16);
            uint64_t t0 =  A[pos]       & low_bit_in_nibble;
            uint64_t t1 = (A[pos] >> 1) & low_bit_in_nibble;
            uint64_t t2 = (A[pos] >> 2) & low_bit_in_nibble;
            uint64_t t3 = (A[pos] >> 3) & low_bit_in_nibble;
            for (size_t t = 0; t < F_TAIL_LEN; t++)
            {
                A[((r+t-PARAM_m(p))/16)*A_width + c + ((r+t-PARAM_m(p))%16)] ^= t0*tab[4*t+0] ^ t1*tab[4*t+1] ^ t2*tab[4*t+2] ^ t3*tab[4*t+3];
            }
        }
    }

#ifdef TARGET_BIG_ENDIAN
    for (int i = 0; i < (((PARAM_o(p)*PARAM_k(p)+15)/16)*16)*MAYO_M_OVER_8; ++i) 
        A[i] = BSWAP64(A[i]);
#endif


    for (int r = 0; r < PARAM_m(p); r+=16)
    {
        for (int c = 0; c < PARAM_A_cols(p)-1 ; c+=16)
        {
            for (int i = 0; i + r < PARAM_m(p); i++)
            {
                decode( (unsigned char *) &A[r*A_width/16 + c + i], A_out + PARAM_A_cols(p)*(r+i) + c, MAYO_MIN(16, PARAM_A_cols(p)-1-c));
            }
        }
    }
}

int forge_signature(const mayo_params_t *p, unsigned char *sig,
              size_t *siglen, const unsigned char *m,
              size_t mlen, uint8_t* O, uint64_t* pk) {
    int ret = MAYO_OK;
    unsigned char tenc[M_BYTES_MAX], t[M_MAX];
    unsigned char y[M_MAX];
    unsigned char salt[SALT_BYTES_MAX];
    unsigned char V[K_MAX * V_BYTES_MAX + R_BYTES_MAX], Vdec[V_MAX * K_MAX];
    unsigned char A[((M_MAX+7)/8*8) * (K_MAX * O_MAX + 1)] = { 0 };
    unsigned char x[K_MAX * N_MAX];
    unsigned char r[K_MAX * O_MAX + 1] = { 0 };
    unsigned char s[K_MAX * N_MAX];
    unsigned char seed_sk[CSK_BYTES_MAX];
    unsigned char Ox[V_MAX];
    unsigned char tmp[DIGEST_BYTES_MAX + SALT_BYTES_MAX + SK_SEED_BYTES_MAX + 1];
    unsigned char *ctrbyte;
    unsigned char *vi;

    const int param_m = PARAM_m(p);
    const int param_n = PARAM_n(p);
    const int param_o = PARAM_o(p);
    const int param_k = PARAM_k(p);
    const int param_v = PARAM_v(p);
    const int param_m_bytes = PARAM_m_bytes(p);
    const int param_v_bytes = PARAM_v_bytes(p);
    const int param_r_bytes = PARAM_r_bytes(p);
    const int param_sig_bytes = PARAM_sig_bytes(p);
    const int param_A_cols = PARAM_A_cols(p);
    const int param_digest_bytes = PARAM_digest_bytes(p);
    const int param_sk_seed_bytes = PARAM_sk_seed_bytes(p);
    const int param_salt_bytes = PARAM_salt_bytes(p);

    if (randombytes(seed_sk, PARAM_sk_seed_bytes(p)) != MAYO_OK) {
        ret = MAYO_ERR;
        goto err;
    }



    shake256(tmp, param_digest_bytes, m, mlen);

    uint64_t *P1 = pk;
    uint64_t *P2 = pk + PARAM_P1_limbs(p);
    uint64_t *L = P2;
    P1P1t_times_O(p, P1, O, L);
    uint64_t Mtmp[K_MAX * O_MAX * M_VEC_LIMBS_MAX] = {0};

#ifdef TARGET_BIG_ENDIAN
    for (int i = 0; i < PARAM_P1_limbs(p); ++i) {
        P1[i] = BSWAP64(P1[i]);
    }
    for (int i = 0; i < PARAM_P2_limbs(p); ++i) {
        L[i] = BSWAP64(L[i]);
    }
#endif


    #if defined(PQM4) || defined(HAVE_RANDOMBYTES_NORETVAL)
    randombytes(tmp + param_digest_bytes, param_salt_bytes);
    #else
    if (randombytes(tmp + param_digest_bytes, param_salt_bytes) != MAYO_OK) {
        ret = MAYO_ERR;
        goto err;
    }
    #endif


    memcpy(tmp + param_digest_bytes + param_salt_bytes, seed_sk,
           param_sk_seed_bytes);
    shake256(salt, param_salt_bytes, tmp,
             param_digest_bytes + param_salt_bytes + param_sk_seed_bytes);

#ifdef ENABLE_CT_TESTING
    VALGRIND_MAKE_MEM_DEFINED(salt, SALT_BYTES_MAX);
#endif


    memcpy(tmp + param_digest_bytes, salt, param_salt_bytes);
    ctrbyte = tmp + param_digest_bytes + param_salt_bytes + param_sk_seed_bytes;

    shake256(tenc, param_m_bytes, tmp, param_digest_bytes + param_salt_bytes);

    decode(tenc, t, param_m);

    for (int ctr = 0; ctr <= 255; ++ctr) {
        *ctrbyte = (unsigned char)ctr;

        shake256(V, param_k * param_v_bytes + param_r_bytes, tmp,
                 param_digest_bytes + param_salt_bytes + param_sk_seed_bytes + 1);


        for (int i = 0; i <= param_k - 1; ++i) {
            decode(V + i * param_v_bytes, Vdec + i * param_v, param_v);
        }


        compute_M_and_VPV(p, Vdec, L, P1, Mtmp, (uint64_t*) A);

        compute_rhs(p, (uint64_t*) A, t, y);
        compute_A(p, Mtmp, A);

        for (int i = 0; i < param_m; i++)
        {
            A[(1+i)*(param_k*param_o + 1) - 1] = 0;
        }

        decode(V + param_k * param_v_bytes, r,
               param_k *
               param_o);

        if (sample_solution(p, A, y, r, x, param_k, param_o, param_m, param_A_cols)) {
            break;
        } else {
            memset(Mtmp, 0, sizeof(Mtmp));
            memset(A, 0, sizeof(A));
        }
    }

    for (int i = 0; i <= param_k - 1; ++i) {
        vi = Vdec + i * (param_n - param_o);
        mat_mul(O, x + i * param_o, Ox, param_o, param_n - param_o, 1);
        mat_add(vi, Ox, s + i * param_n, param_n - param_o, 1);
        memcpy(s + i * param_n + (param_n - param_o), x + i * param_o, param_o);
    }
    encode(s, sig, param_n * param_k);

    memcpy(sig + param_sig_bytes - param_salt_bytes, salt, param_salt_bytes);
    *siglen = param_sig_bytes;

err:
    mayo_secure_clear(V, sizeof(V));
    mayo_secure_clear(Vdec, sizeof(Vdec));
    mayo_secure_clear(A, sizeof(A));
    mayo_secure_clear(r, sizeof(r));
    mayo_secure_clear(Ox, sizeof(Ox));
    mayo_secure_clear(tmp, sizeof(tmp));
    mayo_secure_clear(Mtmp, sizeof(Mtmp));
    return ret;
}


#define CURSED_SCHEME (&MAYO_2)
#define CURSED_N MAYO_2_n
#define CURSED_V MAYO_2_v
#define CURSED_O MAYO_2_o
#define CURSED_K MAYO_2_k
#define CURSED_SIG MAYO_2_sig_bytes

__attribute__((used))
const unsigned char cursed_sigil[19] = {
    'C','M','A','Y','O','-','S','I','G','I','L','-','v','1',0,
    3,21,42,60
};

static unsigned char sigil_offset(unsigned i) {
    return cursed_sigil[15u + (i & 3u)];
}

static int read_exact(const char *path, unsigned char *buf, size_t n) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, buf + off, n - off);
        if (r <= 0) { close(fd); return -1; }
        off += (size_t)r;
    }
    close(fd);
    return 0;
}

static int write_secret(const char *path, const unsigned char *buf, size_t n) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    (void)fchmod(fd, 0600);
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w <= 0) { close(fd); return -1; }
        off += (size_t)w;
    }
    close(fd);
    return 0;
}

static int hex_val(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_hex(const char *in, unsigned char *out, size_t *outlen, size_t maxlen) {
    size_t len = strlen(in);
    if (len & 1u) return -1;
    len >>= 1;
    if (len > maxlen) return -1;
    for (size_t i = 0; i < len; i++) {
        int hi = hex_val((unsigned char)in[2*i]);
        int lo = hex_val((unsigned char)in[2*i+1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    *outlen = len;
    return 0;
}

static void encode_hex(const unsigned char *in, size_t n, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2*i] = h[in[i] >> 4];
        out[2*i+1] = h[in[i] & 15u];
    }
    out[2*n] = 0;
}

static int parse_uint(const char *s, unsigned *v) {
    if (!s || !*s) return -1;
    unsigned long x = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return -1;
        x = x * 10u + (unsigned)(*p - '0');
        if (x > 0xfffffffful) return -1;
    }
    *v = (unsigned)x;
    return 0;
}

static unsigned char get_nib(const unsigned char *b, unsigned idx) {
    return (b[idx >> 1] >> ((idx & 1u) * 4u)) & 15u;
}

static void put_nib(unsigned char *b, unsigned idx, unsigned char v) {
    unsigned sh = (idx & 1u) * 4u;
    b[idx >> 1] = (unsigned char)((b[idx >> 1] & ~(15u << sh)) | ((v & 15u) << sh));
}

static unsigned char fresh_lambda(void) {
    unsigned char b = 0;
    do {
        if (randombytes(&b, 1) != MAYO_OK) {
            fprintf(stderr, "entropy failure\n");
            exit(2);
        }
        b &= 15u;
    } while (b == 0);
    return b;
}

static int cmd_keygen(const char *pk_path, const char *o_path, const char *csk_path) {
    static unsigned char cpk[CPK_BYTES_MAX];
    static unsigned char csk[CSK_BYTES_MAX];
    static sk_t sk;
    if (mayo_keypair_compact(CURSED_SCHEME, cpk, csk) != MAYO_OK) {
        fprintf(stderr, "keygen failed\n");
        return 1;
    }
    if (mayo_expand_sk(CURSED_SCHEME, csk, &sk) != MAYO_OK) {
        fprintf(stderr, "key expansion failed\n");
        return 1;
    }
    if (write_secret(pk_path, cpk, CURSED_SCHEME->cpk_bytes) ||
        write_secret(o_path, sk.O, (size_t)CURSED_V * CURSED_O) ||
        write_secret(csk_path, csk, CURSED_SCHEME->csk_bytes)) {
        fprintf(stderr, "could not write key material\n");
        return 1;
    }
    memset(&sk, 0, sizeof(sk));
    printf("keys forged in the dark\n");
    return 0;
}

static int cmd_ritual(const char *o_path, const char *csk_path,
                      const char *msg_hex, const char *candle_arg) {
    static unsigned char O[V_MAX * O_MAX];
    static unsigned char csk[CSK_BYTES_MAX];
    static unsigned char sig[SIG_BYTES_MAX];
    unsigned char msg[256];
    size_t mlen = 0, sl = 0;
    unsigned candle = 0;

    if (parse_uint(candle_arg, &candle) || candle >= CURSED_V) {
        fprintf(stderr, "invalid candle\n");
        return 1;
    }
    if (decode_hex(msg_hex, msg, &mlen, sizeof(msg)) || mlen == 0) {
        fprintf(stderr, "invalid message\n");
        return 1;
    }
    if (read_exact(o_path, O, (size_t)CURSED_V * CURSED_O) ||
        read_exact(csk_path, csk, CURSED_SCHEME->csk_bytes)) {
        fprintf(stderr, "could not read the secret\n");
        return 1;
    }

    int ok = 0;
    for (int attempt = 0; attempt < 4; attempt++) {
        if (mayo_sign_signature(CURSED_SCHEME, sig, &sl, msg, mlen, csk) == MAYO_OK &&
            sl == (size_t)CURSED_SIG) {
            ok = 1;
            break;
        }
    }
    if (!ok) {
        fprintf(stderr, "the ritual collapsed\n");
        return 1;
    }

    unsigned char lambda = fresh_lambda();
    for (unsigned i = 0; i < CURSED_K; i++) {
        unsigned p = (candle + sigil_offset(i)) % CURSED_V;
        unsigned char acc = 0;
        for (unsigned j = 0; j < CURSED_O; j++) {
            unsigned char xj = get_nib(sig, i * CURSED_N + CURSED_V + j);
            acc ^= mul_f(O[p * CURSED_O + j], xj);
        }
        put_nib(sig, i * CURSED_N + p, mul_f(lambda, acc));
    }

    char out[SIG_BYTES_MAX * 2 + 1];
    encode_hex(sig, (size_t)CURSED_SIG, out);
    printf("message: %s\nhaunted_signature: %s\n", msg_hex, out);
    memset(sig, 0, sizeof(sig));
    return 0;
}

static int cmd_forge(const char *pk_path, const char *o_path, const char *msg_hex) {
    static unsigned char cpk[CPK_BYTES_MAX];
    static unsigned char O[V_MAX * O_MAX];
    static unsigned char sig[SIG_BYTES_MAX];
    static unsigned char sm[SIG_BYTES_MAX + 256];
    static uint64_t pk[P1_LIMBS_MAX + P2_LIMBS_MAX + P3_LIMBS_MAX];
    unsigned char msg[256];
    size_t mlen = 0, sl = 0;

    if (decode_hex(msg_hex, msg, &mlen, sizeof(msg)) || mlen == 0) {
        fprintf(stderr, "invalid message\n");
        return 1;
    }
    if (read_exact(pk_path, cpk, CURSED_SCHEME->cpk_bytes) ||
        read_exact(o_path, O, (size_t)CURSED_V * CURSED_O)) {
        fprintf(stderr, "could not read key material\n");
        return 1;
    }

    int ok = 0;
    for (int attempt = 0; attempt < 4 && !ok; attempt++) {
        memset(pk, 0, sizeof(pk));
        if (mayo_expand_pk(CURSED_SCHEME, cpk, pk) != MAYO_OK) continue;
        if (forge_signature(CURSED_SCHEME, sig, &sl, msg, mlen, O, pk) != MAYO_OK) continue;
        if (sl != (size_t)CURSED_SIG) continue;
        if (mayo_verify(CURSED_SCHEME, msg, mlen, sig, cpk) == MAYO_OK) ok = 1;
    }
    if (!ok) {
        fprintf(stderr, "the curse rejected the forgery\n");
        return 1;
    }

    memcpy(sm, sig, (size_t)CURSED_SIG);
    memcpy(sm + CURSED_SIG, msg, mlen);
    char out[(SIG_BYTES_MAX + 256) * 2 + 1];
    encode_hex(sm, (size_t)CURSED_SIG + mlen, out);
    printf("signature: %s\n", out);
    memset(sig, 0, sizeof(sig));
    memset(O, 0, sizeof(O));
    return 0;
}

static int cmd_verify(const char *pk_path, const char *msg_hex, const char *sm_hex) {
    static unsigned char cpk[CPK_BYTES_MAX];
    static unsigned char sm[SIG_BYTES_MAX + 256];
    unsigned char msg[256];
    size_t mlen = 0, smlen = 0;

    if (decode_hex(msg_hex, msg, &mlen, sizeof(msg)) || mlen == 0 ||
        decode_hex(sm_hex, sm, &smlen, sizeof(sm))) {
        fprintf(stderr, "malformed offering\n");
        return 2;
    }
    if (read_exact(pk_path, cpk, CURSED_SCHEME->cpk_bytes)) {
        fprintf(stderr, "public key unavailable\n");
        return 2;
    }
    if (smlen == (size_t)CURSED_SIG) {
        if (mayo_verify(CURSED_SCHEME, msg, mlen, sm, cpk) == MAYO_OK) {
            printf("the offering is accepted\n");
            return 0;
        }
    } else if (smlen == (size_t)CURSED_SIG + mlen) {
        if (memcmp(sm + CURSED_SIG, msg, mlen) == 0 &&
            mayo_verify(CURSED_SCHEME, msg, mlen, sm, cpk) == MAYO_OK) {
            printf("the offering is accepted\n");
            return 0;
        }
    }
    printf("the curse rejects the offering\n");
    return 1;
}

static int cmd_normalize(const char *pk_path, const char *o_in_path, const char *o_out_path) {
    static unsigned char cpk[CPK_BYTES_MAX];
    static unsigned char Oin[V_MAX * O_MAX];
    static unsigned char Os[V_MAX * O_MAX];
    static unsigned char sig[SIG_BYTES_MAX];
    static uint64_t pk[P1_LIMBS_MAX + P2_LIMBS_MAX + P3_LIMBS_MAX];
    static const unsigned char test_a[32] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,
        0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,
        0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0
    };
    static const unsigned char test_b[32] = {
        0x5a,0xa5,0x3c,0xc3,0x0f,0xf0,0x69,0x96,
        0x11,0xee,0x77,0x88,0x2d,0xd2,0x4b,0xb4,
        0x00,0xff,0x55,0xaa,0x33,0xcc,0x66,0x99,
        0x1e,0xe1,0x7f,0xf7,0x18,0x81,0x24,0x42
    };

    if (read_exact(pk_path, cpk, CURSED_SCHEME->cpk_bytes) ||
        read_exact(o_in_path, Oin, (size_t)CURSED_V * CURSED_O)) {
        fprintf(stderr, "could not read key material\n");
        return 1;
    }

    for (unsigned scale = 1; scale < 16; scale++) {
        for (size_t i = 0; i < (size_t)CURSED_V * CURSED_O; i++) {
            Os[i] = mul_f((unsigned char)scale, Oin[i]);
        }
        int ok = 1;
        for (int which = 0; which < 2 && ok; which++) {
            const unsigned char *m = which ? test_b : test_a;
            int passed = 0;
            for (int attempt = 0; attempt < 4 && !passed; attempt++) {
                memset(pk, 0, sizeof(pk));
                size_t sl = 0;
                if (mayo_expand_pk(CURSED_SCHEME, cpk, pk) != MAYO_OK) continue;
                if (forge_signature(CURSED_SCHEME, sig, &sl, m, 32, Os, pk) != MAYO_OK) continue;
                if (sl == (size_t)CURSED_SIG &&
                    mayo_verify(CURSED_SCHEME, m, 32, sig, cpk) == MAYO_OK) {
                    passed = 1;
                }
            }
            if (!passed) ok = 0;
        }
        if (ok) {
            if (write_secret(o_out_path, Os, (size_t)CURSED_V * CURSED_O)) {
                fprintf(stderr, "could not write the normalized oil\n");
                return 1;
            }
            printf("scale: %u\n", scale);
            memset(Oin, 0, sizeof(Oin));
            memset(Os, 0, sizeof(Os));
            return 0;
        }
    }
    fprintf(stderr, "no meaningful scale found\n");
    memset(Oin, 0, sizeof(Oin));
    memset(Os, 0, sizeof(Os));
    return 1;
}

int main(int argc, char **argv) {
    if (argc == 5 && strcmp(argv[1], "keygen") == 0) {
        return cmd_keygen(argv[2], argv[3], argv[4]);
    }
    if (argc == 6 && strcmp(argv[1], "ritual") == 0) {
        return cmd_ritual(argv[2], argv[3], argv[4], argv[5]);
    }
    if (argc == 5 && strcmp(argv[1], "forge") == 0) {
        return cmd_forge(argv[2], argv[3], argv[4]);
    }
    if (argc == 5 && strcmp(argv[1], "verify") == 0) {
        return cmd_verify(argv[2], argv[3], argv[4]);
    }
    if (argc == 5 && strcmp(argv[1], "normalize") == 0) {
        return cmd_normalize(argv[2], argv[3], argv[4]);
    }
    fprintf(stderr,
        "usage:\n"
        "  %s keygen <pk> <O> <csk>\n"
        "  %s ritual <O> <csk> <message-hex> <candle>\n"
        "  %s forge <pk> <O> <message-hex>\n"
        "  %s verify <pk> <message-hex> <signature-hex>\n"
        "  %s normalize <pk> <O-in> <O-out>\n",
        argv[0], argv[0], argv[0], argv[0], argv[0]);
    return 2;
}
