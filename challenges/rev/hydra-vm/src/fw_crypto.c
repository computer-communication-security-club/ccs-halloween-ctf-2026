#include "fw_crypto.h"

#include <stdlib.h>
#include <string.h>

static const char HYDRA_FW_PASSPHRASE[] = "HYDRA-FIRMWARE-KEY-v1";

static uint64_t le64_load(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

void hydra_kdf(const char *pass, size_t pass_len, uint8_t out[32])
{
    for (int i = 0; i < 32; i++) {
        uint8_t t = (uint8_t)((uint8_t)pass[i % pass_len] ^ (uint8_t)((i * 37 + 11) & 0xFF));
        t = (uint8_t)((t << 3) | (t >> 5));
        out[i] = t;
    }
    for (int i = 1; i < 32; i++)
        out[i] = (uint8_t)(out[i] ^ (uint8_t)((out[i - 1] + i * 7 + 3) & 0xFF));
}

void hydra_keystream(const uint8_t key[32], uint8_t *out, size_t n)
{
    uint64_t s0 = le64_load(key);
    uint64_t s1 = le64_load(key + 8) ^ 0x9E3779B97F4A7C15ull;
    uint64_t s2 = le64_load(key + 16);
    uint64_t s3 = le64_load(key + 24) ^ 0xD1B54A32D192ED03ull;
    size_t off = 0;

    while (off < n) {
        uint64_t z, x, y, w;
        s2 += 0x9E3779B97F4A7C15ull;
        z = s2;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        z = z ^ (z >> 31);

        x = s0;
        y = s1;
        s0 = y;
        x ^= x << 23;
        x ^= x >> 17;
        x ^= y ^ (y >> 26);
        s1 = x;

        s3 = s3 * 0x5851F42D4C957F2Dull + 0x14057B7EF767814Full;
        w = s0 + s1 + z + s3;
        for (int i = 0; i < 8 && off < n; i++, off++)
            out[off] = (uint8_t)(w >> (8 * i));
    }
}

uint32_t hydra_crc32(const uint8_t *data, size_t n)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1u)));
    }
    return ~crc;
}

uint8_t *hydra_fw_decrypt(const uint8_t *blob, size_t blob_len, size_t *out_len)
{
    uint32_t plain_len, crc_file, crc_calc;
    uint8_t key[32];
    uint8_t *plain;

    if (blob_len < 12 || memcmp(blob, HYDRA_FW_MAGIC, 4) != 0)
        return NULL;
    plain_len = (uint32_t)blob[4] | ((uint32_t)blob[5] << 8) |
                ((uint32_t)blob[6] << 16) | ((uint32_t)blob[7] << 24);
    if (blob_len != (size_t)8 + plain_len + 4)
        return NULL;

    plain = (uint8_t *)malloc(plain_len ? plain_len : 1);
    if (!plain)
        return NULL;

    hydra_kdf(HYDRA_FW_PASSPHRASE, sizeof(HYDRA_FW_PASSPHRASE) - 1, key);
    hydra_keystream(key, plain, plain_len);
    for (uint32_t i = 0; i < plain_len; i++)
        plain[i] ^= blob[8 + i];

    crc_file = (uint32_t)blob[8 + plain_len] | ((uint32_t)blob[9 + plain_len] << 8) |
               ((uint32_t)blob[10 + plain_len] << 16) | ((uint32_t)blob[11 + plain_len] << 24);
    crc_calc = hydra_crc32(plain, plain_len);
    if (crc_file != crc_calc) {
        free(plain);
        return NULL;
    }

    *out_len = plain_len;
    return plain;
}
