#ifndef HYDRA_FW_CRYPTO_H
#define HYDRA_FW_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* HYDRA firmware protection (mirrors tools/fw_key.py).
 *
 * File format (little-endian):
 *   magic   4 bytes   "HYFW"
 *   length  u32       plaintext length in bytes
 *   body    length    ciphertext = plaintext XOR keystream
 *   crc     u32       CRC-32 (IEEE) of the plaintext
 */

#define HYDRA_FW_MAGIC "HYFW"

void hydra_kdf(const char *pass, size_t pass_len, uint8_t out[32]);
void hydra_keystream(const uint8_t key[32], uint8_t *out, size_t n);
uint32_t hydra_crc32(const uint8_t *data, size_t n);

/* Decrypt a firmware blob. Returns malloc'd plaintext (caller frees) or NULL
 * on malformed input / CRC mismatch. Stores plaintext length in *out_len. */
uint8_t *hydra_fw_decrypt(const uint8_t *blob, size_t blob_len, size_t *out_len);

#endif /* HYDRA_FW_CRYPTO_H */
