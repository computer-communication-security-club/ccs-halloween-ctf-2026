/* Firmware verifier harness used by tests/test_vm.py and sanitizer probes.
 *
 * usage: fw_probe firmware.enc <nonce-hex-32> <proof-hex-32>
 * prints: "<result> <target-hex>"
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fw_crypto.h"
#include "hydra_vm.h"

static uint8_t *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) {
        fclose(f);
        return NULL;
    }
    uint8_t *buf = malloc((size_t)n + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (n > 0 && fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = (size_t)n;
    return buf;
}

static int hex16(const char *s, uint8_t out[16])
{
    if (strlen(s) != 32)
        return -1;
    for (int i = 0; i < 16; i++) {
        char a = s[2 * i], b = s[2 * i + 1];
        int hi = (a >= '0' && a <= '9') ? a - '0'
               : (a >= 'a' && a <= 'f') ? a - 'a' + 10
               : (a >= 'A' && a <= 'F') ? a - 'A' + 10 : -1;
        int lo = (b >= '0' && b <= '9') ? b - '0'
               : (b >= 'a' && b <= 'f') ? b - 'a' + 10
               : (b >= 'A' && b <= 'F') ? b - 'A' + 10 : -1;
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 4 && argc != 5) {
        fprintf(stderr, "usage: %s firmware.enc nonce proof [max_steps]\n", argv[0]);
        return 2;
    }
    size_t blob_len = 0;
    uint8_t *blob = read_file(argv[1], &blob_len);
    if (!blob)
        return 2;
    uint8_t *fw = hydra_fw_decrypt(blob, blob_len, &blob_len);
    free(blob);
    if (!fw)
        return 2;

    uint8_t nonce[16], proof[16];
    if (hex16(argv[2], nonce) || hex16(argv[3], proof)) {
        free(fw);
        return 2;
    }

    hydra_vm vm;
    hydra_vm_init(&vm);
    if (hydra_vm_load(&vm, fw, blob_len) != 0) {
        free(fw);
        return 2;
    }
    memcpy(vm.mem + HYDRA_NONCE_ADDR, nonce, 16);
    memcpy(vm.mem + HYDRA_PROOF_ADDR, proof, 16);
    uint64_t max_steps = argc == 5 ? strtoull(argv[4], NULL, 10) : 1000000;
    int rc = hydra_vm_run(&vm, max_steps);
    printf("%d %d ", rc, vm.mem[HYDRA_RESULT_ADDR]);
    for (int i = 0; i < 16; i++)
        printf("%02x", vm.mem[HYDRA_TARGET_ADDR + i]);
    printf(" ");
    for (int i = 0; i < 16; i++)
        printf("%02x", vm.mem[HYDRA_G_STATE + i]);
    printf(" %u %llu\n", vm.pc, (unsigned long long)vm.steps);
    free(fw);
    return 0;
}
