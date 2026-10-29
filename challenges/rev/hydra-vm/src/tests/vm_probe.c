/* Minimal CLI used by tests/test_vm.py: execute a bytecode file and print
 * the resulting VM state. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "hydra_vm.h"

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s program.bin max_steps\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f)
        return 2;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0 || n > (long)HYDRA_NONCE_ADDR)
        return 2;
    uint8_t *prog = malloc((size_t)n + 1);
    if (n > 0 && fread(prog, 1, (size_t)n, f) != (size_t)n)
        return 2;
    fclose(f);

    hydra_vm vm;
    hydra_vm_init(&vm);
    if (hydra_vm_load(&vm, prog, (size_t)n) != 0)
        return 2;
    int rc = hydra_vm_run(&vm, strtoull(argv[2], NULL, 10));
    printf("%d %u %u %d %d", rc, vm.pc, vm.sp, vm.z, vm.c);
    for (int i = 0; i < 8; i++)
        printf(" %u", vm.r[i]);
    printf("\n");
    free(prog);
    return 0;
}
