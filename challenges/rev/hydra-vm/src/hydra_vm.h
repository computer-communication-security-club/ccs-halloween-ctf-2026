#ifndef HYDRA_VM_H
#define HYDRA_VM_H

#include <stddef.h>
#include <stdint.h>

/* HYDRA VM: custom 16-bit architecture.
 *
 * 8 general registers (16-bit), 64 KiB flat little-endian memory.
 * PC and SP are 16-bit; SP starts at HYDRA_STACK_TOP and grows down.
 * Flags: Z (zero), C (carry / borrow).
 *
 * The firmware is a verifier, not a tag generator: it computes the target
 * H(nonce), applies a reversible permutation to the candidate proof, and
 * stores only an accept/reject byte at HYDRA_RESULT_ADDR.
 *
 * Memory map (convention, shared with tools/hydra_common.py):
 *   0x0000  firmware entry
 *   0xE000  nonce input   (16 bytes, written by the server)
 *   0xE010  candidate proof (16 bytes, written by the server)
 *   0xE020  H state       (16 bytes)
 *   0xE030  result        (1 byte: 1 accept, 0 reject)
 *   0xE040  H(nonce) target (16 bytes)
 *   0xE050  verifier state (16 bytes)
 *   0xE060  round counter
 *   0xE070  nonce-selected rotation
 *   0xE080  F() scratch
 *   0x4000  verifier constant table
 *   0xF000  stack top
 */

#define HYDRA_MEM_SIZE   0x10000u
#define HYDRA_NONCE_ADDR 0xE000u
#define HYDRA_PROOF_ADDR 0xE010u
#define HYDRA_H_STATE    0xE020u
#define HYDRA_RESULT_ADDR 0xE030u
#define HYDRA_TARGET_ADDR 0xE040u
#define HYDRA_G_STATE    0xE050u
#define HYDRA_STACK_TOP  0xF000u
#define HYDRA_ENTRY_ADDR 0x0000u

typedef struct {
    uint8_t  mem[HYDRA_MEM_SIZE];
    uint16_t r[8];
    uint16_t pc;
    uint16_t sp;
    int      z;
    int      c;
    int      halted;
    int      fault;   /* 1 = invalid instruction / stack underflow */
    uint64_t steps;
} hydra_vm;

void hydra_vm_init(hydra_vm *vm);

/* Load firmware at HYDRA_ENTRY_ADDR. Returns 0 on success, -1 if too large. */
int hydra_vm_load(hydra_vm *vm, const uint8_t *fw, size_t fw_len);

/* Execute until HALT. Returns 0 if halted, 1 if step limit hit, -1 on fault. */
int hydra_vm_run(hydra_vm *vm, uint64_t max_steps);

#endif /* HYDRA_VM_H */
