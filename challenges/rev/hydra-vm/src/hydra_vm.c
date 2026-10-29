#include "hydra_vm.h"

#include <string.h>

static uint16_t ld16(const hydra_vm *vm, uint16_t addr)
{
    return (uint16_t)(vm->mem[addr] | ((uint16_t)vm->mem[(uint16_t)(addr + 1)] << 8));
}

static void st16(hydra_vm *vm, uint16_t addr, uint16_t v)
{
    vm->mem[addr] = (uint8_t)(v & 0xFF);
    vm->mem[(uint16_t)(addr + 1)] = (uint8_t)(v >> 8);
}

static uint16_t rotl16(uint16_t v, unsigned n)
{
    n &= 0xF;
    if (n == 0)
        return v;
    return (uint16_t)((v << n) | (v >> (16 - n)));
}

static uint16_t rotr16(uint16_t v, unsigned n)
{
    n &= 0xF;
    if (n == 0)
        return v;
    return (uint16_t)((v >> n) | (v << (16 - n)));
}

void hydra_vm_init(hydra_vm *vm)
{
    memset(vm, 0, sizeof(*vm));
    vm->sp = HYDRA_STACK_TOP;
}

int hydra_vm_load(hydra_vm *vm, const uint8_t *fw, size_t fw_len)
{
    if (fw_len > HYDRA_NONCE_ADDR)
        return -1;
    memcpy(vm->mem + HYDRA_ENTRY_ADDR, fw, fw_len);
    return 0;
}

static int vm_push(hydra_vm *vm, uint16_t v)
{
    if (vm->sp < 2) {
        vm->fault = 1;
        return -1;
    }
    vm->sp = (uint16_t)(vm->sp - 2);
    st16(vm, vm->sp, v);
    return 0;
}

static int vm_pop(hydra_vm *vm, uint16_t *out)
{
    *out = ld16(vm, vm->sp);
    vm->sp = (uint16_t)(vm->sp + 2);
    return 0;
}

int hydra_vm_run(hydra_vm *vm, uint64_t max_steps)
{
    while (!vm->halted && !vm->fault && vm->steps < max_steps) {
        uint8_t op = vm->mem[vm->pc];
        uint8_t a  = vm->mem[(uint16_t)(vm->pc + 1)];
        uint8_t b  = vm->mem[(uint16_t)(vm->pc + 2)];
        uint16_t imm = ld16(vm, (uint16_t)(vm->pc + 2));
        /* 3-byte branch instructions store their 16-bit target in bytes 1..2;
         * the 4-byte immediate instructions use bytes 2..3 instead. */
        uint16_t jimm = (uint16_t)(a | ((uint16_t)b << 8));
        vm->steps++;

        if ((op == 0x02 || op == 0x13 || op == 0x14 || op == 0x20))
            vm->pc = (uint16_t)(vm->pc + 4);
        else if (op == 0x00 || op == 0x01 || op == 0x1C)
            vm->pc = (uint16_t)(vm->pc + 1);
        else if (op == 0x0A || op == 0x1D || op == 0x1E)
            vm->pc = (uint16_t)(vm->pc + 2);
        else
            vm->pc = (uint16_t)(vm->pc + 3);

        switch (op) {
        case 0x00: /* NOP */
            break;
        case 0x01: /* HALT */
            vm->halted = 1;
            break;
        case 0x02: /* MOVI d, imm16 */
            if (a > 7) { vm->fault = 1; break; }
            vm->r[a] = imm;
            break;
        case 0x03: /* MOV d, s */
            if (a > 7 || b > 7) { vm->fault = 1; break; }
            vm->r[a] = vm->r[b];
            break;
        case 0x04: /* ADD d, s */
        case 0x05: { /* ADC d, s */
            if (a > 7 || b > 7) { vm->fault = 1; break; }
            uint32_t t = (uint32_t)vm->r[a] + vm->r[b] + (op == 0x05 ? (uint32_t)vm->c : 0u);
            vm->c = (t >> 16) & 1;
            vm->r[a] = (uint16_t)(t & 0xFFFF);
            vm->z = (vm->r[a] == 0);
            break;
        }
        case 0x06: /* SUB d, s  (C = borrow) */
            if (a > 7 || b > 7) { vm->fault = 1; break; }
            vm->c = (vm->r[a] < vm->r[b]);
            vm->r[a] = (uint16_t)(vm->r[a] - vm->r[b]);
            vm->z = (vm->r[a] == 0);
            break;
        case 0x07: /* XOR d, s */
            if (a > 7 || b > 7) { vm->fault = 1; break; }
            vm->r[a] = (uint16_t)(vm->r[a] ^ vm->r[b]);
            vm->z = (vm->r[a] == 0);
            break;
        case 0x08: /* AND d, s */
            if (a > 7 || b > 7) { vm->fault = 1; break; }
            vm->r[a] = (uint16_t)(vm->r[a] & vm->r[b]);
            vm->z = (vm->r[a] == 0);
            break;
        case 0x09: /* OR d, s */
            if (a > 7 || b > 7) { vm->fault = 1; break; }
            vm->r[a] = (uint16_t)(vm->r[a] | vm->r[b]);
            vm->z = (vm->r[a] == 0);
            break;
        case 0x0A: /* NOT d */
            if (a > 7) { vm->fault = 1; break; }
            vm->r[a] = (uint16_t)~vm->r[a];
            vm->z = (vm->r[a] == 0);
            break;
        case 0x0B: /* SHL d, s */
        case 0x0C: /* SHR d, s */ {
            if (a > 7 || b > 7) { vm->fault = 1; break; }
            unsigned n = vm->r[b] & 0xF;
            uint16_t v = vm->r[a];
            if (n == 0) {
                vm->c = 0;
            } else if (op == 0x0B) {
                vm->c = (v >> (16 - n)) & 1;
                v = (uint16_t)(v << n);
            } else {
                vm->c = (v >> (n - 1)) & 1;
                v = (uint16_t)(v >> n);
            }
            vm->r[a] = v;
            vm->z = (v == 0);
            break;
        }
        case 0x0D: /* ROTL d, s */
        case 0x0E: /* ROTR d, s */
            if (a > 7 || b > 7) { vm->fault = 1; break; }
            vm->r[a] = (op == 0x0D) ? rotl16(vm->r[a], vm->r[b])
                                    : rotr16(vm->r[a], vm->r[b]);
            vm->z = (vm->r[a] == 0);
            break;
        case 0x0F: /* LDB d, [a] */
            if (a > 7 || b > 7) { vm->fault = 1; break; }
            vm->r[a] = vm->mem[vm->r[b]];
            break;
        case 0x10: /* STB s, [a] */
            if (a > 7 || b > 7) { vm->fault = 1; break; }
            vm->mem[vm->r[b]] = (uint8_t)(vm->r[a] & 0xFF);
            break;
        case 0x11: /* LDW d, [a] */
            if (a > 7 || b > 7) { vm->fault = 1; break; }
            vm->r[a] = ld16(vm, vm->r[b]);
            break;
        case 0x12: /* STW s, [a] */
            if (a > 7 || b > 7) { vm->fault = 1; break; }
            st16(vm, vm->r[b], vm->r[a]);
            break;
        case 0x13: /* ADDI d, imm16 */
            if (a > 7) { vm->fault = 1; break; }
            {
                uint32_t t = (uint32_t)vm->r[a] + imm;
                vm->c = (t >> 16) & 1;
                vm->r[a] = (uint16_t)(t & 0xFFFF);
                vm->z = (vm->r[a] == 0);
            }
            break;
        case 0x14: /* CMPI d, imm16 (C = borrow) */
            if (a > 7) { vm->fault = 1; break; }
            vm->c = (vm->r[a] < imm);
            vm->z = (vm->r[a] == imm);
            break;
        case 0x15: /* CMP d, s */
            if (a > 7 || b > 7) { vm->fault = 1; break; }
            vm->c = (vm->r[a] < vm->r[b]);
            vm->z = (vm->r[a] == vm->r[b]);
            break;
        case 0x16: /* JMP a16 */
            vm->pc = jimm;
            break;
        case 0x17: /* JZ */
            if (vm->z) vm->pc = jimm;
            break;
        case 0x18: /* JNZ */
            if (!vm->z) vm->pc = jimm;
            break;
        case 0x19: /* JC */
            if (vm->c) vm->pc = jimm;
            break;
        case 0x1A: /* JNC */
            if (!vm->c) vm->pc = jimm;
            break;
        case 0x1B: /* CALL a16 */
            if (vm_push(vm, vm->pc) == 0)
                vm->pc = jimm;
            break;
        case 0x1C: { /* RET */
            uint16_t ret;
            if (vm_pop(vm, &ret) == 0)
                vm->pc = ret;
            break;
        }
        case 0x1D: /* PUSH s */
            if (a > 7) { vm->fault = 1; break; }
            vm_push(vm, vm->r[a]);
            break;
        case 0x1E: /* POP d */
            if (a > 7) { vm->fault = 1; break; }
            vm_pop(vm, &vm->r[a]);
            break;
        case 0x1F: { /* MIXW d, s  (custom nonlinear lane mixer) */
            if (a > 7 || b > 7) { vm->fault = 1; break; }
            uint16_t t = (uint16_t)(vm->r[a] ^ vm->r[b]);
            t = (uint16_t)(t + rotl16(t, 5));
            t = (uint16_t)(t ^ rotl16(t, 9));
            vm->r[a] = t;
            vm->z = (t == 0);
            break;
        }
        case 0x20: /* XORI d, imm16 */
            if (a > 7) { vm->fault = 1; break; }
            vm->r[a] = (uint16_t)(vm->r[a] ^ imm);
            vm->z = (vm->r[a] == 0);
            break;
        default:
            vm->fault = 1;
            break;
        }
    }

    if (vm->fault)
        return -1;
    if (!vm->halted)
        return 1;
    return 0;
}
