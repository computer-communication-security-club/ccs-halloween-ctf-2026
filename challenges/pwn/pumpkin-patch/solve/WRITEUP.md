# Intended solution

Inspect `chall.c` and the amd64 ELF. `carve` reads 256 bytes into a 64-byte stack buffer. The configured GCC build keeps a frame pointer: 64 bytes of data plus 8 saved-RBP bytes place the saved return address at offset 72. Verify this with disassembly or a cyclic pattern after any compiler change.

The binary is non-PIE and has no stack canary. Find `win` in the supplied ELF. Overwrite the return address with a plain `ret` gadget followed by `win`, aligning the stack for amd64 libc calls. `win` reads the relative `flag.txt` from the jail's `/app` directory and prints it. NX and full RELRO do not prevent returning to existing code.

The solver derives addresses from `dist/chall` and gets the flag from the remote service. It contains no flag value. Test both the private runtime and the player Dockerfile; the latter must print only the fake flag.
