# HYDRA VM

**Category:** Reverse Engineering · **Difficulty:** Hard

---

HYDRA boots a custom 16-bit virtual machine from an encrypted firmware image.
The service hands every connection a fresh 16-byte nonce and accepts a 16-byte
**candidate proof** only when the firmware's nonce-dependent verifier accepts
it. There is no tag endpoint and no routine in the binary that turns a nonce
into an accepted response.

Your task:

1. Reverse engineer `hydra-server`.
2. Recover the virtual instruction set and decrypt `firmware.enc`.
3. Reconstruct the firmware's nonce-dependent validation constraints.
4. Produce a valid proof and retrieve the flag.

## Connecting

The service listens on TCP port **34001**:

```bash
nc 35.253.220.32 34001
```

The server speaks first. See `PROTOCOL.md` for the exact wire format.

## Files

| File | Purpose |
|---|---|
| `hydra-server` | Stripped, statically linked x86_64 service binary |
| `firmware.enc` | Encrypted HYDRA firmware image |
| `PROTOCOL.md` | Line protocol and message formats |

## Format

- Challenge nonce: **16 bytes** (32 hex characters).
- Candidate proof: **16 bytes** (32 hex characters).
- Flag format: `ccsCTF{...}`.
- The flag is released only when the firmware accepts the candidate.

## Notes

- AI tools and autonomous agents are allowed during the competition.
- The binary contains no plaintext flag.
- Every connection gets a fresh nonce, so a response is single-use.
- Patching a local binary does not reveal the remote flag. You need a proof
  the firmware accepts.
