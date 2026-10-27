# DEAD SIGNAL

**Category:** Reverse Engineering · **Difficulty:** Medium-Hard · **Points:** 300

---

A satellite transmitted its final encrypted authentication sequence before
disappearing. Investigators recovered its authentication software — but the
valid recovery token was never written down.

The recovered terminal will only release its payload to the one correct
**24-character authentication token**.

Your task:

1. Reverse engineer the `dead_signal` executable.
2. Reconstruct the valid authentication token.
3. Run the binary, enter the token, and capture the flag.

## Format

- The authentication token is exactly **24 characters**, drawn from
  `A-Z` and `0-9`.
- Exactly one token is valid. The binary is fair: everything needed to
  recover it is inside the binary.
- The flag has the format `ccsCTF{...}`.

## Running the binary

```bash
chmod +x dead_signal
./dead_signal
```

It runs on any modern x86_64 Linux system (glibc). Enter the token at the
prompt. Invalid tokens are rejected.

## Files

| File         | Purpose                      |
|--------------|------------------------------|
| `dead_signal`| The recovered executable     |
| `SHA256SUMS` | Checksums of the files above |

Verify your copy:

```bash
sha256sum -c SHA256SUMS
```

## Notes

- AI tools are allowed during the competition.
- The flag is not stored in plaintext in the binary, and patching the binary
  to skip the check will not give up the flag. You must find the real token.

Good luck. The signal is dead — the math is not.
