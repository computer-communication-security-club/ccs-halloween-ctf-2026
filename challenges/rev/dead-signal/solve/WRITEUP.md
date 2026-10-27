# DEAD SIGNAL — intended solution

> The real flag lives only in `flag.txt` / `challenge.yml` and is intentionally
> not quoted here (repo rule 2.2). Run `solve/solve.py` or the final step below
> to retrieve it.
>
> Correct token for this build: `QCDP59YT5IDGEKS9ZER5DYFW`.

---

## 1. Overview

`dead_signal` reads a 24-character `[A-Z0-9]` token and runs it through a
five-stage bijective transform. The resulting 24-byte state is compared
against an embedded **target** block. On match, the binary derives a key from
the *supplied* token with an ARX hash and XOR-decrypts the embedded flag
ciphertext.

Because the transform is a bijection on 24-byte strings, exactly one token in
the input domain maps to the target. Because the key is derived from the
supplied token (not stored), patching the acceptance branch cannot reveal the
flag for a wrong token.

## 2. The constant block

All embedded data lives in one 312-byte struct in `.rodata`, prefixed with a
16-byte magic marker `DSIGCONSTv1\0\0\0\0\0`. This is the intended "map" for
the reverse engineer: find the magic (it shows up in `strings`), unpack the
struct.

Layout (little-endian, natural alignment, verified by `_Static_assert` in
`src/dsig_consts.h`):

| Offset | Size | Field       | Meaning                                    |
|-------:|-----:|-------------|--------------------------------------------|
| 0      | 16   | `magic`     | `"DSIGCONSTv1"` + NUL padding              |
| 16     | 24   | `perm`      | Stage A permutation of 0..23               |
| 40     | 24   | `xkey`      | Stage B index keystream                    |
| 64     | 24   | `rots`      | Stage B rotation amounts (1..7)            |
| 88     | 4    | `roll_seed` | Stage C initial state                      |
| 92     | 4    | `roll_mul`  | Stage C multiplier (**odd**)               |
| 96     | 4    | `roll_add`  | Stage C additive constant                  |
| 100    | 24   | `blk_mul`   | Stage D per-dword multipliers (**odd**)    |
| 124    | 24   | `blk_add`   | Stage D per-dword additives                |
| 148    | 6    | `blk_rol`   | Stage D cross-dword chain rotations        |
| 154    | 2    | `reserved`  | padding                                    |
| 156    | 24   | `target`    | expected final state                       |
| 180    | 128  | `flag_ct`   | encrypted flag (padded with NUL)           |
| 308    | 4    | `flag_len`  | flag length                                |

Python unpack format: `"<16s24s24s24sIII6I6I6s2s24s128sI"`.

Note: the compiler constant-folds `roll_seed`/`roll_mul`/`roll_add` into
immediates in `.text`; the struct fields cross-check the disassembly.

## 3. Validation transform (forward)

Input `b[0..23]`, ASCII bytes of the token.

### Stage A — permutation (invertible)

```
c[i] = b[perm[i]]            i = 0..23
```

### Stage B — index-dependent XOR + rotation

```
u[i] = ROL8(c[i] ^ xkey[i], rots[i])     ROL8 = 8-bit rotate left
```

`rots[i] ∈ 1..7`, so `ROR8(u[i], rots[i])` inverts it.

### Stage C — rolling 32-bit state

```
state = roll_seed
for i in 0..23:
    m8    = fold8(state)                # (s ^ s>>8 ^ s>>16 ^ s>>24) & 0xFF
    v[i]  = u[i] ^ m8
    state = state * roll_mul + roll_add + u[i]      (mod 2^32)
```

Byte *i* alters `state`, which perturbs every later byte — this is the
"rolling" dependency that defeats per-byte patching or byte-at-a-time
brute force.

### Stage D — 32-bit ARX blocks + cross-dword chain

```
for j in 0..5:
    d[j] = LE32(v[4j .. 4j+3])
    d[j] = d[j] * blk_mul[j] + blk_add[j]           (mod 2^32)
for j in 1..5:
    d[j] ^= ROL32(d[j-1], blk_rol[j])
```

### Stage E — comparison

```
w = LE32 concat of d[0..5]        # 24 bytes
accept iff w == target
```

The comparison is branchless (OR-accumulated XOR diff), so there is no
match-count or timing oracle.

## 4. Why the token is unique

Every stage is a bijection on 24-byte strings:

- A: permutation — bijective by construction.
- B: XOR-with-constant + fixed rotation — bijective.
- C: at each step `v[i] = u[i] ^ m8(state)` where `state` is a function of
  `u[0..i-1]` only; recovering `u[i] = v[i] ^ m8` then updates the same state.
- D: per-dword affine maps with **odd** multipliers are bijective modulo
  2^32; the chain is unitriangular (each step XORs a value that does not
  depend on `d[j]`), inverted in reverse order.

Composition of bijections is a bijection, so exactly one 24-byte string maps
to `target`. The binary additionally enforces `[A-Z0-9]{24}` on input, and the
generator machine-verifies that the produced token is in that domain.

## 5. Flag protection

Key derivation (`arx_hash`, identical in C and Python):

```
key       = ARX_HASH(token)                  # 32 bytes
keystream = ARX_HASH(key || LE32(j)) for j = 0,1,2,...
flag_ct[i] = flag[i] ^ keystream[i]
```

`ARX_HASH` is a 256-bit ARX sponge: eight 32-bit words initialized from
`0x9E3779B9*(j+1) ^ 0xC2B2AE35`, absorb each byte with rotate/xor/add
feedback, mix in the length, then eight mixing rounds using `ROL32(x, 7)`,
XOR with the word 3 ahead, and multiplication by the odd constant
`0x27D4EB2D`. Output is the eight words serialized little-endian.

At runtime the binary recomputes `key` from **whatever token the user typed**
and only then decrypts. Therefore:

- correct token → correct key → plaintext flag;
- patched acceptance branch + wrong token → wrong key → pseudorandom bytes.

Note that even knowing the flag prefix (`ccsCTF{`, 7 keystream bytes) does not
help: inverting `ARX_HASH` requires the full 32-byte output state.

## 6. Reconstructing the token (solver path)

`solve/solve.py` does exactly what a player would:

1. Locate `DSIGCONSTv1` in the binary, unpack the 312-byte struct.
2. Interpret `target` as six little-endian dwords `d[0..5]`.
3. **Undo the chain** (reverse order): `for j = 5..1: d[j] ^= ROL32(d[j-1], blk_rol[j])`.
4. **Undo the affine mix**: `d[j] = (d[j] - blk_add[j]) * inv(blk_mul[j]) mod 2^32`
   (odd multipliers are invertible mod 2^32; Python: `pow(m, -1, 2**32)`).
5. Serialize back to `v[0..23]`.
6. **Replay the rolling state** forward, un-mixing: `u[i] = v[i] ^ fold8(state)`,
   then `state = state*roll_mul + roll_add + u[i]`.
7. **Undo Stage B**: `c[i] = ROR8(u[i], rots[i]) ^ xkey[i]`.
8. **Undo Stage A**: `b[perm[i]] = c[i]`.
9. Derive `key = ARX_HASH(token)`, decrypt `flag_ct`, print the flag.

Recovered token: `QCDP59YT5IDGEKS9ZER5DYFW`. Entering it into the binary also
prints the flag (the binary derives the same key).

## 7. Test evidence

`src/tests/run_tests.py` (21 checks) and `src/tests/clean_ubuntu_test.sh`,
plus the repository tooling (`dist --verify`, `test`):

| Check | Result |
|-------|--------|
| Correct token accepted, prints flag | PASS |
| 10 wrong tokens (incl. 1-char mutation, rotation) rejected, no leak | PASS |
| Empty / 23 / 25 / 200 chars, no newline, lowercase, symbols, binary garbage — all fail safely | PASS |
| Independent solver (`blind_solver.py`, written from disassembly only) recovers the token | PASS |
| Rebuilt binary with a different random token → solver recovers *that* token (solver is not a hardcoded printer) | PASS |
| No plaintext flag or token in the binary | PASS |
| Forced-success build **and** real NOP patch of the acceptance `je` + wrong token → noise only; + correct token → decrypts (control) | PASS |
| Pipeline bijective over 200 random states; target maps to exactly one in-domain token (uniqueness) | PASS |
| Stock Ubuntu 24.04.3 LTS container: correct token works, wrong/invalid rejected; binary links only libc | PASS |
| 120-case ASan/UBSan fuzz: no crashes, no sanitizer reports | PASS |

## 8. Design notes / why it resists shortcuts

- **No strcmp, no XOR-only, no Base64** — the token is never stored in any
  form; only its 24-byte image under a 5-stage bijective transform.
- **Rolling state** prevents byte-at-a-time dynamic patching; each byte's
  meaning depends on all earlier bytes.
- **Odd-multiplier affine maps** are the classic "looks hard, is invertible"
  trap — solvers who don't know modular inversion get stuck; those who do
  finish quickly (intended: 45–90 min total).
- **Cross-dword chain** forces the solver to process dwords in the right
  order; it is the most common place to get a subtly wrong inverse.
- **Key-from-input flag encryption** makes binary patching useless without
  the real token — genuine protection rather than anti-tamper tricks.
- No sleeps, no anti-debug, no VM tricks: the difficulty is the algorithm.

## 9. Rebuild behavior

`src/generated_constants.h` is committed (exact generator output), so the
Docker build is deterministic. To rotate the token or flag, regenerate with
`src/gen_constants.py` (or `src/build.sh`), commit the new header, and
re-export `dist/`. The write-up's concrete token is valid for the packaged
build only; the algorithm description stays valid.
