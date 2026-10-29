# HYDRA VM — intended solution

> The real flag lives only in `flag.txt` and `challenge.yml`; it is not
> repeated here. `solve/solve.py` recovers it from the live service.

## 1. Player files

`dist/` contains a stripped static x86_64 `hydra-server`, an encrypted
`firmware.enc`, the handout README, and the protocol description.

`hydra-server` contains:

- the `HYFW` firmware loader and custom cipher
- a 16-bit VM interpreter
- the TCP service and nonce generation
- no nonce-to-proof routine

## 2. Firmware container

The blob is:

```text
offset 0   magic      b"HYFW"
offset 4   u32        plaintext length
offset 8   ciphertext plaintext XOR keystream
tail       u32        CRC-32 of plaintext
```

The KDF expands `HYDRA-FIRMWARE-KEY-v1`; the stream is a splitmix64 /
xorshift128+ hybrid. Decrypting and checking the CRC yields 16,448 bytes of
firmware. The cipher is deterministic and the plaintext is stable.

## 3. VM

The firmware runs on a custom 16-bit machine:

- 8 × 16-bit general registers, 16-bit PC and SP
- 64 KiB little-endian memory, stack top `0xF000`
- Z (zero) and C (carry/borrow) flags
- 33 opcodes, 1/2/3/4-byte lengths

Important decoding detail: 3-byte branches carry their target in bytes 1–2;
4-byte immediate instructions carry the immediate in bytes 2–3. The
organizer assembler and VM agree on this.

The firmware's memory map:

```text
0xE000  nonce (16 bytes)       input
0xE010  candidate proof        input
0xE020  H working state
0xE030  result byte            1 = accept, 0 = reject
0xE040  H(nonce) target
0xE050  G working state
0xE060  round counter
0xE070  nonce-selected rotation
0xE080  F scratch
0x4000  G_K constant table    16 × u32
```

Code ends at `0x111E`; the constant table is outside the executed path.

## 4. Target H(nonce)

H is a four-round, four-lane 32-bit ARX routine. For each round `r` and lane
`j`:

```text
x  = (w[j] + w[(j+1) % 4]) mod 2^32
x ^= K[(j+r) % 4]
x ^= RC[r][j]
x  = ROTL32(x, ROT[j])             # 7, 9, 13, 3
t  = x ^ ROTL32(x, 11)
w[j] = (t + ROTL32(t, 7)) mod 2^32
```

The four output words are serialized little-endian into the 16-byte target.
`K` is the ASCII key material embedded in the H section; `RC` is the
π-derived 4×4 table. Both are visible in the firmware's `XORI` immediates.

## 5. Verifier G(proof)

For `r = 0..3`, `i = 0..3`, with `j = (i+1) & 3`:

```text
key = G_K[4*r + i] ^ nonce_word[j]
n   = 7 if nonce[0] is even else 11
y   = ROTL32(state[j] ^ key, n)
lo  = MIXW16(lo(y), hi(y))
y   = (hi(y) << 16) | lo
state[i] = (state[i] + y + state[j]) mod 2^32
```

`MIXW16(a,b)` is the VM's nonlinear mixer:

```text
t = a ^ b
t = t + ROTL16(t, 5)
t = t ^ ROTL16(t, 9)
```

The firmware starts `state` from the candidate proof and writes `1` iff the
final four words equal `H(nonce)`. The state update is reversible: `state[j]`
is not modified by step `i`, so the step can be undone by subtracting the same
`F(state[j], key, n)` after all later steps have been undone.

The nonce parity branch selects rotation 7 or 11. The outer `JNZ` loop runs
four rounds; a successful verification executes 2,042 VM instructions.

## 6. Inversion

1. Compute `target = H(nonce)`.
2. Initialize `w = target`.
3. Walk `r = 3..0`, `i = 3..0` in reverse order.
4. For each step compute the same `key`, `n`, and `F(w[j], key, n)`.
5. Set `w[i] = (w[i] - F) mod 2^32`.
6. Serialize the four resulting words as the 16-byte proof.

Because every step is a bijection in `w[i]` for fixed later state, the proof is
unique. The solver parses `G_K` directly from the decrypted committed firmware;
it does not hardcode a nonce/response pair.

## 7. Submission

```text
S: HYDRA-SVC/1.0 AUTH-REQUIRED
S: NONCE <32 hex>
C: AUTH <32 hex proof>
S: AUTH-OK
S: FLAG ccsCTF{...}
```

A fresh nonce is issued for every connection, so a proof cannot be replayed.
Wrong proofs, old MAC values, malformed lengths, and oversized lines are
rejected without releasing the flag.

## 8. Why the old shortcut is gone

The earlier prototype exposed a native `compute_tag(nonce, out)` function, so
a GDB `call` produced a valid response without any VM analysis. The current
binary has no such function; the firmware only evaluates a supplied candidate.
Calling the old address in the new binary hits unrelated decryption/CRC code,
not a tag writer. The local verifier is a candidate tester, not an answer
generator.
