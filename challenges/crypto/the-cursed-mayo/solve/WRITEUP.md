# The Cursed MAYO — solution writeup

**Category:** crypto / reverse engineering / fault injection
**Target:** MAYO-2 signing oracle with a post-signing fault
**Flag format:** `ccsCTF{...}`
**Flag placement:** the real flag is stored only in the private `flag.txt` and
`challenge.yml`; it is not part of `dist/` or this writeup.

## 1. Challenge summary

The service exposes a MAYO-2 keypair and a signing oracle. Each ritual costs one
query and returns a signature for a fresh message. The signature is computed by
the stock MAYO-2 signer, but four nibbles are overwritten afterwards. The
overwritten values leak scaled products of the secret oil-space basis.

The player must reverse the provided `cursed_signer` binary, recover the four
hidden wound offsets, undo the per-ritual scaling, reconstruct the oil matrix,
resolve its global field scalar against the public key, and forge a signature
for the offering message.

## 2. The fault

MAYO-2 parameters:

```
n = 81, m = 64, o = 17, v = n - o = 64, k = 4, q = 16.
```

Let `O` be the secret `64 x 17` oil-space basis over `F_16`. For a normal
signature the signer chooses, for each chunk `i = 0..3`,

```
x_i in F_16^17,  v_i in F_16^64
s_i = v_i + O x_i
s   = (s_0 || x_0) || (s_1 || x_1) || (s_2 || x_2) || (s_3 || x_3).
```

The first 64 coordinates of each `s_i` are masked by `v_i`; the last 17 are the
public `x_i`.

The challenge binary contains a sigil table after the marker
`CMAYO-SIGIL-v1\0`:

```
delta = (3, 21, 42, 60).
```

For a player-chosen candle `c in [0,63]`, the signer draws a fresh nonzero
`lambda_q in F_16^*` and overwrites

```
p_i = (c + delta_i) mod 64
s_i[p_i] = lambda_q * (O[p_i] . x_i).
```

All four wounds of one ritual share `lambda_q`; the value is not printed and
changes per ritual. The public `x` coordinates are untouched. The returned
signature is generally invalid, but the oracle still returns it.

## 3. Reverse engineering

The binary is unstripped. Useful steps:

```sh
strings -a dist/cursed_signer | grep CMAYO
nm -C dist/cursed_signer | grep -E 'cmd_ritual|sigil|lambda|nib'
```

The offset table can be dumped with:

```python
blob = open("cursed_signer", "rb").read()
at = blob.index(b"CMAYO-SIGIL-v1\x00")
print(list(blob[at + 15:at + 19]))   # [3, 21, 42, 60]
```

Disassembling `cmd_ritual` shows the post-signing loop:

1. call `mayo_sign_signature`;
2. draw one nonzero `lambda`;
3. for each chunk, compute `lambda * dot(O[p_i], x_i)`;
4. overwrite signature nibble `i * 81 + p_i`.

The player parses `x_i` from the last 17 nibbles of each chunk and reads the
leaked value `y_i` at `p_i`:

```
y_{q,i} = lambda_q * (O[p_i] . x_{q,i}).                 (1)
```

## 4. Eliminating the per-ritual stain

Set `u_q = lambda_q^{-1}`. Equation (1) is

```
O[p_i] . x_{q,i} = y_{q,i} u_q.                          (2)
```

This is bilinear in the oil matrix and the scalar `u_q`. Do not solve it
directly. Pair two chunks `i,j` of the same ritual with nonzero leaks:

```
y_{q,j} (O[p_i] . x_{q,i}) + y_{q,i} (O[p_j] . x_{q,j}) = 0.   (3)
```

The two right-hand sides are both `y_i y_j u_q`; in characteristic two they
cancel. Equation (3) is linear in the 1088 unknown entries of `O`.

If a leak is zero, `lambda_q != 0` implies directly

```
O[p_i] . x_{q,i} = 0.                                    (4)
```

A ritual with four nonzero leaks contributes three independent equations
(anchor one leak, pair it with the other three). Zero leaks add direct
equations; a ritual with one nonzero leak still contributes the zero-leak
equations from the other chunks.

## 5. Query budget and rank

There are `v * o = 64 * 17 = 1088` unknowns. Three independent equations per
ritual give a lower bound of `ceil(1088 / 3) = 363` rituals.

The intended collection is six rituals for each of the 64 candles:

```
384 rituals -> 1152 equations.
```

For a fixed oil row `p`, the wounded chunks occur for candles
`p - delta_i (mod 64)`. One round of 64 candles wounds each row four times; six
rounds give 24 `x` samples for every row, more than the 17 needed for full rank
over `F_16`.

The observed homogeneous system has rank 1087 and nullity 1 over `F_16`
(nullity 4 in the GF(2) bitset representation). The global query limit is 600,
leaving room for one or two extra query batches if a run has an unusual number
of zero leaks.

## 6. Solving the linear system

The reference solver represents each `F_16` coefficient as four GF(2) bits.
Multiplication by a field element is a 4x4 GF(2)-linear map, so each equation
becomes four GF(2) equations. Rows are Python integers (bitsets); Gaussian
elimination is fast enough for 4608 rows and 4352 columns.

One nonzero nullspace basis vector is converted from bits back to `F_16`
elements. The result is

```
O' = c O
```

for an unknown nonzero scalar `c in F_16^*`.

## 7. Resolving the global scalar

The public key commits to the real `O`. The binary's `normalize` helper tries
all 15 nonzero scalars, signs two deterministic test messages for each
candidate, and verifies them against the public key. Exactly one scalar passes
both tests. The successful candidate is written to disk.

This is a zero-secret local operation; it uses only the recovered candidate,
the public key, and the public verification routine.

## 8. Forging the offering

With the correct `O` and public key, the `forge` helper reconstructs the MAYO
signing system:

```
L = P2 + (P1 + P1^T) O
```

and outputs

```
sm = signature || message.
```

The oracle's offering command issues a fresh 32-byte message; the solver signs
exactly those bytes, submits `sm`, and receives the flag if `mayo_verify`
accepts the signature.

## 9. Reference solve

```sh
python3 solve/solve.py HOST PORT \
    --signer dist/cursed_signer \
    --workdir <workdir>
```

The solver:

1. fetches the public key;
2. performs 384 rituals (six per candle);
3. recovers the sigil offsets from the binary;
4. builds and solves the GF(16) system;
5. normalizes the oil matrix against the public key;
6. asks for an offering and forges its signature;
7. prints the flag.

Example output (test flag, not the deployment flag):

```
sigil offsets: [3, 21, 42, 60]
public key: 4912 bytes
collected 384/384 rituals
equations: 1152, zero leaks: 101
GF(2) rows: 4608
rank: 4348, nullity: 4
recovered oil candidate: <workdir>/O_recovered.bin
public-key scale: 12
normalized oil: <workdir>/O_normalized.bin
ccsCTF{...}
```

A local end-to-end test compares the normalized recovered oil file byte-for-byte
with the server's `O.bin`, verifies the signature through the server's public
verification path, and checks the reported flag.

## 10. Why this is not a break of real MAYO

The fault is injected by this challenge signer. Real MAYO does not overwrite
signature coordinates with scaled oil-space products, and the public key alone
does not expose the oil basis in this way. The challenge demonstrates a fault
attack on a deliberately faulty implementation, not a weakness in MAYO itself.

## 11. Difficulty and AI-resistance notes

The challenge requires binary reverse engineering, finite-field modeling,
nonlinear-to-linear elimination, efficient GF(2) linear algebra, public-key
scalar resolution, and MAYO signature reconstruction. It is designed as an
expert-level challenge.

The solver and this writeup are private. The handout contains only the player
README, the signer binary, and a protocol helper; it contains no secret keys or
deployment flag.
