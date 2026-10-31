# The Cursed MAYO

```
        .-.
       (   )
        `-'
   the candles are still lit
```

A cryptographic laboratory tried to summon a post-quantum signature scheme that
could not be broken. During the Halloween experiment, the signing ritual
stuttered. The laboratory is gone. Its signing oracle is still here.

Every invocation of the oracle produces a signature, but the signature is
wounded: four nibbles are overwritten after the signature has been computed.
The wounds do not reveal themselves cleanly. The oracle is inconsistent, and
the secret oil-space basis is still hidden.

Your task is to investigate the haunted signer, understand the fault, recover
enough of the secret signing structure, and produce a valid MAYO-2 signature
for the oracle's next message. The laboratory's flag is released only to a
valid offering.

## Connection

The organizers will provide `host` and `port`. The service is line-oriented and
menu-driven. A helper is included:

```sh
python3 ritual_client.py HOST PORT pk
python3 ritual_client.py HOST PORT ritual 0
python3 ritual_client.py HOST PORT status
```

Example interaction:

```
1. read the haunted public key
2. perform a ritual (costs one query)
3. make an offering and ask for the flag
4. count the remaining candles
> 2
candle (0-63): 7
message: 6f...
haunted_signature: 9c...
queries_left: 599
```

The `offering` command generates a fresh 32-byte message and asks for a
signature. You may submit either a bare MAYO signature (186 bytes, hex) or a
`sig || message` blob (218 bytes, hex). A valid offering is free; rituals cost
one query.

**Query budget per instance: 600 rituals by default.** The counter is global
to the instance and is intentionally strict. Always check the `queries_left`
value reported by the live service; organizers may configure a different
budget.

## The signer

The attachment `cursed_signer` is the exact signer used by the oracle. It is an
ELF binary, not stripped. It contains the fault logic and the sigil map that
chooses the wounded coordinates. Build information and MAYO-C source are not
required to solve the challenge, but the signer is the artifact to reverse.

The binary also contains local `forge`, `verify`, and `normalize` helpers; run
it with no arguments to see the accepted commands. These helpers are for local
experimentation and for the final forgery; they do not contain server secrets.

Upstream MAYO-C source: https://github.com/PQCMayo/MAYO-C

The oracle uses MAYO-2:

| parameter | value |
|---|---|
| n | 81 |
| m | 64 |
| o | 17 |
| v = n-o | 64 |
| k | 4 |
| q | 16 |
| signature | 186 bytes |

The last 24 bytes of a MAYO-2 signature are the salt. The first 162 bytes are
the nibble-packed signature vector: four chunks of 81 nibbles. In each chunk,
the first 64 coordinates are the masked oil-space part and the last 17 are the
public `x` coordinates. The wounds only touch the first 64 coordinates.

## Hints from the ruined laboratory notebook

- The signer is not the stock MAYO signer. Something happens after signing.
- A ritual wounds four coordinates, one in each of the four signature chunks.
- All four wounds of a single ritual share one fresh stain drawn from the dark.
  The stain changes between rituals.
- The wounded coordinates are selected by a small map buried in the signer.
  The map carries the mark `CMAYO-SIGIL-v1`.
- The curse does not damage the public verification key.

There are no brute-force shortcuts. The signer is deterministic only in its
structure; its per-ritual stain is not exposed in the output.

## Flag

```
ccsCTF{...}
```

## Fair play

- The vulnerability is in this deliberately faulty implementation, not in the
  real MAYO signature scheme.
- Do not attack the infrastructure or other teams. The service exposes only
  the oracle interface.
- The intended path is a combination of reverse engineering, finite-field
  algebra, and careful experimental reasoning.
