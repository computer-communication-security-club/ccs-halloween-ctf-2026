# DEAD SIGNAL — Progressive Hints

Release these one at a time as players request them (or as time passes).
Each hint reveals more of the solution path. **Organizer only — do not ship
in the player package.**

---

## Hint 1 (gentle nudge)

The binary compares a computed value against some embedded data — but where
does that data live, and what does it mean? Take a close look at the binary's
read-only data: something there is *marked*, and everything you need is
stored in one block right after that marker. Start by mapping the fields of
that block, then trace how the input flows into the comparison.

## Hint 2 (structure of the algorithm)

The check is not one operation — it is a pipeline of five stages over the 24
input bytes: (1) a fixed reordering of the bytes, (2) an index-dependent XOR
and 8-bit rotation step, (3) a 32-bit *rolling state* where each processed
byte changes how every later byte is mixed, (4) a 32-bit mixing stage that
treats the data as six little-endian dwords with a multiply-add and a chain
between neighboring dwords, and (5) a comparison against the target block.
Identify each stage in the disassembly, write down its exact formula, and
note which parameters come from the constant block.

## Hint 3 (how to invert it)

Go backwards from the target. The last stage inverts in two sub-steps: undo
the dword chain from the *last* dword to the first (each step only depends on
the previous dword), then undo the multiply-add per dword — the multipliers
are odd, so they have a modular inverse modulo 2^32 (`pow(m, -1, 2**32)` in
Python). Next, undo the rolling state by *replaying* it forward: at step `i`
the state is known from the already-recovered earlier bytes, so peel off its
mixed byte and update the state exactly as the binary does. Finally undo the
rotation/XOR stage and the permutation. You now hold the only valid token —
entering it makes the binary derive the flag key and print the flag. (If you
only patched the comparison instead: the flag key comes from the token you
type, so a wrong token decrypts to noise.)
