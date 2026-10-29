# Séance runtime — lifetime invariants (maintainer notes)

This file states, in one place, which state is allowed to survive a request and
why — the contract the challenge deliberately violates on exactly one path.

## State classes

| Class | Examples | Lifetime | Backing store |
|---|---|---|---|
| **Engine (worker) state** | `g_echo`, `memory_limit`, the listening socket | whole process, across all requests | globals |
| **Request state** | every Séance `Val` payload (strings, arrays), the top-level unserialize value | one request | the `arena[]`, reset per request |
| **Parse/eval scratch** | tokens, AST nodes, scopes, the rite table | one request | the `pool` (malloc), freed per request |

The parse/eval pool is kept **separate** from the value arena on purpose: the
arena's offsets must be deterministic for the vulnerability to be reasoned about,
so AST/scope allocation must never perturb them.

## The invariant

> **I1.** No *engine* state may reference *request-arena* memory once a request
> has ended. Concretely: `g_echo` must be `NULL` at the moment control returns
> to the accept loop, on **every** exit path.

> **I2.** `recall()` may only ever observe a value that the *current* request
> published via `leave()`/`unserialize()`. It must never observe a value from a
> previous request. (I2 follows from I1: if I1 holds, `g_echo` is `NULL` at the
> start of every request.)

## Where each exit path stands

| Exit path | Clears `g_echo`? | Honors I1? |
|---|---|---|
| Normal completion (`process_request` end) | **yes** | ✅ |
| Non-fatal script error (`script_fault` landing) | **yes** | ✅ |
| **Fatal OOM bailout** (`oom_bailout` in `serve`) | **no** | ❌ **violated** |

The OOM bailout is reached by `longjmp` from `ralloc()` and returns straight to
the accept loop without running `process_request`'s cleanup. That single omission
breaks I1, which breaks I2, which is the use-after-free.

This mirrors the real CVE-2026-109619 precondition ("worker-wide fields point to
memory owned by a single request … freed without clearing the fields") with the
CVE-2026-109618-class fatal OOM as the interrupting event. See
[`cve-analysis.md`](cve-analysis.md).

## The fix

The fix adds `g_echo = NULL;` to the OOM bailout, restoring I1 on every path.
This is the toy analogue of the upstream remediation ("request-owned global state
is reset before reuse … on every exit"). The **handout ships only the vulnerable
source**; organizers build the patched variant separately. The regression harness
(`tests/test_chall.py`) applies that one-line patch to a throwaway copy and
demonstrates the leak on the default build and its absence on the patched build.

## Deliberately safe behaviors (decoys)

These look dangerous but provably uphold the invariants:

* **Non-fatal errors never leak.** Division by zero, unknown variables, parse
  errors, recursion/step-budget overflow all unwind through `script_fault`,
  which still clears `g_echo`. Only a *fatal OOM* skips cleanup.
* **`leave()` on a normal request is harmless.** The value is dismissed at
  request end; the next `recall()` returns `null`.
* **`echo_poke()` / `knell()`** are only interesting *after* the invariant is
  already broken; on a healthy worker they operate on the current request's own
  value (or nothing).
