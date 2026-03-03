# BrownOS v27 — All Stubs Dead with Typed Inputs. Full Dead-End Map.

**Repo**: `https://github.com/SynthNoirLabs/brownos2`  
**Date**: 2026-03-03  
**Previous**: `prompt_v26.md`

---

## What we tested this round

**Your proposal**: sweep all 242 stub globals with typed real-world inputs via CPS composition, not just `{nil, int0, int1}`.

**`probe_stub_typed.py`**: 2420 tests (242 stubs × 10 typed inputs each).

### Typed input matrix per stub `g`:
```
name(/)→C_g           — passes string "/"
name(wtf)→C_g         — passes string "wtf"
readfile(11)→C_g      — passes /etc/passwd content
readfile(65)→C_g      — passes .history content ("ilikephp")
readfile(256)→C_g     — passes "Uhm... yeah... no...\n"
readdir(0)→C_g        — passes root directory listing
backdoor(K*)→C_g      — passes pair(A,B)
quote(sys8)→C_g       — passes bytecode of sys8 function
sys8(N0)→R_g          — passes Right(6) = error code 6
readdir(256)→R_g      — passes Right(4) = error code 4
```
where `C_g = λr. r(g)(K*)` routes Left(x) into `g(x)(K*)`,
and `R_g = λr. r(K*)(g)` routes Right(y) into `g(y)(K*)`.

### Result: **2420/2420 boring. Zero novels.**

Every stub returns Right(1) = "Not implemented" or EMPTY, regardless of whether it receives a string, directory listing, combinator pair, bytecode, or error code.

---

## Step 0: VFS sanity check

`readdir(0)` confirmed: root listing consistent with existing docs. No new nodes found.
The tree is complete and correctly documented.

---

## Complete dead-end map

| Axis | Tests | Verdict |
|------|-------|---------|
| sys8 arg: integers 0–280, special IDs | 700+ | Right(6) |
| sys8 arg: lambdas, pairs, combinators | 50+ | Right(6) |
| sys8 arg: provenance (echo/readfile/backdoor) | 26 | Right(6) |
| sys8 arg: ALL 253 Var(b) values | 253 | Right(6) |
| sys8 continuation: lambdas, globals | 100+ | Right(6) |
| sys8 via forged Either tokens | 40 | Right(6) |
| sys8 via CPS adapter composition | 26 | Right(6) |
| sys8 via computed head (B, I, K, wrappers) | 18 | Right(6) |
| 3-leaf programs (all shapes) | 10000+ | Right(6)/EMPTY |
| 3-leaf continuations (6 forms × globals) | 760 | Right(6) |
| Stub globals with nil/int0/int1 | 253×3 | All Right(1) |
| **Stub globals with typed inputs** | **2420** | **All Right(1)/EMPTY** |
| VFS: hidden file IDs 257–1024 | 768 | No extra IDs |
| Hash candidates | 35+ | No match |

**Total probes**: ~15,000+. The service has been exhaustively probed across every structural axis we could identify.

---

## What we know for certain about the service

**Active globals (11)**: `{0,1,2,4,5,6,7,8,14,42,201}`  
**True stubs (242)**: Every other global, confirmed unresponsive to all typed inputs.  
**VFS**: Complete. No hidden nodes beyond the documented tree + unlinked ID 256.  
**sys8**: Always Right(6). Provenance-independent, structure-independent, type-independent.  
**Backdoor**: Only accepts nil; returns fixed pair(A,B) = `(λa.λb.bb, λa.λb.ab)`.  
**Adapter algebra**: Fully functional. Any Left/Right value routes cleanly between active syscalls.

---

## The only hypotheses that survive

At this point, the exhaustive empirical evidence forces one of these conclusions:

### H1: The answer is derivable from the filesystem data we already have
We know:
- Password: `ilikephp` (confirmed by crypt match against gizmore's hash)
- Hash: `GZKc.2/VQffio`
- Mail content: backdoor hint pointing to sys201
- File "wtf" at ID 256

All WeChall-submitted string candidates derived from these are REJECTED. But what if the answer requires a specific *transformation* of this data that we haven't tried? (Different encoding, different combination, different hash function?)

### H2: sys8 has an unlocking condition we haven't modeled

Something about the evaluator state, connection context, or a specific byte sequence makes sys8 return Left. We've tested the structural space exhaustively. The remaining possibility is something *meta* — timing, connection ordering, rate of requests, IP-based state, something in the TCP stream we haven't tried.

### H3: The answer requires a multi-connection stateful approach

The access.log changes per connection. What if some sequence of syscalls across multiple connections unlocks sys8? (We know the service doesn't persist state within a connection, but across connections?)

### H4: We're fundamentally misunderstanding what "sys8 succeeds" means

The challenge says "make syscall 8 succeed." We've assumed this means it returns Left. But what if success is defined differently — e.g., sys8 produces a side effect that writes the answer somewhere, and we need to read it from a different location? Or what if the WeChall answer is something already visible (like a crypt hash or a specific bytecode string) that we just haven't tried in the right format?

---

## Your call

We've now exhausted the straightforward structural space. What's left is either:
1. A non-obvious meta-level trick (timing, state, connection ordering)
2. A reinterpretation of what "success" means
3. Something in the challenge setup we're missing entirely

What do you see that we're blind to?

**Reference**: `BROWNOS_MASTER.md`, `probe_stub_typed.py`, all prior probes in `archive/probes_feb2026/`
