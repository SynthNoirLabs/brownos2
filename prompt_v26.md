# BrownOS v26 — 3-Leaf Continuation Sweep: Dead. What Now?

**Repo**: `https://github.com/SynthNoirLabs/brownos2`  
**Date**: 2026-03-03  
**Previous**: `prompt_v25.md` (computed-head retired)

---

## What we tested this round

You proposed a systematic sweep of all 3-leaf terms with lambdas, used as **continuations** to producers (esp. sys8), since prior sweeps only tested them as standalone programs.

### What "probe_3leaf_continuations.py" ran

**Phase 1: 6 canonical 1-lambda forms × 10 interesting globals = 600 tests**

All 6 forms used as continuations to `sys8(N0)(T)`:
```
Form 1: λr. ((r a) b)   — C_g family
Form 2: λr. (r (a b))
Form 3: λr. ((a r) b)   = a(r)(b)
Form 4: λr. (a (r b))   = a(r(b))
Form 5: λr. ((a b) r)   = a(b)(r)  — Rerr family
Form 6: λr. (a (b r))   = a(b(r))
```

Globals: `{exc=0, err_str=1, write=2, quote=4, readdir=5, name=6, readfile=7, sys8=8, echo=14, backdoor=201}`

**Result: ALL 600 boring (Permission denied / empty).**

**Phase 2: Same 6 forms with echo(N256) as producer — 600 tests**

**Result: ALL 600 boring.** Even the non-Cg forms don't produce visible output with echo.

**Phase 4: 6 two-lambda forms × 10 globals = 60 tests**

```
λa.λb. ((g a) b)       λa.λb. (a (g b))
λa.λb. (g (a b))       λa.λb. ((a b) g)
λa.λb. (a (b g))       λa.λb. ((b g) a)
```

**Result: ALL 60 boring.**

---

## Clarification on the "Left" results from 3leaf_targeted_results.json

The JSON file showed `(echo (backdoor sys8)) + QD` returning `hex=01cb0afdfdfefeff` labeled "interesting." This is **NOT** Left from sys8. QD wraps its output in Left(bytes). Those "Left" entries are QD printing the bytecode of the *application term* `App(backdoor, sys8)` — i.e., `(backdoor sys8)` has bytecode `c9 08 fd`. QD then outputs `Left([0xCB, 0x0A])` which is just `0xC9=201` and `0x08=8` encoded as a 2-byte Scott list. No anomaly.

---

## Complete axis retirement table (cumulative)

| Axis | Tests | Verdict |
|------|-------|---------|
| sys8 arg value (0–280, special IDs) | 700+ | Right(6) |
| sys8 arg structure (lambdas, pairs, combinators) | 50+ | Right(6) |
| sys8 arg provenance (echo/readfile/backdoor-produced) | 26 | Right(6) |
| sys8 with ALL 253 Var(b) args via QD | 253 | Right(6) |
| sys8 continuation variants (lambdas, globals) | 100+ | Right(6) |
| Forged Either tokens | 40 | Right(6) |
| CPS adapter composition (echo→sys8, bdoor→sys8) | 26 | Right(6) |
| Computed head / function-position (B, I, K, wrappers) | 18 | Runtime check, not syntactic |
| 3-leaf programs (left-assoc, right-assoc, 0-2 lambdas) | 10000+ | All Right(6)/EMPTY |
| **3-leaf continuations** (6 forms × 10 globals, 2-lambda forms) | **760** | **Right(6) / EMPTY** |
| Hidden VFS nodes | 30+ | Only 256 exists |
| Hash candidates | 35+ | No match |

---

## What the 3-leaf sweep now tells us

The LLM's hypothesis was: "3 leafs" = the shape of the **continuation**, not the argument. We've now tested:
- All 6 placement forms (where r lands relative to a,b)
- All 6 two-lambda structures
- Every interesting global as a and b

None of it changed sys8's behavior. This means either:
1. **The 3-leaf hint is about something other than the continuation shape**
2. **The specific globals matter and we're missing the right pair** — but we covered all 10 meaningful ones
3. **"3 leafs" doesn't mean what we think**

---

## The honest picture

At 1000+ probes on sys8, every structural class returns Right(6). Let's re-read the hints cold:

> "A lot of you are focusing on 8 directly, but... the mail points to the way to get access there. My record is 3 leafs IIRC."

Key phrase: **"focusing on 8 directly"**. The author is contrasting "direct focus on 8" vs "the mail" (sys201/backdoor). "My record is 3 leafs" is the author's personal shortest solution — not necessarily the shape of the argument or continuation.

> "IT is always casting its dark magic, it wont even realize we hacked it."

We've interpreted "IT" as the permission gate. But what if "IT" is something else entirely?

> "Good input gives good stuff back." (l3st3r)

This says sys8 CAN return Left. We haven't found it yet, but it's possible.

---

## Genuinely untested territory

After exhausting arguments, continuations, computed heads, and adapter compositions, here's what remains:

### 1. The VFS is under-explored

We only know files: 11 (`/etc/passwd`), 65 (command log), 256 (`wtf`). We scanned 0–280 and a few special IDs. But:
- `readdir(256)` returns Right(4) = "Not a directory" — so 256 is NOT a directory, but there ARE directories
- `readdir(0)` — we know name(0) = "/" — did we `readdir(0)` to get the full root listing?
- File IDs are encoded as 9-lambda additive integers. The scan was limited.

### 2. sys8 might need a specific FILE ID, not an integer

What if sys8 wants a file ID that points to a credential/token file, and returns Left(token) when the right file is passed? We've tried 0–280 and a few others, but not a systematic readdir-guided scan.

### 3. The `?? ?? FD QD FD` cheat sheet hint

"The second example in the cheat sheet is useful in figuring out crucial properties." The two examples are:
- `QD ?? FD` — apply QD as function to arbitrary arg
- `?? ?? FD QD FD` — apply something(something) to QD

We've used QD as continuation extensively. But have we used QD **as an argument** (first position `??`) systematically? What does `QD(sys8)` do?

### 4. The stub globals (1–252, excluding known syscalls)

242 globals return Right(1) = "Not implemented." But this was tested with QD-style arguments. What if a specific stub responds differently with a specific continuation? The space is 242 × many — too large without a clue.

---

## Recommended next probe

**Readdir scan from root to map the VFS:**

```python
# readdir(0) → list the root directory
# Then for each directory entry, readdir recursively
# Then sys8 with each file ID found
```

This is the only structured search space left that we haven't exhausted. We know:
- name(0) = "/" (root)
- readdir(256) = Right(4) "Not a directory" (256 is a file, not dir)
- We've never done readdir(0)

**What to look for**: any file in the VFS that we haven't found yet, especially files named "solution", "credentials", "key", etc.

---

## Your call

What do you recommend? The three options I see:

1. **VFS deep scan** — readdir(0) then follow the tree
2. **Stub global sweep with non-standard args** — 242 globals × richer arg set
3. **Something completely different** — re-read the hints from scratch and propose a new axis

**Full reference**: `BROWNOS_MASTER.md`, `probe_3leaf_continuations.py`, `probe_computed_head.py`
