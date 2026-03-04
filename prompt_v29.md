# BrownOS v29 — Full Forum Analysis + Naked Pair Retired

**Repo**: `https://github.com/SynthNoirLabs/brownos2`  
**Date**: 2026-03-04  
**Previous**: `prompt_v28.md`

---

## What we tested this round

### `probe_naked_pair.py` — 14 probes

Key new axes:

| Probe | What | Result |
|-------|------|--------|
| P1 | backdoor(nil)→unwrap Left→sys8(pair)(OBS) | Permission denied |
| P2 | sys8(naked A = λa.λb.b b)(OBS) | Permission denied |
| P3 | sys8(naked B = λa.λb.a b)(OBS) | Permission denied |
| P4 | sys8(directly-constructed pair(A,B))(OBS) | Permission denied |
| P5 | sys8(nil)(raw write cont — skips Either) | EMPTY |
| P6 | sys8(nil)(λr. r(write_A)(write_B)) | BRANCH_B (= Right picks second — expected) |
| P7 | echo(Var(251))→unwrap Left→sys8(Left_V253)(OBS) | Permission denied |
| P8 | echo(Var(252))→unwrap Left→sys8(Left_V254)(OBS) | Permission denied |
| P9-P10 | sys8 with quote-write observer | EMPTY (observer bug) |
| P12a-c | sys8(A(A)), sys8(B(A)), sys8(A(B)) (OBS) | Permission denied |

**All Right(6). Naked pair hypothesis definitively closed.**

Note P6 "BRANCH_B" is the standard Right(6) behavior: `Right(6)(write_A)(write_B) = (λl.λr.r(int6))(write_A)(write_B) = write_B(int6)` — expected, not a breakthrough.

---

## New intel from full forum re-read (t917_p1, t917_p2, t917_p3, t1575, b321)

### dloser 2016 spoilers (t917_p1, post 6307)

Two spoilers:

> **Spoiler 1**: "The second example in the cheat sheet, besides providing a way to get some easy outputs, is also useful in figuring out some crucial properties of the codes."

> **Spoiler 2**: "The different outputs betray some core structures. This should give you some substructures that might be helpful elsewhere."

And: "**don't be too literal with the ??s**" — both for QD and for the second example.

The cheat sheet's two examples:
```
For example: QD ?? FD   or   ?? ?? FD QD FD
```

**Second example** = `App(App(??1, ??2), QD)` — run a syscall with arg, use QD as continuation. The `??`s are encoded terms, not literal bytes. Running this with different syscalls/args teaches you the Scott encoding output shapes (Left/Right, lists, integers) that you'll need to build inputs for other syscalls.

### l3st3r (solver) May 2018 (t917_p2, post 7008)

> "I can make it return 'a towel!' and 'O' ' towel!' (two consecutive reads) using the exact same input data. Granted, I had to send a bad QD."

**Interpretation**: A "bad QD" = a continuation that skips the `quote` step and tries to write the result directly as bytes. This works if the result IS already a bytes-list (e.g. echo or readfile result already unwrapped). The "two consecutive reads" are likely TCP chunking of a single write, or a continuation that writes head/tail separately.

**Why it matters**: Confirms a single lambda term can trigger multiple writes. Also confirms l3st3r was experimenting with echo (newly added in Sep 2018) — this comment is from May 2018, so maybe not echo. He may have been iterating on continuation shapes.

### Forum exchange Sep 2018 (t917_p3, posts 7172/7174)

l3st3r:
> "Does it indicate success?" (about EMPTY output from server)

dloser (author):
> "If you didn't want it to return anything, yes."

**This is KEY**: EMPTY (port closes, no data) can mean SUCCESS — if your program intentionally produces no output. sys8 might succeed and produce a program state that writes nothing visible. We've been assuming sys8 success would produce visible output. But what if sys8(correct_arg) just... succeeds silently (EMPTY)?

We tested `sys8(nil)(λr. ...)` where the continuation prints. If sys8 SUCCEEDED with Left(something), OBS would print "LEFT\n". We never saw that. BUT:

**We haven't tested `sys8(correct_arg)` WITHOUT any continuation** — just `sys8(arg)` alone (2-leaf, no continuation). P4c from probe_sys8_protocol.py did test `sys8(nil)` alone and got EMPTY. But that's because sys8 is strict CPS — needs 2nd arg.

### space (solver) Nov 2025 (t1575, post 9542)

> "Folks, you should try it again! It's fun! I just found my old stuff on a legacy hard drive. Don't give up."

One of the 4 solvers saying it's doable. Email: `space@wechall.net`.

---

## Oracle analysis (consulted March 2026)

Key points:

1. **"Don't be too literal"**: The `??` in the second example are encoded terms (not single bytes). The syscall position can be a COMPUTED HEAD (not just a literal Var(n)). This is a "crucial property" the example teaches.

2. **QD fails silently**: Quote (sys4) fails on terms containing `Var(FD/FE/FF)` at runtime. "Good QD" fails exactly when things get interesting. → We confirmed this doesn't affect our OBS-based probes since OBS uses sys2(write) not quote.

3. **Runtime-only terms**: Values constructible at runtime (via echo/backdoor) can contain `Var(253..255)` — unquotable but valid at runtime. These are likely not the answer since P7/P8 tested them.

4. **Computed head confirmed from probes**: All computed-head variants (B(sys8), I(sys8), K(sys8)(y), etc.) were tested in probe_computed_head.py and all Right(6). This was right the first time.

5. **The hard part**: Requires either a capability that can only be constructed in a specific way, or something completely outside the lambda term argument space.

---

## Updated dead-end map

| Axis | Tests | Verdict |
|------|-------|---------|
| sys8 arg: integers 0–280, special IDs | 700+ | Right(6) |
| sys8 arg: lambdas, pairs, combinators | 60+ | Right(6) |
| sys8 arg: provenance (echo/readfile/backdoor) | 26 | Right(6) |
| sys8 arg: ALL 253 Var(b) values | 253 | Right(6) |
| sys8 arg: **naked pair(A,B) from backdoor** | **4** | **Right(6)** |
| sys8 arg: **echo-mediated Var(251/252) runtime terms** | **2** | **Right(6)** |
| sys8 continuation: all shapes | 100+ | Right(6) |
| sys8 via forged Either tokens | 40 | Right(6) |
| sys8 via CPS adapter composition | 26 | Right(6) |
| sys8 via computed head (B, I, K, wrappers) | 18 | Right(6) |
| 3-leaf programs (all shapes) | 10000+ | Right(6)/EMPTY |
| 3-leaf continuations (6 forms × globals) | 760 | Right(6) |
| Stub globals with nil/int0/int1 | 253×3 | All Right(1) |
| Stub globals with typed inputs | 2420 | All Right(1)/EMPTY |
| VFS: hidden file IDs 257–1024 | 768 | No extra IDs |
| Connection context token | 7 | All Right(6) |
| Multi-term per connection | 3 | Processes only first |
| Hash candidates | 35+ | No WeChall match |

**Total: ~16,000+ probes. sys8 has never returned anything other than Right(6).**

---

## The EMPTY-as-success insight we haven't fully exploited

dloser confirmed EMPTY = success if you "didn't want it to return anything."

All our sys8 probes use a continuation that writes output. But what if:
1. **sys8 needs a continuation that does nothing** (K* or nil as continuation) — just `sys8(arg)(nil)` or `sys8(arg)(K*)`?
2. The program should produce EMPTY, and EMPTY = sys8 succeeded silently
3. The WeChall "answer" isn't returned BY sys8, it's auto-registered when sys8 succeeds

If sys8 succeeds, maybe it writes something to WeChall's backend directly, and you just submit any reasonable string, OR the WeChall challenge page auto-marks you as solved?

**This would explain why we never see Left from sys8** — it doesn't return Left. It returns something that, when reached, produces EMPTY output (success, no output needed) — or it writes directly.

We HAVE tested `sys8(nil)(K*)` (4c in probe_sys8_protocol.py) and got EMPTY. But that's because sys8 is strict CPS (needs 2nd arg). So `sys8(nil)` without continuation → EMPTY due to CPS structure, not success.

---

## The strongest remaining hypothesis

**sys8 is gated by a runtime capability/credential we haven't correctly constructed.** The backdoor pair (A, B) is the hint — but maybe it needs to be combined with filesystem data (the password `ilikephp`, or a crypt hash) in a specific term structure.

Untested specific combinations:
1. `sys8(crypt_hash_bytes)(OBS)` — passing the full hash string as bytes list
2. `sys8(pair(hash_bytes, password_bytes))(OBS)` — hash + password as pair
3. `sys8(pair(user_id_as_int, password_bytes))(OBS)` — note: we tested `pair(uid=1000, "ilikephp")` with big_int but maybe the UID encoding matters
4. `sys8(A(pair(A,B)))(OBS)` — applying A to the backdoor pair
5. `sys8(B(pair(A,B)))(OBS)` — applying B to the backdoor pair
6. Term constructed from backdoor pair USED AS FUNCTION applied to credential: `pair(A,B)(credential)`

---

## What do you think we're missing?

Given:
- sys8 returns Right(6) for all ~16,000 probe attempts
- EMPTY = success is confirmed by dloser
- The backdoor hint exists but pair(A,B) as arg gives Right(6)
- space (solver) says it's "fun" and doable
- Only 4 solvers in 12 years
- The challenge was solvable before echo was added (2014-2018 two solvers, l3st3r and space)

**The pre-echo solution** (2014-2018) must have used only: readdir, readfile, name, write, quote, backdoor, plus the filesystem/passwd data.

**What specific combination** of backdoor pair + filesystem data could make sys8 succeed?

**Reference**: `BROWNOS_MASTER.md`, all probes in `archive/probes_feb2026/`, new `probe_naked_pair.py`
