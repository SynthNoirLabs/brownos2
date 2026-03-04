# BrownOS v35 — v34 Probe Results + The Wall

**Repo**: `https://github.com/SynthNoirLabs/brownos2`  
**Date**: 2026-03-04  
**Previous**: `prompt_v34.md`  
**Status**: UNSOLVED. 16,000+ probes all Right(6). Every proposed theory tested and failed.

---

## WHAT WE TESTED SINCE v34

### `probe_v34_combined.py` — 38 probes, ALL FAILED

**Group 1: Poisoned-ADT Ladder (fingerprinting sys8's internal decoder)**

We passed "poisoned" arguments that look like a specific ADT shell (int, 2-way list, 3-way dirlist, Either) but diverge (Omega) if the evaluator descends into the body.

| Probe | Shape | Result | Time |
|-------|-------|--------|------|
| sys8(λ^9. Ω) | poisoned int | Permission denied | 740ms |
| sys8(λc.λn. Ω) | poisoned 2-way list | Permission denied | 468ms |
| sys8(λd.λf.λn. Ω) | poisoned 3-way dirlist | Permission denied | 477ms |
| sys8(λl.λr. Ω) | poisoned Either | Permission denied | 469ms |
| sys8(λ^9. V1(Ω)) | poisoned int body | Permission denied | 473ms |
| sys8(λc.λn. c(byte0)(Ω)) | poisoned cons tail | Permission denied | 619ms |

**Controls**: `write(λc.λn. Ω)` and `readfile(λ^9. Ω)` both returned EMPTY instantly too — meaning even *known consumers* in this lazy VM don't force the argument body before returning via CPS.

**CONCLUSION**: sys8 does NOT structurally decode its argument. It rejects before inspecting the lambda body. The gate is shallower than ANY proposed "type-matching" theory.

**Group 2: Stateful Backdoor → Password → sys8**

Called `backdoor(nil)` first, then `sys8(password)` in the same CPS chain.

| Probe | Password | Result |
|-------|----------|--------|
| backdoor→sys8("ilikephp") PSE | ilikephp | Permission denied |
| backdoor→sys8("boss@evil.com") PSE | boss@evil.com | Permission denied |
| backdoor→sys8("gizmore") PSE | gizmore | Permission denied |
| backdoor→sys8("root") PSE | root | Permission denied |
| backdoor→sys8(nil) PSE | nil | Permission denied |

**VFS State Check**: `readdir(0)→QD` output is byte-for-byte IDENTICAL with and without prior backdoor call. **The backdoor does NOT change VFS state.**

**Group 3: Bare 3-Leaf Programs**

`((201 nil) X)` for X ∈ {0,1,2,4,5,6,7,8,9,14,42,201}: ALL return EMPTY. These are partial applications — the CPS result is a function waiting for more args.

**Group 4: Offline Hash Candidates**

15 bytecode hex strings and phrases: ZERO matches against the target hash.

---

## THE COMPLETE PICTURE (What We Know With Certainty)

### About sys8's behavior:
1. **Always returns Right(6)** for every tested input (16,000+)
2. **Does NOT call/apply its argument** (proven: arity ladder with Ω — instant return, no hang)
3. **Does NOT descend into the argument's lambda body** (proven: poisoned-ADT ladder — instant return)
4. **Normalizes outer redexes before inspecting** (proven: sys8((I nil)) ≡ sys8(nil))
5. **Is NOT sensitive to provenance** (forged terms ≡ natively-minted terms)
6. **Is NOT a stateful gate** (backdoor call before sys8 changes nothing)

### About the backdoor:
7. **backdoor(nil) → Left(pair(A,B))** where A=λab.bb, B=λab.ab. Always. Deterministic.
8. **backdoor(anything_else) → Right(2)**. Only accepts nil.
9. **Does NOT change VFS state** — filesystem is identical before and after.

### About the answer:
10. **Case-insensitive** (from WeChall source code: `CHALL_CASE_I`)
11. **Verified by sha1^56154** (PHP `sha1()` returns lowercase hex, iterated 56154 times)
12. **EMPTY = success** if program intentionally produces no output (dloser 2018)

### About the solution constraints:
13. **Pre-2018 solvers existed** — echo (0x0E) is NOT required
14. **"3 leafs"** is achievable (dloser Jan 2026)
15. **"the mail points to the way to get access there"** (dloser Jan 2026)
16. **"focusing on 8 directly" is wrong** (dloser Jan 2026)
17. **There's a "visit things" phase after cracking access** (pouniok Mar 2026)

---

## THE CRITICAL QUESTION

Given facts 1-6, sys8 is a black box that:
- Receives a normalized value
- Does NOT apply it
- Does NOT descend into it
- Does NOT check provenance
- Does NOT respond to prior state changes
- Yet somehow decides "Permission denied" for ALL 16,000+ inputs

**What mechanism could possibly gate sys8?**

There are very few remaining possibilities:

### Possibility 1: sys8 checks de Bruijn depth / lambda count
Maybe sys8 counts the number of outer lambdas. It could expect exactly N lambdas (e.g., 9 for an int, 2 for Either, etc.) and rejects if the count is wrong. Our poisoned-ADT ladder tested specific counts but returned instantly — however, the *control* consumers also returned instantly (lazy CPS). So we can't distinguish "sys8 checked and rejected the lambda count" from "sys8 didn't check at all." We need a **timing oracle** approach: test sys8 with arguments of widely varying lambda depths and measure response times.

### Possibility 2: sys8 is gated by something OUTSIDE the lambda argument
Maybe the gate isn't in the argument at all. It could be:
- The **continuation** (second argument to sys8) — but we tested many continuations
- The **call site** — somehow the surrounding program structure matters
- A **global environment variable** we haven't discovered — maybe there's a global index that's normally a stub but becomes active under specific conditions

### Possibility 3: The "3 leafs" program does NOT call sys8 as `sys8(arg)(k)`
Maybe the 3-leaf program uses sys8 in a completely unexpected way. For example:
- `pair(A,B)(sys8)` = `sys8(A)(B)` — the backdoor pair APPLIES sys8 to A and B
- Some other combinator application where sys8 ends up in a position we never tried

### Possibility 4: The answer doesn't come from sys8 at all
"The mail points to the way to get access there" — maybe "there" isn't sys8. Maybe the backdoor unlocks something else entirely, and sys8 is a distraction. The "3 leafs" could be a program that:
- Uses the backdoor pair(A,B) to construct a specific term
- Then writes it or quotes it
- The OUTPUT is the answer

### Possibility 5: Pure-lambda echo clone + special bytes
dloser says "why would an OS even need an echo? I can easily write that myself." A pure-lambda echo: `E = λx.λk. k(Left(x))` wraps any term in `Left(...)`. Combined with high-index Vars (251, 252), this could create terms containing Var(253)=FD, Var(254)=FE which can't normally exist. Maybe THESE terms are what sys8 accepts.

---

## DLOSER'S VERIFIED HINTS (Complete, from actual forum HTML)

### 2016, thread t917:
1. *"The second example in the cheat sheet [?? ?? FD QD FD], besides providing a way to get some easy outputs, is also useful in figuring out some crucial properties of the codes."*
2. *"The different outputs betray some core structures. This should give you some substructures that might be helpful elsewhere."*
3. *"I haven't heard of anyone figuring out the meaning of the input codes. Figuring out that part is probably the most important thing to do."*
4. *"don't be too literal with the ??s"*

### Sep 2018, thread t917:
5. *"If you didn't want it to return anything, yes."* (EMPTY = success)

### Jan 2026, thread t1575 page 2 (THE KEY HINT):
6. *"a lot of you are focusing on 8 directly, but for me it is quite obvious that the mail points to the way to get access there. My record is 3 leafs IIRC."*
7. *"did anyone play a bit with that new syscall? Could be a bug, but I'm getting some interesting results when combining the special bytes... once it froze my whole system! ... Besides, why would an OS even need an echo? I can easily write that myself..."*

### l3st3r (solver) — May 2018, thread t917:
8. *"I can make it return 'a towel!' and 'O' ' towel!' (two consecutive reads) using the exact same input data. Granted, I had to send a bad QD."*

### space (solver) — Nov 2025, thread t1575:
9. *"Folks, you should try it again! It's fun! I just found my old stuff on a legacy hard drive. Don't give up."*

### pouniok — Mar 2026, thread t1575:
10. *"If you manage to reach the part where you need to visit things, I would be glad to have some help"*

---

## WHAT THE "3 LEAFS" PROGRAM MIGHT LOOK LIKE

`((backdoor nil) X)` has exactly 3 leaves: Var(201), Var(0), Var(X).

But dloser says "don't focus on 8 directly" and "the mail points the way." So maybe X is NOT 8.

Unexplored X values in `((201 nil) X)`:
- We tested X ∈ {0,1,2,4,5,6,7,8,9,14,42,201} — all EMPTY
- We have NOT tested all 253 possible X values (0..252)
- But all bare 3-leaf programs are partial applications and should be EMPTY

**Alternative 3-leaf structures** we haven't tried:
- `(Var(a) (backdoor nil))` = `a C9 00 FE FE FD FD FF` — apply a syscall TO backdoor's result
- `((Var(a) Var(b)) nil)` where a,b are not 201 — 3 leaves but different syscalls
- Programs with Lam inside: `Lam(App(Var(a), Var(b)))` + one more Var somewhere

**The pair(A,B) as function applicator:**
`pair(A,B) = λs. s(A)(B)`. If the program is `((backdoor nil) continuation)` and continuation gets `Left(pair)`, then `Left(pair)(continuation) = continuation(pair)`. But that's CPS with 2 stages, needing an outer observer...

Unless we think about it as: the 3-leaf program produces a VALUE, and that value IS the answer. EMPTY output, but the program structure/bytecode itself encodes the answer.

---

## SUGGESTED NEXT STEPS

1. **Test pair(A,B) applied to sys8**: `backdoor(nil)(λpair. pair(sys8))(λ_. nil)` → this computes `sys8(A)(B)` where A is the argument and B is the continuation. A = λab.bb, B = λab.ab. This is different from passing pair directly!

2. **Test the "pure-lambda echo clone" with special bytes**: Build `E = λx.λk. k(λl.λr. l(x))` and use it with Var(251), Var(252) to create terms with Var(253/254) that can't normally be typed.

3. **Full sweep of `((201 nil) X)` for X = 0..252** — even though they should all be EMPTY partial applications, one might trigger different behavior.

4. **Re-read "the mail points to the way" more literally**: The mail says "Backdoor is ready at syscall 201; start with 00 FE FE." What if "start with 00 FE FE" doesn't mean "pass nil" but literally "the bytecode starts with 00 FE FE"? Programs starting with `00 FE FE` = `Lam(Lam(Var(0)))` = nil at the top level. But that's just sending nil as the entire program — which gives EMPTY.

5. **Think about what "visit things" means as a clue to the answer format**: If after cracking sys8, you need to "visit" a directory tree, then the answer is probably a string found inside that tree. The answer is case-insensitive and goes through sha1^56154, so it's likely a recognizable English word or phrase.
