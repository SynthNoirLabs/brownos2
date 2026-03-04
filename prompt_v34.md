# BrownOS v34 — The Real Hints (dloser Jan 2026) + Full Context

**Repo**: `https://github.com/SynthNoirLabs/brownos2`  
**Date**: 2026-03-04  
**Previous**: `prompt_v33.md`  
**Status**: UNSOLVED after 16,000+ probes. Major new hints discovered.

---

## CRITICAL NEW DISCOVERY: DLOSER'S JANUARY 2026 HINT

On **January 16, 2026**, dloser (the challenge author) posted a disguised hint on the WeChall Disappointment Thread (t1575 page 2). This is in response to user `kom0d0` asking about sys8. dloser wrote it as an in-character "BOS BBS" post:

> *"Yeah, agreed. IT always seems too busy casting their dark magic instead of making life easier for us. At least they won't notice us trying to hack it... ;)"*
>
> *"Anyway, it seems like a lot of you are **focusing on 8 directly**, but for me it is quite obvious that **the mail points to the way to get access there**. My record is **3 leafs** IIRC. I'm trying to focus on actually understanding the code a bit better now, though. That has to help getting something more compact."*
>
> *"B.t.w., did anyone play a bit with that **new syscall**? Could be a bug, but I'm getting some **interesting results when combining the special bytes**. I'll make a post about it soon. Be careful though: **once it froze my whole system!** (Took a week before IT came to turn it off and on again!) Besides, **why would an OS even need an echo? I can easily write that myself...**"*

### Line-by-line Interpretation

| Quote | Meaning |
|-------|---------|
| "focusing on 8 directly" | **STOP attacking sys8 head-on.** We've been doing exactly this for 16,000 probes. |
| "the mail points to the way to get access there" | The mail says "Backdoor at syscall 201; start with 00 FE FE." The backdoor IS the path to sys8. |
| "My record is 3 leafs" | The solution program has **3 Var (leaf) nodes**. Extremely tiny. |
| "understanding the code a bit better" | Understanding the bytecodes themselves matters. |
| "that new syscall" / "echo" | Echo (0x0E) produces interesting results but is **not required** ("I can easily write that myself"). |
| "combining the special bytes" | FD/FE/FF (the protocol markers) combined with echo or other syscalls produce novel effects. |
| "froze my whole system" | Creating terms with Var(253/254/255) at runtime causes non-termination / evaluator confusion. |

### Also From the Same Thread

**pouniok** (March 3, 2026 — yesterday):
> *"If you manage to reach the part where you need to **visit things**, I would be glad to have some help"*

pouniok claims to have gotten PAST the sys8 wall into a "visit things" phase. He's asking for help with what comes AFTER.

**kom0d0** (January 15, 2026):
> *"I managed to get a good amount of things... I'm currently hitting my head against the wall trying to put together the goddamn 0x08, the mysterious email and THAT password"*

---

## ADDITIONAL DISCOVERY: SOURCE CODE

The WeChall web framework (`gizmore/gwf3` on GitHub) contains the challenge's web-side code at `www/challenge/dloser/brownos/`:

**`install.php`** reveals: `WC_Challenge::CHALL_CASE_I` → **The answer is CASE INSENSITIVE.**

**`index.php`** shows verification logic:
```php
$answ = $_POST['answer'];
for ($i = 0; $i < 56154; $i++) {
    $answ = sha1($answ);
}
// compared against "9252ed65ffac2aa763adb21ef72c0178f1d83286"
```

The VM binary itself is NOT in the repo — it runs separately on port 61221.

---

## THE "3 LEAFS" CONSTRAINT

A program with exactly 3 Var (leaf) nodes. Examples:

| Structure | Bytecode | Leaves |
|-----------|----------|--------|
| `((Var(a) Var(b)) Var(c))` | `a b FD c FD FF` | 3: a, b, c |
| `(Var(a) (Var(b) Var(c)))` | `a b c FD FD FF` | 3: a, b, c |
| `((Var(a) Lam(Var(b))) Var(c))` | `a b FE FD c FD FF` | 3: a, b, c |
| `((Var(a) Lam(Lam(Var(b)))) Var(c))` | `a b FE FE FD c FD FF` | 3: a, b, c |

**Critical**: `nil = Lam(Lam(Var(0)))` contains 1 leaf (Var(0)). So `((backdoor nil) X)` = `((Var(201) Lam(Lam(Var(0)))) Var(X))` has exactly 3 leaves: Var(201), Var(0), Var(X).

The most natural 3-leaf program following the mail hint:
```
((backdoor nil) sys8) = C9 00 FE FE FD 08 FD FF
```
This calls backdoor(nil), gets Left(pair(A,B)), then passes it to sys8 as the CPS continuation.

**What happens**: `backdoor(nil)` → `Left(pair(A,B))` → `Left(pair)(sys8)` → `sys8(pair(A,B))` ... but wait, that's not right. In CPS:
- `Left(x) = λl.λr. l(x)`, so `Left(pair)(sys8) = λr. sys8(pair)` — partial application, returns a function.

The more likely CPS interpretation: `((backdoor nil) sys8)` means sys8 is the LEFT handler of the backdoor's Either result. So `sys8` receives `pair(A,B)` as its argument. We tested `sys8(pair)` and got Right(6). But we tested it WITH an observer. Without an observer, the bare program just returns EMPTY.

**What if EMPTY IS the answer?** dloser said EMPTY = success. Maybe `C9 00 FE FE FD 08 FD FF` actually SUCCEEDS silently, and the answer is derived from the program itself, not from output?

---

## THE COMPLETE DEAD-END MAP (16,000+ Probes)

Everything below has been tested and returns Right(6) / Permission denied:

| Category | Tests | Result |
|----------|-------|--------|
| Direct values to sys8 | 700+ integers, strings, combinators | Right(6) |
| Credential strings | "ilikephp", "gizmore", "root", etc. | Right(6) |
| Backdoor pair → sys8 | naked pair, A, B, pair(A,B) | Right(6) |
| Combinator algebra | A(A), B(A), A(B), etc. | Right(6) |
| File contents → sys8 | passwd, history, mail, access.log | Right(6) |
| Bytecode-as-data | Scott byte-lists of raw programs | Right(6) |
| Quote→sys8 pipeline | quote(T)→unwrap→sys8 | Right(6) |
| Raw minted capabilities | sys8 as direct CPS continuation | Right(6) |
| Higher-order testing | Arity ladder (sys8 does NOT call its arg) | Right(6) |
| Syntactic differential | sys8((I nil)) vs sys8(nil) — identical | Right(6) |
| VFS state unlock | backdoor→readfile/readdir (no change) | Same as without |
| Unwrapped ADTs | 3-way readdir list, file bytes → sys8 | Right(6) |
| Forged tokens | Left/Right wrappers | Right(6) |
| CPS adapters | All compositions | Right(6) |
| 3-leaf brute force | 10,000+ programs | Right(6)/EMPTY |
| Stub globals | 242 stubs with typed inputs | Right(1) |
| Hidden files | IDs 257-1024 | None found |
| Offline hash | 34+ string candidates | No match |

---

## ALL VERIFIED FORUM HINTS (from actual HTML, not hallucinated)

### dloser (author) — 2016, thread t917
1. *"The second example in the cheat sheet, besides providing a way to get some easy outputs, is also useful in figuring out some crucial properties of the codes."*
2. *"The different outputs betray some core structures. This should give you some substructures that might be helpful elsewhere."*
3. *"I haven't heard of anyone figuring out the meaning of the input codes. Figuring out that part is probably the most important thing to do."*
4. *"don't be too literal with the ??s"*

### dloser — Sep 2018, thread t917
5. (to l3st3r who got EMPTY): *"If you didn't want it to return anything, yes."* (EMPTY = success)

### dloser — Jan 2026, thread t1575 (THE KEY HINT)
6. *"focusing on 8 directly [is wrong]... the mail points to the way to get access there. My record is 3 leafs."*
7. *"combining the special bytes... froze my whole system... why would an OS even need an echo? I can easily write that myself"*

### l3st3r (solver) — May 2018, thread t917
8. *"I can make it return 'a towel!' and 'O' ' towel!' (two consecutive reads) using the exact same input data. Granted, I had to send a bad QD."*

### space (solver) — Nov 2025, thread t1575
9. *"Folks, you should try it again! It's fun! I just found my old stuff on a legacy hard drive. Don't give up."*

### pouniok — Mar 2026, thread t1575
10. *"If you manage to reach the part where you need to visit things, I would be glad to have some help"*

---

## WHAT WE KNOW FOR CERTAIN

1. **The answer is case-insensitive** (from source code)
2. **The answer goes through sha1^56154** (from source code)
3. **sys8 should NOT be attacked directly** (dloser Jan 2026)
4. **The backdoor IS the path** (dloser Jan 2026)
5. **3 leaves is achievable** (dloser Jan 2026)
6. **Echo is not required** (pre-2018 solvers existed; dloser says "I can write that myself")
7. **Special bytes (FD/FE/FF) produce interesting effects** (dloser Jan 2026)
8. **There's a "visit things" phase AFTER cracking access** (pouniok Mar 2026)
9. **The backdoor returns pair(A,B)** where A=λab.bb, B=λab.ab
10. **sys8 does NOT call its argument** (proven with omega ladder)
11. **sys8 appears to normalize before inspecting** (syntactic differential shows identical responses)

---

## REMAINING THEORIES

### Theory A: The 3-Leaf Backdoor Program (HIGHEST PRIORITY)
The program `((backdoor nil) X)` has 3 leaves. What should X be?
- `X = sys8` (Var(8)) → `C9 00 FE FE FD 08 FD FF`
- `X = quote` (Var(4)) → `C9 00 FE FE FD 04 FD FF`
- `X = write` (Var(2)) → `C9 00 FE FE FD 02 FD FF`
- `X = readdir` (Var(5)) → `C9 00 FE FE FD 05 FD FF`
- `X = readfile` (Var(7)) → `C9 00 FE FE FD 07 FD FF`
- Other globals?

Or maybe the structure is different:
- `(Var(a) (backdoor nil))` → `a C9 00 FE FE FD FD FF`
- `(backdoor (Var(a) Var(b)))` → different arg to backdoor (but it only accepts nil!)

### Theory B: EMPTY Output IS the Answer
What if `C9 00 FE FE FD 08 FD FF` (or another 3-leaf) produces EMPTY, and EMPTY means "the server registered your solve"? The answer would then be something we submit on the webpage — perhaps derived from the program itself.

### Theory C: The Answer Is the Bytecode Itself
If the answer is case-insensitive and the bytecode `C9 00 FE FE FD 08 FD FF` is the solve, maybe we submit the hex string "c900fefefd08fdff" or similar on the challenge page.

### Theory D: "Visit Things" = Filesystem Traversal After Unlock
pouniok says there's a "visit things" phase. After getting past sys8, you might need to traverse the filesystem (readdir = "visit" directories) to find the flag string somewhere.

### Theory E: Special Bytes Create a Capability
"Combining the special bytes" with echo creates Var(253)=FD, Var(254)=FE, Var(255)=FF at runtime. These might be secret capabilities that bypass the sys8 gate. But echo isn't required, so maybe there's another way to construct them.

---

## BRUTE FORCE FEASIBILITY

We built a C brute-forcer (`brute_brownos.c`). On an M2 Max:
- Dictionary (272 challenge-themed words): **8 seconds** — DONE, no match
- a-z, 1-5 chars: **~3 hours**
- a-z + digits, 1-5 chars: **~14 hours**
- a-z, 1-6 chars: **~3 days**

---

## WHAT TO DO NEXT

1. **Test ALL 3-leaf bare programs** `((backdoor nil) Var(X))` for X = 0..252. This is 253 probes. If any produces novel behavior (not EMPTY, not an error), that's the breakthrough.

2. **Test if the bytecode itself is the answer**. Submit hex strings like "c900fefefd08fdff" on WeChall.

3. **Think about what "3 leafs" means differently**. Maybe it's not `((201 nil) X)` but a completely different structure with 3 leaves.

4. **Think about what "the mail points to the way"** means concretely. The mail says two things: (a) syscall 201, (b) "start with 00 FE FE". Maybe "00 FE FE" is not just nil — maybe it's literally the start of the bytecode and the rest follows.

5. **Think about "visit things"**. If pouniok is past the gate, what does visiting mean in this context?
