# BrownOS v24 — CPS Adapter Algebra Confirmed, sys8 Still Locked

**Repo**: `https://github.com/SynthNoirLabs/brownos2`  
**Date**: 2026-03-02  
**Previous**: `prompt_v23.md`

---

## What we tested (19 live probes, ALL succeeded)

Your CPS adapter hypothesis is **completely confirmed**. Every single adapter works exactly as predicted.

### Adapter building blocks verified ✅

| Adapter | AST | Hex | Function |
|---------|-----|-----|----------|
| `Cw` | `λr. r(write)(K*)` | `0003fd00fefefdfe` | Route Left→write |
| `Cn` | `λr. r(name)(K*)` | `0007fd00fefefdfe` | Route Left→name |
| `Cr` | `λr. r(readfile)(K*)` | `0008fd00fefefdfe` | Route Left→readfile |
| `Cq` | `λr. r(quote)(K*)` | `0005fd00fefefdfe` | Route Left→quote |
| `C_sys8` | `λr. r(sys8)(K*)` | `0009fd00fefefdfe` | Route Left→sys8 |
| `Rerr` | `λr. r(K*)(error_string)` | `0000fefefd02fdfe` | Route Right→error_string |

### Full probe results (all 19)

```
P1:  error_string(N6)→Cw→write       → "Permission denied"          ✅
P2:  name(N256)→Cw→write             → "wtf"                        ✅
P3:  readfile(N256)→Cw→write         → "Uhm... yeah... no...\n"     ✅
P4:  echo(N256)→Cn→name→PS           → "wtf"                        ✅ NOVEL
P5:  echo(N256)→Cr→readfile→PS       → "Uhm... yeah... no...\n"     ✅ NOVEL
P6:  backdoor(K*)→Cq→quote→PS        → pair bytecode                ✅
P7:  sys8(N0)→Rerr→err_str→Cw→write  → "Permission denied"          ✅
P8:  readdir(N256)→Rerr→err_str→Cw   → "Not a directory"            ✅ NOVEL
P4e: echo(N256)→Cn→name→PSE          → "wtf"                        ✅
P9:  echo(N256)→C_sys8→sys8→PSE      → "Permission denied"          ✅
P10: echo(N0)→Cn→name→PSE            → "/"                          ✅ (name(0)=root)
P11: echo(N256)→Cq→quote→PS          → N256 bytecode                ✅
E1:  echo(Var(8))→C_sys8→PSE         → "Permission denied"          ✅ sys8(sys8)
E2:  echo(A)→C_sys8→PSE              → "Permission denied"          ✅ sys8(ω)
E3:  echo(B)→C_sys8→PSE              → "Permission denied"          ✅ sys8(B)
E4:  echo(pair)→C_sys8→PSE           → "Permission denied"          ✅ sys8(pair)
E5:  backdoor→C_sys8→PSE             → "Permission denied"          ✅ sys8(pair) via bdoor
E6:  readfile(11)→C_sys8→PSE         → "Permission denied"          ✅ sys8(/etc/passwd)
E7:  readfile(65)→C_sys8→PSE         → "Permission denied"          ✅ sys8(command log)
```

### Confirmed facts from this batch

1. **Echo IS a generic Left producer**: `echo(X)→C_g→g(X)` works for g ∈ {name, readfile, quote, sys8}
2. **Adapter composition chains work end-to-end**: 4-step chains (sys8→Rerr→error_string→Cw→write) execute correctly
3. **Right-routing works**: `Rerr = λr. r(K*)(error_string)` correctly routes Right codes into error_string
4. **sys8 is IMPENETRABLE through any adapter composition**: E1–E7 tested sys8 with itself, omega, B, pair, /etc/passwd content, command log content — all Right(6)
5. **P10 confirms name(0) = "/"**: file ID 0 is the root directory

---

## Bug found in your hex

Your "most informative query" hex had a **de Bruijn bug in the PSE inner write reference**:

```
Position 79 (byte 40 of the PSE):
  Your hex: ...0300fd000400fd...  ← Var(4) at depth 4 = global[0] (WRONG)
  Correct:  ...0300fd000600fd...  ← Var(6) at depth 4 = global[2] = write (CORRECT)
```

Inside PSE's `λe → λc → λr2 → λstr`, write (global[2]) is Var(2+4) = Var(6), not Var(4). Same bug class as the CW incident. Our AST-built payloads had the correct indices — this is why we always generate hex from AST, never trust hand-assembly.

---

## What the adapter algebra DOES and DOES NOT give us

### DOES give us
- Clean Left/Right routing between any two syscalls
- Multi-step pipelines (producer → adapter → consumer → adapter → consumer)
- Proof that echo, backdoor, readdir, sys8 all play nicely in the CPS framework
- Verified that "3 leafs" matches the adapter size regime (C_g has 3 leaf variables: V0, V(g+1), V0_in_K*)

### DOES NOT give us
- Any way to make sys8 return Left
- sys8 remains Right(6) for every argument type: integers, strings, pairs, combinators, file contents, syscall functions themselves, omega
- The adapters are a **tool** but not the **key**

---

## Exhaustively retired (after this batch)

| Approach | Probes | Result |
|----------|--------|--------|
| sys8 with integer args (0–280+) | 700+ | Right(6) |
| sys8 with lambda structures (I, K, K*, S, ω, pair, A, B) | 50+ | Right(6) |
| sys8 via adapter composition (echo→sys8, backdoor→sys8) | 7 new | Right(6) |
| sys8 with file contents (passwd, cmd log) | 2 new | Right(6) |
| sys8 with its own function as arg | 1 new | Right(6) |
| Hash candidates (adapters, passwords, filenames, etc.) | 35+ | No match |
| Forged tokens / non-standard Either wrappers | 40 | Right(6) |
| Runtime-vs-wire exploit | 10 | Retired |
| Hidden VFS nodes (scan 0–280, special IDs) | 30+ | Only 256 exists |
| Provenance sensitivity | 5 | None |
| Side effects during decode | 5 | None reach socket |

---

## What's still live

### The gap
We have a **complete, working CPS pipeline toolkit** but no idea what to PUT THROUGH IT that makes sys8 succeed. The direct argument space is saturated. The adapter composition space doesn't change sys8's behavior.

### Author hints still unexplained
1. **"3 leafs"** — C_g adapters have exactly 3 leaves. But we've tested them and they don't unlock sys8. Is "3 leafs" about something else?
2. **"the mail points to the way"** — backdoor→sys8 gives Right(6). backdoor→quote→write gives pair bytecode. What else can we DO with the pair?
3. **"IT is always casting its dark magic, it wont even realize we hacked it"** — "IT" = the evaluator. This implies TRICKING the evaluator into not recognizing that sys8 is being called. How?
4. **l3st3r: "Good input gives good stuff back"** — implies sys8 CAN return Left. But what input?

### Unexplored directions
1. **Evaluator trickery**: Can we construct a term where sys8 is invoked during reduction in a way the evaluator doesn't catch? (e.g., building sys8 from components rather than using Var(8) directly)
2. **Computed syscall numbers**: What if we can construct a "syscall" by building the function from the global environment rather than referencing it directly?
3. **Hidden global behaviors**: The 242 "stub" globals were tested with I and QD as args. What if a specific stub responds differently with a different specific arg? (253 × many = huge space)
4. **The pair as a COMBINATOR**: pair = λf.λg. f(A)(B) where A=ω, B=λ.λ.(1 0). What if applying pair to specific terms produces something useful?
5. **Backdoor with non-nil arg**: ~~We always call backdoor(K*). What if backdoor(something_else) returns a different value?~~ **TESTED AND ANSWERED**: backdoor returns `Right(2) = Invalid argument` for EVERY arg except `K*` (nil). Only `backdoor(K*)` → `Left(pair)`. Backdoor is a single-value accessor, not parameterized.

### Additional findings from this batch
- **backdoor(K*)→PSE = EMPTY**: pair is not a valid Scott string, so write's eager decoder fails on it silently
- **pair(K)(I) = A = ω** and **pair(K*)(I) = B** (via quote): pair projections work but produce known trivial values
- **quote doesn't reduce** confirmed again: quote(pair(K)(I)) returns bytecode of the unevaluated App, not bytecode of ω

### What I'd test next if I knew what to look for
- Test whether building a "fake sys8" from the environment (not Var(8) directly) bypasses permission checks
- Investigate whether the evaluator's syscall recognition is based on Var identity vs reduction result
- Broader file ID scan at scale (there may be a file at a non-obvious ID containing the answer)
- Try sys8 with a continuation other than CPS-standard — maybe sys8 checks its continuation structure?

---

## Your call

The adapter algebra is proven but it's a tool, not the answer. What direction do you recommend?

**Full technical reference**: `BROWNOS_MASTER.md`, `solve_brownos_answer.py`, `probe_cps_adapters.py` (all in the repo)
