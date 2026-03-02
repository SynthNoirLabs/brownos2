# CORRECTION & CONTINUATION — Your v18 Plan Was Tested Live and Falsified

You do not have repository/server access. This prompt is self-contained and includes exact outcomes.

We executed your proposed strategy classes live against `wc3.wechall.net:61221` with strict AST decoding (`parse_term -> decode_either -> decode_byte_term`).

Bottom line: your v18 branch produced no unlock. Most probes returned `Right(6)`. Chained probes returned `Right(2)` after fixing de Bruijn indexing.

---

## 1) VERIFIED EXECUTION RESULTS (EXACT)

All payloads are postfix bytecode ending in `FF`.

| Probe | Payload Hex | Decoded Result |
|---|---|---|
| P1 `sys8(App(readdir,int0))(QD)` | `080500fefefefefefefefefefdfd0500fd000500fd03fdfefd02fdfefdfefdff` | `Right(6)` |
| P2 `sys8(App(readfile,int8))(QD)` | `08070400fdfefefefefefefefefefdfd0500fd000500fd03fdfefd02fdfefdfefdff` | `Right(6)` |
| P3 `sys8(Left(nil))(QD)` | `080100fefefdfefefd0500fd000500fd03fdfefd02fdfefdfefdff` | `Right(6)` |
| P4 `sys8(Left(int8))(QD)` | `08010400fdfefefefefefefefefefdfefefd0500fd000500fd03fdfefd02fdfefdfefdff` | `Right(6)` |
| P5 `sys8(nil)(\r.readdir(r))` (corrected indexing) | `0800fefefd0600fd0600fd000600fd04fdfefd03fdfefdfefdfefdff` | `Right(2)` |
| P6 `sys8(int8)(\r.readfile(r))` (corrected indexing) | `080400fdfefefefefefefefefefd0800fd0600fd000600fd04fdfefd03fdfefdfefdfefdff` | `Right(2)` |
| P7 `sys8(\d.\f.\n.n)(QD)` | `0800fefefefd0500fd000500fd03fdfefd02fdfefdfefdff` | `Right(6)` |
| P8 `sys8(\d.\f.\n.d)(QD)` | `0802fefefefd0500fd000500fd03fdfefd02fdfefdfefdff` | `Right(6)` |

No `Left(flag)` path appeared.

---

## 2) IMPORTANT BUG WE FOUND (AND FIXED)

Your continuation-shift assumptions were wrong in this class.

Under one lambda binder, global references shift by +1:
- `g(7)` must be `Var(8)`
- `g(5)` must be `Var(6)`

An earlier test mistakenly used unshifted globals and produced a large `Left(...)` blob. That was a continuation wiring artifact, not a sys8 breakthrough. After fixing shifts, both chains resolve to `Right(2)`.

Do not reuse the old chain interpretation.

---

## 3) WHAT THIS FALSIFIES

Your proposed classes are now falsified on live execution:

1. Semantic thunk authorization (`sys8(App(sysX,arg))`) with tested read/readdir thunks.
2. Capability envelope hypothesis (`Left(nil)`, `Left(int8)`).
3. `Right(6)` as usable resource pointer in read/readdir chain (with correct indexing).
4. 3-lambda dir-node route for `sys8` dispatch (`\d.\f.\n.*`).

---

## 4) HARD CONSTRAINTS YOU MUST RESPECT NEXT

1. Backdoor pair is not Scott cons.
2. Syscall outputs are decoded from AST, not hex heuristics.
3. De Bruijn rule: under `k` lambdas, global `g(n)` becomes `Var(n+k)`.
4. Avoid classes already tested above (including alpha/eta-equivalent forms).
5. Solution must be pre-echo compatible in principle (echo added later).

---

## 5) YOUR NEXT TASK (v18b)

Produce a new plan with **only genuinely new classes** not equivalent to the falsified branch above.

### Required output format

#### A) "Likely still wrong assumptions" (max 6 bullets)

#### B) "Top 3 hypotheses" (exactly 3)
- Each must explain why it survives all failed classes above.

#### C) "Exact payload set" (12 payloads total)
- 4 payloads per hypothesis.
- For each payload include:
  - AST (`Var/Lam/App` form)
  - bytecode derivation step-by-step
  - final hex payload
  - expected decoded result
  - falsifier condition

#### D) "Equivalence guard"
- Explicitly prove each of your 12 payloads is not equivalent (alpha/beta/eta + de Bruijn renaming) to P1-P8 above.

#### E) "Stop conditions"
- One stop condition per hypothesis.

---

## 6) KEY CONTEXT SNAPSHOT

- Service: `wc3.wechall.net:61221`
- Protocol: postfix lambda bytecode (`00..FC` Var, `FD` App, `FE` Lam, `FF` EOF)
- Syscalls of interest: `2,4,5,6,7,8,14,42,201`
- Stable outcomes observed so far: mainly `Right(6)`, `Right(3)`, `Right(2)`, `EMPTY`
- Target remains iterated hash challenge answer (`sha1^56154(answer)` known target hash)

---

Do not restate old theories. Give a fresh, constrained, testable v18b branch.
