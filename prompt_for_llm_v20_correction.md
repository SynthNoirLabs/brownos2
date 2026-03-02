# CORRECTION & NEW RESULTS — v20 (Runtime-vs-Wire Retired + β-Equivalence Breakthrough)

You do not have repository/server access. This prompt contains exact live-tested evidence.

---

## 1) CRITICAL BUG IN YOUR PREVIOUS P1-P8 PAYLOADS

Your CW (continuation for quote→write) had a **de Bruijn index bug**:

```
CW = λr. (r (λbytes. (V2 bytes K*)) K*)
```

Under `λr.λbytes` (depth 2), `V2` resolves to `global[0]` (which diverges), **NOT** `global[2]` (sys2/write). To reference sys2 at depth 2, you need `V4`.

**This bug caused ALL P1-P8 to return EMPTY.** Every single one silently called `global[0]` instead of `write`, which diverges.

---

## 2) CORRECTED P1-P4 RESULTS (Boundary Depth-Shift)

| Probe | Description | Result | Interpretation |
|---|---|---|---|
| P1 | echo(V250) partial-K → quote → write | **Bytes printed** (Left_V252 structure) | V252 serializable; partial-unwrap works |
| P2 | echo(V251) partial-K → quote → write | **Encoding failed!** | V253=0xFD unserializable ✓ |
| P3 | echo(V252) partial-K → quote → write | **Encoding failed!** | V254=0xFE unserializable ✓ |
| P4 | echo(V252) full-KK* → quote → write | **Encoding failed!** ← YOUR PREDICTION WRONG | Quote serializes the UNEVALUATED App tree (CBN). Full unwrap via K/K* doesn't help. |

D1-D3 (partial-unwrap → sys8 directly): all **Permission denied**. sys8 doesn't distinguish depth-shifted terms.

---

## 3) ORACLE FALSIFIER RESULTS (3 Decisive Probes)

| Falsifier | Test | Verdict |
|---|---|---|
| 1. Boundary round-trip | `quote(g(248..252))` → all `<N>FF` | **Idempotent. No boundary bug.** |
| 2. Provenance round-trip | live `sys201→pair→quote` = literal `pair→quote` | **Zero provenance sensitivity.** |
| 3. Arity/structure | `quote(pair(K))` = unevaluated `App(pair,K)` (19 bytes) | **quote does NOT reduce. CBN serialization confirmed.** |

**Runtime-vs-wire hypothesis formally retired on all 3 axes.**

---

## 4) YOUR v20 PROBES — TESTED LIVE WITH CORRECT PS CONTINUATION

Your PS continuation was verified correct: `λe. e(λs. write(s)(K*))(K*)`
hex: `00 04 00 FD 00 FE FE FD FE FD 00 FE FE FD FE`
(V4 at depth 2 = global[2] = sys2/write ✓)

### Results:

| Probe | Description | Result | Significance |
|---|---|---|---|
| P1 | `name(256)` canonical | **`wtf`** ✅ | PS works; baseline for hidden node |
| P2 | `readfile(256)` canonical | **`Uhm... yeah... no...\n`** ✅ | File content confirmed with trailing newline |
| **P3** | **`name(I(256))`** β-equivalent arg | **`wtf`** ✅ | **BREAKTHROUGH: decoder accepts computed integers!** |
| **P4** | **`readfile(I(256))`** β-equivalent arg | **`Uhm... yeah... no...\n`** ✅ | **CONFIRMED: decoder is operational, not syntactic** |
| P5 | `name((K 256) Ω)` lazy test | **EMPTY** | Decoder is NOT lazy enough — diverges on omega |
| P6 | `name(257)` adjacent node | EMPTY | No hidden node at 257 |

### Bonus probes:
- `name(258..280)`: all EMPTY — node 256 is isolated
- `readfile(257..260)`: all EMPTY
- `sys8(I(int0))`: Right(6) — sys8 also reduces but still rejects
- `sys8((K int8) int0)`: Right(6) — same

### Hash candidates (10 exact file content variants):
All miss target hash. Tested: mail content, history, passwd, backdoor line, gizmore passwd line — each with and without trailing `\n`.

---

## 5) WHAT THE β-EQUIVALENCE FINDING MEANS

**P3/P4 succeeding is the most significant new finding in this entire project.** It proves:

1. **Syscall decoders REDUCE their arguments** before processing. `name(App(I, N256))` reduces `I(N256)` → `N256` → looks up file 256 → returns `wtf`.
2. **The decoder is call-by-name** — it evaluates just enough to extract the integer. `I(N256)` works because I reduces away. But `(K N256)(Ω)` diverges because the evaluator tries to reduce both K-arguments (or at least touches Ω).
3. **The search space is larger than canonical literals** — but for sys8, we already tested all VALUE TYPES (ints, strings, lambdas, pairs, Left/Right wrappers). β-equivalence doesn't help when the rejection is by type, not by value.

### Implications for sys8

sys8 also reduces its argument (confirmed: `sys8(I(int0))` still gives Right(6), same as `sys8(int0)`). The decoder evaluates the argument and then rejects it. This means sys8's rejection is based on the REDUCED VALUE, not the syntactic form. We've tested every reduced-value type. sys8 is still a wall.

### Implications for the solution path

If the solution doesn't go through sys8, then the β-equivalence finding opens a different angle: **readfile with a COMPUTED file ID**. If there exists a file whose ID is only reachable through computation (not a literal), the flag could be there.

But we scanned name() for 0-280 (all empty beyond 256). Unless the flag file ID is much higher (thousands? hash-derived?), this seems unlikely.

---

## 6) UPDATED HARD CONSTRAINTS

| Fact | Evidence |
|---|---|
| sys8 = static wall for ALL value types | 700+ probes |
| Decoders are operational (reduce args) | P3/P4 β-equivalence success |
| Decoders reduce multi-step (I(I(256)) works) | Q1 = `wtf` |
| Decoders are EAGER, not lazy (touch discarded subterms) | Q2/Q3/P5 all EMPTY (Ω diverges even when discarded) |
| `(λx.N256)(Ω)` diverges despite Ω being discarded | Q2 EMPTY — decoder is NOT call-by-name |
| quote does NOT reduce | Falsifier 3 |
| No provenance sensitivity (live=literal under all syscalls) | Falsifier 2 + Q4-Q8 |
| Backdoor pair/A/B are Invalid Argument for name/readfile | Q4-Q8 + literal baselines — 2 lambdas ≠ 9-lambda Scott int |
| VFS has no hidden files beyond 256 (through 280) | name() scan |
| Node 256 is isolated | name(257..280) all empty |
| PSE (error-aware printer) works correctly | Q4-Q8 print `Invalid argument` instead of EMPTY |

---

## 7) v21 PROBE RESULTS (YOUR PROPOSALS, TESTED LIVE)

### β-Normalization Depth

| Probe | Description | Result | Interpretation |
|---|---|---|---|
| Q1 | `name(I(I(256)))` — 2-step benign | **`wtf`** ✅ | Decoder handles multi-step reduction |
| Q2 | `name((λx.N256)(Ω))` — 1-step, Ω discarded | **EMPTY** | **Decoder diverges on Ω even though it's discarded!** |
| Q3 | `name(((λx.λy.N256) I) Ω)` — 2-step, Ω discarded | **EMPTY** | Same: Ω causes divergence |
| P5 rerun | `name((K 256) Ω)` with QD | **EMPTY** | Confirmed: was divergence, not error suppression |

**Sharp conclusion**: The decoder's evaluator is **eager/strict**, not call-by-name. It reduces `I(I(256))` fine (all subterms are benign), but diverges whenever Ω appears ANYWHERE in the argument, even in positions a lazy evaluator would never touch.

### Backdoor-as-Numeral

| Probe | Description | Result |
|---|---|---|
| Q4 | `name(pair)` — raw backdoor pair | `Invalid argument` |
| Q5 | `name(pair(K))` = name(live A) | `Invalid argument` |
| Q6 | `name(pair(K*))` = name(live B) | `Invalid argument` |
| Q7 | `readfile(pair(K))` | `Invalid argument` |
| Q8 | `readfile(pair(K*))` | `Invalid argument` |
| baseline | `name(literal_A)` | `Invalid argument` |
| baseline | `name(literal_B)` | `Invalid argument` |
| baseline | `readfile(literal_A)` | `Invalid argument` |
| baseline | `readfile(literal_B)` | `Invalid argument` |

**Conclusion**: A (2 lambdas) and B (2 lambdas) are structurally incompatible with the 9-lambda Scott integer decoder. Live and literal behave identically — zero provenance sensitivity. The backdoor pair is NOT a usable numeral for VFS syscalls.

### Hash Candidates
All 5 exact byte-level candidates miss: `Uhm... yeah... no...\n`, `sodu deluser dloser`, `sudo deluser dloser`, `dloser@brownos`, `mailer@brownos`.

---

## 8) WHAT IS NOW KNOWN ABOUT THE DECODER

The integer decoder:
1. **Reduces** its argument (not syntactic-only)
2. **Handles multi-step** benign reductions (I(I(N)) → N)
3. **Is eager/strict** — touches ALL subterms, diverges on Ω even in discarded positions
4. **Rejects non-9-lambda terms** as Invalid Argument (A, B, pair all rejected)
5. **Has no provenance sensitivity** (live backdoor = literal terms)

This means the "operational input" hypothesis is partially right (decoders DO reduce) but the "backdoor-derived numeral" sub-hypothesis is dead (A/B are wrong shape).

---

## 9) YOUR TASK FOR v21

### What to focus on
1. **The decoder is eager, not lazy.** This is a major constraint. Any computed argument must be Ω-free.
2. **A/B are 2-lambda terms, not 9-lambda integers.** They cannot be VFS file IDs. Drop this path.
3. **What 9-lambda Scott integer could be COMPUTED (not literal) that we haven't tried as a file ID?**
4. **If not VFS, what other 3-leaf mechanism prints the flag?**
5. **"Dark magic" + eager decoder** — could the decoder's eagerness itself be exploited?

### Output format
- A) What we're STILL wrong about (max 3 bullets)
- B) Top 2 hypotheses (must explain ALL hints)
- C) 8 exact payloads (AST + hex + expected result + what we learn)
- D) 5 offline hash candidates
- E) The single most informative server query