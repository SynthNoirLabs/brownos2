# Session Analysis & Results Summary — March 04, 2026

This document summarizes the analysis of the external LLM responses and the results of the subsequent 50+ probes run against the BrownOS server today.

## 1. ANALYSIS OF EXTERNAL LLM RESPONSES (v34 -> v35)

We evaluated two distinct responses from external models and ran their proposed probes.

### Response 1 (Structural Analysis)
- **Proposed**: A "Poisoned ADT Ladder" to see if `sys8` decodes its argument.
- **My Verdict**: Partially successful as a diagnostic, but ultimately failed as a breakthrough.
- **Why**: The original controls were flawed (gave FALSE NEGATIVES). I rebuilt the experiment with **valid controls** (`name` and `write` which we confirmed DO force lambda bodies).
- **Result**: Proved definitively that **`sys8` is a SHALLOW gate**. It rejects everything (~234ms) before looking inside the argument.

### Response 2 (Stateful Chain Analysis)
- **Proposed**: Stateful `backdoor -> sys8(password)` chains.
- **Claimed**: A "shift bug" in our Python DSL was corrupting passwords.
- **My Verdict**: **FALSE**. I verified our named-term DSL mathematically and via `quote` inspection. There is no shift bug. Our stateful chains were correct; the VM simply rejected them.
- **Result**: Stateful chains with `ilikephp`, `boss@evil.com`, and others all returned `Permission denied`.

---

## 2. KEY PROBE RESULTS (MARCH 04)

### Group 1: The "Shallow Gate" Proof
| Probe | Control | `sys8` Result | Conclusion |
|-------|---------|---------------|------------|
| `λ^9. Ω` | `name` hangs | Permission Denied | sys8 doesn't check body |
| `λc.λn. cons(A, Ω)` | `write` hangs | Permission Denied | sys8 doesn't check body |

### Group 2: Stateful Backdoor
- **Rereaddir(0)** before and after `backdoor(nil)` → **IDENTICAL**.
- **Conclusion**: The backdoor does not modify the VFS or system state in any detectable way.

### Group 3: Bytecode-as-Data
- Passed raw bytecode hex strings as Scott byte-lists to `sys8`.
- **Result**: All `Permission denied`. Sys8 is not a bytecode loader/verifier in that format.

---

## 3. THE "3 LEAFS" PARADOX

We have tested all 253 variations of `((201 nil) X)` bare. All return `EMPTY` (as expected for a partial application). 
dloser (Jan 2026) says: **"My record is 3 leafs IIRC."**

If 3 leaves is the record, and `((201 nil) X)` is just a partial app, then either:
1. The 3-leaf program is **not** `((201 nil) X)`.
2. The 3-leaf program **is** `((201 nil) X)`, and the "success" is so silent it doesn't even close the connection differently.
3. The 3-leaf program involves **special bytes** (Var 253-255) generated via runtime shifting.

---

## 4. CURRENT STATUS & NEXT STEPS

- **Brute Force**: `brute_brownos.c` is ready. Run it in terminal: `./brute_brownos brute`.
- **Pure-Lambda Echo**: We need to test the special byte range (253-255) using the pure-lambda wrapper `E = λx.λk. k(Left x)`.
- **Access Goal**: The gate is shallow. It's likely checking for a **capability term** (a very specific AST shape containing reserved indices) rather than a data value.

Everything is synthesized in **`prompt_v36.md`**.
