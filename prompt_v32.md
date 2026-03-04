# BrownOS v32 — Higher-Order Argument Theory Debunked

**Repo**: `https://github.com/SynthNoirLabs/brownos2`  
**Date**: 2026-03-04  
**Previous**: `prompt_v31.md`

---

## 1. What We Tested This Round

We tested the hypothesis that **sys8 is a higher-order function that calls its argument** (acting as a caller rather than a consumer). If sys8 expects a function to which it will pass a hidden capability or challenge, it would attempt to apply its argument.

To test this without side-effect dependencies, we used an "Arity Ladder" consisting of functions that immediately diverge (using `Ω = (λx. x x)(λx. x x)`) if applied.
If `sys8` applied its argument:
- `sys8(λx. Ω)` would hang if sys8 applies 1 argument.
- `sys8(λx. λy. Ω)` would hang if sys8 applies 2 arguments.
- `sys8(λx. λy. λz. Ω)` would hang if sys8 applies 3 arguments.

We also tested using `QD` directly as the argument, which would have printed the hidden capability if sys8 had passed it one.

### `probe_sys8_higher_order.py` Results

| Probe | Shape | Result |
|-------|-------|--------|
| P1 | `sys8(λx. Ω) PSE` | **Permission denied** |
| P2 | `sys8(λx. λy. Ω) PSE` | **Permission denied** |
| P3 | `sys8(λx. λy. λz. Ω) PSE` | **Permission denied** |
| P4 | `sys8(QD) K*` | EMPTY |
| P5 | `sys8(QD) PSE` | **Permission denied** |
| P6 | `sys8(λx. QD(x)) K*` | EMPTY |
| P7 | `sys8(λx. λy. QD(x)) K*` | EMPTY |
| P8 | `sys8(λx. λy. QD(y)) K*` | EMPTY |
| P9 | `sys8(λx. quote(x) PS) PSE` | **Permission denied** |
| P10 | `sys8(λx. error_string(x) PS) PSE` | **Permission denied** |
| P11 | `sys8(λx. name(x) PS) PSE` | **Permission denied** |
| P12 | `sys8(λx. readfile(x) PS) PSE` | **Permission denied** |

*(Note: EMPTY results in P4, P6-P8 are due to `K*` swallowing the `Right(6)` without printing. When `PSE` is used to observe, we see `Permission denied`.)*

---

## 2. Analysis & Synthesis

The "higher-order callback" hypothesis is **DEAD**.

1. **`sys8` never applies its argument**: Because `sys8(λx. Ω)` returns `Right(6)` instantly instead of timing out, the VM never attempts to beta-reduce the application of `sys8`'s argument to anything. 
2. **The gate is strictly an inspection/pre-condition**: `sys8` inspects the argument or the environment *before* applying it, or the gate is entirely orthogonal to the argument's structure as a function.

We have now ruled out:
- Direct data values (pairs, strings, integers)
- Forged structures (Either, Scott lists)
- Raw minted capabilities from other syscalls (passing `sys8` as the direct CPS continuation)
- Higher-order callbacks (sys8 applying the argument)

---

## 3. What is left?

The walls are closing in on the VM's mechanics. The remaining avenues point towards environmental/contextual states rather than argument manipulation.

### A. The "Execution Context" (Theory 3 from v30)
Instead of passing the backdoor pair *to* `sys8`, we must use the backdoor pair to *wrap or execute* `sys8`.
- `backdoor_pair(sys8)(credential)`
- `A(sys8)(credential)` or `B(sys8)(credential)`
Since we now know `sys8` doesn't call its argument, maybe it expects to be *called by* a specific structure (or under a specific scope). 

### B. Index Laundering via Internal Lambdas (Theory 4 from v30)
The 2016 hinting around "crucial properties of the codes" might refer to dynamically generated de Bruijn indices.
- A term with `Var(251)` passed into a destructing function gets shifted. If it hits `253` (FD), `254` (FE), or `255` (FF), the VM might interpret it as a built-in macro or capability marker that we couldn't type directly on the wire.

### C. Specific Data Structures We Haven't Crafted Perfectly
Is there a specific 3-part or 4-part Scott ADT that we haven't fed to `sys8`? E.g., `[username, password, access_log]` all properly encoded as byte-lists and nested in a specific tuple shape. (Though P1-P3 suggest `sys8` doesn't even destruct functions properly if they aren't the exact ADT, it might do a fast fail if the arity of the top-level lambdas doesn't match an expected 3-way list... wait, we tested 3-way lists directly from `readdir` in v31, and it failed).

---

## 4. Next Steps

1. **Test Theory 3 (Backdoor as Execution Context)**: 
   Write a probe that flips the relationship: `backdoor_pair(sys8)(credential)`.
   Specifically test:
   - `(((backdoor nil) λpair. ((pair 8) credential)) PSE)`
   - `(((backdoor nil) λpair. ((8 pair) credential)) PSE)`
   - `A(8)`, `B(8)`

2. **Test Theory 4 (Index Laundering)**:
   Pass high-index vars inside lambdas to see if the VM shifting logic overflows them into `FD/FE/FF` and triggers hidden behavior.
