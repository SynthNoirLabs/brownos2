# BrownOS — Open Questions, What Remains, and Common LLM Mistakes

## ⚠️ COMMON LLM MISTAKES — DO NOT REPEAT THESE

### Mistake 1: "Sys201 as Continuation Sets Authentication State"
**Wrong.** There is no authentication state. Each evaluation is stateless within a single term reduction. Running sys201 before sys8 does not "authenticate" you. This was tested: `(((sys201 nil) sys8) QD)` → Right(6). Stateful chaining across syscalls within the same program was tested exhaustively — no effect.

### Mistake 2: "Pair is Topologically Identical to Cons"
**Factually wrong.** Pair = `λs.(s A B)` has 1 lambda, selector V0. Cons = `λc.λn.(c h t)` has 2 lambdas, selector V1. They are structurally distinct. No "duck-typing" confusion occurs.

### Mistake 3: "CBN Lazy Evaluation Means Arguments Aren't Evaluated"
**Partially true but irrelevant.** The VM may use call-by-name, but sys8's permission gate returns Right(6) whether it receives an evaluated value or an unevaluated thunk. This was directly tested: `sys8(g201(nil))(OBS)` → Right(6). The thunk vs value distinction doesn't bypass the permission check.

### Mistake 4: "Empty Responses = Broken QD Due to Shifting"
**Wrong.** The probes use a named-term DSL with automatic de Bruijn shifting. Manually shifted QD was also tested. Empty responses have many causes (no write side-effect, divergence, timeout) and are normal behavior, not QD bugs.

### Mistake 5: "The 3-Leaf Solution Hasn't Been Tried"
**Wrong.** 5,346+ 3-leaf term combinations were exhaustively tested including all variations of `((a b) c)` and `(a (b c))` with all relevant syscall globals. See file 08_NEGATIVE_RESULTS.md.

### Mistake 6: "Guaranteed/Mathematical Proof"
No LLM should claim any payload is "mathematically guaranteed" or "proven" to work. Every such claim has been tested and failed. The VM's internal logic is unknown — we only observe input/output behavior.

### Mistake 7: "Syscalls Are Lambdas You Can Beta-Reduce"
**Wrong.** Syscalls are opaque C++ primitives handled by native dispatch. The C++ evaluator intercepts `App(App(primitive, arg), cont)` at the native level. You CANNOT beta-reduce `sys8` as if it were `λcont. cont(Right 6)`. Partial applications without continuations just stop at WHNF → EMPTY. There is no user-space lambda body to manipulate.

### Mistake 8: "Conflating Var(N) with sys_N(nil)"
**Wrong.** `echo(Var(201))` wraps the **raw variable reference** `Var(201)` in Left. It does NOT invoke syscall 201 or return the backdoor pair. To get the pair, you must call `sys201(nil)` = `App(App(Var(201), nil), cont)`. Just referencing `Var(201)` gives you an opaque pointer to the syscall primitive, not its output.

### Mistake 9: "3-Leaf Limit Mathematically Proves Strings Are Impossible"
**Wrong.** Syscalls generate data at runtime from minimal inputs. Example: `sys7(int(11))` → `Left("root:x:0:0:root:/:/bin/false\nmailer:x:100...")` — 181 bytes of string data from a 2-leaf term. The 3-leaf limit constrains the **program**, not the **data the program manipulates**.

### Mistake 10: "Silent Success — Check Your WeChall Score"
**Wrong.** The TCP socket is anonymous — no authentication, no session, no IP binding. The server literally cannot know who connected. WeChall requires you to submit a string answer on the website. The VM MUST physically write the flag to the TCP socket so we can read it. If 0 bytes come back, nothing happened.

---

## What Is Definitively Known

1. Syscall 8 is CPS-compliant — calls its continuation with Right(6)
2. Syscall 8 is argument-independent (for most types) — Right(6) regardless
3. String arguments enter a different code path → Right(3) NoSuchFile
4. The backdoor pair also triggers Right(3) (pair is duck-typed as string due to structural similarity... but NOT identical to cons — see Mistake 2)
5. No hidden syscalls in 0–252
6. No cross-connection state
7. No timing-based checks
8. Echo manufactures Var(253+) — the only way to create these values
9. Quote cannot serialize Var(253+)

---

## Remaining Unexplored Directions (Genuinely Not Yet Tested)

### ~~Direction A: Wire-Format Confusion with Var(253) in Specific Positions~~ TESTED
**DISPROVED**: Var(253) in function position was tested in 6+ probes (probe_var255.py, probe_extended_ids.py, probe_continuation_hypothesis.py, probe_hidden_globals.py, probe_use_unserializable.py). No OOB behavior, no hidden syscall, no special response. See file 08 section 16 and file 11 Correction 2.

### Direction B: Non-Standard Term Structures (PARTIALLY EXPLORED)
We've used the standard CPS pattern `((sys8 arg) QD)`. The "consumer inversion" pair(sys8)=sys8(A)(B) was tested in 10+ probes (see file 08 section 15). But:
- What if the solution doesn't use CPS at all?
- What if sys8 should appear inside another syscall's reduction?
- What about terms where sys8 is NOT the outermost function?

### Direction C: IDs Beyond 1024
We scanned filesystem IDs 0–1024. The additive encoding supports arbitrary large numbers. There might be hidden entries at much higher IDs.

### Direction D: The Answer Might Not Come from Syscall 8
Maybe the WeChall answer comes from:
- A transformation of known filesystem data we haven't computed
- The bytecode of the solution term itself
- Something derivable from A, B combinators that we haven't recognized
- A different syscall interaction entirely

### Direction E: Deeper Combinator Algebra
A and B are related to application and omega. Their deeper algebraic properties might construct:
- A fixed-point combinator (Y combinator analog)
- A specific Church/Scott encoding
- Something that, when applied in a precise way, produces a recognizable answer

### Direction F: The Pre-2018 Solution Path
Before echo existed (2014–2018), the challenge was solvable. The original solution might be:
- Purely based on understanding the VM reduction model
- Related to how sys8 interacts with specific lambda structures
- Not dependent on echo/Var(253) at all (echo might just be a shortcut)

### Direction G: What "3 Leafs" Really Means
We've interpreted "3 leafs" as 3 Var nodes. Other interpretations not fully explored:
- 3 bytes in the raw bytecode (before FF)
- 3 tokens/units in some other counting method
- The "3 leafs" might be about the ANSWER STRING, not the program
- "Leafs" might mean lambda bodies, not variables

---

## NEW: 7 Possibility Directions (from v13 analysis)

These are the most promising avenues based on accumulated evidence:

### Possibility A: Flag Derivable from Known Data Without sys8 Succeeding
We have: password `ilikephp`, hash `GZKc.2/VQffio`, combinators A and B, the backdoor pair, file ID 256 (`wtf`), all file contents. Maybe the WeChall answer is a transformation of known data we haven't computed. The `sha1^56154(answer)` target hash exists — maybe the answer is something we already have but haven't recognized.

### Possibility B: Flag Printed via Non-sys8 Mechanism
- `sys4(term)` serializing a specific term that encodes the answer
- `sys2` writing data derived from backdoor combinators
- `sys1(N)` for some N we haven't tried (tested 0–7, but not higher)
- Chain: `backdoor → manipulate pair → write result`

### Possibility C: sys8's Right(6) IS the Answer (or Part of It)
- What if "Permission denied" or error code 6 is itself a clue?
- What if applying sys1 to 6 and doing something with that string matters?

### Possibility D: "3 Leafs" Involves QD as a Non-Counted Constant
- If QD counts as "0 leaves" (it's a constant), then all 3 leaves can be syscall globals
- But if QD's internal variables count, it has more than 3 leaves
- The counting method matters: does the author count QD's leaves or not?

### Possibility E: Echo + Quote Interaction Produces the Answer
- `echo(Var(251))` creates `Var(253)` at runtime
- `quote(Left(Var(253)))` produces `Encoding failed!` (ASCII text, no 0xFF)
- What if we echo other values and quote the results?
- What about `echo(Var(252))` → `Var(254)` → quote produces what?
- What if the "Encoding failed!" text is part of a chain?

### Possibility F: The Pre-Echo Solution Path
- Before echo (2014–2018), 0 solvers. After echo (Sept 2018), l3st3r and space solved it.
- Author 2016: *"figuring out the meaning of the input codes is probably the most important thing to do"*
- "Input codes" = bytecode format. What "meaning" beyond obvious parsing semantics?
- Maybe there's a dual interpretation of the bytecode that matters.

### Possibility G: Y-Combinator Construction from A and B
- `B = λa.λb. (a b)` = function application combinator
- `A = λa.λb. (b b)` = self-application combinator
- `A B = ω = λx.(x x)`, `ω ω = Ω` (diverges)
- `B` can compose functions: `B f g x = f(g(x))`
- A fixed-point combinator could be built from these
- What if `Y(sys8)` or `Y(something)` produces a useful fixpoint?

---

## Strategic Summary

The most promising unexplored area is understanding **WHY** sys8 distinguishes between string arguments (Right(3)) and non-string arguments (Right(6)). This suggests sys8 internally attempts a file-path lookup for string-shaped inputs. Finding the right "path" (or the right non-path structure) might be the key.

The solution is likely something elegant and minimal (per "3 leafs") that we're missing conceptually, not something that requires more brute-force testing. After 500+ test cases, the gap is likely in *understanding*, not in *coverage*.

---

## Repository File Guide

| File | Purpose |
|---|---|
| `solve_brownos.py` | Quick test (syscall 0x2A) |
| `solve_brownos_answer.py` | Full reference client |
| `BROWNOS_MASTER.md` | Single source of truth (technical docs) |
| `challenge.html` | Saved challenge page |
| `archive/probes_feb2026/` | 130+ latest probe scripts |
| `archive/probes_jan2026/` | 55 earlier probe scripts |
| `archive/logs/` | Probe output logs |
| `archive/data/` | JSON scan results |
| `archive/docs/` | Previous analyses and summaries |
