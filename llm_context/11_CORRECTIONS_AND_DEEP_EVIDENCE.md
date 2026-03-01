# BrownOS — Corrections to Previous LLM Analysis & Deep Evidence

## Purpose

This file corrects specific claims from a second LLM analysis session, provides probe-level evidence for why those claims fail, and offers deeper context about what was explored and how.

---

## Correction 1: "Consumer Inversion" pair(sys8) = sys8(A)(B) — NOT NOVEL

### What the LLM claimed
> Apply the backdoor pair TO sys8 instead of passing pair as argument.
> `pair(sys8) = (λs. s A B)(sys8) = sys8(A)(B)` — sys8 with A as arg, B as continuation.
> Empty responses from B as continuation = "success trapped in a lambda."

### Why this is wrong

This exact pattern was the subject of **entire dedicated probe scripts**:

**`probe_pair_sys8.py`** — 13 phases testing this pattern:
- Phase 1: `pair(sys8)(nil) = sys8(A)(B)` — B as continuation
- Phase 2: `pair(λa.λb. sys8(a)(QD))(nil)` — extract A, sys8(A) with QD
- Phase 3: `pair(λa.λb. sys8(b)(QD))(nil)` — extract B, sys8(B) with QD
- Phase 4: `pair(λa.λb. sys8(a(b))(QD))(nil)` — sys8(ω) via pair
- Phase 5: `pair(λa.λb. sys8(b(a))(QD))(nil)` — sys8(B(A)) via pair
- Phase 11: `pair(λa.λb. sys8(pair(a,b))(QD))(nil)` — reconstruct pair, pass to sys8
- Phase 12-13: `pair(λa.λb. sys8(a)(λr. r(QD)(QD)))(nil)` — Either-aware extraction

**`probe_pair_syscall_destr.py`** — Dedicated to "pair as destructor":
- T1: `backdoor→pair(sys8)→QD` — live backdoor pair dispatching sys8
- T7: "The CRITICAL test — pair(sys8) with backdoor pair" — sys8 with kernel-minted A, continuation B
- T8: `backdoor→sys8(Left(pair))(QD)` — pass whole Either to sys8

**`probe_pivot.py`**:
- `201(nil)->pair, (pair sys8) = ((sys8 A_live) B_live)` — live pair dispatching
- `201(nil)->pair, ((pair sys8) QD)` — with QD observer

**`probe_high_index_syscall.py`**:
- `((backdoor nil) (λ pair. ((pair sys8) QD↑1)))` — "pair dispatches sys8"
- Also tested `sys8(pair)` as arg in same batch

**`probe_double_question.py`**:
- `((pair sys8) QD)` — with inline pair bytecode
- Followed by chain: `backdoor → use pair.A as arg to sys8`
- Phase 5: "sys8 with pair/A/B as continuation"

**`probe_decode_quote_k252.py`**:
- `pair(sys8) QD` — direct application
- `pair(sys8)(left_handler)(right_handler)` — apply TWO arguments to extract trapped result

### The "Empty Response = Success Trapped in Lambda" Theory

This was explicitly anticipated and tested. `probe_decode_quote_k252.py` lines 395-431 tested `pair(sys8)(left_handler)(right_handler)` to extract any value trapped in a partial application. The `probe_pair_sys8.py` Phases 12-13 used Either-aware extractors: `λr. r(QD)(QD)` to handle both Left and Right results. All returned Right(6) or remained empty.

The empty responses are explained by the normal CPS behavior: when B is the continuation, `B(Right(6)) = (λa.λb. a b)(Right(6)) = λb. Right(6)(b)`. This is a lambda (WHNF), so the VM stops — but the value inside is still Right(6), not a flag.

---

## Correction 2: Var(253) as Function / OOB Execution — NOT NOVEL

### What the LLM claimed
> Extract Var(253) from echo, execute it in function position to trigger OOB array read.
> If globals[253] is mapped to the true backdoor handler, it executes.

### Why this is wrong

Tested in 6+ probe scripts:

**`probe_var255.py`** — "V253(sys8)(QD) — Var(253)=FD as function"
**`probe_extended_ids.py`** — "Call echo's internal Var(253) as a function directly"
**`probe_continuation_hypothesis.py`** — "(Var(253) syscall8) - treating Var(253) as a function"
**`probe_hidden_globals.py`** — "The key question: can Var(253) be called as a function?"
**`probe_use_unserializable.py`** — "Apply Var(253) directly (it might be a function)"
**`probe_understand_253.py`** — "suggests Var(253) might be a function that constructs Left(Right(...))"

Results: Empty responses or errors. No special behavior observed. Var(253) in function position does not trigger any OOB mechanism, hidden syscall, or different response.

### Why OOB is unlikely

The VM is a C++ lambda calculus evaluator. Variables are resolved by looking up the environment chain (de Bruijn index = number of frames to walk up). If `Var(253)` is a free variable referencing global 253, it resolves to `globals[253]` — but we tested all globals 0–252 and they return "Not implemented." Global 253 (if it exists) would likely also return "Not implemented" or the VM would error on out-of-bounds access (which we'd see as a connection reset, not the "froze my system" the author described).

The author's "froze my system" likely refers to constructing Ω-like divergent terms through echo manipulation, not OOB access.

---

## Correction 3: Valid Filesystem Paths — ALREADY TESTED

### What the LLM claimed
> You only tested nonexistent paths. Test a valid path like "/bin/sh" to see if it returns Right(6) instead of Right(3).

### What actually happened

**`probe_oracle_v4.py`** (lines 375-384) tested valid filesystem paths as sys8 string arguments:

```python
credentials = [
    # ... other strings ...
    ("/bin/sh", b"/bin/sh"),           # EXISTS in FS as id 14
    ("/home/gizmore", b"/home/gizmore"), # EXISTS in FS as id 39
]
for name, data in credentials:
    byte_list = NConst(encode_bytes_list(data))
    run_named(f"sys8(bytestr {name!r})", apps(g(8), byte_list, DISC8))
```

Result: Still Right(3) NoSuchFile — even for valid existing paths.

### What this means

sys8 does NOT perform path-to-ID resolution. The VFS theory is disproven. All string-shaped arguments return Right(3) uniformly, regardless of whether the string matches an actual filesystem path. This means:

1. The Right(3) code path is NOT a file-path lookup
2. It's more likely: sys8 tries to interpret the argument as a "name" or "identifier" and fails for all string inputs
3. OR: sys8's string check is just a type-tag check — "this is a string but not what I expected" → Right(3)
4. The Right(3) vs Right(6) distinction might simply reflect: "wrong type of argument" (Right(3) for string-shaped) vs "right type but no permission" (Right(6) for non-string)

---

## Deep Context: What Right(3) vs Right(6) Actually Tells Us

The most careful interpretation of the error code asymmetry:

| Argument Shape | Error | Interpretation |
|---|---|---|
| 9-lambda integer (Church numeral) | Right(6) | sys8 RECOGNIZED this as a valid argument type, checked permissions, DENIED |
| 2-lambda string (Scott byte list) | Right(3) | sys8 RECOGNIZED this as a string, attempted some lookup, FAILED to find |
| 1-lambda backdoor pair | Right(3) | sys8 misinterpreted as string (partial decode), lookup failed |
| 0-lambda or N-lambda (other) | Right(6) | sys8 couldn't decode, fell through to permission check |

The key insight is: Right(6) "Permission denied" on integer arguments means **sys8 KNOWS what you're asking for (a file by ID) but won't give it to you**. This is the "correct" argument type — you just lack permission.

Right(3) "No such file" on string arguments means **sys8 tried to interpret a string as something (a filename? a command?) but couldn't find a match**. This is a different failure mode.

The challenge is: how do you make the Right(6) path return Left(success) instead?

---

## Extra Context: The Named-Term DSL

Many probes use a named-term DSL that handles de Bruijn shifting automatically. This is important because it means "shifting bugs" are NOT the cause of test failures:

```python
@dataclass(frozen=True)
class NGlob:
    index: int  # global index, auto-shifted by to_db()

def to_db(term, env=()):
    if isinstance(term, NGlob):
        return Var(term.index + len(env))  # AUTO SHIFT
    if isinstance(term, NLam):
        return Lam(to_db(term.body, (term.param,) + env))
    # ...
```

When a probe uses `g(8)` inside a lambda, the DSL automatically shifts it to `Var(9)`, `Var(10)`, etc. based on nesting depth. This eliminates manual shifting errors.

---

## Extra Context: How Probe Results Are Classified

Probe scripts classify responses into categories:

| Classification | Meaning |
|---|---|
| `RIGHT6` | 19-byte encoded Right(6) = standard Permission denied |
| `RIGHT3` | Encoded Right(3) = No such file |
| `EMPTY` | 0 bytes received = no write side-effect |
| `TEXT:Permission denied` | ASCII text "Permission denied" (from write + error_string) |
| `CONN_ERR` | Connection refused/reset/timeout |
| `HEX:...` | Other hex output (potential breakthrough) |

"EMPTY" does NOT mean success — it means the continuation didn't produce any write to the socket. This happens when:
- The continuation is a lambda that reaches WHNF without calling write
- The term diverges and the timeout triggers
- The continuation is nil or identity

---

## Extra Context: What We Know About the VM's Evaluation Model

From systematic testing:

1. **Evaluation order**: Likely call-by-name / lazy. Evidence: `sys8(Ω)` returns immediately instead of diverging.
2. **WHNF**: The VM reduces to Weak Head Normal Form and stops. Lambdas are not evaluated further.
3. **CPS is real**: Syscalls genuinely call their continuation with the result. `sys8(nil)(write_K)` prints K.
4. **Single-term**: Server evaluates exactly one term per connection and closes.
5. **No side-channel**: Response timing is uniform across all argument types (~0.5-0.8s).
6. **No hidden state**: access.log shows no state change after sys8 calls.

---

## What the 3-Leaf Exhaustive Search Actually Covered

`probe_3leaf_exhaustive.py` tested 8 different AST shapes across globals {0, 2, 4, 5, 7, 8, 14, 42, 201}:

| Shape | Description | Count |
|---|---|---|
| A1 | `g(a)(g(b))(g(c))(QD)` — left-associated chain | 729 |
| A2 | `g(a)(g(b)(g(c)))(QD)` — right-associated arg | 729 |
| A3 | `(λ.V)(g(b))(g(c))(QD)` — lambda in function | ~500 |
| A4 | `g(a)((λ.V)(g(c)))(QD)` — lambda in arg | ~500 |
| A5 | `g(a)(g(b))(λ.V)(QD)` — lambda as 2nd arg | ~500 |
| A6 | `(λ.λ.V)(g(b))(g(c))(QD)` — double lambda | ~500 |
| A8 | `(λ.V(m)(V(n)))(g(c))(QD)` — internal App | ~500 |
| B1 | `g(a)(g(b))(g(c))` raw (no QD) | 729 |

Total: **5,346 test cases**. All returned Right(6), empty, or "Not implemented."

---

## Genuinely Unexplored Directions (Updated)

After 2 rounds of LLM analysis, these remain genuinely untested:

1. **Non-CPS structures involving sys8** — What if the solution doesn't use `((sys8 arg) cont)` at all? What if sys8 appears nested inside another term's reduction?

2. **The pre-2018 solution path** — Before echo existed, 0 people solved it. After echo, 2+ solved. What changed? Echo enables Var(253+), but maybe it also enabled something else we haven't considered.

3. **Filesystem IDs beyond 1024** — Only 0-1024 scanned. The additive encoding supports arbitrary large numbers.

4. **The answer might not come from sys8** — Maybe the WeChall answer is derivable from known data (filesystem contents, combinator algebra) without making sys8 succeed.

5. **Deeper combinator algebra** — A and B can build a Y combinator analog. What if the answer requires a fixed-point computation?

6. **Alternative interpretations of "3 leafs"** — Maybe it's about the ANSWER string length, not the program. Or about some counting method we haven't considered.
