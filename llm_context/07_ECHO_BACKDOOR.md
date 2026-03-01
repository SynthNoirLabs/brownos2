# BrownOS — Echo & Backdoor Deep Dive

## 1. Echo Syscall (0x0E)

### Basic Behavior
Echo takes any term and returns it wrapped in `Left(...)`:
```
echo(X) → Left(X)
```

### The +2 Index Shift

`Left(X) = λl.λr. (l X)` — the payload X sits under 2 lambdas. So any free de Bruijn index in X appears shifted by +2 when you inspect the raw structure (e.g., via quote/QD).

This shift **cancels** when you properly unpack the Either by applying it to selectors. It is NOT a bug — it's how Scott encoding works.

### Manufacturing "Impossible" Variables

Echo is the **only mechanism** that can create runtime variables with indices ≥ 253:

| Input | Inside Left payload | Why it matters |
|---|---|---|
| `echo(Var(251))` | `Var(253)` = byte 0xFD | App marker as a variable |
| `echo(Var(252))` | `Var(254)` = byte 0xFE | Lambda marker as a variable |

These values:
- **Cannot exist in source code** (parser interprets 0xFD/0xFE as structural markers)
- **Cannot be serialized** by `quote` → "Encoding failed!" with no trailing 0xFF
- **Can only exist at runtime** inside a `Left` wrapper from echo

### What We Tested With Echo-Manufactured Values

All of the following were tested and returned Right(6) or EMPTY:
- `echo(g251) → Left(V253) → sys8(Left(V253))` → Right(6)
- Extracting V253 from Left, passing to sys8 → Right(6)
- Echo-mediated with nil, int(8), g(8), str("ilikephp") → all Right(6)
- Echo(X) → unwrap → sys8(unwrapped) for various X → all Right(6)

### The "Encoding failed!" Behavior

When you pass a term containing Var(253+) to `quote` (syscall 4):
- Quote tries to serialize, encounters byte 0xFD/0xFE in variable position
- Returns ASCII `Encoding failed!` WITHOUT trailing 0xFF
- Naive clients hang waiting for 0xFF that never comes

## 2. Backdoor (Syscall 0xC9 / 201)

### Invocation
Input MUST be exactly `nil` (Scott-encoded `λλ.V0` = bytes `00 FE FE`). Any other argument → Right(2) "Invalid argument".

### Output: Pair (A, B)

```
pair = λs. (s A B)

A = λa.λb. (b b)    bytecode: 00 00 FD FE FE
B = λa.λb. (a b)    bytecode: 01 00 FD FE FE
```

### Combinator Properties

| Expression | Result |
|---|---|
| `A x` | `λb.(b b)` — ignores first arg, self-applies second |
| `B f x` | `f x` — standard function application |
| `A B` = `B A` | `λx.(x x) = ω` — little omega |
| `ω ω` | `Ω` — diverges (infinite loop) |
| `A A` | `λb.(b b)` then applied → diverges |
| `B B` | `λx.(B x) = B` — B is idempotent in this sense |

### Structural Comparison: Pair vs Cons

**These are NOT the same** (a common LLM mistake):
- **Pair**: `λs. (s A B)` → 1 lambda, selector is V0
- **Cons**: `λc.λn. (c h t)` → 2 lambdas, selector is V1

The backdoor pair has a different number of lambdas and different selector index than a Scott cons cell. They are structurally distinct.

### What We Tested With Backdoor Values

All tested, all failed:
- `sys8(A)`, `sys8(B)`, `sys8(pair)` → Right(6) or Right(3)
- `sys8(ω)`, `sys8(Ω)` → Right(6) or timeout
- `sys8(A(A))`, `sys8(A(B))`, `sys8(B(A))`, `sys8(B(B))`, `sys8(B(A(B)))` → diverge or Right(6)
- Backdoor pair applied to various selectors → sys8 → Right(6)
- `backdoor(nil) → sys8(pair)` in-process chaining → Right(6)
- `sys8(nil) → backdoor(nil) → sys8(pair)` stateful chain → Right(6)

## 3. Combined Echo + Backdoor Tests

- `echo(((sys8 nil) id)) → thunk → sys8(thunk)` → Right(6)
- `echo(((backdoor nil) handler)) → thunk → sys8(thunk)` → Right(6)
- Echo-captured backdoor thunks with various selectors → Right(6)
- 3-leaf thunks captured by echo, passed to sys8 → Right(6)
