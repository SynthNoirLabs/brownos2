# BrownOS — Raw Data, Byte Patterns & Verification Reference

## Purpose

This file provides concrete byte-level data that lets you verify encoding logic, check payload construction, and understand exactly what the server returns. Use this to sanity-check any payload you construct.

---

## 1. Key Response Patterns (What QD Returns)

When you send `((sys8 arg) QD)`, QD serializes the result via `write(quote(result))`. The response is the postfix bytecode of the result term, terminated by `0xFF`.

### Right(6) = "Permission denied" — The Most Common sys8 Response

```
Raw hex: 00 03 02 00 FD FD FE FE FE FE FE FE FE FE FD FE FE FF
```

Parse this postfix:
```
00       → Var(0)              stack: [V0]
03       → Var(3)              stack: [V0, V3]
02       → Var(2)              stack: [V0, V3, V2]
00       → Var(0)              stack: [V0, V3, V2, V0]
FD       → App(V2, V0)        stack: [V0, V3, App(V2,V0)]
FD       → App(V3, App(V2,V0)) stack: [V0, App(V3, App(V2,V0))]
FE x9    → 9 Lam wrappers     stack: [Lam^9(App(V3,App(V2,V0)))]  ← this is int(6)
FD       → App(V0, int6)      stack: [App(V0, int(6))]
FE       → Lam(App(V0,int6))  stack: [Lam(App(V0,int6))]
FE       → Lam(Lam(App(V0,int6))) stack: [λl.λr.(r int6)]
FF       → stop
```

**Result**: `λl.λr. (r int(6))` = `Right(6)` = "Permission denied"

Key identifier: responses containing the substring `00030200fdfd` in hex are Right(6).

### Right(3) = "No such file" — sys8 String Argument Response

The structure is the same as Right(6) but with int(3) instead of int(6):
```
int(3) = λ^9. (V2 (V1 V0))    bytecode: 02 01 00 FD FD FE FE FE FE FE FE FE FE FE
int(6) = λ^9. (V3 (V2 V0))    bytecode: 03 02 00 FD FD FE FE FE FE FE FE FE FE FE
```

### Left(X) — Success Response

`Left(X) = λl.λr. (l X)`:
```
Outer structure: ... <X_bytes> FD FE FE FF
```

The `l` selector is `Var(1)` (second-to-inner lambda), so you'll see `01` before the payload:
```
01 <payload_bytes> FD FE FE FF
```

### Empty Response (0 bytes)

Means: no `write` side-effect occurred. This is normal for:
- Continuations that don't call write (identity, nil, A, B, etc.)
- Terms that diverge (Ω, timeout)
- Terms where the result is a lambda (WHNF reached, VM stops, no output)

**Empty ≠ error. Empty ≠ success. Empty = "your program didn't print anything."**

---

## 2. QD Step-by-Step Parse

QD hex: `05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE`

This is itself a lambda term. Let's parse:

```
05       → V5                  [V5]
00       → V0                  [V5, V0]
FD       → App(V5, V0)        [App(V5,V0)]        = quote(input)
00       → V0                  [App(V5,V0), V0]
05       → V5                  [quote(input), V0, V5]
00       → V0                  [quote(input), V0, V5, V0]
FD       → App(V5, V0)        [quote(input), V0, App(V5,V0)]  = quote(input2)?
03       → V3                  [quote(input), V0, quote(input2), V3]
FD       → App(quote2, V3)    [quote(input), V0, App(quote(input2), V3)]
FE       → Lam(...)           [quote(input), V0, Lam(...)]
FD       → App(V0, Lam(...))  [quote(input), App(V0, Lam(...))]
02       → V2                  [quote(input), App(V0, Lam(...)), V2]
FD       → App(App(V0,...),V2) [quote(input), App(App(V0,...), V2)]
FE       → Lam(...)           [quote(input), Lam(...)]
FD       → App(quote(input), Lam(...))  [App(quote(input), Lam(...))]
FE       → Lam(App(quote(input), Lam(...)))
```

**Conceptually**: QD = `λterm. quote(term)(λbytes. write(bytes)(nil))`
= "serialize the term to bytes, then write those bytes to the socket"

### QD's Internal References (at depth)

When QD sits at top level (depth 0), its body references:
- `V5` (at depth 0) = global 5 = readdir... wait, that seems wrong!

**The trick**: QD is `Lam(body)`, so body is at depth 1. Inside the body:
- `V5` at depth 1 = global 4 = **quote** ✓
- `V3` at depth 2 (inside another lambda) = global 1 = **error_string**? No...

Actually QD is best understood as an opaque constant. Just know:
- At top level: `QD(term)` = `write(quote(term))(nil)`
- Under 1 lambda: shift all QD's free vars by +1
- Under 2 lambdas: shift by +2, etc.

**For shifting QD under N lambdas**: replace each byte < 0xFD in QD with `byte + N`, but ONLY for bytes that are free variables (not bound by QD's own lambdas). In practice, use the named-term DSL to avoid manual shifting.

---

## 3. Backdoor Response — Exact Bytes

Send: `C9 00 FE FE FD` + QD + `FD FF`
= `((sys201 nil) QD)` — call backdoor with nil, print result via QD

Response hex (the Left(pair)):
```
01 00 00 FD FE FE 00 01 00 FD FE FE FD FE FD FE FE FF
```

Parse:
```
01                → V1 (Left selector)
00 00 FD FE FE   → A = λa.λb.(b b)
00 01 00 FD FE FE → B = λa.λb.(a b)  
FD               → App(A, B) ... no wait, it's nested differently
```

The full structure is: `λl.λr. (l (λs. (s A B)))` = `Left(pair)`

Where:
- `pair = λs. (s A B)`
- `A = λa.λb. (V0 V0)` = λa.λb.(b b) — bytecode `00 00 FD FE FE`
- `B = λa.λb. (V1 V0)` = λa.λb.(a b) — bytecode `01 00 FD FE FE`

### Extracting A and B from pair

Apply pair to selectors:
- `pair(λa.λb.a) = A` — apply pair to K (Church true) to get first element
- `pair(λa.λb.b) = B` — apply pair to KI (Church false) to get second element

---

## 4. Known Syscall Quote Outputs

`quote(g(N))` returns the bytecode of global N:

| Global | quote output (hex before FF) |
|---|---|
| `g(0)` = identity/non-syscall | `00` |
| `g(8)` = sys8 | `08` |
| `g(14)` = echo | `0E` |
| `g(42)` = towel | `2A` |
| `g(201)` = backdoor | `C9` |
| `nil` = λλ.V0 | `00 FE FE` |
| `true` = λλ.V1 | `01 FE FE` |
| `identity` = λ.V0 | `00 FE` |

---

## 5. Integer Encoding Quick Reference

| Value | Body (under 9 lambdas) | Bytecode (full term) |
|---|---|---|
| 0 | V0 | `00 FE FE FE FE FE FE FE FE FE` |
| 1 | App(V1, V0) | `01 00 FD FE FE FE FE FE FE FE FE FE` |
| 3 | App(V2, App(V1, V0)) | `02 01 00 FD FD FE...FE` |
| 6 | App(V3, App(V2, V0)) | `03 02 00 FD FD FE...FE` |
| 8 | App(V4, V0) | `04 00 FD FE...FE` |
| 42 | App(V6, App(V4, App(V2, V0))) | `06 04 02 00 FD FD FD FE...FE` |
| 255 | App(V8, App(V7, App(V6, ...V0))) | all bits set |
| 256 | App(V8, App(V8, V0)) | 128+128 |

---

## 6. g(0) Behavior — Non-Syscall Gotcha

`Var(0)` is NOT a syscall. When called as `((g(0) arg) QD)`:
- The VM tries to evaluate `((Var(0) arg) QD)`
- `Var(0)` is a free variable that resolves to... itself (or the environment's entry 0)
- The application `(Var(0) arg)` doesn't reduce — it's stuck
- The VM reaches an irreducible term, produces no output, closes connection

Quote confirms: `quote(g(0))` returns `00` — just a raw variable, not a lambda/function.

This means the environment entry 0 is NOT a callable function. It's an opaque value or unbound.

---

## 7. "Encoding failed!" Exact Behavior

When `quote` encounters a Var with index 253, 254, or 255:

1. It tries to serialize: Var(253) would need byte `0xFD`, but that's the App marker
2. Instead of returning `Left(bytes)`, it writes the ASCII string `Encoding failed!` to the socket
3. **Critically**: no trailing `0xFF` is sent
4. Naive clients that wait for `0xFF` will hang/timeout

This is the ONLY way to get "Encoding failed!" — it's specific to quote on Var(253+).

---

## 8. Payload Construction Cheat Sheet

### Standard CPS syscall with QD:
```
<syscall_byte> <arg_bytes> FD <QD_bytes> FD FF
```

### Chaining two syscalls (CPS):
```
syscall1(arg1)(λresult. syscall2(result)(QD))
```
In postfix, under 1 lambda (result=V0, globals shift +1):
```
<syscall1> <arg1> FD <syscall2+1> 00 FD <QD_shifted_+1> FD FE FD FF
```

### Backdoor → extract pair → do something:
```
backdoor(nil)(λeither. either(λpair. BODY)(λerr. nil))
```
Under 2 lambdas (either, pair): globals shift +2

### Important: multi-byte variables
Variables > 252 can only exist at runtime (via echo). You CANNOT type `Var(253)` in source bytecode — the parser sees `0xFD` as App marker.
```
echo(Var(251)) → Left(Var(253))   ← only way to create Var(253)
echo(Var(252)) → Left(Var(254))   ← only way to create Var(254)
```
