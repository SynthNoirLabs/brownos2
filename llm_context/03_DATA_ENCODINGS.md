# BrownOS — Data Encodings

All data in BrownOS is represented as lambda calculus terms using Scott encodings.

## 1. Either Type (Scott Encoding)

Most syscalls return results wrapped in an Either type:

```
Left x  = λl.λr. (l x)   → success
Right y = λl.λr. (r y)    → error
```

In De Bruijn terms:
- **Left(x)**: `Lam(Lam(App(Var(1), x)))` — body applies the outer lambda's parameter to x
- **Right(y)**: `Lam(Lam(App(Var(0), y)))` — body applies the inner lambda's parameter to y

### Decoding Algorithm

```python
def decode_either(term):
    # Must be: Lam(Lam(App(Var(selector), payload)))
    body = term.body.body  # strip 2 lambdas
    if body.f.i == 1:  return ("Left", body.x)   # success
    if body.f.i == 0:  return ("Right", body.x)   # error
```

### Bytecode Examples

| Either Value | Bytecode (postfix) |
|---|---|
| `Left(nil)` | `01 00 FE FE FD FE FE` |
| `Right(int_6)` | `00 <int6_bytes> FD FE FE` |

## 2. Integer / Byte Term (9-Lambda Additive Bitset)

Numbers are encoded with 9 leading lambdas. The body is a nested application chain where each variable index represents a bit weight:

| Var Index (inside 9 lambdas) | Weight |
|:---:|:---:|
| V0 | 0 (base) |
| V1 | 1 |
| V2 | 2 |
| V3 | 4 |
| V4 | 8 |
| V5 | 16 |
| V6 | 32 |
| V7 | 64 |
| V8 | 128 |

### Encoding Formula

A number `n` is encoded as:
1. Decompose `n` into powers of 2
2. Build a nested application: `V_highest(V_next(...(V_lowest(V0))))`
3. Wrap in 9 lambdas

### Examples

| Number | Body Expression | Calculation |
|:---:|---|---|
| 0 | `V0` | 0 |
| 1 | `App(V1, V0)` | 1+0 |
| 3 | `App(V2, App(V1, V0))` | 2+1+0 |
| 42 | `App(V6, App(V4, App(V2, V0)))` | 32+8+2+0 |
| 255 | `App(V8, App(V7, App(V6, App(V5, App(V4, App(V3, App(V2, App(V1, V0))))))))` | 128+64+32+16+8+4+2+1+0 |

### Non-Byte IDs (>255)

The encoding is **additive**, so weights can be **repeated** to represent values >255:
- `256 = 128 + 128` → body: `App(V8, App(V8, V0))`
- This is how hidden file ID 256 was discovered

### Python Encoder

```python
def encode_byte_term(n):
    expr = Var(0)  # base
    for idx, weight in ((1,1),(2,2),(3,4),(4,8),(5,16),(6,32),(7,64),(8,128)):
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term
```

### Python Decoder

```python
WEIGHTS = {0:0, 1:1, 2:2, 3:4, 4:8, 5:16, 6:32, 7:64, 8:128}

def decode_byte_term(term):
    body = strip_lams(term, 9)
    return eval_bitset_expr(body)

def eval_bitset_expr(expr):
    if isinstance(expr, Var): return WEIGHTS[expr.i]
    if isinstance(expr, App): return WEIGHTS[expr.f.i] + eval_bitset_expr(expr.x)
```

## 3. Strings / Byte Lists (Scott List of Byte Terms)

Strings and file contents are **Scott-encoded linked lists** of byte terms:

```
nil    = λc.λn. n         → Lam(Lam(Var(0)))
cons h t = λc.λn. (c h t) → Lam(Lam(App(App(Var(1), h), t)))
```

### Decoding Algorithm

```python
def uncons_scott_list(term):
    body = term.body.body  # strip 2 lambdas
    if isinstance(body, Var) and body.i == 0:
        return None  # nil
    # cons: body = App(App(Var(1), head), tail)
    return (body.f.x, body.x)  # (head, tail)

def decode_bytes_list(term):
    result = []
    while (pair := uncons_scott_list(term)) is not None:
        head, term = pair
        result.append(decode_byte_term(head))
    return bytes(result)
```

### Encoding Algorithm

```python
def encode_bytes_list(bs):
    nil = Lam(Lam(Var(0)))
    def cons(h, t): return Lam(Lam(App(App(Var(1), h), t)))
    cur = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur
```

## 4. Directory Listing (3-Way Scott List)

`readdir` (syscall 0x05) returns a **3-way** Scott list that distinguishes files from directories:

```
nil  = λd.λf.λn. n              → 3 lambdas, body V0
dir  = λd.λf.λn. (d <id> <rest>) → selector V2
file = λd.λf.λn. (f <id> <rest>) → selector V1
```

### Decoding Algorithm

After stripping 3 leading lambdas:
- `V0` → end of list
- `App(App(Var(2), id_term), rest_term)` → directory entry
- `App(App(Var(1), id_term), rest_term)` → file entry

The `<id>` is the 9-lambda integer encoding (file/directory ID number).

## 5. Scott Pair

Used by the backdoor syscall:

```
pair a b = λs. (s a b) → Lam(App(App(Var(0), a), b))
```

To extract components:
- `pair true` → a (first component)
- `pair false` → b (second component)

Where `true = λa.λb. a` and `false = λa.λb. b`.

## 6. Common Constant Terms

| Name | Term | Bytecode (hex) |
|------|------|-----------------|
| nil / false | `λλ.V0` | `00 FE FE` |
| true / K | `λλ.V1` | `01 FE FE` |
| identity / I | `λ.V0` | `00 FE` |
| little omega / ω | `λ.(V0 V0)` | `00 00 FD FE` |
| big Omega / Ω | `(ω ω)` | `00 00 FD FE 00 00 FD FE FD` |
| S combinator | complex | (not commonly used) |

## 7. Error Codes

Error codes are encoded as integer terms (9-lambda additive bitset) inside `Right(...)`:

| Code | Meaning | When Observed |
|:---:|---|---|
| 0 | Unexpected exception | Rare |
| 1 | Not implemented | Unknown syscall IDs |
| 2 | Invalid argument | Wrong argument type |
| 3 | No such directory or file | Invalid path/ID |
| 4 | Not a directory | readdir on file ID |
| 5 | Not a file | readfile on directory ID |
| 6 | Permission denied | **Syscall 8 always** |
| 7 | Not so fast! | Rate limiting |

**Note**: There's a discrepancy in historical notes — some documents report syscall 8 as returning Right(3) and others Right(6). The BROWNOS_MASTER.md (single source of truth) confirms **Right(6) = Permission denied** as the consistent current behavior.
