# BrownOS — Data Encodings

All data is represented as lambda calculus terms using Scott encodings.

## 1. Either Type

```
Left  x = λl.λr. (l x)   → success / normal result
Right y = λl.λr. (r y)   → error / failure
```

In de Bruijn notation:
- `Left x`  = `Lam(Lam(App(Var(1), x_shifted)))`
- `Right y` = `Lam(Lam(App(Var(0), y_shifted)))`

Most syscalls return Either. `Left` = success, `Right` = error code.

## 2. Integer / Byte-Term Encoding (9-Lambda Additive Bitset)

Numbers are encoded as 9 leading lambdas with an additive body:

| Var index (inside body) | Weight |
|:---:|:---:|
| V0 | 0 |
| V1 | 1 |
| V2 | 2 |
| V3 | 4 |
| V4 | 8 |
| V5 | 16 |
| V6 | 32 |
| V7 | 64 |
| V8 | 128 |

Example: `3 = λ^9. (V2 (V1 V0))` → 2 + 1 + 0 = 3

### Non-Byte IDs (>255)

The encoding is **additive** — weights can be repeated:
- `256 = 128 + 128` → body `(V8 (V8 V0))`
- This is how hidden file id 256 was reached

## 3. Strings / Byte Lists (Scott List)

```
nil    = λc.λn. n          → end of list
cons h t = λc.λn. (c h t)  → element h followed by tail t
```

Each element is a byte-term (section 2 above). So a string is a linked list of 9-lambda encoded bytes.

## 4. Directory Listings (3-Way Scott List)

`readdir` returns a special 3-way variant:

```
nil  = λd.λf.λn. n              → end (V0 under 3 lambdas)
dir  = λd.λf.λn. (d <id> <rest>) → directory entry (V2 selector)
file = λd.λf.λn. (f <id> <rest>) → file entry (V1 selector)
```

## 5. Python Encode/Decode Reference

```python
def encode_byte_term(n: int) -> object:
    expr = Var(0)
    for idx, weight in ((1,1),(2,2),(3,4),(4,8),(5,16),(6,32),(7,64),(8,128)):
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term

def decode_byte_term(term: object) -> int:
    body = strip_lams(term, 9)
    return eval_bitset_expr(body)

def decode_either(term):
    # Left x  = λ.λ.(1 x) → ("Left", x)
    # Right y = λ.λ.(0 y) → ("Right", y)
    body = term.body.body
    if body.f.i == 1: return ("Left", body.x)
    if body.f.i == 0: return ("Right", body.x)
```
