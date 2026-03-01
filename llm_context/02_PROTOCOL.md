# BrownOS — Wire Protocol & Virtual Machine

## 1. Transport Layer

- **Protocol**: Raw binary over TCP
- **Port**: 61221
- **No TLS, no framing** — raw byte stream
- Server closes connection after processing one term

## 2. Bytecode Format

The byte stream (terminated by `0xFF`) encodes a term in a **postfix** lambda calculus using **de Bruijn indices**:

| Byte | Meaning |
|:---:|---|
| `0x00`–`0xFC` | `Var(i)` — variable reference (de Bruijn index) |
| `0xFD` | Application node: pop `x`, pop `f`, push `App(f, x)` |
| `0xFE` | Lambda node: pop `body`, push `Lam(body)` |
| `0xFF` | End-of-code marker (not part of the term) |

### Postfix Parsing

The parser is a stack machine:
1. Push `Var(i)` for bytes `< 0xFD`
2. On `0xFD`: pop `x`, pop `f`, push `App(f, x)`
3. On `0xFE`: pop `body`, push `Lam(body)`
4. Stop at `0xFF`
5. Stack must contain exactly 1 item — else "Invalid term!"

### Postfix Encoding Examples

```
Var(8)           → 08 FF
App(Var(8), Var(0))  → 08 00 FD FF
Lam(Var(0))      → 00 FE FF     (identity λx.x)
nil = λλ.V0      → 00 FE FE FF
```

## 3. De Bruijn Indices

Variables are referenced by distance to binding lambda, not by name:
- `Var(0)` = innermost enclosing lambda's parameter
- `Var(1)` = next enclosing lambda
- `Var(N)` with N ≥ number-of-enclosing-lambdas = free variable = global/syscall

**CRITICAL**: Indices shift under lambdas. The same byte value means different things at different nesting depths.

Example: `Var(5)` at top level = global 5 (readdir). Inside 1 lambda, `Var(5)` = global 4 (quote). Inside 2 lambdas, `Var(5)` = global 3 (unused/not-impl).

This is the #1 source of bugs when constructing payloads.

## 4. CPS Syscall Convention

Syscalls use **continuation-passing style**:

```
((syscall argument) continuation) + 0xFF
```

Postfix: `<syscall> <arg> FD <continuation> FD FF`

The VM evaluates this as:
```
((syscall argument) continuation)  →  (continuation result)
```

### Quick Debug (QD)

A known-good continuation that prints the encoded result to the socket:

```
QD = 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
```

Conceptually: `QD(term) = write(quote(term))` — serializes the result term and writes it to the TCP stream, terminated by `0xFF`.

**QD gotcha**: QD's raw bytes contain `0x05`, `0x03`, `0x02`, but these reference globals `write` (2), `quote` (4), `readdir` (5) because QD is itself a lambda term — de Bruijn indices shift inside it.

## 5. Server Behavior Summary

| Input | Response |
|---|---|
| Valid term with QD continuation | FF-terminated bytecode of result |
| Valid term, no write side-effect | Empty response (0 bytes) |
| Invalid bytecode | `Invalid term!` (ASCII text) |
| Oversized term | `Term too big!` (ASCII text) |
| Quote of Var(253+) | `Encoding failed!` (no trailing FF) |
| Too many requests | `Right(7)` = "Not so fast!" |
