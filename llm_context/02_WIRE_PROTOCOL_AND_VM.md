# BrownOS — Wire Protocol & Virtual Machine

## 1. Transport Layer

- **Protocol**: Raw binary over TCP
- **Host/Port**: `wc3.wechall.net:61221`
- **Framing**: Client sends a byte stream terminated by `0xFF`; server optionally replies with bytes terminated by `0xFF`
- **Critical**: You must send **raw bytes**, not ASCII hex. Sending the characters "F" "D" instead of byte `0xFD` is a common mistake that produces "Invalid term!" errors.

### Connection Lifecycle

1. Client opens TCP connection
2. Client sends a complete term (byte stream ending with `0xFF`)
3. Client calls `shutdown(SHUT_WR)` to signal end of input
4. Server evaluates the term and optionally writes output
5. Server closes the connection
6. If the program doesn't explicitly write to the socket (via syscall 0x02), there is **no output** — this is normal, not an error

### Error Responses

| Response | Meaning |
|----------|---------|
| No output (0 bytes) | Normal — program ran but didn't write to socket |
| `Invalid term!` | Parser error — malformed bytecode |
| `Term too big!` | Payload exceeds ~2KB limit |
| `Encoding failed!` | Quote syscall can't serialize a term with Var(253+) |
| `FF`-terminated bytes | Normal syscall result (parse as a lambda term) |

## 2. Bytecode Format (Postfix Lambda Calculus with De Bruijn Indices)

The byte stream encodes a term in a **postfix** lambda calculus using **De Bruijn indices**:

| Byte Range | Meaning | Description |
|------------|---------|-------------|
| `0x00–0xFC` | `Var(n)` | Variable with De Bruijn index n |
| `0xFD` | Application | Pop x, pop f, push `App(f, x)` |
| `0xFE` | Lambda | Pop body, push `Lam(body)` |
| `0xFF` | End of Code | Stop parsing (required terminator) |

### Parsing Algorithm (Postfix Stack Machine)

```
stack = []
for each byte b in input:
    if b == 0xFF: STOP
    if b < 0xFD:  push Var(b)
    if b == 0xFD: x = pop(); f = pop(); push App(f, x)
    if b == 0xFE: body = pop(); push Lam(body)
result = stack[0]  # must be exactly 1 item
```

If the stack doesn't have exactly 1 item at `0xFF`, the server returns "Invalid term!".

### Examples

| Bytes (hex) | Parsed Term | Common Name |
|-------------|-------------|-------------|
| `00 FE FE` | `λλ.V0` | nil / false / Church 0 |
| `01 FE FE` | `λλ.V1` | K / true |
| `00 FE` | `λ.V0` | identity (I combinator) |
| `00 00 FD FE` | `λ.(V0 V0)` | ω (little omega) |
| `00 00 FD FE 00 00 FD FE FD` | `(λ.(V0 V0))(λ.(V0 V0))` | Ω (big omega — diverges) |

## 3. De Bruijn Indices

This is the most important conceptual trap in the challenge. De Bruijn indices replace named variables with numeric indices counting how many lambdas you need to cross to reach the binding site:

- `Var(0)` refers to the **innermost** enclosing lambda
- `Var(1)` refers to the **next** lambda out
- `Var(n)` with n >= (number of enclosing lambdas) is a **free variable** that references a global/builtin

### Critical Implication: Shifting

**The same byte value means different things at different nesting depths.**

At the top level (no enclosing lambdas):
- `Var(2)` = global builtin #2 (write syscall)
- `Var(8)` = global builtin #8 (the target syscall)

Inside one lambda (`λ.___`):
- `Var(0)` = the lambda's parameter
- `Var(3)` = global builtin #2 (shifted by +1)
- `Var(9)` = global builtin #8 (shifted by +1)

This is why QD (Quick Debug) contains bytes like `0x05`, `0x03`, `0x02` — inside its own lambda, these are shifted references to globals 4 (quote), 2 (write), 1 (error) respectively.

## 4. Syscall Convention (Continuation-Passing Style / CPS)

Syscalls use **continuation-passing style**. The general pattern is:

```
((syscall argument) continuation) + 0xFF
```

In postfix bytecode:
```
<syscall_byte> <argument_bytes> FD <continuation_bytes> FD FF
```

The VM reduces this as:
```
(syscall argument continuation) → (continuation result)
```

### Quick Debug (QD) — The Standard Continuation

QD is a pre-built continuation that prints (serializes and writes) the result:

```
QD = 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
```

As a term: `λresult. ((write (quote result)) (...))`

QD works by:
1. Taking the result as its parameter
2. Calling `quote` (syscall 4) to serialize the result to bytes
3. Calling `write` (syscall 2) to send those bytes to the socket

**Inside QD's lambda body**, the global references are shifted by +1:
- `V3` inside = `V2` at top level = write (syscall 2)
- `V5` inside = `V4` at top level = quote (syscall 4)

### Example Payload

To call syscall 0x2A with nil as argument and QD as continuation:
```
Postfix: 2A 00FEFE FD 0500FD000500FD03FDFEFD02FDFEFDFE FD FF
         ^   ^       ^   ^                               ^  ^
         |   |       |   |                               |  End
         |   nil     App QD                              App
         syscall
```

## 5. Global Builtins

At the top level (outside any lambda), `Var(n)` references **global builtins** — the syscalls and other primitives:

| Var Index | Builtin | Description |
|-----------|---------|-------------|
| 0 | (non-syscall) | Unbound — hangs if applied |
| 1 | error_string | Returns error message for code |
| 2 | write | Writes bytes to socket |
| 3 | (not implemented) | Returns Right(1) |
| 4 | quote | Serializes a term to bytecode |
| 5 | readdir | Lists directory entries |
| 6 | name | Returns filesystem entry name |
| 7 | readfile | Reads file content |
| 8 | **TARGET** | Always returns Permission denied |
| 14 (0x0E) | echo | Returns input wrapped in Left |
| 42 (0x2A) | towel | Returns decoy string |
| 201 (0xC9) | backdoor | Returns combinator pair |
| All others (0–252) | not implemented | Returns Right(1) |

**Important**: The same byte value used at top level as a direct term reference and inside lambdas as a shifted reference will mean different things. Always account for lambda nesting when constructing payloads.

## 6. Server Behavioral Notes

- **Rate limiting**: Too many requests in a short period returns error code 7 ("Not so fast!"). Use exponential backoff.
- **Input size limit**: Payloads over ~2KB trigger "Term too big!" error.
- **Single term per connection**: Server processes only the first complete term. Bytes after the first `0xFF` are ignored.
- **No session state**: Each TCP connection is independent. No shared state between connections.
- **Evaluation timeout**: The server has a timeout for term evaluation. Divergent terms (like Ω) will eventually be killed.
- **No interactive mode**: This is request-response, not a REPL. One input, one output, connection closes.
