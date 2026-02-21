# BrownOS — Client Code Reference

## Core Data Types

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class Var:
    i: int      # De Bruijn index (0–252 in source, 253+ at runtime via echo)

@dataclass(frozen=True)
class Lam:
    body: object  # The lambda body term

@dataclass(frozen=True)
class App:
    f: object     # Function term
    x: object     # Argument term
```

## Constants

```python
HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD  # Application marker
FE = 0xFE  # Lambda marker
FF = 0xFF  # End-of-code marker

# Quick Debug continuation (from cheat sheet)
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

# Common terms
NIL = Lam(Lam(Var(0)))         # λλ.V0 = nil = false = Church 0
TRUE = Lam(Lam(Var(1)))        # λλ.V1 = true = K combinator
IDENTITY = Lam(Var(0))          # λ.V0 = I combinator
```

## Network Functions

```python
import socket
import time

def recv_until_ff(sock, timeout_s=3.0):
    """Receive bytes until 0xFF terminator or timeout."""
    sock.settimeout(timeout_s)
    out = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        out += chunk
        if FF in chunk:
            break
    if FF not in out:
        raise RuntimeError("No FF terminator in response")
    return out[:out.index(FF) + 1]

def query(payload, retries=5, timeout_s=3.0):
    """Send payload to BrownOS server and receive response."""
    delay = 0.15
    last_err = None
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_until_ff(sock, timeout_s=timeout_s)
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed to query {HOST}:{PORT}") from last_err
```

## Term Parsing & Encoding

```python
def parse_term(data):
    """Parse postfix bytecode into an AST."""
    stack = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    if len(stack) != 1:
        raise ValueError(f"Invalid parse: stack size {len(stack)}")
    return stack[0]

def encode_term(term):
    """Encode an AST back to postfix bytecode."""
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported: {type(term)}")
```

## Data Type Encoders/Decoders

### Integer (Byte Term)

```python
WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}

def encode_byte_term(n):
    """Encode integer n as a 9-lambda additive bitset term."""
    expr = Var(0)
    for idx, weight in ((1,1),(2,2),(3,4),(4,8),(5,16),(6,32),(7,64),(8,128)):
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term

def strip_lams(term, n):
    """Strip n leading lambdas from a term."""
    cur = term
    for _ in range(n):
        if not isinstance(cur, Lam):
            raise ValueError("Not enough lambdas")
        cur = cur.body
    return cur

def eval_bitset_expr(expr):
    """Evaluate the body of a byte term to an integer."""
    if isinstance(expr, Var):
        return WEIGHTS[expr.i]
    if isinstance(expr, App):
        return WEIGHTS[expr.f.i] + eval_bitset_expr(expr.x)
    raise ValueError(f"Unexpected: {type(expr)}")

def decode_byte_term(term):
    """Decode a 9-lambda byte term to an integer."""
    return eval_bitset_expr(strip_lams(term, 9))
```

### Wide Integer (>255)

```python
def encode_wide_int(n):
    """Encode integer n (can be >255) using additive weight repetition."""
    expr = Var(0)
    remaining = n
    for idx in range(8, 0, -1):
        weight = WEIGHTS[idx]
        while remaining >= weight:
            expr = App(Var(idx), expr)
            remaining -= weight
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term
```

### Either

```python
def decode_either(term):
    """Decode a Scott Either into ('Left', payload) or ('Right', payload)."""
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not an Either")
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var) and body.f.i in (0, 1):
        return ("Left" if body.f.i == 1 else "Right", body.x)
    raise ValueError("Unexpected Either shape")
```

### Byte List (String)

```python
def uncons_scott_list(term):
    """Deconstruct a Scott list cons cell, or return None for nil."""
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not a Scott list node")
    body = term.body.body
    if isinstance(body, Var) and body.i == 0:
        return None  # nil
    if (isinstance(body, App)
        and isinstance(body.f, App)
        and isinstance(body.f.f, Var)
        and body.f.f.i == 1):
        return body.f.x, body.x  # (head, tail)
    raise ValueError("Unexpected list shape")

def decode_bytes_list(term):
    """Decode a Scott list of byte terms to a bytes object."""
    out = []
    cur = term
    for _ in range(1_000_000):
        res = uncons_scott_list(cur)
        if res is None:
            return bytes(out)
        head, cur = res
        out.append(decode_byte_term(head))
    raise RuntimeError("List too long")

def encode_bytes_list(bs):
    """Encode a bytes object as a Scott list of byte terms."""
    nil = Lam(Lam(Var(0)))
    def cons(h, t):
        return Lam(Lam(App(App(Var(1), h), t)))
    cur = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur
```

## High-Level Helpers

```python
def call_syscall(syscall_num, argument):
    """Call a BrownOS syscall with QD as continuation and parse the result."""
    payload = (bytes([syscall_num])
              + encode_term(argument)
              + bytes([FD])
              + QD
              + bytes([FD, FF]))
    out = query(payload)
    return parse_term(out)

def call_and_decode(syscall_num, argument):
    """Call a syscall and decode the Either result."""
    result = call_syscall(syscall_num, argument)
    return decode_either(result)

def read_file(file_id):
    """Read a file by ID and return its content as string."""
    tag, payload = call_and_decode(0x07, encode_byte_term(file_id))
    if tag != "Left":
        raise RuntimeError(f"readfile({file_id}) failed: {tag}")
    return decode_bytes_list(payload).decode("utf-8", "replace")

def list_dir(dir_id):
    """List directory entries by ID."""
    tag, payload = call_and_decode(0x05, encode_byte_term(dir_id))
    if tag != "Left":
        raise RuntimeError(f"readdir({dir_id}) failed: {tag}")
    # Returns 3-way Scott list — decode separately
    return payload
```

## Password Cracking

```python
import ctypes, ctypes.util

def libc_crypt(password, salt):
    """Call libc crypt(3) for DES password hashing."""
    libname = ctypes.util.find_library("crypt")
    lib = ctypes.CDLL(libname)
    crypt_fn = lib.crypt
    crypt_fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    crypt_fn.restype = ctypes.c_char_p
    return crypt_fn(password.encode(), salt.encode()).decode()

# Usage: libc_crypt("ilikephp", "GZ") == "GZKc.2/VQffio"
```

## Full Working Examples

### Example 1: Call syscall 0x2A (towel string)

```python
payload = bytes([0x2A, 0x00, FD]) + QD + bytes([FD, FF])
# Sends: ((0x2A Var(0)) QD) + FF
# Returns: "Oh, go choke on a towel!"
```

### Example 2: Read /etc/passwd

```python
result = call_syscall(0x07, encode_byte_term(11))
tag, payload = decode_either(result)
text = decode_bytes_list(payload).decode("utf-8")
print(text)
```

### Example 3: Call backdoor

```python
nil = Lam(Lam(Var(0)))
result = call_syscall(0xC9, nil)
tag, payload = decode_either(result)
# payload is a Scott pair: λs.(s A B)
```

### Example 4: Call syscall 8 (always fails)

```python
nil = Lam(Lam(Var(0)))
result = call_syscall(0x08, nil)
tag, payload = decode_either(result)
# tag == "Right", decode_byte_term(payload) == 6 ("Permission denied")
```

## Repository File Locations

| File | Purpose |
|---|---|
| `solve_brownos.py` | Minimal demo — calls syscall 0x2A, decodes string |
| `solve_brownos_answer.py` | Full reference — filesystem exploration, password cracking |
| `registry_globals.py` | Global registry scanner — probes all syscalls systematically |
| `utils/decode_backdoor.py` | Step-by-step backdoor response decoder |
| `utils/parse_qd.py` | QD structure analysis and explanation |
