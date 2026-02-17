#!/usr/bin/env python3
"""
Build a program that calls syscall 253 (hidden/forbidden index).

Strategy:
1. echo(Var(251)) produces Left(Var(253))
2. Extract Var(253) from Either by applying handlers
3. Call Var(253) as syscall WITHOUT serializing
4. Use write to produce observable output
"""

from __future__ import annotations
import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


@dataclass(frozen=True)
class Var:
    i: int

@dataclass(frozen=True)
class Lam:
    body: object

@dataclass(frozen=True)
class App:
    f: object
    x: object


def recv_all(sock: socket.socket, timeout_s: float = 5.0) -> bytes:
    sock.settimeout(timeout_s)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    return out


def query(payload: bytes, retries: int = 3, timeout_s: float = 5.0) -> tuple[bytes, float]:
    delay = 0.2
    last_err: Exception | None = None
    for _ in range(retries):
        try:
            start = time.time()
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                result = recv_all(sock, timeout_s=timeout_s)
                elapsed = time.time() - start
                return result, elapsed
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed to query") from last_err


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        if term.i > 252:
            raise ValueError(f"Cannot encode Var({term.i}) - index too high for wire format")
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported: {type(term)}")


def shift_term(term: object, delta: int, cutoff: int = 0) -> object:
    """Shift all free variables >= cutoff by delta (de Bruijn adjustment)"""
    if isinstance(term, Var):
        if term.i >= cutoff:
            return Var(term.i + delta)
        return term
    if isinstance(term, Lam):
        return Lam(shift_term(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_term(term.f, delta, cutoff), shift_term(term.x, delta, cutoff))
    return term


def parse_term(data: bytes) -> object:
    stack: list[object] = []
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
        raise ValueError(f"Invalid: {len(stack)}")
    return stack[0]


def pp_term(term: object) -> str:
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{pp_term(term.body)}"
    if isinstance(term, App):
        return f"({pp_term(term.f)} {pp_term(term.x)})"
    return str(term)


def format_response(data: bytes) -> str:
    if not data:
        return "(empty)"
    if b"Invalid term!" in data:
        return "Invalid term!"
    if b"Encoding failed!" in data:
        return "Encoding failed!"
    try:
        text = data.decode('utf-8', errors='replace')
        if len(text) < 60 and text.isprintable():
            return repr(text)
    except:
        pass
    return data[:50].hex() + ("..." if len(data) > 50 else "")


def encode_byte_term(n: int) -> object:
    expr: object = Var(0)
    for idx, weight in ((1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)):
        if n & weight:
            expr = App(Var(idx), expr)
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_bytes_list(bs: bytes) -> object:
    nil: object = Lam(Lam(Var(0)))
    def cons(h: object, t: object) -> object:
        return Lam(Lam(App(App(Var(1), h), t)))
    cur: object = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


nil_term = Lam(Lam(Var(0)))
QD_term = parse_term(QD)

print("="*70)
print("ATTEMPTING TO CALL HIDDEN SYSCALL 253")
print("="*70)

# Build the program that:
# 1. Calls echo(Var(251)) -> Left(Var(253))
# 2. Pattern matches the Either to extract Var(253)
# 3. Calls Var(253) as syscall with nil argument
# 4. Uses QD to print result (or write to show it worked)

# Program structure:
# ((echo Var(251)) handler)
# 
# handler receives the Either and pattern matches:
# handler = λe. ((e leftH) rightH)
#
# leftH (receives the Left payload = Var(253)):
# leftH = λx. ((x nil) QD)   ; call x as syscall, print with QD
#
# rightH (receives Right payload if any):
# rightH = λy. nil           ; just return nil, shouldn't happen

# De Bruijn considerations:
# At top level: syscalls at Var(N) for syscall N
# Under handler (1 lambda): syscalls shift to N+1
# Under leftH (2 lambdas): syscalls shift to N+2
# 
# Inside leftH body:
#   Var(0) = x (the extracted Var(253))
#   Var(1) = e (the Either result)  
#   Var(2+N) = syscall N at top level
# 
# nil at top level = constant term, doesn't shift
# QD at top level = constant term with internal vars, needs shifting!

# Let's build step by step:

# leftH body: ((Var(0) nil_shifted) QD_shifted)
# nil doesn't have free vars, no shift needed
# QD has vars referencing syscalls 2, 3, 4, 5 - need +2 shift

QD_shifted = shift_term(QD_term, 2)
leftH_body = App(App(Var(0), nil_term), QD_shifted)
leftH = Lam(leftH_body)

print(f"leftH = {pp_term(leftH)}")

# rightH body: nil (but under 2 lambdas, doesn't matter since nil has no free vars)
rightH_body = nil_term
rightH = Lam(rightH_body)

print(f"rightH = {pp_term(rightH)}")

# handler body: ((Var(0) leftH_shifted) rightH_shifted)
# Var(0) = e at this level
# leftH has internal vars, but its free vars are syscall refs that need +1 shift
leftH_shifted = shift_term(leftH, 1)
rightH_shifted = shift_term(rightH, 1)

handler_body = App(App(Var(0), leftH_shifted), rightH_shifted)
handler = Lam(handler_body)

print(f"handler = {pp_term(handler)}")

# Full program: ((echo Var(251)) handler)
# echo = syscall 0x0E = Var(14) at top level
# Program: ((Var(14) Var(251)) handler)

try:
    prog = App(App(Var(14), Var(251)), handler)
    print(f"\nFull program: {pp_term(prog)}")
    
    prog_bytes = encode_term(prog) + bytes([FF])
    print(f"Encoded: {prog_bytes.hex()}")
    print(f"Length: {len(prog_bytes)} bytes")
    
    print("\nSending to server...")
    resp, elapsed = query(prog_bytes, timeout_s=6.0)
    print(f"Response: {format_response(resp)} [{elapsed:.2f}s]")
    
    if resp and resp != b"Encoding failed!" and resp != b"Invalid term!":
        print(f"Raw hex: {resp.hex()}")
        try:
            parsed = parse_term(resp)
            print(f"Parsed: {pp_term(parsed)}")
        except Exception as e:
            print(f"Parse error: {e}")

except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()


print("\n" + "="*70)
print("VARIANT: Use write to show observable output regardless of result")
print("="*70)

# Alternative: leftH prints "CALLED" then calls x as syscall
# leftH = λx. ((write "CALLED") (λ_. ((x nil) QD)))

# write = syscall 2 = Var(2) at top level
# Inside leftH (2 lambdas deep): write = Var(4)
# Inside the inner lambda (3 lambdas deep): write = Var(5), x = Var(1)

msg_bytes = encode_bytes_list(b"CALLED_253")
msg_shifted = shift_term(msg_bytes, 2)  # shift for being under 2 lambdas

# Inner continuation: λ_. ((x nil) QD)
# x here is Var(1) (from enclosing leftH lambda)
# nil doesn't shift
# QD needs +3 shift (under 3 lambdas now)
QD_shifted3 = shift_term(QD_term, 3)
inner_body = App(App(Var(1), nil_term), QD_shifted3)
inner_cont = Lam(inner_body)

# leftH body: ((write msg) inner_cont)
# write = Var(4) here (2 lambdas deep)
leftH2_body = App(App(Var(4), msg_shifted), inner_cont)
leftH2 = Lam(leftH2_body)

print(f"leftH2 = {pp_term(leftH2)}")

# handler with leftH2
leftH2_shifted = shift_term(leftH2, 1)
handler2_body = App(App(Var(0), leftH2_shifted), rightH_shifted)
handler2 = Lam(handler2_body)

try:
    prog2 = App(App(Var(14), Var(251)), handler2)
    print(f"\nFull program: {pp_term(prog2)}")
    
    prog2_bytes = encode_term(prog2) + bytes([FF])
    print(f"Encoded: {prog2_bytes.hex()}")
    print(f"Length: {len(prog2_bytes)} bytes")
    
    print("\nSending to server...")
    resp2, elapsed2 = query(prog2_bytes, timeout_s=6.0)
    print(f"Response: {format_response(resp2)} [{elapsed2:.2f}s]")
    
    if resp2:
        print(f"Raw hex: {resp2.hex()}")

except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()


print("\n" + "="*70)
print("VARIANT: Even simpler - just extract and call, see if anything happens")
print("="*70)

# Simplest possible: 
# ((echo 251) (λe. (e (λx. (x nil)) (λ_. nil))))
# This extracts Var(253), calls it with nil, no continuation handling

# leftH = λx. (x nil) = λ. ((V0 nil))
simple_left_body = App(Var(0), nil_term)
simple_left = Lam(simple_left_body)

simple_right = Lam(nil_term)

simple_handler_body = App(App(Var(0), shift_term(simple_left, 1)), shift_term(simple_right, 1))
simple_handler = Lam(simple_handler_body)

try:
    prog3 = App(App(Var(14), Var(251)), simple_handler)
    print(f"\nSimple program: {pp_term(prog3)}")
    
    prog3_bytes = encode_term(prog3) + bytes([FF])
    print(f"Encoded: {prog3_bytes.hex()}")
    
    print("\nSending...")
    resp3, elapsed3 = query(prog3_bytes, timeout_s=6.0)
    print(f"Response: {format_response(resp3)} [{elapsed3:.2f}s]")
    
except Exception as e:
    print(f"ERROR: {e}")
