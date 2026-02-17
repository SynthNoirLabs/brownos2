#!/usr/bin/env python3
"""
Syscall 8 via backdoor gives Right(2) = Invalid Argument.
The pair applies A as argument and B as continuation.

A = λ.λ.(V0 V0) = λab.bb (self-apply second)
B = λ.λ.(V1 V0) = λab.ab (apply first to second)

What if we need to pass a DIFFERENT argument to syscall8?
We can construct custom selectors that inject our own argument.

Pattern: pair (λA.λB. syscall8 <our_arg> <cont>) nil
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
PORT = 61221

FD, FE, FF = 0xFD, 0xFE, 0xFF
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


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


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError


def encode_int(n: int) -> object:
    expr: object = Var(0)
    remaining = n
    weights = [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]
    for idx, weight in weights:
        while remaining >= weight:
            expr = App(Var(idx), expr)
            remaining -= weight
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def query(payload: bytes, timeout_s: float = 5.0) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except:
            pass
        sock.settimeout(timeout_s)
        out = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                out += chunk
                if FF in chunk:
                    break
            except socket.timeout:
                break
        return out


def parse_term(data: bytes) -> object:
    stack = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x, f = stack.pop(), stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            stack.append(Lam(stack.pop()))
        else:
            stack.append(Var(b))
    return stack[0] if len(stack) == 1 else None


def decode_either(term):
    if isinstance(term, Lam) and isinstance(term.body, Lam):
        body = term.body.body
        if isinstance(body, App) and isinstance(body.f, Var):
            return ("Left" if body.f.i == 1 else "Right", body.x)
    return None, None


def strip_lams(term, n):
    cur = term
    for _ in range(n):
        if isinstance(cur, Lam):
            cur = cur.body
        else:
            return None
    return cur


def eval_bitset(expr):
    if isinstance(expr, Var):
        return WEIGHTS.get(expr.i, 0)
    if isinstance(expr, App) and isinstance(expr.f, Var):
        return WEIGHTS.get(expr.f.i, 0) + eval_bitset(expr.x)
    return 0


def decode_byte_term(term):
    body = strip_lams(term, 9)
    return eval_bitset(body) if body else None


def uncons_list(term):
    if isinstance(term, Lam) and isinstance(term.body, Lam):
        body = term.body.body
        if isinstance(body, Var) and body.i == 0:
            return None
        if isinstance(body, App) and isinstance(body.f, App):
            if isinstance(body.f.f, Var) and body.f.f.i == 1:
                return body.f.x, body.x
    return None


def decode_bytes_list(term):
    out = []
    cur = term
    for _ in range(100000):
        res = uncons_list(cur)
        if res is None:
            return bytes(out)
        head, cur = res
        b = decode_byte_term(head)
        if b is not None:
            out.append(b)
    return bytes(out)


def test_syscall8_with_arg(arg_desc: str, arg_term: object) -> str:
    nil = Lam(Lam(Var(0)))
    syscall8 = Var(8)
    
    selector = Lam(Lam(App(App(syscall8, arg_term), Var(0))))
    cont = Lam(App(App(Var(0), selector), nil))
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(cont) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    
    if not resp:
        return "(empty)"
    
    term = parse_term(resp)
    if not term:
        return f"parse error: {resp.hex()[:40]}"
    
    tag, p = decode_either(term)
    if tag == "Right":
        code = decode_byte_term(p)
        codes = {0: "Exception", 1: "NoSyscall", 2: "InvalidArg", 3: "UnknownId", 4: "NotDir", 5: "NotFile", 6: "PermDenied"}
        return f"Right({code}) = {codes.get(code, '?')}"
    elif tag == "Left":
        try:
            content = decode_bytes_list(p)
            return f"Left! content={content.decode('utf-8', 'replace')!r}"
        except:
            return f"Left! (non-bytes, len={len(resp)})"
    
    return f"unknown: {resp.hex()[:60]}"


def main():
    print("=== Syscall 8 Argument Testing via Backdoor ===\n")
    
    nil = Lam(Lam(Var(0)))
    I = Lam(Var(0))
    K = Lam(Lam(Var(1)))
    
    print("Testing syscall8 with different arguments via backdoor bypass:\n")
    
    print("1. Basic terms:")
    for desc, arg in [
        ("nil", nil),
        ("I", I),
        ("K", K),
        ("Var(0)", Var(0)),
        ("Var(8)", Var(8)),
    ]:
        result = test_syscall8_with_arg(desc, arg)
        print(f"   syscall8({desc}): {result}")
        time.sleep(0.15)
    
    print("\n2. Integer arguments (file/dir IDs):")
    for n in [0, 1, 2, 11, 65, 88, 256]:
        result = test_syscall8_with_arg(f"int({n})", encode_int(n))
        print(f"   syscall8({n}): {result}")
        time.sleep(0.15)
    
    print("\n3. Using A and B from the pair itself:")
    
    A = Lam(Lam(App(Var(0), Var(0))))
    B = Lam(Lam(App(Var(1), Var(0))))
    
    for desc, arg in [("A=λab.bb", A), ("B=λab.ab", B), ("A A", App(A, A)), ("B B", App(B, B))]:
        result = test_syscall8_with_arg(desc, arg)
        print(f"   syscall8({desc}): {result}")
        time.sleep(0.15)
    
    print("\n4. Pass the pair as argument to syscall8:")
    
    pair = Lam(Lam(App(App(Var(1), A), B)))
    result = test_syscall8_with_arg("pair", pair)
    print(f"   syscall8(pair): {result}")
    
    print("\n5. What if the argument should be a callback that receives capabilities?")
    
    callback_I = Lam(Var(0))
    callback_fst = Lam(Lam(Var(1)))
    callback_snd = Lam(Lam(Var(0)))
    
    for desc, arg in [("λx.x", callback_I), ("λxy.x", callback_fst), ("λxy.y", callback_snd)]:
        result = test_syscall8_with_arg(desc, arg)
        print(f"   syscall8({desc}): {result}")
        time.sleep(0.15)


if __name__ == "__main__":
    main()
