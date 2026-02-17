#!/usr/bin/env python3
"""
Deep analysis of the backdoor response.
Maybe the pair isn't just (A, B) - maybe there's more structure.
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
PORT = 61221

FD, FE, FF = 0xFD, 0xFE, 0xFF
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


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError


def term_to_str(term: object, depth=0) -> str:
    if depth > 20:
        return "..."
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{term_to_str(term.body, depth+1)}"
    if isinstance(term, App):
        return f"({term_to_str(term.f, depth+1)} {term_to_str(term.x, depth+1)})"
    return "?"


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


def main():
    print("=== Deep Backdoor Analysis ===\n")
    
    nil = Lam(Lam(Var(0)))
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    
    print(f"Response hex: {resp.hex()}")
    print(f"Response length: {len(resp)}")
    
    term = parse_term(resp)
    print(f"\nFull parsed term:\n{term_to_str(term)}")
    
    tag, pair = decode_either(term)
    print(f"\nEither tag: {tag}")
    print(f"Pair term:\n{term_to_str(pair)}")
    
    if isinstance(pair, Lam):
        print("\n=== Extracting pair components ===")
        pair_body = pair.body
        print(f"Pair body: {term_to_str(pair_body)}")
        
        if isinstance(pair_body, App) and isinstance(pair_body.f, App):
            selector = pair_body.f.f
            A = pair_body.f.x
            B = pair_body.x
            
            print(f"\nSelector: {term_to_str(selector)}")
            print(f"A: {term_to_str(A)}")
            print(f"B: {term_to_str(B)}")
            
            print(f"\nA bytes: {encode_term(A).hex()}")
            print(f"B bytes: {encode_term(B).hex()}")
            
            print("\n=== Test A and B as syscall arguments ===")
            
            for name, arg in [("A", A), ("B", B), ("A A", App(A, A)), ("A B", App(A, B)), ("B A", App(B, A)), ("B B", App(B, B))]:
                payload = bytes([0x08]) + encode_term(arg) + bytes([FD]) + QD + bytes([FD, FF])
                resp = query(payload)
                result_term = parse_term(resp)
                if result_term:
                    rtag, rp = decode_either(result_term)
                    if rtag == "Right" and isinstance(rp, Lam):
                        code = None
                        body = rp.body
                        for _ in range(9):
                            if isinstance(body, Lam):
                                body = body.body
                        if isinstance(body, Var):
                            code = body.i
                        elif isinstance(body, App):
                            pass
                        print(f"syscall8({name}): {rtag}, code estimate from structure")
                    else:
                        print(f"syscall8({name}): {rtag}")
                else:
                    print(f"syscall8({name}): parse error")
                time.sleep(0.2)
            
            print("\n=== Test using pair components as continuations ===")
            
            for name, cont in [("A", A), ("B", B)]:
                payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(cont) + bytes([FD, FF])
                resp = query(payload)
                if resp:
                    print(f"syscall8(nil) with {name} as cont: {resp.hex()[:60]}")
                else:
                    print(f"syscall8(nil) with {name} as cont: (empty)")
                time.sleep(0.2)
    
    print("\n=== What if we apply the pair to syscall 8 directly? ===")
    
    syscall8 = Var(8)
    pair_applied = App(pair, syscall8)
    payload = encode_term(pair_applied) + QD + bytes([FD, FF])
    resp = query(payload)
    print(f"(pair syscall8): {resp.hex()[:80] if resp else '(empty)'}")
    
    print("\n=== Apply pair to different syscalls ===")
    
    for sc_num, sc_name in [(1, "errstr"), (4, "quote"), (5, "readdir"), (7, "readfile"), (14, "echo"), (201, "backdoor")]:
        sc = Var(sc_num)
        term = App(pair, sc)
        payload = encode_term(term) + QD + bytes([FD, FF])
        resp = query(payload)
        result = resp.hex()[:60] if resp else "(empty)"
        if resp and resp.hex().startswith("01"):
            result = "Left!"
        print(f"(pair {sc_name}): {result}")
        time.sleep(0.2)


if __name__ == "__main__":
    main()
