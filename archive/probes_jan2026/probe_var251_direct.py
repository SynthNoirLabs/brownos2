#!/usr/bin/env python3
"""
Var(251) appears to be a special global binding.

Let's test what Var(251) does when called directly
(without going through echo to manufacture Var(253) first).

Var(251) = 0xFB in wire format, which is valid (< 0xFD).
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


def encode_term(term) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unknown term type: {type(term)}")


def query(payload: bytes, timeout_s: float = 5.0) -> bytes:
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except:
                pass
            sock.settimeout(timeout_s)
            out = b""
            deadline = time.time() + timeout_s
            while time.time() < deadline:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out += chunk
                except socket.timeout:
                    break
            return out
    except Exception as e:
        return f"ERROR: {e}".encode()


nil = Lam(Lam(Var(0)))
identity = Lam(Var(0))


def encode_string(s: str):
    def encode_byte(n):
        expr = Var(0)
        for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
            if n & weight:
                expr = App(Var(idx), expr)
        term = expr
        for _ in range(9):
            term = Lam(term)
        return term
    def cons(h, t):
        return Lam(Lam(App(App(Var(1), h), t)))
    cur = nil
    for b in reversed(s.encode()):
        cur = cons(encode_byte(b), cur)
    return cur


def main():
    print("=" * 70)
    print("TESTING VAR(251) DIRECTLY")
    print("=" * 70)
    
    print("\n=== Test 1: ((Var(251) nil) QD) ===")
    
    # Direct call: ((0xFB nil) QD)
    payload1 = bytes([0xFB]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    resp1 = query(payload1)
    print(f"  Response: {resp1.hex() if resp1 else 'empty'}")
    
    print("\n=== Test 2: Quote Var(251) directly ===")
    
    # ((quote Var(251)) continuation)
    # quote = 0x04
    payload2 = bytes([0x04, 0xFB, FD]) + QD + bytes([FD, FF])
    resp2 = query(payload2)
    print(f"  Response: {resp2.hex() if resp2 else 'empty'}")
    
    print("\n=== Test 3: Apply Var(251) to nil with Either handlers ===")
    
    # Build: ((Var(251) nil) (λx. write "L") (λx. write "R"))
    term3 = App(
        App(
            App(Var(0xFB), nil),  # (Var(251) nil)
            Lam(  # Left handler
                App(App(Var(4), encode_string("L")), nil)  # write "L"
            )
        ),
        Lam(  # Right handler
            App(App(Var(4), encode_string("R")), nil)  # write "R"
        )
    )
    
    payload3 = encode_term(term3) + bytes([FF])
    resp3 = query(payload3)
    print(f"  Response: {resp3}")
    
    print("\n=== Test 4: Sweep high Var indices for syscall-like behavior ===")
    
    # Check Var(200) through Var(252) with QD
    interesting = []
    for i in range(200, 253):
        payload = bytes([i]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
        resp = query(payload, timeout_s=1)
        if resp and not resp.startswith(b'\x00\x01\x00\xfe\xfe'):  # Not Right(1) = Not implemented
            interesting.append((i, resp[:30]))
        time.sleep(0.1)
    
    print("  Interesting responses (not 'Not implemented'):")
    for i, resp in interesting:
        print(f"    Var({i}) = 0x{i:02X}: {resp}")
    
    print("\n=== Test 5: Var(251) applied to identity then nil ===")
    
    # ((Var(251) identity) nil) - CPS call
    term5 = App(
        App(Var(0xFB), identity),
        nil
    )
    payload5 = encode_term(term5) + bytes([FF])
    resp5 = query(payload5)
    print(f"  ((Var(251) identity) nil): {resp5}")
    
    # With QD
    term5b = App(
        App(Var(0xFB), identity),
        Lam(  # CPS continuation
            App(Var(3), Var(0))  # (QD result)
        )
    )
    payload5b = encode_term(term5b) + bytes([FF])
    resp5b = query(payload5b)
    print(f"  ((Var(251) identity) λ.(QD 0)): {resp5b}")


if __name__ == "__main__":
    main()
