#!/usr/bin/env python3
"""
Quick probe for next steps.

Key insight from probe_direct_extraction:
- quote(key) = FB FF = Var(251)
- The key doesn't reduce - it stays as Var(251)

What if Var(251) IS the answer or leads to it?
Or what if we need to use it WITH syscall 8 in a specific way?
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


def make_church(n):
    expr = Var(0)
    for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def test_syscall8_from_within_echo():
    """
    What if syscall 8 must be called from within echo's continuation?
    
    echo(x) returns Left(x+2), and the continuation might be in a "privileged" context.
    """
    print("=" * 70)
    print("SYSCALL 8 FROM WITHIN ECHO CONTINUATION")
    print("=" * 70)
    
    # In echo's continuation, we're inside 1 lambda (the Either handler)
    # So syscall numbers shift: syscall8 = Var(8+1) = Var(9)
    
    # Pattern: echo(x) -> Left handler calls syscall8
    test_term = Lam(
        App(
            App(Var(0),  # echoResult (Either)
                Lam(  # Left handler: val at Var(0)
                    # Inside 1 extra lambda, so syscall8 = Var(9)
                    App(
                        App(Var(9), Var(0)),  # syscall8(echoedValue)
                        Lam(  # syscall8 result handler (Either)
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), Var(0)), nil))  # Left: write payload
                                ),
                                Lam(App(App(Var(6), encode_string("PD")), nil))  # Right: Permission denied
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))  # Right: echo error
        )
    )
    
    # Try with different echo inputs
    for x in [0, 1, 251, 252]:
        payload = bytes([0x0E, x, FD]) + encode_term(test_term) + bytes([FD, FF])
        resp = query(payload, timeout_s=3)
        print(f"  echo({x}) -> syscall8(echoed): {resp}")
        time.sleep(0.2)


def test_syscall8_with_syscall8_as_arg():
    """
    What if we pass the syscall8 reference itself to syscall8?
    """
    print("\n" + "=" * 70)
    print("SYSCALL 8 WITH SYSCALL8 AS ARGUMENT")
    print("=" * 70)
    
    # ((syscall8 syscall8) QD) - syscall8 itself as argument
    payload = bytes([0x08, 0x08, FD]) + QD + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  syscall8(syscall8): {resp}")
    
    # ((syscall8 echo) QD)
    payload = bytes([0x08, 0x0E, FD]) + QD + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  syscall8(echo): {resp}")
    
    # ((syscall8 backdoor) QD)
    payload = bytes([0x08, 0xC9, FD]) + QD + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  syscall8(backdoor): {resp}")


def test_syscall_1_error_strings():
    """
    Syscall 1 gives error strings. Let's check what error codes exist.
    """
    print("\n" + "=" * 70)
    print("ERROR STRINGS (syscall 1)")
    print("=" * 70)
    
    for n in range(0, 20):
        # ((syscall1 n) QD)
        payload = bytes([0x01]) + encode_term(make_church(n)) + bytes([FD]) + QD + bytes([FD, FF])
        resp = query(payload, timeout_s=2)
        if resp and len(resp) < 100:
            print(f"  error({n}): {resp}")
        time.sleep(0.1)


def test_very_minimal_wire():
    """
    The hint says "3 leafs" - what if it means 3 bytes before FF?
    """
    print("\n" + "=" * 70)
    print("VERY MINIMAL WIRE PATTERNS")
    print("=" * 70)
    
    # Just 3 bytes + FF
    patterns_3 = [
        bytes([0x08, FD, FF]),  # (syscall8 ?)
        bytes([0x08, FE, FF]),  # λ.syscall8
        bytes([0xC9, FD, FF]),  # (backdoor ?)
        bytes([0x0E, FD, FF]),  # (echo ?)
        bytes([0xFB, FD, FF]),  # (Var251 ?)
        bytes([0xFB, FE, FF]),  # λ.Var251
    ]
    
    for p in patterns_3:
        resp = query(p, timeout_s=2)
        print(f"  {p.hex()}: {resp[:50] if resp else 'empty'}")
        time.sleep(0.1)
    
    # 4 bytes + FF
    print("\n  4 bytes:")
    patterns_4 = [
        bytes([0x08, 0x00, FD, FF]),  # syscall8(Var0)
        bytes([0x08, 0xFB, FD, FF]),  # syscall8(Var251)
        bytes([0xFB, 0x00, FD, FF]),  # Var251(Var0)
        bytes([0xFB, 0xFB, FD, FF]),  # Var251(Var251)
        bytes([0x0E, 0xFB, FD, FF]),  # echo(Var251)
    ]
    
    for p in patterns_4:
        resp = query(p, timeout_s=2)
        print(f"  {p.hex()}: {resp[:50] if resp else 'empty'}")
        time.sleep(0.1)


def main():
    test_syscall8_from_within_echo()
    time.sleep(0.3)
    
    test_syscall8_with_syscall8_as_arg()
    time.sleep(0.3)
    
    test_syscall_1_error_strings()
    time.sleep(0.3)
    
    test_very_minimal_wire()


if __name__ == "__main__":
    main()
