#!/usr/bin/env python3
"""
Investigate echo behavior on different inputs.
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
    raise TypeError


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


def test(desc: str, payload: bytes):
    resp = query(payload)
    if not resp:
        result = "(empty/timeout)"
    elif b"Encoding failed" in resp:
        result = "Encoding failed!"
    elif b"Invalid term" in resp:
        result = "Invalid term!"
    else:
        try:
            text = resp.decode('utf-8', 'replace')
            result = f"OUTPUT: {repr(text[:100])}"
        except:
            result = f"hex: {resp.hex()[:100]}"
    print(f"{desc}: {result}")
    return resp


def encode_string(s: str):
    nil = Lam(Lam(Var(0)))
    
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
    print("ECHO BEHAVIOR INVESTIGATION")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print("\n=== Test echo on simple inputs with QD ===\n")
    
    print("echo(nil):")
    payload = bytes([0x0E]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    test("  QD result", payload)
    
    print("\necho(Var(0)):")
    payload = bytes([0x0E, 0x00, FD]) + QD + bytes([FD, FF])
    test("  QD result", payload)
    
    print("\necho(I) where I = λ.0:")
    I = Lam(Var(0))
    payload = bytes([0x0E]) + encode_term(I) + bytes([FD]) + QD + bytes([FD, FF])
    test("  QD result", payload)
    
    print("\n=== Test echo return type with branch handler ===\n")
    
    branch_handler = Lam(
        App(
            App(Var(0),
                Lam(App(App(Var(4), encode_string("LEFT\n")), nil))
            ),
            Lam(App(App(Var(4), encode_string("RIGHT\n")), nil))
        )
    )
    
    print("echo(nil) -> branch:")
    payload = bytes([0x0E]) + encode_term(nil) + bytes([FD]) + encode_term(branch_handler) + bytes([FD, FF])
    test("  result", payload)
    
    print("\necho(Var(0)) -> branch:")
    payload = bytes([0x0E, 0x00, FD]) + encode_term(branch_handler) + bytes([FD, FF])
    test("  result", payload)
    
    print("\necho(I) -> branch:")
    payload = bytes([0x0E]) + encode_term(I) + bytes([FD]) + encode_term(branch_handler) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Test backdoor -> echo chain more carefully ===\n")
    
    backdoor_print_left_right = Lam(
        App(
            App(Var(0),
                Lam(App(App(Var(4), encode_string("BD-LEFT\n")), nil))
            ),
            Lam(App(App(Var(4), encode_string("BD-RIGHT\n")), nil))
        )
    )
    
    print("backdoor(nil) -> branch directly:")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_print_left_right) + bytes([FD, FF])
    test("  result", payload)
    
    echo_pair_then_branch = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(15), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), encode_string("ECHO-LEFT\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("ECHO-RIGHT\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD-RIGHT\n")), nil))
        )
    )
    
    print("\nbackdoor(nil) -> extract pair -> echo(pair) -> branch:")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(echo_pair_then_branch) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Simpler: echo the A combinator directly ===\n")
    
    A = Lam(Lam(App(Var(0), Var(0))))
    
    print("echo(A) where A = λλ.(0 0):")
    payload = bytes([0x0E]) + encode_term(A) + bytes([FD]) + QD + bytes([FD, FF])
    test("  QD result", payload)
    
    payload = bytes([0x0E]) + encode_term(A) + bytes([FD]) + encode_term(branch_handler) + bytes([FD, FF])
    test("  branch result", payload)
    
    print("\n=== Echo(pair) where pair = λs.s A B ===\n")
    
    B = Lam(Lam(App(Var(1), Var(0))))
    pair = Lam(App(App(Var(0), A), B))
    
    print("echo(pair):")
    payload = bytes([0x0E]) + encode_term(pair) + bytes([FD]) + encode_term(branch_handler) + bytes([FD, FF])
    test("  branch result", payload)
    
    print("\n=== What if echo requires specific argument type? ===\n")
    
    omega = Lam(App(Var(0), Var(0)))
    
    print("echo(ω) where ω = λ.(0 0):")
    payload = bytes([0x0E]) + encode_term(omega) + bytes([FD]) + encode_term(branch_handler) + bytes([FD, FF])
    test("  branch result", payload)


if __name__ == "__main__":
    main()
