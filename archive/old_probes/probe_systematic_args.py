#!/usr/bin/env python3
"""
Systematically test different syscall 8 arguments.
Maybe the argument determines which byte we get,
and the answer is a sequence of bytes from specific arguments.
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
PORT = 61221

FD, FE, FF = 0xFD, 0xFE, 0xFF


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


nil = Lam(Lam(Var(0)))
identity = Lam(Var(0))


def make_church(n):
    expr = Var(0)
    for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def test_arg(arg, name):
    """
    Test syscall8(arg) with the Var(253) transform.
    Returns the quoted inner byte if successful.
    """
    test_term = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), arg),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(
                                        App(
                                            App(Var(0), identity),
                                            Lam(
                                                App(
                                                    App(Var(9), Var(0)),
                                                    Lam(
                                                        App(
                                                            App(Var(0),
                                                                Lam(App(App(Var(12), Var(0)), nil))
                                                            ),
                                                            Lam(App(App(Var(12), b"QF"), nil))
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), b"TR"), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), b"ER"), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    return resp


def main():
    print("=" * 70)
    print("SYSTEMATIC ARGUMENT TESTING")
    print("=" * 70)
    
    print("\nTesting various arguments to syscall8 and checking the transformed byte:\n")
    
    results = []
    
    args_to_test = [
        (nil, "nil"),
        (identity, "id"),
        (Var(0), "Var(0)"),
        (Var(1), "Var(1)"),
        (Var(6), "Var(6)"),
        (make_church(0), "Church0"),
        (make_church(1), "Church1"),
        (make_church(6), "Church6"),
        (make_church(42), "Church42"),
        (Lam(Lam(Var(1))), "true"),
        (Lam(Lam(Var(0))), "false"),
    ]
    
    for arg, name in args_to_test:
        resp = test_arg(arg, name)
        if resp and b"QF" not in resp and b"TR" not in resp and b"ER" not in resp and len(resp) > 5:
            print(f"  {name}: HEX={resp.hex()}")
            results.append((name, resp))
        elif resp:
            print(f"  {name}: {resp[:20]}...")
        else:
            print(f"  {name}: (empty)")
        time.sleep(0.2)
    
    print("\n\nParsing successful results:")
    for name, data in results:
        if b'\xff' in data:
            term_data = data[:data.index(b'\xff')]
            print(f"  {name}: term bytes = {term_data.hex()}")


if __name__ == "__main__":
    main()
