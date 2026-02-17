#!/usr/bin/env python3
"""
Always getting byte 1 regardless of Right(n) value.
Let's try different input SHAPES:
1. Left(n) instead of Right(n)
2. Raw Church numerals
3. Pairs
4. Different structures entirely
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


def make_church(n):
    expr = Var(0)
    for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def make_right(payload):
    return Lam(Lam(App(Var(0), payload)))


def make_left(payload):
    return Lam(Lam(App(Var(1), payload)))


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


def test_with_input(input_term, desc):
    """Apply key to input_term and try to extract a byte."""
    test_term = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(
                            App(Var(0), input_term),
                            Lam(
                                App(
                                    App(Var(0), identity),
                                    Lam(
                                        App(
                                            App(Var(6),
                                                Lam(Lam(App(App(Var(1), Var(2)), nil)))
                                            ),
                                            nil
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("TR")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    
    if resp == b'TR':
        return f"Transform-Right"
    elif resp == b'ER':
        return f"Echo-Right"
    elif resp and len(resp) == 1:
        return f"byte {resp[0]}"
    elif resp:
        return f"output: {resp[:20]}"
    return "(empty)"


def main():
    print("=" * 70)
    print("TESTING DIFFERENT INPUT SHAPES")
    print("=" * 70)
    
    print("\n=== First, verify Church decoding works ===\n")
    
    # Write Church2 directly to verify decoding
    church2 = make_church(2)
    verify_term = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(4),
                            Lam(Lam(App(App(Var(1), church2), nil)))
                        ),
                        nil
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(verify_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"Write [Church2] directly: {resp} (expect byte 0x02)")
    
    print("\n=== Test different input shapes to key ===\n")
    
    tests = [
        (nil, "nil"),
        (identity, "identity"),
        (make_church(0), "Church0"),
        (make_church(1), "Church1"),
        (make_church(6), "Church6"),
        (make_church(42), "Church42"),
        (make_left(make_church(0)), "Left(Church0)"),
        (make_left(make_church(6)), "Left(Church6)"),
        (make_left(nil), "Left(nil)"),
        (make_right(nil), "Right(nil)"),
        (Var(0), "Var(0)"),
        (Var(1), "Var(1)"),
        (Lam(Var(0)), "λ.0 (identity)"),
        (Lam(Lam(Var(1))), "λλ.1 (true/fst)"),
        (Lam(Lam(Var(0))), "λλ.0 (false/snd)"),
    ]
    
    for input_term, desc in tests:
        result = test_with_input(input_term, desc)
        print(f"  key({desc:20s}) -> {result}")
        time.sleep(0.2)
    
    print("\n=== Try applying key with NO argument ===\n")
    
    # What if key itself IS the answer when used a certain way?
    key_alone = Lam(
        App(
            App(Var(0),
                Lam(
                    # Just try to quote the key itself
                    App(
                        App(Var(6), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(8), Var(0)), nil))
                                ),
                                Lam(App(App(Var(8), encode_string("QF")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(key_alone) + bytes([FD, FF])
    resp = query(payload)
    print(f"quote(key) alone: {resp[:50] if resp else '(empty)'}")


if __name__ == "__main__":
    main()
