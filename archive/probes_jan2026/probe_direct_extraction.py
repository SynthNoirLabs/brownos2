#!/usr/bin/env python3
"""
Try different ways to extract/use the value from (key anything).

We've been assuming it's Left(Right(Church1)).
But maybe the structure is different.

Let's try:
1. Direct write (key x) as bytes
2. Use (key x) directly without Either unwrapping
3. Apply (key x) to different numbers of arguments
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


def make_church(n):
    expr = Var(0)
    for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


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


def test_quote_key_with_more_args():
    """
    Quote (key a b) with varying numbers of arguments.
    """
    print("=" * 70)
    print("QUOTE (key ...) WITH VARYING ARGUMENTS")
    print("=" * 70)
    
    # Get key, then quote (key), (key nil), (key nil nil), etc.
    
    print("\n=== quote(key) - no args ===")
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # key
                    App(
                        App(Var(6), Var(0)),  # quote(key)
                        Lam(
                            App(App(Var(0), Lam(App(App(Var(6), Var(0)), nil))), Lam(App(App(Var(6), encode_string("QF")), nil)))
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  quote(key): {resp.hex() if resp and resp not in [b'QF', b'ER'] else resp}")
    
    print("\n=== quote(key nil) - 1 arg ===")
    test_term = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(6), App(Var(0), nil)),  # quote(key nil)
                        Lam(
                            App(App(Var(0), Lam(App(App(Var(6), Var(0)), nil))), Lam(App(App(Var(6), encode_string("QF")), nil)))
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  quote(key nil): {resp.hex() if resp and resp not in [b'QF', b'ER'] else resp}")
    
    print("\n=== quote((key nil) nil) - 2 args total ===")
    test_term = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(6), App(App(Var(0), nil), nil)),  # quote((key nil) nil)
                        Lam(
                            App(App(Var(0), Lam(App(App(Var(6), Var(0)), nil))), Lam(App(App(Var(6), encode_string("QF")), nil)))
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  quote((key nil) nil): {resp.hex() if resp and resp not in [b'QF', b'ER'] else resp}")
    
    print("\n=== quote(((key nil) nil) nil) - 3 args total ===")
    test_term = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(6), App(App(App(Var(0), nil), nil), nil)),
                        Lam(
                            App(App(Var(0), Lam(App(App(Var(6), Var(0)), nil))), Lam(App(App(Var(6), encode_string("QF")), nil)))
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  quote(((key nil) nil) nil): {resp.hex() if resp and resp not in [b'QF', b'ER'] else resp}")


def test_key_applied_to_succ_zero():
    """
    If key behaves like Church1 (λfx.fx), then:
    (key succ zero) should give Church1 (succ applied once to zero)
    """
    print("\n=== key applied to succ and zero (Church test) ===")
    
    # Church encoding: succ = λn.λf.λx.f(n f x)
    # But we're using the 9-lambda bitset encoding, not standard Church
    
    # Let's try: (key f x) where f=identity, x=Church42
    # If key=Church1, result should be f(x) = identity(Church42) = Church42
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # key
                    App(
                        App(Var(6),  # quote
                            App(App(Var(0), identity), make_church(42))  # (key identity church42)
                        ),
                        Lam(
                            App(App(Var(0), Lam(App(App(Var(6), Var(0)), nil))), Lam(App(App(Var(6), encode_string("QF")), nil)))
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  quote(key identity church42): {resp[:40].hex() if resp and resp not in [b'QF', b'ER'] else resp}")
    
    if resp and resp not in [b'QF', b'ER', b'Encoding failed!']:
        print(f"  Length: {len(resp)} bytes")


def test_apply_key_many_times():
    """
    What if we need to apply key multiple times to collect multiple bytes?
    """
    print("\n=== Apply key multiple times (stateful test) ===")
    
    # Apply key 3 times to nil and collect results
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # key
                    # First: (key nil) -> extract byte1
                    App(
                        App(App(Var(0), nil), Lam(
                            App(App(Var(0), identity), Lam(
                                # Write byte1
                                App(App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                    # Second: (key nil) -> extract byte2
                                    App(
                                        App(App(Var(3), nil), Lam(
                                            App(App(Var(0), identity), Lam(
                                                App(App(Var(10), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                                    # Third: (key nil) -> extract byte3
                                                    App(
                                                        App(App(Var(7), nil), Lam(
                                                            App(App(Var(0), identity), Lam(
                                                                App(App(Var(14), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                                            ))
                                                        )),
                                                        Lam(App(App(Var(13), encode_string("3R")), nil))
                                                    )
                                                )
                                            ))
                                        )),
                                        Lam(App(App(Var(9), encode_string("2R")), nil))
                                    )
                                )
                            ))
                        )),
                        Lam(App(App(Var(5), encode_string("1R")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  3x (key nil) extractions: {resp}")
    if len(resp) == 3:
        print(f"  Bytes: {resp[0]}, {resp[1]}, {resp[2]}")


def main():
    test_quote_key_with_more_args()
    time.sleep(0.3)
    
    test_key_applied_to_succ_zero()
    time.sleep(0.3)
    
    test_apply_key_many_times()


if __name__ == "__main__":
    main()
