#!/usr/bin/env python3
"""
Analyze the structure of the payload from (key nil).

Working pattern: (payload identity) then extract
This suggests payload might be Left(something) or a function.
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


def test_payload_applied_to_identity():
    """
    (payload identity) then extract - this works.
    What exactly does (payload identity) return?
    """
    print("=" * 70)
    print("PAYLOAD APPLIED TO IDENTITY")
    print("=" * 70)
    
    # Working pattern from earlier:
    # (key nil) -> Left(payload)
    # (payload identity) -> something
    # Then: (something handler) where handler extracts byte
    
    # What if payload is Left(innerValue)?
    # Then (payload identity) = (Left(innerValue) identity)
    # But Left = λx.λl.λr. l x
    # So (Left(x) identity) = λr. identity x = λr. x
    # That doesn't quite make sense...
    
    # What if payload is like Right(innerValue)?
    # Right = λx.λl.λr. r x
    # (Right(x) identity) = λr. r x
    # Still doesn't work...
    
    # Let me just test what happens when we apply different things
    
    args = [
        ("identity", Lam(Var(0))),
        ("nil", nil),
        ("true (λxy.x)", Lam(Lam(Var(1)))),
        ("false (λxy.y)", Lam(Lam(Var(0)))),
        ("K (λxy.x)", Lam(Lam(Var(1)))),  # Same as true
    ]
    
    for name, arg in args:
        test_term = Lam(
            App(
                App(Var(0),  # echo result
                    Lam(  # key at Var(0)
                        App(
                            App(App(Var(0), nil),  # (key nil)
                                Lam(  # Left: payload at Var(0)
                                    # (payload arg)
                                    App(
                                        App(Var(0), arg),
                                        Lam(  # result
                                            # Write result as byte
                                            App(
                                                App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                                nil
                                            )
                                        )
                                    )
                                )
                            ),
                            Lam(App(App(Var(5), encode_string("KR")), nil))
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("ER")), nil))
            )
        )
        
        payload_bytes = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
        resp = query(payload_bytes, timeout_s=5)
        print(f"  (payload {name}): {resp} -> {[b for b in resp] if resp else 'empty'}")
        time.sleep(0.2)


def test_payload_is_either():
    """
    Test if payload IS an Either by applying two handlers.
    """
    print("\n" + "=" * 70)
    print("PAYLOAD AS EITHER")
    print("=" * 70)
    
    # Either = λl.λr. l payload  (Left)
    # Either = λl.λr. r payload  (Right)
    
    # So: (payload LeftHandler RightHandler) should invoke one of them
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # key at Var(0)
                    App(
                        App(App(Var(0), nil),  # (key nil)
                            Lam(  # Left: payload at Var(0)
                                # (payload LeftHandler RightHandler)
                                App(
                                    App(Var(0),
                                        Lam(  # LeftHandler: receives inner value
                                            # Write inner value as byte
                                            App(
                                                App(Var(7), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                                nil
                                            )
                                        )
                                    ),
                                    Lam(  # RightHandler
                                        App(App(Var(7), encode_string("R")), nil)
                                    )
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("KR")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload_bytes = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload_bytes, timeout_s=5)
    print(f"  (payload L R): {resp} -> {[b for b in resp] if resp else 'empty'}")


def test_double_application():
    """
    The working pattern was: (payload identity) then handler
    So it's: ((payload identity) handler)
    
    This suggests payload is curried and expects 2 arguments.
    """
    print("\n" + "=" * 70)
    print("DOUBLE APPLICATION ANALYSIS")
    print("=" * 70)
    
    # ((payload arg1) arg2) = ?
    
    # Test 1: ((payload identity) nil)
    test_term = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(App(Var(0), nil),
                            Lam(
                                # ((payload identity) nil)
                                App(
                                    App(App(Var(0), identity), nil),
                                    Lam(
                                        App(
                                            App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                            nil
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("KR")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload_bytes = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload_bytes, timeout_s=5)
    print(f"  ((payload identity) nil): {resp} -> {[b for b in resp] if resp else 'empty'}")
    
    # Test 2: ((payload nil) identity)
    test_term2 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(App(Var(0), nil),
                            Lam(
                                App(
                                    App(App(Var(0), nil), identity),
                                    Lam(
                                        App(
                                            App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                            nil
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("KR")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload_bytes = bytes([0x0E, 251, FD]) + encode_term(test_term2) + bytes([FD, FF])
    resp = query(payload_bytes, timeout_s=5)
    print(f"  ((payload nil) identity): {resp} -> {[b for b in resp] if resp else 'empty'}")


def test_exactly_as_original():
    """
    Reproduce the exact original pattern that gave byte 1.
    """
    print("\n" + "=" * 70)
    print("EXACT ORIGINAL PATTERN")
    print("=" * 70)
    
    # From probe_direct_extraction.py:
    # App(App(Var(0), identity), Lam(
    #     App(App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
    # ))
    
    # This is: ((inner identity) handler)
    # Where handler writes the result as a byte
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # key at Var(0)
                    App(
                        App(App(Var(0), nil),  # (key nil)
                            Lam(  # Left: inner at Var(0)
                                App(
                                    App(Var(0), identity),  # (inner identity)
                                    Lam(  # handler for (inner identity) result
                                        App(
                                            App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                            nil
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("KR")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload_bytes = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload_bytes, timeout_s=5)
    print(f"  Exact original: {resp} -> {[b for b in resp] if resp else 'empty'}")


def main():
    test_payload_applied_to_identity()
    time.sleep(0.3)
    
    test_payload_is_either()
    time.sleep(0.3)
    
    test_double_application()
    time.sleep(0.3)
    
    test_exactly_as_original()


if __name__ == "__main__":
    main()
