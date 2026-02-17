#!/usr/bin/env python3
"""
Try to extract multiple bytes from the key transformation.

Key insight: We consistently get byte 1 from (key Right(6)).
What if we need to apply key multiple times to the SAME result
to get successive bytes?

Or: What if the answer IS just byte 1, and we need to understand
what that 1 means?
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
    """Build Church numeral for n (0-255)"""
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


def test_basic_extraction():
    """Confirm we can still extract byte 1"""
    print("\n=== Basic extraction (should give byte 1) ===")
    
    # De Bruijn indices:
    # Lam: echoCont at Var(0) initially
    # Inside echoCont (Left branch), key is at Var(0)
    # syscall8 = Var(10) (0x08 + 2 for the Lams we're inside)
    # Inside syscall8 continuation, sc8Result at Var(0), key at Var(1)
    # write = Var(4) (0x02 + 2 for Lams)
    
    test_term = Lam(  # echoCont
        App(
            App(Var(0),  # echoCont is Either
                Lam(  # Left handler: key at Var(0)
                    # Call syscall8(nil)
                    App(
                        App(Var(10), nil),  # syscall8 = 0x08, +2 for Lams = Var(10)
                        Lam(  # sc8Result at Var(0), key at Var(1)
                            # (key sc8Result) -> Left(Right(ChurchByte))
                            App(
                                App(
                                    App(Var(1), Var(0)),  # (key sc8Result)
                                    Lam(  # Left - outer contains Right(ChurchByte)
                                        App(
                                            App(Var(0), identity),  # unwrap Right
                                            Lam(  # ChurchByte at Var(0)
                                                # Write [ChurchByte]
                                                # write = 0x02 + 4 Lams = Var(6)
                                                App(
                                                    App(
                                                        Var(6),  # write
                                                        Lam(Lam(App(App(Var(1), Var(2)), nil)))  # [Var(2)]
                                                    ),
                                                    nil  # continuation
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(  # Right - error
                                    App(App(Var(5), encode_string("R")), nil)
                                )
                            )
                        )
                    )
                )
            ),
            Lam(  # echo Right handler - error
                App(App(Var(4), encode_string("E")), nil)
            )
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  Result: {resp} (hex: {resp.hex() if resp else 'empty'})")
    return resp


def test_extract_then_apply_again():
    """
    After extracting byte1, apply key to sc8Result AGAIN.
    See if we get a different byte.
    """
    print("\n=== Extract byte1, then apply key again ===")
    
    test_term = Lam(  # echoCont
        App(
            App(Var(0),
                Lam(  # key at Var(0)
                    App(
                        App(Var(10), nil),  # syscall8
                        Lam(  # sc8Result at Var(0), key at Var(1)
                            # First application
                            App(
                                App(
                                    App(Var(1), Var(0)),  # (key sc8Result)
                                    Lam(  # Left - outer
                                        App(
                                            App(Var(0), identity),
                                            Lam(  # byte1 at Var(0)
                                                # Write byte1
                                                # write = Var(6) 
                                                App(
                                                    App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                                    # Now apply key to sc8Result again
                                                    # key = Var(3), sc8Result = Var(2)
                                                    App(
                                                        App(
                                                            App(Var(3), Var(2)),  # (key sc8Result) again
                                                            Lam(  # Left
                                                                App(
                                                                    App(Var(0), identity),
                                                                    Lam(  # byte2 at Var(0)
                                                                        # write = Var(8)
                                                                        App(
                                                                            App(Var(8), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                                                            nil
                                                                        )
                                                                    )
                                                                )
                                                            )
                                                        ),
                                                        Lam(  # Right for second call
                                                            App(App(Var(7), encode_string("R2")), nil)
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(  # Right for first call
                                    App(App(Var(5), encode_string("R1")), nil)
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  Result: {resp} (hex: {resp.hex() if resp else 'empty'})")
    

def test_apply_key_to_different_args():
    """
    Try applying key to different values (not just sc8Result).
    Maybe the key is a function that takes any input.
    """
    print("\n=== Apply key to different values ===")
    
    test_cases = [
        ("nil", nil),
        ("identity", identity),
        ("Church0", make_church(0)),
        ("Church1", make_church(1)),
        ("Church42", make_church(42)),
    ]
    
    for desc, arg in test_cases:
        test_term = Lam(
            App(
                App(Var(0),
                    Lam(  # key at Var(0)
                        # Directly apply key to arg
                        App(
                            App(
                                App(Var(0), arg),  # (key arg)
                                Lam(  # Left
                                    App(
                                        App(Var(0), identity),
                                        Lam(  # ChurchByte
                                            App(App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                        )
                                    )
                                )
                            ),
                            Lam(  # Right
                                App(App(Var(5), encode_string("R")), nil)
                            )
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("E")), nil))
            )
        )
        
        payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
        resp = query(payload)
        print(f"  key({desc:12s}) -> {resp}")
        time.sleep(0.3)


def test_nested_key_application():
    """
    What about (key (key arg))?
    """
    print("\n=== Nested key application: key(key(arg)) ===")
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # key at Var(0)
                    App(
                        App(Var(10), nil),  # syscall8
                        Lam(  # sc8Result at Var(0), key at Var(1)
                            # First: (key sc8Result)
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(  # Left - result1
                                        # Now apply key to result1: (key result1)
                                        App(
                                            App(
                                                App(Var(2), Var(0)),  # (key result1)
                                                Lam(  # Left - result2
                                                    App(
                                                        App(Var(0), identity),
                                                        Lam(
                                                            App(App(Var(8), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                                        )
                                                    )
                                                )
                                            ),
                                            Lam(
                                                App(App(Var(7), encode_string("N2")), nil)
                                            )
                                        )
                                    )
                                ),
                                Lam(
                                    App(App(Var(5), encode_string("N1")), nil)
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  Result: {resp} (hex: {resp.hex() if resp else 'empty'})")


def test_what_if_answer_is_1():
    """
    What if the answer is literally the number 1?
    Or "1"?
    Let's try to understand what byte 1 means in context.
    """
    print("\n=== Interpreting byte 1 ===")
    print("  Byte 1 could mean:")
    print("    - Literal '1' as the answer")
    print("    - Index into something")
    print("    - First character of multi-char answer")
    print("    - Boolean true")
    print("    - Start of message (SOH)")


def main():
    print("=" * 70)
    print("MULTI-BYTE EXTRACTION ATTEMPTS")
    print("=" * 70)
    
    result = test_basic_extraction()
    time.sleep(0.3)
    
    test_extract_then_apply_again()
    time.sleep(0.3)
    
    test_apply_key_to_different_args()
    time.sleep(0.3)
    
    test_nested_key_application()
    time.sleep(0.3)
    
    test_what_if_answer_is_1()


if __name__ == "__main__":
    main()
