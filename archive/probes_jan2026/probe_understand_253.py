#!/usr/bin/env python3
"""
Let's understand what Var(253) actually is.

echo(251) -> Left(Var(253))
Var(253) = 251 + 2 = byte that's unserializable

What happens when we:
1. Apply Var(253) to different things
2. Use Var(253) in different ways
3. Quote Var(253)

Key observation: The transformation (Var(253) Right(6)) -> Left(Right(Church1))
suggests Var(253) might be a function that constructs Left(Right(...))
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


def test_key_structure_discovery():
    """
    Theory: Var(253) = λx. Left(Right(Church1))  (constant function)
    
    Let's test by applying it with TWO arguments to see structure.
    """
    print("\n=== Testing key structure ===")
    
    # (key arg1 arg2) - apply with two args
    # If key = λx.Left(Right(c1)), then (key arg1) = Left(Right(c1))
    # and ((key arg1) leftHandler rightHandler) should call leftHandler
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # key at Var(0)
                    # (key nil leftHandler rightHandler)
                    # key nil = result, then result leftHandler rightHandler
                    App(
                        App(
                            App(Var(0), nil),  # (key nil)
                            Lam(  # leftHandler - receives inner value
                                # inner should be Right(Church1)
                                # Try to extract it
                                App(
                                    App(Var(0), identity),  # unwrap Right
                                    Lam(  # should be Church1
                                        App(
                                            App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                            nil
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(  # rightHandler
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
    print(f"  (key nil) applied to Either handlers: {resp}")


def test_key_is_constant():
    """
    If key is a constant function, (key x) = (key y) for all x, y.
    We already know this returns byte 1 for various inputs.
    
    Now test: what if key itself IS Church1?
    """
    print("\n=== Test: Is key literally Church1? ===")
    
    # If key = Church1 = λfx.fx, then:
    # (key f x) = f x
    # So (key (λ.42) nil) should give 42
    
    church42 = make_church(42)
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # key at Var(0)
                    # (key (λ.church42) nil)
                    App(
                        App(Var(0), Lam(church42)),  # (key (λ.42))
                        nil  # second arg
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    # This would return a Church numeral... we'd need to quote or write it
    # Let's just check what comes out
    
    # Actually, let's check: (key true false) where true = λλ.1, false = λλ.0
    # If key = Church1, then (key true false) = true false = false (since true takes first of two)
    # No wait, Church1 = λfx.fx, so (Church1 f x) = f x
    
    # Let's test: if key is Church1, then (key identity x) = identity x = x
    
    test_term2 = Lam(
        App(
            App(Var(0),
                Lam(  # key at Var(0)
                    # Quote ((key identity) church42)
                    # If key = Church1, result = identity church42 = church42
                    App(
                        App(Var(6),  # quote
                            App(
                                App(Var(0), identity),  # (key identity)
                                church42
                            )
                        ),
                        Lam(  # quote continuation
                            App(
                                App(Var(0),  # Either from quote
                                    Lam(App(App(Var(6), Var(0)), nil))  # Left - write bytes
                                ),
                                Lam(App(App(Var(6), encode_string("QF")), nil))  # Right - quote failed
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term2) + bytes([FD, FF])
    resp = query(payload)
    print(f"  Quote((key identity) church42): {resp[:50] if resp else 'empty'} len={len(resp)}")


def test_direct_var253_behavior():
    """
    What if we skip the Either unpacking and just try to use key directly?
    """
    print("\n=== Direct Var(253) behavior tests ===")
    
    # After echo(251) we get Left(Var(253))
    # The Left wrapper means we must unwrap it first
    # Then Var(253) is the raw key
    
    # What if Var(253) is not a function at all, but a special value?
    
    # Test: just write Var(253) directly (as a single byte list)
    # This would require having the key in scope for the write
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # key at Var(0)
                    # Try to write the key's VALUE as bytes
                    # Create list [key] and write it
                    # This will probably fail since key can't be serialized
                    App(
                        App(Var(4),  # write syscall
                            Lam(Lam(App(App(Var(1), Var(2)), nil)))  # [Var(2)] = [key]
                        ),
                        nil
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  Write [key] directly: {resp}")


def test_is_key_related_to_answer():
    """
    The transformation always gives byte 1.
    What if we need to use byte 1 to DO something else?
    
    Like: read file at index 1?
    Or: syscall 1?
    """
    print("\n=== Use byte 1 as index/input ===")
    
    # Get byte 1, then use it somehow
    # One idea: byte 1 might be an index into /etc/passwd or similar
    
    # Let's try reading byte at position 1 from a file
    # First, let's read /etc/passwd and see what's at position 1
    
    # Build path "/etc/passwd"
    path = encode_string("/etc/passwd")
    
    # open syscall = 0x05
    # read syscall = 0x07
    test_term = Lam(  # open continuation
        App(
            App(Var(0),  # open result
                Lam(  # Left - fd at Var(0)
                    App(
                        App(
                            App(Var(9), Var(0)),  # read(fd)
                            make_church(2)  # read 2 bytes
                        ),
                        Lam(  # read result at Var(0), fd at Var(1)
                            App(
                                App(Var(0),
                                    Lam(  # Left - bytes
                                        App(App(Var(6), Var(0)), nil)  # write bytes
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("RF")), nil))  # Right - read failed
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("OF")), nil))  # Right - open failed
        )
    )
    
    payload = bytes([0x05]) + encode_term(path) + bytes([FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  First 2 bytes of /etc/passwd: {resp}")
    
    # What about position 1 specifically?
    test_term2 = Lam(
        App(
            App(Var(0),
                Lam(  # fd
                    # seek to position 1, then read
                    # Actually, let's just read more and look at byte[1]
                    App(
                        App(
                            App(Var(9), Var(0)),
                            make_church(10)  # read 10 bytes
                        ),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), Var(0)), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("RF")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("OF")), nil))
        )
    )
    
    payload = bytes([0x05]) + encode_term(path) + bytes([FD]) + encode_term(test_term2) + bytes([FD, FF])
    resp = query(payload)
    print(f"  First 10 bytes of /etc/passwd: {resp}")
    if len(resp) > 1:
        print(f"    Byte at index 1: {resp[1]} = '{chr(resp[1]) if 32 <= resp[1] < 127 else '?'}'")


def main():
    print("=" * 70)
    print("UNDERSTANDING VAR(253)")
    print("=" * 70)
    
    test_key_structure_discovery()
    time.sleep(0.3)
    
    test_key_is_constant()
    time.sleep(0.3)
    
    test_direct_var253_behavior()
    time.sleep(0.3)
    
    test_is_key_related_to_answer()


if __name__ == "__main__":
    main()
