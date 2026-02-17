#!/usr/bin/env python3
"""
Key insight: We can manufacture Var(253) which does SOMETHING.

What if the proper usage is:
- Use Var(253) as an ARGUMENT to syscall 8, not as a function on its result

syscall8 normally returns Right(6) = permission denied
What if syscall8(Var(253)) unlocks something?
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


def test_syscall8_with_key_as_arg():
    """
    Get key from echo, then call syscall8(key) instead of syscall8(nil).
    """
    print("\n=== syscall8(key) - use key as argument ===")
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # key at Var(0)
                    # syscall8(key) instead of syscall8(nil)
                    # syscall8 = Var(10)
                    App(
                        App(Var(10), Var(0)),  # syscall8(key)
                        Lam(  # result at Var(0), key at Var(1)
                            App(
                                App(Var(0),
                                    Lam(  # Left - success?
                                        App(
                                            App(Var(6), Var(0)),  # quote the Left contents
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
                                Lam(  # Right - check error code
                                    # Var(0) is error, try to write it as a Church numeral
                                    App(
                                        App(Var(5), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                        nil
                                    )
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
    print(f"  syscall8(key) result: {resp} (hex: {resp.hex() if resp else 'empty'})")


def test_syscall8_with_pair():
    """
    What if syscall8 needs a pair (key, something)?
    """
    print("\n=== syscall8(pair(key, nil)) ===")
    
    # pair = λf. f a b
    def make_pair(a, b):
        return Lam(App(App(Var(0), a), b))
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # key at Var(0)
                    App(
                        App(Var(10), make_pair(Var(0), nil)),  # syscall8(pair(key, nil))
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
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
                                Lam(
                                    App(App(Var(5), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
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
    print(f"  syscall8(pair(key,nil)): {resp}")


def test_backdoor_then_syscall8():
    """
    Get backdoor combinators, use them with syscall8.
    """
    print("\n=== backdoor then syscall8 combinations ===")
    
    # backdoor -> Left(pair(A, B))
    # A = λab.bb (omega-like)
    # B = λab.ab (application)
    
    # Test: syscall8(A) or syscall8(B) or syscall8(pair(A,B))
    
    # First just get backdoor and apply to syscall8
    test_term = Lam(
        App(
            App(Var(0),  # backdoor result
                Lam(  # pair at Var(0), has fst=A, snd=B
                    # Extract A and B
                    App(
                        App(Var(0), Lam(Lam(Var(1)))),  # fst -> A
                        Lam(  # A at Var(0), pair at Var(1)
                            App(
                                App(Var(1), Lam(Lam(Var(0)))),  # snd -> B
                                Lam(  # B at Var(0), A at Var(1), pair at Var(2)
                                    # syscall8(A)
                                    App(
                                        App(Var(13), Var(1)),  # syscall8(A)
                                        Lam(
                                            App(
                                                App(Var(0),
                                                    Lam(
                                                        App(
                                                            App(Var(8), Var(0)),
                                                            Lam(
                                                                App(
                                                                    App(Var(0),
                                                                        Lam(App(App(Var(10), Var(0)), nil))
                                                                    ),
                                                                    Lam(App(App(Var(10), encode_string("QF")), nil))
                                                                )
                                                            )
                                                        )
                                                    )
                                                ),
                                                Lam(
                                                    App(App(Var(7), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BR")), nil))
        )
    )
    
    payload = bytes([0xC9, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  syscall8(A from backdoor): {resp}")


def test_syscall8_with_various_args():
    """
    Try syscall8 with different arguments to understand what it accepts.
    """
    print("\n=== syscall8 with various arguments ===")
    
    args = [
        ("nil", nil),
        ("identity", identity),
        ("true (λλ.1)", Lam(Lam(Var(1)))),
        ("false (λλ.0)", Lam(Lam(Var(0)))),
        ("Church0", make_church(0)),
        ("Church1", make_church(1)),
        ("Church6", make_church(6)),
        ("pair(nil,nil)", Lam(App(App(Var(0), nil), nil))),
    ]
    
    for desc, arg in args:
        test_term = Lam(  # syscall8 continuation
            App(
                App(Var(0),  # Either
                    Lam(  # Left
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
                Lam(  # Right - error code
                    # Write error code as byte
                    App(
                        App(Var(4), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                        nil
                    )
                )
            )
        )
        
        payload = bytes([0x08]) + encode_term(arg) + bytes([FD]) + encode_term(test_term) + bytes([FD, FF])
        resp = query(payload)
        print(f"  syscall8({desc:18s}): {resp}")
        time.sleep(0.3)


def test_combine_echo_backdoor_syscall8():
    """
    Full chain: backdoor -> echo -> syscall8 using all pieces.
    """
    print("\n=== Combined: backdoor + echo + syscall8 ===")
    
    # Idea: Use backdoor's B combinator to compose echo and syscall8
    # B = λab.ab, so B f g x = f (g x)
    # Or just use backdoor pair as argument to syscall8
    
    test_term = Lam(
        App(
            App(Var(0),  # backdoor Left
                Lam(  # pair at Var(0)
                    # Use pair directly as arg to syscall8
                    App(
                        App(Var(11), Var(0)),  # syscall8(pair)
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
                                        App(
                                            App(Var(7), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(9), Var(0)), nil))
                                                    ),
                                                    Lam(App(App(Var(9), encode_string("QF")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(
                                    App(App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BR")), nil))
        )
    )
    
    payload = bytes([0xC9, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  syscall8(backdoor_pair): {resp}")


def main():
    print("=" * 70)
    print("SYSCALL8 WITH KEY AS ARGUMENT")
    print("=" * 70)
    
    test_syscall8_with_key_as_arg()
    time.sleep(0.3)
    
    test_syscall8_with_pair()
    time.sleep(0.3)
    
    test_backdoor_then_syscall8()
    time.sleep(0.3)
    
    test_syscall8_with_various_args()
    time.sleep(0.3)
    
    test_combine_echo_backdoor_syscall8()


if __name__ == "__main__":
    main()
