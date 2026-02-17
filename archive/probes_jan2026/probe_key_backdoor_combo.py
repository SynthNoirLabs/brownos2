#!/usr/bin/env python3
"""
Combine backdoor combinators with the echo key.

Backdoor gives: pair(A, B) where
  A = λab.bb  (self-application)
  B = λab.ab  (normal application / composition helper)

Echo gives: Var(253) which transforms things into Left(Right(Church1))

What if:
1. A applied to key does something special (A key = key key)
2. B applied to key and something composes them
3. The pair itself is meant to be given to syscall8
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


def test_A_with_key():
    """
    Get backdoor A, then echo key, then apply A to key.
    A = λab.bb, so (A key x) = x x
    What if (A key key) = key key does something?
    """
    print("\n=== (A key key) where A from backdoor, key from echo ===")
    
    # backdoor -> echo -> combine
    test_term = Lam(  # backdoor cont
        App(
            App(Var(0),  # backdoor result
                Lam(  # pair at Var(0)
                    # Extract A = fst
                    App(
                        App(Var(0), Lam(Lam(Var(1)))),  # fst
                        Lam(  # A at Var(0), pair at Var(1)
                            # Now get key from echo
                            App(
                                App(Var(16), nil),  # echo(nil) - but we want echo(251)
                                Lam(  # echo result
                                    App(
                                        App(Var(0),
                                            Lam(  # key at Var(0) from Left
                                                # (A key key) - self-apply key via A
                                                # A at Var(3)
                                                App(
                                                    App(Var(3), Var(0)),  # (A key)
                                                    Var(0)  # key again
                                                )
                                                # This returns key key
                                                # Try to quote and write result
                                            )
                                        ),
                                        Lam(App(App(Var(6), encode_string("ER")), nil))
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
    resp = query(payload, timeout_s=3)
    print(f"  Result: {resp}")


def test_echo_directly_in_backdoor():
    """
    Get backdoor first, then use echo with a specific value.
    The proper echo call is: echo(251) which gives Left(Var(253))
    """
    print("\n=== backdoor -> echo(251) -> extract key -> apply to syscall8 result ===")
    
    test_term = Lam(  # backdoor cont
        App(
            App(Var(0),  # backdoor Left
                Lam(  # pair at Var(0)
                    # Extract A
                    App(
                        App(Var(0), Lam(Lam(Var(1)))),
                        Lam(  # A at Var(0)
                            # Extract B
                            App(
                                App(Var(1), Lam(Lam(Var(0)))),
                                Lam(  # B at Var(0), A at Var(1)
                                    # Now get key via echo(251)
                                    # echo = 0x0E, under 4 Lams = Var(0x0E + 4) = Var(18)
                                    # Wait, we're inside multiple Lams...
                                    # Let's count: backdoor cont Lam, Left handler Lam, fst cont Lam, snd cont Lam = 4 Lams
                                    # echo syscall = 0x0E = 14, so Var(14+4) = Var(18)
                                    # Actually need to use echo with raw argument
                                    Lam(  # echo cont - extra Lam for CPS
                                        App(
                                            App(Var(0),  # echo result
                                                Lam(  # key at Var(0)
                                                    # syscall8 = 0x08 = 8, under 6 Lams = Var(14)
                                                    App(
                                                        App(Var(14), nil),
                                                        Lam(  # sc8 result at Var(0)
                                                            # (key sc8result)
                                                            App(
                                                                App(
                                                                    App(Var(1), Var(0)),  # key(sc8result)
                                                                    Lam(  # Left
                                                                        App(
                                                                            App(Var(0), identity),
                                                                            Lam(  # byte
                                                                                App(
                                                                                    App(Var(10), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                                                                    nil
                                                                                )
                                                                            )
                                                                        )
                                                                    )
                                                                ),
                                                                Lam(App(App(Var(9), encode_string("KR")), nil))
                                                            )
                                                        )
                                                    )
                                                )
                                            ),
                                            Lam(App(App(Var(8), encode_string("ER")), nil))
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
    
    # Need to call echo(251) to the inner Lam
    # Build: backdoor nil -> ... -> then somehow inject echo
    # This is getting complex. Let me try a simpler structure.
    
    payload = bytes([0xC9, FD]) + encode_term(test_term) + bytes([FD, FF])
    # But we haven't actually called echo yet...
    # Let me try the raw payload approach
    
    # Actually, the structure needs to be:
    # backdoor(nil, backdoorCont) where backdoorCont processes result
    # Then inside, call echo(251, echoCont)
    
    # Let me build it differently - use the full syscall CPS chain
    print(f"  (Skipping malformed test)")


def test_proper_chain():
    """
    Build: ((backdoor nil) (λpair. ((echo 251) (λechoRes. ...))))
    """
    print("\n=== Proper CPS chain: backdoor then echo ===")
    
    # Inner: after getting echo result (Left with key)
    inner_echo_handler = Lam(  # echoResult at Var(0)
        App(
            App(Var(0),  # Either
                Lam(  # Left - key at Var(0)
                    # Now syscall8(nil)
                    # syscall8 = 0x08, we're under 3 Lams (backdoor Left, echo Left, this Lam)
                    # So Var(8+3) = Var(11)? Let's check de Bruijn...
                    # Actually in CPS, syscall is called directly, not via Var
                    # We need: ((0x08 nil) cont)
                    # But we're inside a Lam body, so this is tricky
                    # Let's just try to extract and print the key behavior
                    App(
                        App(
                            App(Var(0), nil),  # (key nil)
                            Lam(  # Left
                                App(
                                    App(Var(0), identity),
                                    Lam(  # byte
                                        # write = 0x02, under 5 Lams = Var(7)
                                        App(
                                            App(Var(7), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                            nil
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(App(App(Var(6), encode_string("KR")), nil))
                    )
                )
            ),
            Lam(App(App(Var(5), encode_string("ER")), nil))
        )
    )
    
    # Outer: after getting backdoor result
    outer_backdoor_handler = Lam(  # backdoorResult at Var(0)
        App(
            App(Var(0),
                Lam(  # Left - pair at Var(0)
                    # Now call echo(251)
                    # But we need to actually call the echo syscall
                    # This requires building the CPS call
                    # For now, let's just output something to verify the chain works
                    App(App(Var(5), encode_string("BL")), nil)
                )
            ),
            Lam(App(App(Var(4), encode_string("BR")), nil))
        )
    )
    
    # Full payload: ((0xC9 nil) handler)
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(outer_backdoor_handler) + bytes([FD, FF])
    resp = query(payload)
    print(f"  backdoor then check: {resp}")


def test_simpler_combo():
    """
    Simpler: Just get echo key and backdoor in same program, combine them.
    """
    print("\n=== Simple combo: echo(251) first, verify byte 1 still works ===")
    
    # Verify the basic extraction still works
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # key
                    App(
                        App(
                            App(Var(0), nil),  # (key nil)
                            Lam(
                                App(
                                    App(Var(0), identity),
                                    Lam(
                                        App(App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                    )
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("R")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  echo(251) -> key(nil) -> byte: {resp}")
    
    # Now try with syscall8 result
    print("\n=== echo(251) -> syscall8(nil) -> key(result) ===")
    
    test_term2 = Lam(
        App(
            App(Var(0),
                Lam(  # key at Var(0)
                    # syscall8(nil) - syscall8 = 0x08, under 2 Lams = Var(10)
                    App(
                        App(Var(10), nil),
                        Lam(  # sc8Result at Var(0), key at Var(1)
                            App(
                                App(
                                    App(Var(1), Var(0)),  # (key sc8Result)
                                    Lam(
                                        App(
                                            App(Var(0), identity),
                                            Lam(
                                                App(App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("R")), nil))
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
    print(f"  Result: {resp}")


def main():
    print("=" * 70)
    print("KEY + BACKDOOR COMBINATIONS")
    print("=" * 70)
    
    test_simpler_combo()
    time.sleep(0.3)
    
    test_proper_chain()
    time.sleep(0.3)
    
    test_A_with_key()


if __name__ == "__main__":
    main()
