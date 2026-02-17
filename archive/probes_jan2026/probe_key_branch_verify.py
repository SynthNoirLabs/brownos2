#!/usr/bin/env python3
"""
Verify which branch (key nil) fires.

Earlier we found: (key nil) fires Left
Now we found: (Var253 nil) fires Right

These should be the same thing! Let me verify.

The key is obtained from echo(251), which gives Left(Var(253)).
When we extract the Left payload, we get Var(253).
Then (Var(253) nil) should be the same as (key nil).
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


def test_key_nil_branch():
    """
    Original test: (key nil) where key is from echo(251).
    """
    print("=" * 70)
    print("ORIGINAL: (key nil) BRANCH TEST")
    print("=" * 70)
    
    # echo(251) -> Left(key)
    # In Left handler: (key nil) as Either
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # Left: key at Var(0)
                    App(
                        App(App(Var(0), nil),  # (key nil)
                            Lam(App(App(Var(5), encode_string("LEFT")), nil))),  # Left handler
                        Lam(App(App(Var(5), encode_string("RIGHT")), nil))  # Right handler
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHOERR")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  (key nil): {resp}")


def test_var253_nil_branch():
    """
    Different approach: Get Var(253), then test ((Var253 nil) L R).
    """
    print("\n" + "=" * 70)
    print("NEW: ((Var253 nil) L R) BRANCH TEST")
    print("=" * 70)
    
    # Same as above but let me check if the handler structure is correct
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # Left: Var(253) at Var(0)
                    # Now: ((Var(0) nil) L) R
                    # This is: ((Var253 nil) LeftHandler) RightHandler
                    App(
                        App(App(Var(0), nil),  # (Var253 nil) 
                            Lam(App(App(Var(5), encode_string("LEFT")), nil))),
                        Lam(App(App(Var(5), encode_string("RIGHT")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHOERR")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  ((Var253 nil) L R): {resp}")


def test_raw_either_pattern():
    """
    Test the raw Either pattern more carefully.
    
    Either = λlr. l payload  (for Left)
    Either = λlr. r payload  (for Right)
    
    So (Either LeftHandler RightHandler) should:
    - For Left: apply LeftHandler to payload
    - For Right: apply RightHandler to payload
    """
    print("\n" + "=" * 70)
    print("RAW EITHER PATTERN TEST")
    print("=" * 70)
    
    # Let's make a true Left(nil)
    # Left = λx.λl.λr. l x = λλλ.(1 2) = 02 01 FD FE FE FE
    # Actually: Left(x) = λl.λr. l x
    # So Left(nil) = (λx.λl.λr. l x) nil = λl.λr. l nil
    
    # Test with known Left
    left_nil = Lam(Lam(App(Var(1), nil)))  # λlr. l nil
    
    test_term = App(
        App(left_nil,
            Lam(App(App(Var(3), encode_string("LEFT")), nil))),  # Left handler
        Lam(App(App(Var(3), encode_string("RIGHT")), nil))  # Right handler
    )
    
    payload = encode_term(test_term) + bytes([FF])
    resp = query(payload, timeout_s=3)
    print(f"  True Left(nil) with handlers: {resp}")
    
    # Test with known Right
    right_nil = Lam(Lam(App(Var(0), nil)))  # λlr. r nil
    
    test_term2 = App(
        App(right_nil,
            Lam(App(App(Var(3), encode_string("LEFT")), nil))),
        Lam(App(App(Var(3), encode_string("RIGHT")), nil))
    )
    
    payload2 = encode_term(test_term2) + bytes([FF])
    resp2 = query(payload2, timeout_s=3)
    print(f"  True Right(nil) with handlers: {resp2}")


def test_key_structure():
    """
    What exactly IS the key?
    
    echo(251) returns Left(something).
    What is that something?
    
    quote(key) = FB FF = Var(251)
    
    But Var(251) should reduce to... nothing, it's a free variable!
    Unless Var(251) is bound in the evaluator's context.
    
    Let's see: the global context has syscalls bound.
    Var(0) = ???
    ...
    Var(8) = syscall8
    Var(14) = echo
    ...
    Var(251) = ???
    
    If Var(251) is a special global, applying it might do something special.
    """
    print("\n" + "=" * 70)
    print("KEY STRUCTURE INVESTIGATION")
    print("=" * 70)
    
    # Let's try calling Var(251) directly (not via echo)
    # ((Var(251) nil) handler)
    
    test_term = App(
        App(Var(251), nil),
        Lam(
            App(
                App(Var(0),
                    Lam(App(App(Var(5), encode_string("L")), nil))),
                Lam(App(App(Var(5), encode_string("R")), nil))
            )
        )
    )
    
    payload = encode_term(test_term) + bytes([FF])
    resp = query(payload, timeout_s=3)
    print(f"  Direct ((Var251 nil) handler): {resp}")
    
    # Now echo(251) -> Var(253). What if Var(253) is just Var(251) + 2?
    # And that's still in the global context?
    
    # Try Var(253) directly - but we can't encode it!
    # 253 = 0xFD = App marker
    
    # What about Var(252)?
    test_term2 = App(
        App(Var(252), nil),
        Lam(
            App(
                App(Var(0),
                    Lam(App(App(Var(5), encode_string("L")), nil))),
                Lam(App(App(Var(5), encode_string("R")), nil))
            )
        )
    )
    
    payload2 = encode_term(test_term2) + bytes([FF])
    resp2 = query(payload2, timeout_s=3)
    print(f"  Direct ((Var252 nil) handler): {resp2}")


def test_three_levels_deep():
    """
    What if we need to go 3 levels deep?
    
    (((something) x) y) z
    """
    print("\n" + "=" * 70)
    print("THREE LEVELS DEEP")
    print("=" * 70)
    
    # Get key, apply to nil, then apply result to something, then to something else
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # Left: key at Var(0)
                    # (((key nil) nil) nil)
                    App(
                        App(App(App(Var(0), nil), nil), nil),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), encode_string("L")), nil))),
                                Lam(App(App(Var(6), encode_string("R")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  (((key nil) nil) nil) as Either: {resp}")


def main():
    test_key_nil_branch()
    time.sleep(0.3)
    
    test_var253_nil_branch()
    time.sleep(0.3)
    
    test_raw_either_pattern()
    time.sleep(0.3)
    
    test_key_structure()
    time.sleep(0.3)
    
    test_three_levels_deep()


if __name__ == "__main__":
    main()
