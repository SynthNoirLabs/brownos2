#!/usr/bin/env python3
"""
What can we compute with the backdoor combinators?

A = λab.bb (self-application: applies second arg to itself)
B = λab.ab (normal application: applies first arg to second)

These are interesting combinators. What can we build from them?
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

# The backdoor combinators
A = Lam(Lam(App(Var(0), Var(0))))  # λab.bb
B = Lam(Lam(App(Var(1), Var(0))))  # λab.ab


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


def test_combinator_applications():
    """
    Try applying the combinators to each other and other things.
    """
    print("=" * 70)
    print("COMBINATOR APPLICATIONS")
    print("=" * 70)
    
    print("\n  Direct combinator tests:")
    
    # (A A) = (λab.bb)(λab.bb) = λb.bb - omega!
    # Actually: (A A) x = (λab.bb)(λab.bb)(x) = (λb.bb)(x) = xx
    
    # (B B) = (λab.ab)(λab.ab) = λb.(λab.ab)b = λb.λb'.bb' -- identity-ish
    
    # Let's quote these to see their structure
    
    combos = [
        ("A", A),
        ("B", B),
        ("(A B)", App(A, B)),
        ("(B A)", App(B, A)),
        ("(A A)", App(A, A)),
        ("(B B)", App(B, B)),
        ("((A B) nil)", App(App(A, B), nil)),
        ("((B A) nil)", App(App(B, A), nil)),
        ("((A A) identity)", App(App(A, A), identity)),
        ("((B B) identity)", App(App(B, B), identity)),
    ]
    
    for name, term in combos:
        # quote(term)
        payload = bytes([0x04]) + encode_term(term) + bytes([FD]) + QD + bytes([FD, FF])
        resp = query(payload, timeout_s=3)
        print(f"    quote({name}): {resp.hex()[:40] if resp else 'empty'}")
        time.sleep(0.1)


def test_backdoor_extract():
    """
    Extract A and B from the backdoor and use them.
    """
    print("\n" + "=" * 70)
    print("EXTRACT AND USE BACKDOOR COMBINATORS")
    print("=" * 70)
    
    # backdoor(nil) -> Left(pair) where pair = λs. s A B
    # To get A: pair true where true = λxy.x
    # To get B: pair false where false = λxy.y
    
    true_ = Lam(Lam(Var(1)))
    false_ = Lam(Lam(Var(0)))
    
    # Get A: (pair true)
    print("\n  Extract A via (pair true):")
    test_term = Lam(
        App(
            App(Var(0),  # backdoor result
                Lam(  # Left: pair
                    # (pair true) to get A
                    App(
                        App(Var(6), App(Var(0), true_)),  # quote((pair true))
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(8), Var(0)), nil))),
                                Lam(App(App(Var(8), encode_string("QF")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BR")), nil))
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"    quote(A): {resp.hex()[:40] if resp and resp not in [b'QF', b'BR'] else resp}")
    
    # Get B: (pair false)
    print("\n  Extract B via (pair false):")
    test_term2 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(6), App(Var(0), false_)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(8), Var(0)), nil))),
                                Lam(App(App(Var(8), encode_string("QF")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BR")), nil))
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(test_term2) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"    quote(B): {resp.hex()[:40] if resp and resp not in [b'QF', b'BR'] else resp}")


def test_compute_with_combinators():
    """
    Try computing things with the extracted A and B.
    """
    print("\n" + "=" * 70)
    print("COMPUTE WITH EXTRACTED COMBINATORS")
    print("=" * 70)
    
    true_ = Lam(Lam(Var(1)))
    false_ = Lam(Lam(Var(0)))
    
    # Get pair, extract A and B, apply them to syscall8
    
    print("\n  (A syscall8):")
    test_term = Lam(
        App(
            App(Var(0),  # backdoor result
                Lam(  # pair
                    # Get A = (pair true), then (A syscall8)
                    App(
                        App(App(Var(0), true_), Var(10)),  # ((pair true) syscall8) = (A syscall8)
                        Lam(  # result handler
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(8), Var(0)), nil))),
                                Lam(App(App(Var(8), encode_string("R")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BR")), nil))
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"    Result: {resp}")
    
    # Try (B syscall8 nil)
    print("\n  ((B syscall8) nil):")
    test_term2 = Lam(
        App(
            App(Var(0),
                Lam(
                    # Get B = (pair false), then ((B syscall8) nil)
                    App(
                        App(App(App(Var(0), false_), Var(10)), nil),  # (((pair false) syscall8) nil)
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(8), Var(0)), nil))),
                                Lam(App(App(Var(8), encode_string("R")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BR")), nil))
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(test_term2) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"    Result: {resp}")


def test_combine_key_and_backdoor():
    """
    Get both the key and the backdoor combinators, combine them.
    """
    print("\n" + "=" * 70)
    print("COMBINE KEY AND BACKDOOR")
    print("=" * 70)
    
    true_ = Lam(Lam(Var(1)))
    
    # First get key from echo, then get backdoor pair
    # This requires chaining syscalls
    
    # Simpler: use the raw combinators with the key
    # A = λab.bb
    # key = Var(253) (from echo)
    # (A key nil) = (λab.bb)(key)(nil) = nil nil = nil
    
    # B = λab.ab
    # (B key nil) = (λab.ab)(key)(nil) = key nil
    
    # Hmm, we need to get the key into the context with backdoor combinators
    
    print("\n  This is complex - skipping for now")
    

def test_minimal_backdoor_pattern():
    """
    What's the minimal thing we can do with backdoor that might be 3 leaves?
    """
    print("\n" + "=" * 70)
    print("MINIMAL BACKDOOR PATTERNS")
    print("=" * 70)
    
    # ((backdoor nil) handler) 
    # backdoor = 0xC9, nil = 00 FE FE
    # Simplest: just backdoor(nil) with minimal handler
    
    # 3 leaves would be something like: ((backdoor nil) (Var X))
    # Or: ((backdoor nil) λ.Var0)
    
    patterns = [
        ("((backdoor nil) identity)", bytes([0xC9, 0x00, FE, FE, FD, 0x00, FE, FD, FF])),
        ("((backdoor nil) nil)", bytes([0xC9, 0x00, FE, FE, FD, 0x00, FE, FE, FD, FF])),
        ("((backdoor nil) Var0)", bytes([0xC9, 0x00, FE, FE, FD, 0x00, FD, FF])),
    ]
    
    for name, payload in patterns:
        resp = query(payload, timeout_s=3)
        print(f"  {name}: {resp.hex()[:40] if resp else 'empty'}")
        time.sleep(0.1)


def main():
    test_combinator_applications()
    time.sleep(0.3)
    
    test_backdoor_extract()
    time.sleep(0.3)
    
    test_compute_with_combinators()
    time.sleep(0.3)
    
    test_minimal_backdoor_pattern()


if __name__ == "__main__":
    main()
