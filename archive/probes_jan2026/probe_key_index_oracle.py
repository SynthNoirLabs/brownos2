#!/usr/bin/env python3
"""
Oracle hypothesis: The key (Var(253)) might be an indexable oracle.
Test (key (church n)) for various n to see if we get different bytes.

Also test:
1. Var(251) with different argument counts
2. Key applied to backdoor combinators A and B
3. Backdoor combinators applied to key
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

# Backdoor combinators
A = Lam(Lam(App(Var(0), Var(0))))  # λab.bb
B = Lam(Lam(App(Var(1), Var(0))))  # λab.ab


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


def extract_byte_from_key(key_arg):
    """
    Apply key to key_arg, then extract byte from Left(Right(ChurchByte)) structure.
    Returns the byte value or None if extraction failed.
    """
    # Structure: echo(251) -> Left(key)
    # (key arg) -> ??? -> extract byte
    
    test_term = Lam(  # echo cont
        App(
            App(Var(0),  # echo result
                Lam(  # key at Var(0)
                    # (key arg) then apply Either handlers
                    App(
                        App(
                            App(Var(0), key_arg),  # (key arg)
                            Lam(  # Left handler - inner at Var(0)
                                # inner should be Right(ChurchByte) or just ChurchByte
                                # Try to extract it
                                App(
                                    App(Var(0), identity),  # try unwrapping as Either
                                    Lam(  # Right handler for inner - byte at Var(0)
                                        App(
                                            App(Var(6),  # write
                                                Lam(Lam(App(App(Var(1), Var(2)), nil)))  # [Var(2)]
                                            ),
                                            nil
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(  # Right handler for outer
                            App(App(Var(5), encode_string("R")), nil)
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=2)
    
    if resp == b'R' or resp == b'E':
        return None
    if len(resp) == 1:
        return resp[0]
    return None


def test_key_with_church_index():
    """Test (key (church n)) for various n."""
    print("\n" + "=" * 70)
    print("TEST 1: (key (church n)) for n = 0..20")
    print("=" * 70)
    
    results = []
    for n in range(21):
        byte_val = extract_byte_from_key(make_church(n))
        results.append(byte_val)
        char = chr(byte_val) if byte_val and 32 <= byte_val < 127 else '?'
        print(f"  key(church({n:2d})): {byte_val} = '{char}'")
        time.sleep(0.15)
    
    if all(r == results[0] for r in results if r is not None):
        print(f"\n  All results identical: {results[0]}")
    else:
        print(f"\n  VARYING RESULTS! Bytes: {results}")
        # If varying, this might be the flag!
        flag_bytes = bytes(r for r in results if r is not None)
        print(f"  As string: {flag_bytes}")
    
    return results


def test_key_with_backdoor_combinators():
    """Test key with A and B from backdoor."""
    print("\n" + "=" * 70)
    print("TEST 2: Key with backdoor combinators A and B")
    print("=" * 70)
    
    tests = [
        ("key(A)", A),
        ("key(B)", B),
        ("key(pair(A,B))", Lam(App(App(Var(0), A), B))),
    ]
    
    for desc, arg in tests:
        byte_val = extract_byte_from_key(arg)
        char = chr(byte_val) if byte_val and 32 <= byte_val < 127 else '?'
        print(f"  {desc:20s}: {byte_val} = '{char}'")
        time.sleep(0.2)


def test_var251_arity():
    """Test Var(251) with different argument counts."""
    print("\n" + "=" * 70)
    print("TEST 3: Var(251) with varying argument counts (arity)")
    print("=" * 70)
    
    # Test: (Var(251) x)
    # Then: (Var(251) x y)
    # Then: (Var(251) x y z)
    # Using Either handlers to see what comes out
    
    # 1 arg: ((Var(251) nil) L R)
    term1 = App(
        App(
            App(Var(0xFB), nil),
            Lam(  # L
                App(App(Var(4), encode_string("L1:")), nil)
            )
        ),
        Lam(  # R
            App(App(Var(4), encode_string("R1:")), nil)
        )
    )
    payload1 = encode_term(term1) + bytes([FF])
    resp1 = query(payload1)
    print(f"  (Var(251) nil) with handlers: {resp1}")
    
    # 2 args: (((Var(251) nil) nil) L R)
    term2 = App(
        App(
            App(
                App(Var(0xFB), nil),
                nil
            ),
            Lam(App(App(Var(4), encode_string("L2:")), nil))
        ),
        Lam(App(App(Var(4), encode_string("R2:")), nil))
    )
    payload2 = encode_term(term2) + bytes([FF])
    resp2 = query(payload2)
    print(f"  ((Var(251) nil) nil) with handlers: {resp2}")
    
    # Try with church numerals as args
    term3 = App(
        App(
            App(Var(0xFB), make_church(0)),
            Lam(App(App(Var(4), encode_string("L3:")), nil))
        ),
        Lam(App(App(Var(4), encode_string("R3:")), nil))
    )
    payload3 = encode_term(term3) + bytes([FF])
    resp3 = query(payload3)
    print(f"  (Var(251) church0) with handlers: {resp3}")


def test_combinators_applied_to_key():
    """Test A and B applied to key."""
    print("\n" + "=" * 70)
    print("TEST 4: Backdoor combinators applied to key")
    print("=" * 70)
    
    # Get key and backdoor, then try (A key B), (B key A), etc.
    
    # First: (A key key) = key key (since A = λab.bb)
    # This might trigger self-application on the key
    
    test_term = Lam(  # echo cont
        App(
            App(Var(0),  # echo Left
                Lam(  # key at Var(0)
                    # Get backdoor
                    App(
                        App(Var(0xC9 + 2), nil),  # backdoor
                        Lam(  # backdoor cont
                            App(
                                App(Var(0),  # backdoor Left
                                    Lam(  # pair at Var(0)
                                        # Extract A = fst
                                        App(
                                            App(Var(0), Lam(Lam(Var(1)))),  # fst
                                            Lam(  # A at Var(0), pair at Var(1), key at Var(2)
                                                # Try (A key key) = key key
                                                App(
                                                    App(
                                                        App(App(Var(0), Var(2)), Var(2)),  # (A key key) = key key
                                                        Lam(  # Left handler
                                                            App(
                                                                App(Var(0), identity),
                                                                Lam(
                                                                    App(App(Var(10), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                                                )
                                                            )
                                                        )
                                                    ),
                                                    Lam(App(App(Var(9), encode_string("R")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(8), encode_string("BR")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  (A key key) extracted byte: {resp}")


def test_key_ab():
    """Test (key A B) - key with two backdoor combinators as args."""
    print("\n" + "=" * 70)
    print("TEST 5: (key A B) - key with both combinators")
    print("=" * 70)
    
    # Get key and backdoor pair, then call (key A B)
    test_term = Lam(  # echo cont
        App(
            App(Var(0),
                Lam(  # key at Var(0)
                    App(
                        App(Var(0xC9 + 2), nil),  # backdoor
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(  # pair at Var(0), key at Var(2)
                                        # Extract A and B
                                        App(
                                            App(Var(0), Lam(Lam(Var(1)))),  # fst -> A
                                            Lam(  # A at Var(0)
                                                App(
                                                    App(Var(1), Lam(Lam(Var(0)))),  # snd -> B
                                                    Lam(  # B at Var(0), A at Var(1), key at Var(4)
                                                        # (key A B)
                                                        App(
                                                            App(
                                                                App(App(Var(4), Var(1)), Var(0)),  # ((key A) B)
                                                                Lam(  # Left
                                                                    App(
                                                                        App(Var(0), identity),
                                                                        Lam(
                                                                            App(App(Var(12), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                                                        )
                                                                    )
                                                                )
                                                            ),
                                                            Lam(App(App(Var(11), encode_string("R")), nil))
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(8), encode_string("BR")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  (key A B) result: {resp}")


def main():
    print("=" * 70)
    print("KEY AS INDEXABLE ORACLE TESTS")
    print("=" * 70)
    print("Based on Oracle's hypothesis: key might return different bytes")
    print("depending on the index (Church numeral) passed to it.")
    
    results = test_key_with_church_index()
    time.sleep(0.3)
    
    test_key_with_backdoor_combinators()
    time.sleep(0.3)
    
    test_var251_arity()
    time.sleep(0.3)
    
    test_combinators_applied_to_key()
    time.sleep(0.3)
    
    test_key_ab()
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    unique = set(r for r in results if r is not None)
    if len(unique) == 1:
        print(f"Key appears to be CONSTANT (always returns {unique.pop()})")
        print("Try alternative approaches: wire format exploits, different elimination")
    else:
        print(f"Key is INDEXABLE! Unique bytes: {unique}")
        print("Continue extracting bytes to find the flag!")


if __name__ == "__main__":
    main()
