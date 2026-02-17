#!/usr/bin/env python3
"""
Verify we can still extract byte 1 from (key nil).
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


def test_original_extraction():
    """
    The original method from probe_direct_extraction.py that gave byte 1.
    """
    print("=" * 70)
    print("ORIGINAL BYTE 1 EXTRACTION")
    print("=" * 70)
    
    # From probe_direct_extraction.py:
    # Apply key multiple times (stateful test)
    # This was: get key, apply to nil, extract byte, repeat 3 times
    # Result was: b'\x01'
    
    # The structure was:
    # echo(251) -> Left(key)
    # (key nil) -> Left handler -> extract -> write as cons byte
    
    # Simple version: just extract once
    test_term = Lam(
        App(
            App(Var(0),  # echoResult (Either)
                Lam(  # Left handler - key at Var(0)
                    App(
                        App(App(Var(0), nil),  # (key nil)
                            Lam(  # Left handler - inner at Var(0)
                                # According to original, this somehow gives byte 1
                                # The original used:
                                # App(App(Var(0), identity), Lam(
                                #     App(App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                # ))
                                
                                # Let's try that pattern:
                                # (inner identity) then extract byte
                                App(
                                    App(Var(0), identity),  # (inner identity)
                                    Lam(  # result handler
                                        # Write result as a single byte in cons format
                                        App(
                                            App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                            nil
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("KR")), nil))  # key Right
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))  # echo Right
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  Original pattern: {resp}")
    if resp and len(resp) > 0:
        print(f"  Bytes: {[b for b in resp]}")


def test_simpler_extraction():
    """
    Simpler: just write the Left payload directly as a cons byte.
    """
    print("\n" + "=" * 70)
    print("SIMPLER EXTRACTION")
    print("=" * 70)
    
    # From session summary: the payload when written as byte gives \x01
    
    # Pattern: (key nil) -> Left(payload)
    # Write payload using: Lam(Lam(App(App(Var(1), payload), nil)))
    # This creates a cons cell with payload as the "byte" and nil as tail
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # key at Var(0)
                    App(
                        App(App(Var(0), nil),  # (key nil)
                            Lam(  # Left: payload at Var(0)
                                # Write using cons pattern
                                # write = Var(5) (4+1 for lambda)
                                # cons(payload, nil) = Lam(Lam(App(App(Var(1), payload), nil)))
                                # But payload is at Var(0), which becomes Var(2) inside the two lambdas
                                App(
                                    App(Var(5), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                    nil
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
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  Direct cons write: {resp}")
    if resp and len(resp) > 0:
        print(f"  Bytes: {[b for b in resp]}")


def test_nested_either_extraction():
    """
    The payload might be Left(something) or Right(something).
    Let's handle both branches.
    """
    print("\n" + "=" * 70)
    print("NESTED EITHER EXTRACTION")
    print("=" * 70)
    
    # (key nil) -> Left(something)
    # If something is also an Either, we need to handle it
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # key at Var(0)
                    App(
                        App(App(Var(0), nil),  # (key nil)
                            Lam(  # Left: outer_payload at Var(0)
                                # Check if outer_payload is an Either by applying handlers
                                App(
                                    App(Var(0),  # outer_payload as Either
                                        Lam(  # Left handler
                                            App(
                                                App(Var(7), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                                nil
                                            )
                                        )
                                    ),
                                    Lam(  # Right handler
                                        App(
                                            App(Var(7), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
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
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  Nested Either extraction: {resp}")
    if resp and len(resp) > 0:
        print(f"  Bytes: {[b for b in resp]}")


def test_direct_byte1():
    """
    Just write Church numeral 1 directly to verify the cons pattern.
    """
    print("\n" + "=" * 70)
    print("REFERENCE: WRITE CHURCH 1 DIRECTLY")
    print("=" * 70)
    
    # Church 1 = λf.λx. f x
    church1 = Lam(Lam(App(Var(1), Var(0))))
    
    # Write it using cons pattern: Lam(Lam(App(App(Var(1), church1), nil)))
    # But church1 needs to be encoded properly for the byte encoding...
    
    # Actually, the byte encoding is different. Let me use the proper encoding.
    # A byte is encoded as: 9 lambdas, with applications of Var(1-8) to Var(0)
    # For byte 1: just apply Var(1) once to Var(0)
    
    byte1 = Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(App(Var(1), Var(0)))))))))))
    
    # cons(byte1, nil)
    cons_byte1_nil = Lam(Lam(App(App(Var(1), byte1), nil)))
    
    # write(cons_byte1_nil, nil)
    test_term = App(App(Var(2), cons_byte1_nil), nil)
    
    payload = encode_term(test_term) + bytes([FF])
    resp = query(payload, timeout_s=5)
    print(f"  Direct Church 1 write: {resp}")
    if resp:
        print(f"  Bytes: {[b for b in resp]}")


def main():
    test_original_extraction()
    time.sleep(0.3)
    
    test_simpler_extraction()
    time.sleep(0.3)
    
    test_nested_either_extraction()
    time.sleep(0.3)
    
    test_direct_byte1()


if __name__ == "__main__":
    main()
