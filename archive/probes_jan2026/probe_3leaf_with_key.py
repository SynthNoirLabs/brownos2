#!/usr/bin/env python3
"""
Try truly minimal 3-leaf patterns involving the key.

"3 leafs" = exactly 3 Var nodes in the term.

Key insight: We get the key from echo(251).
What if the minimal solution involves:
1. Getting the key
2. Applying it minimally (maybe to syscall8?)
3. The result IS the answer
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


nil = Lam(Lam(Var(0)))  # 1 leaf


def count_leaves(term):
    """Count Var nodes in a term."""
    if isinstance(term, Var):
        return 1
    if isinstance(term, Lam):
        return count_leaves(term.body)
    if isinstance(term, App):
        return count_leaves(term.f) + count_leaves(term.x)
    return 0


def test_minimal_patterns():
    """
    Try minimal patterns with exactly 3 leaves total.
    """
    print("=" * 70)
    print("MINIMAL 3-LEAF PATTERNS")
    print("=" * 70)
    
    # The continuation (QD) has more than 3 leaves, so we need to count
    # just the "interesting" part of the program.
    
    # Simplest 3-leaf patterns:
    # 1. (Var Var) Var - two applications
    # 2. λ.(Var Var) Var - one lambda + two apps
    # 3. Var (Var Var) - one app of Var to (Var Var)
    
    # Let's try with special vars:
    # Var(251) = key ref
    # Var(8) = syscall8
    # Var(14) = echo
    
    patterns = [
        # ((key arg) QD) - 2 leaves + QD leaves
        ("((Var251 Var0) QD)", bytes([251, 0, FD]) + QD + bytes([FD, FF])),
        ("((Var251 Var8) QD)", bytes([251, 8, FD]) + QD + bytes([FD, FF])),
        
        # ((syscall8 key) QD) - 2 leaves + QD
        ("((syscall8 Var251) QD)", bytes([8, 251, FD]) + QD + bytes([FD, FF])),
        
        # (key (syscall8 X)) QD
        ("((Var251 (syscall8 nil)) QD)", 
         bytes([251]) + bytes([8]) + encode_term(nil) + bytes([FD, FD]) + QD + bytes([FD, FF])),
        
        # λ.((Var0 Var8) write) - handler that applies result to syscall8
        # Skipping complex patterns for now
        
        # What about just Var251 with minimal handler?
        ("Var251 alone with QD", bytes([251]) + QD + bytes([FD, FF])),
    ]
    
    for name, payload in patterns:
        resp = query(payload, timeout_s=3)
        print(f"  {name}: {resp[:50] if resp else 'empty'}")
        time.sleep(0.2)


def test_key_to_syscall8_direct():
    """
    What if we apply the key DIRECTLY to syscall8 (not extract first)?
    
    Pattern: ((Var251 Var8) continuation)
    """
    print("\n" + "=" * 70)
    print("KEY APPLIED TO SYSCALL8 DIRECTLY")
    print("=" * 70)
    
    # ((Var251 Var8) QD)
    # This has 2 leaves (251, 8) + QD leaves
    
    payload = bytes([251, 8, FD]) + QD + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  ((Var251 Var8) QD): {resp}")
    
    # What if we need a simpler continuation?
    # Just identity: λx.x
    simple_cont = Lam(Var(0))
    payload2 = bytes([251, 8, FD]) + encode_term(simple_cont) + bytes([FD, FF])
    resp2 = query(payload2, timeout_s=5)
    print(f"  ((Var251 Var8) identity): {resp2}")
    
    # What about nil as continuation?
    payload3 = bytes([251, 8, FD]) + encode_term(nil) + bytes([FD, FF])
    resp3 = query(payload3, timeout_s=5)
    print(f"  ((Var251 Var8) nil): {resp3}")


def test_syscall8_to_key_direct():
    """
    ((syscall8 Var251) continuation)
    """
    print("\n" + "=" * 70)
    print("SYSCALL8 APPLIED TO VAR251")
    print("=" * 70)
    
    payload = bytes([8, 251, FD]) + QD + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  ((syscall8 Var251) QD): {resp}")


def test_echo_key_to_syscall8():
    """
    Pattern: echo(251) -> key
    Then: (key syscall8) with continuation
    
    In the continuation, key is Var(0), syscall8 is Var(9)
    """
    print("\n" + "=" * 70)
    print("ECHO -> KEY -> SYSCALL8")
    print("=" * 70)
    
    # Simple: echo(251) then apply result to syscall8 ref
    # λ.(Var0 Var9) where 0 is the echo result, 9 is syscall8
    
    cont = Lam(App(Var(0), Var(9)))  # λ.(key syscall8)
    
    payload = bytes([0x0E, 251, FD]) + encode_term(cont) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  echo(251) -> (key Var9): {resp}")
    
    # Try with proper Either handling
    cont2 = Lam(
        App(
            App(Var(0),  # echo result (Either)
                Lam(App(Var(0), Var(10)))),  # Left: (key syscall8)
            Lam(Var(0))  # Right: identity
        )
    )
    
    payload2 = bytes([0x0E, 251, FD]) + encode_term(cont2) + bytes([FD, FF])
    resp2 = query(payload2, timeout_s=5)
    print(f"  echo(251) -> Left handler -> (key syscall8): {resp2}")


def test_raw_wire_3leaf():
    """
    Raw wire patterns with exactly 3 bytes before FD/FE/FF markers.
    """
    print("\n" + "=" * 70)
    print("RAW 3-BYTE PATTERNS")
    print("=" * 70)
    
    # Pattern: A B FD C FD FF = ((A B) C) - exactly 3 leaves
    # 
    # With: A=251 (key), B=8 (syscall8), C varies
    
    for c in [0, 8, 14, 42, 201, 251, 252]:
        pattern = bytes([251, 8, FD, c, FD, FF])
        resp = query(pattern, timeout_s=2)
        status = resp[:30].hex() if resp else "empty"
        print(f"  ((251 8) {c}): {status}")
        time.sleep(0.1)
    
    print()
    
    # Pattern: A B C FD FD FF = (A (B C)) - exactly 3 leaves
    for a in [251, 8]:
        for b in [251, 8]:
            for c in [0, 251]:
                if a == b == c:
                    continue
                pattern = bytes([a, b, c, FD, FD, FF])
                resp = query(pattern, timeout_s=2)
                status = resp[:30].hex() if resp else "empty"
                print(f"  ({a} ({b} {c})): {status}")
                time.sleep(0.1)


def main():
    test_minimal_patterns()
    time.sleep(0.3)
    
    test_key_to_syscall8_direct()
    time.sleep(0.3)
    
    test_syscall8_to_key_direct()
    time.sleep(0.3)
    
    test_echo_key_to_syscall8()
    time.sleep(0.3)
    
    test_raw_wire_3leaf()


if __name__ == "__main__":
    main()
