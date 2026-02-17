#!/usr/bin/env python3
"""
Author hint: "My record is 3 leafs IIRC"

A "leaf" in lambda calculus is a Var node.
What's the minimal term with exactly 3 Var nodes that produces the answer?

Possibilities:
1. Three specific syscall references
2. Syscall + arg + something
3. A combinator application

We know:
- echo(251) manufactures Var(253) which is special
- syscall8 returns Right(6) but (key Right(6)) -> Left(Right(Church1))
- backdoor gives pair(A, B) where A=λab.bb, B=λab.ab

What 3-leaf term combines these?
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


def count_vars(term):
    """Count number of Var nodes (leafs) in a term."""
    if isinstance(term, Var):
        return 1
    if isinstance(term, Lam):
        return count_vars(term.body)
    if isinstance(term, App):
        return count_vars(term.f) + count_vars(term.x)
    return 0


def main():
    print("=" * 70)
    print("MINIMAL 3-LEAF TERM ANALYSIS")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print(f"\nnil = Lam(Lam(Var(0))) has {count_vars(nil)} leaf(s)")
    
    # What if "3 leafs" means the program sent to the server?
    # A program like: ((syscall arg) cont)
    # Has leafs: syscall, arg-leafs, cont-leafs
    
    print("\n=== Simple 3-leaf patterns ===")
    
    # Pattern 1: ((Var(a) Var(b)) Var(c))
    # 3 leafs total
    
    patterns_3leaf = [
        # ((echo 251) QD) - but QD has multiple leafs
        # What about ((syscall nil) continuation)?
        # nil = λλ.Var(0) = 1 leaf
        # continuation needs to be 2 more leafs
        
        # Simplest: ((Var(a) nil) identity)
        # nil = 1 leaf, identity = 1 leaf
        # So: Var(a), nil-leaf, identity-leaf = 3 leafs
    ]
    
    # Let's test: ((echo nil) identity)
    # echo = 0x0E = 14
    # nil = λλ.0
    # identity = λ.0
    
    term1 = App(App(Var(0x0E), nil), Lam(Var(0)))
    print(f"((echo nil) identity) has {count_vars(term1)} leafs")
    
    payload1 = encode_term(term1) + bytes([FF])
    resp1 = query(payload1)
    print(f"  Result: {resp1}")
    
    # What about ((syscall8 nil) identity)?
    term2 = App(App(Var(0x08), nil), Lam(Var(0)))
    print(f"((syscall8 nil) identity) has {count_vars(term2)} leafs")
    
    payload2 = encode_term(term2) + bytes([FF])
    resp2 = query(payload2)
    print(f"  Result: {resp2}")
    
    # What about using raw bytes to construct minimal terms?
    print("\n=== Raw byte patterns with ~3 variable bytes ===")
    
    # The wire format: variables are just bytes < 0xFD
    # A minimal program might be just 3 variable bytes + FD + FD + FF
    
    # Try: a b FD c FD FF = ((Var(a) Var(b)) Var(c))
    for a in [0x0E, 0x08, 0xC9]:  # echo, syscall8, backdoor
        for b in [0, 0xFB, 0xFC]:  # nil/0, near-special values
            for c in [0, 0xFB, 0xFC]:
                payload = bytes([a, b, FD, c, FD, FF])
                resp = query(payload, timeout_s=1)
                if resp and resp != b'Invalid term!' and len(resp) > 0:
                    print(f"  ({a:02X} {b:02X} FD {c:02X} FD FF): {resp[:30]}")
                time.sleep(0.1)
    
    print("\n=== Special focus: echo with values near FD ===")
    
    # echo(251) gives Left(Var(253))
    # What about echo(252) or echo(253)?
    
    for echo_arg in range(250, 253):
        # ((echo n) identity)
        term = App(App(Var(0x0E), Var(echo_arg)), Lam(Var(0)))
        payload = encode_term(term) + bytes([FF])
        resp = query(payload, timeout_s=2)
        print(f"  ((echo {echo_arg}) identity): {resp}")
        time.sleep(0.2)
    
    print("\n=== What if 3 leafs means in the ANSWER, not the query? ===")
    
    # The answer we get is byte 1 = Church 1
    # Church 1 in our encoding is λ^9.(Var1 Var0)
    # That has 2 leafs (Var1, Var0)
    
    # Maybe we need to extract more bytes?
    # Or the "3 leafs" term produces output with 3 leafs?


if __name__ == "__main__":
    main()
