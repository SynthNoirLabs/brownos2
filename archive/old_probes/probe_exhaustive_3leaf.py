#!/usr/bin/env python3
"""
Exhaustive 3-leaf search with proper CPS handling.

The issue: we need a continuation that OUTPUTS the result.
QD = quote then write - but counts as many more leaves.

What if we can construct something simpler?

Key insight: The VM might have special handling for certain
combinations that we haven't tried.
"""

import socket
import time
from dataclasses import dataclass
from itertools import product

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


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError


def query(payload: bytes, timeout_s: float = 3.0) -> bytes:
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except:
                pass
            sock.settimeout(timeout_s)
            out = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out += chunk
                except socket.timeout:
                    break
            return out
    except:
        return b""


def main():
    print("=" * 70)
    print("EXHAUSTIVE 3-LEAF SEARCH")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    important_indices = [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201, 251, 252]
    
    print("\n=== Pattern: ((Var(a) nil) Var(c)) with QD ===\n")
    print("This is ((syscall nil) cont) where cont is a raw Var\n")
    
    found = []
    
    for a in important_indices:
        for c in [2, 4]:
            term = App(App(Var(a), nil), Var(c))
            payload = encode_term(term) + bytes([FF])
            resp = query(payload)
            if resp and not resp.startswith(b"Invalid"):
                desc = f"((Var({a}) nil) Var({c}))"
                if b"Encoding failed" in resp:
                    print(f"{desc}: Encoding failed")
                elif resp:
                    print(f"{desc}: {resp.hex()[:60]}")
                    found.append((desc, resp))
            time.sleep(0.05)
    
    print("\n=== Pattern: Var(a) nil FD Var(c) FD (raw bytes) ===\n")
    
    for a in [201, 14, 8, 7, 5, 4, 2, 1, 42]:
        for c in [2, 4, 8, 14, 201]:
            payload = bytes([a]) + encode_term(nil) + bytes([FD, c, FD, FF])
            resp = query(payload)
            if resp and len(resp) > 0 and not resp.startswith(b"Invalid"):
                desc = f"{a:02x} nil FD {c:02x} FD"
                if b"Encoding failed" in resp:
                    result = "Encoding failed"
                else:
                    result = resp.hex()[:60]
                print(f"{desc}: {result}")
                if len(resp) > 20:
                    found.append((desc, resp))
            time.sleep(0.05)
    
    print("\n=== Test: backdoor with various raw continuations ===\n")
    
    for c in [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
        payload = bytes([0xC9]) + encode_term(nil) + bytes([FD, c, FD, FF])
        resp = query(payload)
        if resp:
            desc = f"backdoor(nil) Var({c})"
            if len(resp) > 5:
                print(f"{desc}: {resp.hex()[:80]}")
        time.sleep(0.05)
    
    print("\n=== Test: echo with various continuations ===\n")
    
    for a in [0, 1, 8, 14, 201, 251, 252]:
        for c in [2, 4, 8, 14, 201]:
            payload = bytes([0x0E, a, FD, c, FD, FF])
            resp = query(payload)
            if resp and len(resp) > 5:
                desc = f"echo(Var({a})) Var({c})"
                print(f"{desc}: {resp.hex()[:60]}")
            time.sleep(0.05)
    
    print("\n=== Test: combining backdoor and echo ===\n")
    
    backdoor_then_echo = Lam(App(App(Var(14), Var(0)), nil))
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_then_echo) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    print(f"backdoor >> λpair. echo(pair) nil: {resp.hex()[:80] if resp else '(empty)'}")
    
    echo_then_backdoor = Lam(App(App(Var(201), Var(0)), nil))
    payload = bytes([0x0E, 0, FD]) + encode_term(echo_then_backdoor) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    print(f"echo(V0) >> λx. backdoor(x) nil: {resp.hex()[:80] if resp else '(empty)'}")
    
    print("\n=== Summary of interesting responses ===\n")
    
    for desc, resp in found:
        try:
            text = resp.decode('utf-8', 'replace')
            print(f"{desc}: TEXT={text[:50]!r}")
        except:
            print(f"{desc}: len={len(resp)}")


if __name__ == "__main__":
    main()
