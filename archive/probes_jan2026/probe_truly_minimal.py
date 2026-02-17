#!/usr/bin/env python3
"""
Author hint: "My record is 3 leafs IIRC"

Let's try TRULY minimal programs - programs with exactly 3 Var nodes total.
These might trigger special behaviors.

The wire format allows very compact programs.
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
PORT = 61221

FD, FE, FF = 0xFD, 0xFE, 0xFF
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


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


def test_raw_3leaf_patterns():
    """
    Try various 3-leaf patterns as raw bytes.
    
    Patterns:
    - a b FD c FD FF = ((a b) c)
    - a b FD c FE FD FF = ((a b) λ.c)
    - a b c FD FD FF = ((a b) c) - no this is wrong
    """
    print("=" * 70)
    print("TRULY MINIMAL 3-LEAF PROGRAMS")
    print("=" * 70)
    
    print("\n=== Pattern: ((Var(a) Var(b)) Var(c)) ===")
    
    # Key syscall numbers
    syscalls = {
        0x02: "write",
        0x04: "quote",
        0x05: "readdir",
        0x06: "name",
        0x07: "readfile",
        0x08: "syscall8",
        0x0E: "echo",
        0x2A: "towel",
        0xC9: "backdoor",
        0xFB: "Var251",
        0xFC: "Var252",
    }
    
    interesting = []
    
    # ((a b) c) patterns where total is exactly 3 vars
    print("\n  Testing ((syscall arg) cont) patterns...")
    
    for a in [0x0E, 0x08, 0xC9, 0xFB, 0xFC]:
        for b in range(0, 0xFD, 50):  # sample arg values
            for c in range(0, 0xFD, 50):  # sample cont values
                # ((a b) c) = a b FD c FD FF
                payload = bytes([a, b, FD, c, FD, FF])
                resp = query(payload, timeout_s=0.5)
                
                if resp and resp != b'Invalid term!' and len(resp) > 0:
                    # Check if it's a standard error response
                    is_standard = False
                    if len(resp) > 10:
                        # Might be a Right(n) encoded response
                        is_standard = True
                    
                    if not is_standard:
                        desc = f"(({syscalls.get(a, hex(a))} {b}) {c})"
                        interesting.append((payload.hex(), resp[:30], desc))
                
                # Don't flood the server
                time.sleep(0.05)
    
    if interesting:
        print("\n  Interesting responses:")
        for phex, resp, desc in interesting:
            print(f"    {phex}: {resp} ({desc})")
    else:
        print("  No interesting non-standard responses found")
    
    print("\n=== Pattern: ((Var(a) Var(b)) λ.Var(c)) ===")
    
    # ((a b) λ.c) = a b FD c FE FD FF
    for a in [0x0E, 0x08, 0xC9]:
        for b in [0, 0xFB, 0xFC]:
            for c in [0, 1, 2]:
                payload = bytes([a, b, FD, c, FE, FD, FF])
                resp = query(payload, timeout_s=0.5)
                
                if resp and resp != b'Invalid term!':
                    desc = f"(({syscalls.get(a, hex(a))} {b}) λ.{c})"
                    print(f"    {payload.hex()}: {resp[:30]} ({desc})")
                
                time.sleep(0.05)
    
    print("\n=== Pattern: (Var(a) (Var(b) Var(c))) ===")
    
    # (a (b c)) = a b c FD FD FF
    for a in [0x0E, 0x08, 0xC9, 0xFB]:
        for b in [0x0E, 0x08, 0xFB]:
            for c in [0, 0xFB, 0xFC]:
                if a == b == c:
                    continue  # Skip trivial
                payload = bytes([a, b, c, FD, FD, FF])
                resp = query(payload, timeout_s=0.5)
                
                if resp and resp != b'Invalid term!':
                    print(f"    {payload.hex()}: {resp[:30]} (({hex(a)} ({hex(b)} {hex(c)})))")
                
                time.sleep(0.05)


def test_specific_3leaf():
    """
    Test specific 3-leaf patterns that might be meaningful.
    """
    print("\n=== Specific meaningful 3-leaf patterns ===")
    
    patterns = [
        # echo variants
        (bytes([0x0E, 0xFB, FD, 0, FE, FD, FF]), "((echo Var251) λ.0)"),
        (bytes([0x0E, 0xFC, FD, 0, FE, FD, FF]), "((echo Var252) λ.0)"),
        
        # backdoor variants  
        (bytes([0xC9, 0, FE, FE, FD, 0, FE, FD, FF]), "((backdoor nil) λ.0)"),
        
        # syscall8 variants
        (bytes([0x08, 0xFB, FD, 0, FE, FD, FF]), "((syscall8 Var251) λ.0)"),
        
        # Var251 direct
        (bytes([0xFB, 0, FE, FE, FD, 0, FE, FD, FF]), "((Var251 nil) λ.0)"),
        (bytes([0xFB, 0xFB, FD, 0, FE, FD, FF]), "((Var251 Var251) λ.0)"),
        
        # Mix of echo and syscall8
        (bytes([0x0E, 0x08, FD, 0, FE, FD, FF]), "((echo syscall8) λ.0)"),
        (bytes([0x08, 0x0E, FD, 0, FE, FD, FF]), "((syscall8 echo) λ.0)"),
    ]
    
    for payload, desc in patterns:
        resp = query(payload, timeout_s=1)
        status = resp[:40] if resp else "empty"
        print(f"  {payload.hex():30s} {desc:30s} -> {status}")
        time.sleep(0.1)


def test_echo_with_high_bytes():
    """
    echo(251) -> Var(253), echo(252) -> Var(254), echo(253) -> Var(255)
    What about echo(254), echo(255)? They map to FE, FF which are wire markers!
    """
    print("\n=== Echo with very high bytes (if encodable) ===")
    
    # echo(254) can't be directly encoded as 254 is FE (Lam marker)
    # But we could try encoding it indirectly
    
    # Actually, Var(254) = FE = Lam marker, so we can't put it in the wire format
    # The only way to create it is via echo(252) -> Left(Var(254))
    
    # Let's see what echo does with 250, 251, 252 again
    for n in [250, 251, 252]:
        # ((echo n) QD)
        payload = bytes([0x0E, n, FD]) + QD + bytes([FD, FF])
        resp = query(payload)
        if resp.startswith(b'\x01'):  # Left
            print(f"  echo({n}): Left (response starts with 01)")
        elif resp.startswith(b'\x00'):  # Right
            print(f"  echo({n}): Right (response starts with 00)")
        elif resp == b'Encoding failed!':
            print(f"  echo({n}): Encoding failed")
        else:
            print(f"  echo({n}): {resp.hex()[:30] if resp else 'empty'}")
        time.sleep(0.1)


def test_combined_echo_backdoor_minimal():
    """
    Minimal combination: get backdoor result, apply echo to it.
    """
    print("\n=== Minimal echo+backdoor combo ===")
    
    # What if: ((echo (backdoor nil)) QD)?
    # This would echo the backdoor result
    
    # backdoor nil = 0xC9 0x00 0xFE 0xFE 0xFD
    # (echo (backdoor nil)) = 0x0E [backdoor nil] 0xFD
    # Then apply QD
    
    backdoor_nil = bytes([0xC9, 0x00, FE, FE, FD])
    payload = bytes([0x0E]) + backdoor_nil + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    print(f"  ((echo (backdoor nil)) QD): {resp.hex()[:50] if resp else 'empty'}")
    
    # What about: ((backdoor (echo nil)) QD)?
    # echo nil = 0x0E 0x00 0xFE 0xFE 0xFD
    echo_nil = bytes([0x0E, 0x00, FE, FE, FD])
    payload2 = bytes([0xC9]) + echo_nil + bytes([FD]) + QD + bytes([FD, FF])
    resp2 = query(payload2)
    print(f"  ((backdoor (echo nil)) QD): {resp2.hex()[:50] if resp2 else 'empty'}")


def main():
    test_raw_3leaf_patterns()
    time.sleep(0.3)
    
    test_specific_3leaf()
    time.sleep(0.3)
    
    test_echo_with_high_bytes()
    time.sleep(0.3)
    
    test_combined_echo_backdoor_minimal()


if __name__ == "__main__":
    main()
