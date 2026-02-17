#!/usr/bin/env python3
"""
WIRE FORMAT INJECTION

The wire format uses:
- 0xFD = App marker
- 0xFE = Lambda marker  
- 0xFF = End marker

Normally you can't have Var(253), Var(254), Var(255) because those bytes
are reserved. But what if we try to inject them anyway?

"combining special bytes froze my system" - maybe this reveals something!
"""

import socket
import time

HOST = "82.165.133.222"
PORT = 61221

FD, FE, FF = 0xFD, 0xFE, 0xFF


def query_raw(payload: bytes, timeout_s: float = 5.0) -> bytes:
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


def test_raw_byte_sequences():
    print("=" * 70)
    print("RAW WIRE FORMAT INJECTION")
    print("=" * 70)
    
    sequences = [
        ("Single FD (App with no args)", bytes([FD, FF])),
        ("Single FE (Lam with no body)", bytes([FE, FF])),
        ("FD FE FF", bytes([FD, FE, FF])),
        ("FE FD FF", bytes([FE, FD, FF])),
        ("FD FD FF", bytes([FD, FD, FF])),
        ("FE FE FF", bytes([FE, FE, FF])),
        ("00 FD FF (App 0 missing)", bytes([0x00, FD, FF])),
        ("00 FE FD FF", bytes([0x00, FE, FD, FF])),
        ("FE 00 FF (Lam with var 0)", bytes([FE, 0x00, FF])),
        ("00 00 FE FD FF", bytes([0x00, 0x00, FE, FD, FF])),
        ("FD FE FE FF", bytes([FD, FE, FE, FF])),
        ("FE FD FE FF", bytes([FE, FD, FE, FF])),
        ("Just FF", bytes([FF])),
        ("Empty", bytes([])),
        ("00 FF", bytes([0x00, FF])),
        ("FB FF (Var 251)", bytes([0xFB, FF])),
        ("FC FF (Var 252)", bytes([0xFC, FF])),
    ]
    
    for name, payload in sequences:
        resp = query_raw(payload, timeout_s=3)
        print(f"  {name}: {resp!r}")
        time.sleep(0.2)


def test_syscall_with_malformed():
    print("\n" + "=" * 70)
    print("SYSCALLS WITH MALFORMED ARGUMENTS")
    print("=" * 70)
    
    QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
    
    tests = [
        ("syscall 0 with QD", bytes([0x00]) + QD + bytes([FD, FF])),
        ("syscall FD (253) with 00 FE FE", bytes([FD]) + bytes([0x00, FE, FE, FD]) + QD + bytes([FD, FF])),
        ("syscall 8 with raw FD arg", bytes([0x08, FD, FD]) + QD + bytes([FD, FF])),
        ("backdoor with FD FE FE", bytes([0xC9, FD, FE, FE, FD]) + QD + bytes([FD, FF])),
    ]
    
    for name, payload in tests:
        resp = query_raw(payload, timeout_s=3)
        print(f"  {name}: {resp!r}")
        time.sleep(0.2)


def test_triple_special_bytes():
    print("\n" + "=" * 70)
    print("COMBINATIONS OF SPECIAL BYTES")
    print("=" * 70)
    
    print("\n'combining special bytes froze my system'")
    print("Let's try various combinations of FD, FE, FF...")
    
    import itertools
    
    special = [FD, FE, FF]
    
    for combo in itertools.product(special, repeat=3):
        name = ' '.join(f'{b:02X}' for b in combo)
        payload = bytes(combo)
        
        if combo[-1] == FF:
            resp = query_raw(payload, timeout_s=2)
            print(f"  {name}: {resp!r}")
            time.sleep(0.1)


def test_boundary_indices():
    print("\n" + "=" * 70)
    print("BOUNDARY VAR INDICES (250-252)")
    print("=" * 70)
    
    for idx in range(250, 253):
        payload = bytes([idx, FF])
        resp = query_raw(payload, timeout_s=2)
        print(f"  Var({idx}): {resp!r}")
        time.sleep(0.1)


def test_nested_special():
    print("\n" + "=" * 70)
    print("NESTED STRUCTURES WITH SPECIAL BYTES")
    print("=" * 70)
    
    tests = [
        ("λ.λ.FD (Lam Lam App)", bytes([FD, FE, FE, FF])),
        ("λ.FD (Lam App)", bytes([FD, FE, FF])),
        ("(FD FD)", bytes([FD, FD, FD, FF])),
        ("((FD FD) FD)", bytes([FD, FD, FD, FD, FD, FF])),
        ("λ.λ.λ.0 (triple lambda)", bytes([0x00, FE, FE, FE, FF])),
        ("(0 (0 FD))", bytes([0x00, 0x00, FD, FD, FF])),
    ]
    
    for name, payload in tests:
        resp = query_raw(payload, timeout_s=2)
        print(f"  {name}: {resp!r}")
        time.sleep(0.2)


def test_echo_with_special():
    print("\n" + "=" * 70)
    print("ECHO WITH BOUNDARY VALUES")
    print("=" * 70)
    
    QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
    
    for idx in range(249, 253):
        payload = bytes([0x0E, idx, FD]) + QD + bytes([FD, FF])
        resp = query_raw(payload, timeout_s=3)
        print(f"  echo(Var({idx})): {resp!r}")
        time.sleep(0.2)


def test_minimal_valid_terms():
    print("\n" + "=" * 70)
    print("MINIMAL VALID TERMS")
    print("=" * 70)
    
    print("\n'3 leafs' - what are the simplest valid 3-Var terms?")
    
    valid_3var = [
        ("(0 (0 0))", bytes([0x00, 0x00, 0x00, FD, FD, FF])),
        ("((0 0) 0)", bytes([0x00, 0x00, FD, 0x00, FD, FF])),
        ("(0 (1 0))", bytes([0x00, 0x01, 0x00, FD, FD, FF])),
        ("((0 1) 0)", bytes([0x00, 0x01, FD, 0x00, FD, FF])),
        ("(1 (0 0))", bytes([0x01, 0x00, 0x00, FD, FD, FF])),
        ("((1 0) 0)", bytes([0x01, 0x00, FD, 0x00, FD, FF])),
        ("(8 (0 0))", bytes([0x08, 0x00, 0x00, FD, FD, FF])),
        ("((8 0) 0)", bytes([0x08, 0x00, FD, 0x00, FD, FF])),
        ("(201 (0 0))", bytes([0xC9, 0x00, 0x00, FD, FD, FF])),
        ("((201 0) 0)", bytes([0xC9, 0x00, FD, 0x00, FD, FF])),
    ]
    
    for name, payload in valid_3var:
        resp = query_raw(payload, timeout_s=2)
        print(f"  {name}: {resp!r}")
        time.sleep(0.2)


def test_what_prints_something():
    print("\n" + "=" * 70)
    print("WHAT MINIMAL TERMS PRINT SOMETHING?")
    print("=" * 70)
    
    for a in range(0, 256, 20):
        for b in range(0, 256, 20):
            payload = bytes([a, b, FD, FF])
            resp = query_raw(payload, timeout_s=1)
            if resp and b'Invalid' not in resp and resp != b'':
                print(f"  ({a} {b}): {resp[:30]!r}")
        time.sleep(0.1)


def main():
    test_raw_byte_sequences()
    time.sleep(0.3)
    
    test_syscall_with_malformed()
    time.sleep(0.3)
    
    test_triple_special_bytes()
    time.sleep(0.3)
    
    test_boundary_indices()
    time.sleep(0.3)
    
    test_nested_special()
    time.sleep(0.3)
    
    test_echo_with_special()
    time.sleep(0.3)
    
    test_minimal_valid_terms()
    time.sleep(0.3)
    
    test_what_prints_something()
    
    print("\n" + "=" * 70)
    print("WIRE INJECTION TESTS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
