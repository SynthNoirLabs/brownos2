#!/usr/bin/env python3
"""
Ultra-minimal wire-level approach.

"3 leafs" might mean a minimal valid program with just 3 Var bytes.

Standard syscall pattern: syscall arg FD cont FD FF
That's: V_syscall V_arg FD V_cont FD FF

If we use syscall 8: 08 ?? FD ?? FD FF

What if the "continuation" is a special global that gives us permission?
"""

import socket
import time

HOST = "82.165.133.222"
PORT = 61221

FD, FE, FF = 0xFD, 0xFE, 0xFF


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


def test(desc: str, payload: bytes):
    resp = query(payload)
    if not resp:
        result = "(empty/timeout)"
    elif b"Encoding failed" in resp:
        result = "Encoding failed!"
    elif b"Invalid term" in resp:
        result = "Invalid term!"
    elif b"Permission" in resp:
        result = f"Permission denied"
    elif len(resp) > 0:
        try:
            text = resp.decode('utf-8', 'replace')
            if text.isprintable() or '\n' in text or '\r' in text:
                result = f"TEXT: {repr(text[:80])}"
            else:
                result = f"hex={resp.hex()[:80]}"
        except:
            result = f"hex={resp.hex()[:80]}"
    else:
        result = "(empty)"
    print(f"{desc}: {result}")
    return resp


def main():
    print("=" * 70)
    print("ULTRA-MINIMAL WIRE PATTERNS")
    print("=" * 70)
    
    print("\n=== Pattern: 08 arg FD cont FD FF ===\n")
    print("Try ALL possible 1-byte continuations")
    
    nil = bytes([0x00, FE, FE])
    
    found_interesting = []
    
    for cont in range(0, 0xFD):
        payload = bytes([0x08]) + nil + bytes([FD, cont, FD, FF])
        resp = query(payload, timeout_s=2.0)
        
        if resp and b"Encoding failed" not in resp and b"Invalid term" not in resp:
            desc = f"08 nil FD {hex(cont)} FD FF"
            if b"Permission" in resp:
                pass
            else:
                found_interesting.append((cont, resp))
                print(f"INTERESTING: {desc} -> {resp.hex()[:60]}")
        
        if cont % 50 == 0:
            print(f"  Scanned up to {cont}...")
        time.sleep(0.05)
    
    print(f"\nFound {len(found_interesting)} interesting responses (not Permission denied)")
    
    print("\n=== Now try echo as continuation ===\n")
    
    payload = bytes([0x08]) + nil + bytes([FD, 0x0E, FD, FF])
    test("08 nil FD 0E FD FF (echo as cont)", payload)
    
    print("\n=== Try backdoor as continuation ===\n")
    
    payload = bytes([0x08]) + nil + bytes([FD, 0xC9, FD, FF])
    test("08 nil FD C9 FD FF (backdoor as cont)", payload)
    
    print("\n=== Try write as continuation ===\n")
    
    payload = bytes([0x08]) + nil + bytes([FD, 0x02, FD, FF])
    test("08 nil FD 02 FD FF (write as cont)", payload)
    
    print("\n=== What if we need NESTED continuations? ===\n")
    print("Pattern: syscall arg FD (another syscall ... FD) FD FF")
    
    payload = bytes([0x08]) + nil + bytes([FD, 0xC9]) + nil + bytes([FD, FD, FF])
    test("08 nil FD (C9 nil FD) FD FF", payload)
    
    payload = bytes([0xC9]) + nil + bytes([FD, 0x08]) + nil + bytes([FD, FD, FF])
    test("C9 nil FD (08 nil FD) FD FF", payload)
    
    print("\n=== Try QD parts as continuation ===\n")
    
    QD_parts = [
        ("05", bytes([0x05])),
        ("05 00 FD", bytes([0x05, 0x00, FD])),
    ]
    
    for desc, part in QD_parts:
        payload = bytes([0x08]) + nil + bytes([FD]) + part + bytes([FD, FF])
        test(f"08 nil FD ({desc}) FD FF", payload)
        time.sleep(0.1)
    
    print("\n=== Minimal valid 3-leaf programs ===\n")
    
    patterns_3_leaf = [
        ("V8 V0 FD V0 FD FF", bytes([0x08, 0x00, FD, 0x00, FD, FF])),
        ("V8 V8 FD V8 FD FF", bytes([0x08, 0x08, FD, 0x08, FD, FF])),
        ("VC9 V0 FD V8 FD FF", bytes([0xC9, 0x00, FD, 0x08, FD, FF])),
        ("V8 VC9 FD V0 FD FF", bytes([0x08, 0xC9, FD, 0x00, FD, FF])),
    ]
    
    for desc, payload in patterns_3_leaf:
        test(desc, payload)
        time.sleep(0.1)


if __name__ == "__main__":
    main()
