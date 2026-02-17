#!/usr/bin/env python3
"""
The MOST minimal syscall 8 tests.

"3 leafs" = exactly 3 Var nodes in the entire term?
Or 3 bytes total?

Let's try literally everything minimal.
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
        result = "(empty)"
    elif b"Encoding failed" in resp:
        result = "Encoding failed!"
    elif b"Invalid term" in resp:
        result = "Invalid term!"
    elif b"Permission" in resp:
        result = "Permission denied"
    elif resp == b'\xff':
        result = "Just FF (nil output)"
    elif resp.startswith(b'\x01\x00'):
        result = f"Left(something) hex={resp.hex()[:40]}"
    elif resp.startswith(b'\x01\x01'):
        result = f"Left(Left...) hex={resp.hex()[:40]}"
    elif resp.startswith(b'\x00'):
        try:
            text = resp.decode('utf-8', 'replace')[:50]
            result = f"ASCII: {repr(text)}"
        except:
            result = f"hex={resp.hex()[:60]}"
    else:
        result = f"hex={resp.hex()[:60]}"
    print(f"{desc}: {result}")


def main():
    print("=" * 70)
    print("ABSOLUTE MINIMAL SYSCALL 8 TESTS")
    print("=" * 70)
    
    print("\n=== Single byte + FF ===\n")
    for b in [0x08, 0x00, 0x01, 0x02]:
        test(f"byte {hex(b)} + FF", bytes([b, FF]))
    
    print("\n=== Two bytes + FF ===\n")
    two_byte_patterns = [
        (0x08, 0x00),
        (0x08, 0x08),
        (0x08, FE),
        (0x00, 0x08),
        (FE, 0x08),
    ]
    for a, b in two_byte_patterns:
        test(f"{hex(a)} {hex(b)} FF", bytes([a, b, FF]))
    
    print("\n=== Three bytes (potentially '3 leafs') + FF ===\n")
    three_byte_patterns = [
        (0x08, 0x00, 0x00),
        (0x08, 0x08, 0x08),
        (0x00, 0x08, 0x00),
        (0x00, 0x00, 0x08),
        (0x08, FE, 0x00),
        (0x08, 0x00, FE),
        (FE, 0x08, 0x00),
    ]
    for a, b, c in three_byte_patterns:
        test(f"{hex(a)} {hex(b)} {hex(c)} FF", bytes([a, b, c, FF]))
    
    print("\n=== Minimal valid terms with syscall 8 ===\n")
    
    minimal_terms = [
        ("(08 00)", bytes([0x08, 0x00, FD, FF])),
        ("(08 (08 00))", bytes([0x08, 0x08, 0x00, FD, FD, FF])),
        ("((08 00) 08)", bytes([0x08, 0x00, FD, 0x08, FD, FF])),
        ("λ.(08 0)", bytes([0x08, 0x00, FD, FE, FF])),
        ("((08 nil) I) where nil=λλ.0, I=λ.0", 
         bytes([0x08, 0x00, FE, FE, FD, 0x00, FE, FD, FF])),
    ]
    
    for desc, payload in minimal_terms:
        test(desc, payload)
        time.sleep(0.15)
    
    print("\n=== Using backdoor result directly with syscall 8 ===\n")
    
    nil = bytes([0x00, FE, FE])
    QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
    
    backdoor_then_sc8 = bytes([0xC9]) + nil + bytes([FD, 0x08, FD, FF])
    test("(backdoor nil) -> syscall8 as cont", backdoor_then_sc8)
    
    sc8_of_backdoor = bytes([0x08, 0xC9]) + nil + bytes([FD, FD]) + QD + bytes([FD, FF])
    test("syscall8(backdoor nil) with QD", sc8_of_backdoor)
    
    print("\n=== The 'A' and 'B' combinators from backdoor ===\n")
    
    A = bytes([0x00, 0x00, FD, FE, FE])
    B = bytes([0x01, 0x00, FD, FE, FE])
    
    test("syscall8(A) + QD", bytes([0x08]) + A + bytes([FD]) + QD + bytes([FD, FF]))
    test("syscall8(B) + QD", bytes([0x08]) + B + bytes([FD]) + QD + bytes([FD, FF]))
    
    test("A as cont: (08 nil) -> A", bytes([0x08]) + nil + bytes([FD]) + A + bytes([FD, FF]))
    test("B as cont: (08 nil) -> B", bytes([0x08]) + nil + bytes([FD]) + B + bytes([FD, FF]))
    
    print("\n=== Chaining backdoor and syscall 8 ===\n")
    
    chain1 = bytes([0xC9]) + nil + bytes([FD]) + bytes([0x08]) + nil + bytes([FD, FD, FF])
    test("backdoor -> syscall8 chain (no cont)", chain1)
    
    chain2 = bytes([0xC9]) + nil + bytes([FD]) + bytes([0x08]) + nil + bytes([FD, FD]) + QD + bytes([FD, FF])
    test("backdoor -> syscall8 chain + QD", chain2)
    
    chain3 = bytes([0x08]) + bytes([0xC9]) + nil + bytes([FD, FD]) + bytes([0x00, FE, FD, FF])
    test("syscall8(backdoor(nil)) -> I", chain3)
    
    print("\n=== Raw special byte combinations ===\n")
    
    special = [
        bytes([0x08, FD, FF]),
        bytes([0x08, FE, FF]),
        bytes([0x08, FD, FE, FF]),
        bytes([0x08, FE, FD, FF]),
        bytes([0x08, FE, FE, FD, FF]),
        bytes([FE, 0x08, FD, FF]),
        bytes([FE, FE, 0x08, FD, FF]),
    ]
    
    for s in special:
        test(f"raw: {s.hex()}", s)
        time.sleep(0.1)


if __name__ == "__main__":
    main()
