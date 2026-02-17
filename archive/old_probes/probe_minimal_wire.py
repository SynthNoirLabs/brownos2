#!/usr/bin/env python3
"""
Test MINIMAL wire patterns with syscall 8.

The "3 leafs" hint might mean:
1. Literally 3 Var bytes (leaf nodes)
2. A minimal term structure
3. A specific raw byte sequence

Key insight: QD takes the result and prints it. If we DON'T use QD,
maybe syscall 8 behaves differently?

Also: What if syscall 8 needs to be called with NO continuation at all?
The service pattern is: syscall arg FD cont FD FF
What if: syscall arg FD FF (no cont)?
Or even: syscall FD FF (no arg)?
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


def test(desc: str, payload: bytes) -> str:
    resp = query(payload)
    if not resp:
        result = "(empty)"
    elif b"Encoding failed" in resp:
        result = "Encoding failed!"
    elif b"Invalid term" in resp:
        result = "Invalid term!"
    elif b"Term too big" in resp:
        result = "Term too big!"
    elif b"Permission" in resp:
        result = "Permission denied (text)"
    else:
        # Show both hex and ASCII
        ascii_safe = resp.replace(b'\n', b'\\n').replace(b'\r', b'\\r')
        try:
            text = ascii_safe.decode('ascii', 'replace')[:40]
        except:
            text = ""
        result = f"hex={resp.hex()[:60]} ascii={text}"
    print(f"{desc}: {result}")
    return result


def main():
    print("=" * 70)
    print("MINIMAL WIRE PATTERNS FOR SYSCALL 8")
    print("=" * 70)
    
    nil = bytes([0x00, FE, FE])  # λλ.0
    identity = bytes([0x00, FE])  # λ.0
    
    print("\n=== Syscall 8 with minimal / no continuation ===\n")
    
    # Standard pattern: syscall arg FD cont FD FF
    # What if we omit parts?
    
    patterns = [
        # Just syscall + FF (no arg, no cont)
        ("08 FF", bytes([0x08, FF])),
        
        # syscall + nil + FD + FF (no cont)
        ("08 nil FD FF", bytes([0x08]) + nil + bytes([FD, FF])),
        
        # syscall + 0 + FD + FF
        ("08 00 FD FF", bytes([0x08, 0x00, FD, FF])),
        
        # syscall + identity + FD + FF
        ("08 I FD FF", bytes([0x08]) + identity + bytes([FD, FF])),
        
        # 3 leaf vars only: 0 0 0 FF
        ("00 00 00 FF", bytes([0x00, 0x00, 0x00, FF])),
        
        # 08 0 0 FD FD FF (apply apply)
        ("08 00 00 FD FD FF", bytes([0x08, 0x00, 0x00, FD, FD, FF])),
        
        # Literal "3 leafs": ((08 0) 0) = 08 00 FD 00 FD FF
        ("((08 0) 0) FF", bytes([0x08, 0x00, FD, 0x00, FD, FF])),
        
        # What if write(2) is used directly as continuation?
        ("08 nil FD 02 FD FF", bytes([0x08]) + nil + bytes([FD, 0x02, FD, FF])),
        
        # Use syscall 8 AS the continuation
        ("nil 08 FD FF", nil + bytes([0x08, FD, FF])),
        
        # Double syscall 8 application
        ("08 08 FD FF", bytes([0x08, 0x08, FD, FF])),
    ]
    
    for desc, payload in patterns:
        test(desc, payload)
        time.sleep(0.15)
    
    print("\n=== Syscall 8 with specific byte patterns ===\n")
    
    # Test if syscall 8 wants a specific "magic" argument
    magic_patterns = [
        # The backdoor starts with 00 FE FE
        ("08 (00 FE FE) FD 02 FD FF", bytes([0x08, 0x00, FE, FE, FD, 0x02, FD, FF])),
        
        # What if FD FE FF themselves are the key?
        ("08 FD FE FF (raw)", bytes([0x08, FD, FE, FF])),
        
        # The pair from backdoor: λs.s A B
        # A = λab.bb, B = λab.ab
        # What if we need to use A or B directly?
        
        # A = λλ.(0 0) = 00 00 FD FE FE
        ("08 A FD 02 FD FF", bytes([0x08, 0x00, 0x00, FD, FE, FE, FD, 0x02, FD, FF])),
        
        # B = λλ.(1 0) = 01 00 FD FE FE  
        ("08 B FD 02 FD FF", bytes([0x08, 0x01, 0x00, FD, FE, FE, FD, 0x02, FD, FF])),
        
        # ω = λ.(0 0) = 00 00 FD FE
        ("08 omega FD 02 FD FF", bytes([0x08, 0x00, 0x00, FD, FE, FD, 0x02, FD, FF])),
    ]
    
    for desc, payload in magic_patterns:
        test(desc, payload)
        time.sleep(0.15)
    
    print("\n=== Raw syscall 8 + special bytes ===\n")
    
    # The hint says "combining special bytes froze my system"
    # What if we send syscall 8 with FD/FE/FF in the raw stream?
    
    special_byte_patterns = [
        # 08 with raw special bytes (malformed but might trigger something)
        ("08 FD FD FF", bytes([0x08, FD, FD, FF])),
        ("08 FE FD FF", bytes([0x08, FE, FD, FF])),
        ("08 FE FE FF", bytes([0x08, FE, FE, FF])),
        ("08 FE FE FE FF", bytes([0x08, FE, FE, FE, FF])),
        
        # What about FD FD FD?
        ("08 00 FD FD FD FF", bytes([0x08, 0x00, FD, FD, FD, FF])),
        
        # The QD constant itself might be special
        ("08 QD FD FF (no outer)", bytes([0x08]) + bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe") + bytes([FD, FF])),
    ]
    
    for desc, payload in special_byte_patterns:
        test(desc, payload)
        time.sleep(0.15)
    
    print("\n=== Testing if syscall 8 outputs directly (no QD needed) ===\n")
    
    # Maybe syscall 8 writes directly to socket without needing write()?
    # Standard syscalls use CPS, but syscall 8 might be special
    
    direct_patterns = [
        # Just call syscall 8 with nil, then identity continuation
        ("08 nil FD I FD FF", bytes([0x08]) + nil + bytes([FD]) + identity + bytes([FD, FF])),
        
        # Call syscall 8, use the result directly (no write)
        ("(08 nil) FF", bytes([0x08]) + nil + bytes([FD, FF])),
    ]
    
    for desc, payload in direct_patterns:
        test(desc, payload)
        time.sleep(0.15)
    
    print("\n=== The literal '3 leaf' patterns ===\n")
    
    # If "3 leafs" means exactly 3 variable nodes (Var), what terms have exactly 3?
    # Vars are bytes 0x00-0xFC
    
    three_leaf_patterns = [
        # ((a b) c) = a b FD c FD
        ("((0 0) 0)", bytes([0x00, 0x00, FD, 0x00, FD, FF])),
        ("((0 1) 2)", bytes([0x00, 0x01, FD, 0x02, FD, FF])),
        ("((8 0) 0)", bytes([0x08, 0x00, FD, 0x00, FD, FF])),  # 3 leafs with syscall 8
        
        # (a (b c)) = a b c FD FD
        ("(0 (0 0))", bytes([0x00, 0x00, 0x00, FD, FD, FF])),
        ("(8 (0 0))", bytes([0x08, 0x00, 0x00, FD, FD, FF])),  # syscall 8 applied to (0 0)
        
        # λ.((a b) c) = a b FD c FD FE
        ("λ.((0 0) 0)", bytes([0x00, 0x00, FD, 0x00, FD, FE, FF])),
        ("λ.((8 0) 0)", bytes([0x08, 0x00, FD, 0x00, FD, FE, FF])),
    ]
    
    for desc, payload in three_leaf_patterns:
        test(desc, payload)
        time.sleep(0.15)


if __name__ == "__main__":
    main()
