#!/usr/bin/env python3
"""
Bytecode fuzzing around FD/FE/FF special bytes.

Oracle's alternative: "malformed FD/FE/FF sequences causing stack underflow/overflow
in the decoder, potentially letting you smuggle a different syscall id or corrupt 
a permission flag."

The hint was "combining special bytes" and "froze my whole system".
"""
from __future__ import annotations

import socket
import time
import itertools

FF = 0xFF
FE = 0xFE
FD = 0xFD

HOST = "82.165.133.222"
PORT = 61221


def query_raw(payload: bytes, timeout_s: float = 3.0) -> bytes:
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            sock.settimeout(timeout_s)
            out = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out += chunk
                except socket.timeout:
                    break
            return out
    except Exception:
        return b''


def classify(resp: bytes) -> str:
    if not resp:
        return "silent"
    if resp.startswith(b"Invalid"):
        return "invalid"
    if resp.startswith(b"Encoding failed"):
        return "encfail"
    if resp.startswith(b"Term too big"):
        return "toobig"
    if 0xFF in resp:
        return f"term:{resp[:20].hex()}"
    return resp[:30].decode('utf-8', 'replace')


def test_short_patterns():
    """Test very short byte patterns around special bytes."""
    print("=" * 60)
    print("SHORT BYTECODE PATTERNS (1-4 bytes + FF)")
    print("=" * 60)
    
    seen = set()
    
    for length in range(1, 5):
        print(f"\n--- Length {length} ---")
        found = 0
        
        for pattern in itertools.product(range(256), repeat=length):
            payload = bytes(pattern) + bytes([FF])
            resp = query_raw(payload, timeout_s=2.0)
            result = classify(resp)
            
            if result not in ("silent", "invalid") and result not in seen:
                print(f"  {bytes(pattern).hex()} FF -> {result}")
                seen.add(result)
                found += 1
            
            if found > 20:
                break
        
        time.sleep(0.1)


def test_fd_fe_combinations():
    """Focus specifically on FD/FE combinations."""
    print("\n" + "=" * 60)
    print("FD/FE COMBINATIONS")
    print("=" * 60)
    
    special = [0xFD, 0xFE]
    normal = [0x00, 0x01, 0x08, 0xC9]
    
    patterns = []
    
    for n1 in normal:
        for s1 in special:
            patterns.append(bytes([n1, s1]))
            for s2 in special:
                patterns.append(bytes([n1, s1, s2]))
                for n2 in normal:
                    patterns.append(bytes([n1, s1, n2, s2]))
                    patterns.append(bytes([n1, n2, s1, s2]))
    
    for n1 in normal:
        for n2 in normal:
            for s in special:
                patterns.append(bytes([n1, n2, s]))
                patterns.append(bytes([s, n1, n2]))
    
    seen = set()
    for pattern in patterns:
        payload = pattern + bytes([FF])
        resp = query_raw(payload, timeout_s=2.0)
        result = classify(resp)
        
        key = (pattern.hex(), result)
        if result not in ("silent", "invalid") and key not in seen:
            print(f"  {pattern.hex()} FF -> {result}")
            seen.add(key)
        
        time.sleep(0.05)


def test_stack_underflow():
    """
    Try patterns that might cause stack underflow.
    FD (App) pops 2 from stack, FE (Lam) pops 1.
    Starting with FD on empty stack might do something weird.
    """
    print("\n" + "=" * 60)
    print("POTENTIAL STACK UNDERFLOW PATTERNS")
    print("=" * 60)
    
    underflow_patterns = [
        bytes([FD, FF]),
        bytes([FE, FF]),
        bytes([FD, FD, FF]),
        bytes([FE, FE, FF]),
        bytes([FD, FE, FF]),
        bytes([FE, FD, FF]),
        bytes([0x00, FD, FD, FF]),
        bytes([FD, 0x00, FF]),
        bytes([FE, FD, 0x00, FF]),
        bytes([0x08, FD, FF]),
        bytes([FD, 0x08, FF]),
        bytes([0x08, 0x00, FD, FD, FF]),
    ]
    
    for pattern in underflow_patterns:
        resp = query_raw(pattern, timeout_s=2.0)
        result = classify(resp)
        print(f"  {pattern[:-1].hex()} FF -> {result}")
        time.sleep(0.1)


def test_syscall8_with_embedded_special():
    """
    Try syscall 8 patterns with FD/FE embedded in unusual places.
    """
    print("\n" + "=" * 60)
    print("SYSCALL 8 WITH EMBEDDED SPECIAL BYTES")
    print("=" * 60)
    
    patterns = [
        bytes([0x08, 0x00, FE, FE, FD]),
        bytes([0x08, FD, 0x00, FE, FE]),
        bytes([FD, 0x08, 0x00, FE, FE]),
        bytes([0x08, 0x00, FE, FE, FD, 0x02, FD]),
        bytes([0x08, 0x00, FE, FE, FD, FE, FD]),
        bytes([0x08, FE, 0x00, FE, FD]),
        bytes([FE, 0x08, 0x00, FD, FE]),
        bytes([0x08, 0x00, 0x00, FD, FD]),
        bytes([0x08, 0x00, FD, 0x00, FD]),
    ]
    
    for pattern in patterns:
        payload = pattern + bytes([FF])
        resp = query_raw(payload, timeout_s=2.0)
        result = classify(resp)
        print(f"  {pattern.hex()} FF -> {result}")
        time.sleep(0.1)


def test_echo_with_special():
    """
    Echo (0x0E) with special byte patterns.
    The hint says echo has a hidden purpose and combining special bytes 
    can freeze the system.
    """
    print("\n" + "=" * 60)
    print("ECHO (0x0E) WITH SPECIAL BYTES")
    print("=" * 60)
    
    patterns = [
        bytes([0x0E, FD, FF]),
        bytes([0x0E, FE, FF]),
        bytes([0x0E, 0xFB, FE, FE, FD]),
        bytes([0x0E, 0xFC, FE, FE, FD]),
        bytes([0x0E, 0x00, FE, FE, FD, 0x0E, FD]),
        bytes([0x0E, 0x0E, FD]),
        bytes([0x0E, 0x08, FD]),
    ]
    
    for pattern in patterns:
        payload = pattern + bytes([FF])
        resp = query_raw(payload, timeout_s=3.0)
        result = classify(resp)
        print(f"  {pattern.hex()} FF -> {result}")
        time.sleep(0.1)


def test_backdoor_with_special():
    """
    Backdoor (0xC9) combined with special patterns.
    """
    print("\n" + "=" * 60)
    print("BACKDOOR (0xC9) WITH SPECIAL PATTERNS")
    print("=" * 60)
    
    nil = bytes([0x00, FE, FE])
    
    patterns = [
        bytes([0xC9]) + nil + bytes([FD, FD]),
        bytes([0xC9]) + nil + bytes([FD, FE]),
        bytes([0xC9, FD]) + nil,
        bytes([0xC9, FE]) + nil,
        bytes([FD, 0xC9]) + nil,
        bytes([FE, 0xC9]) + nil,
        bytes([0xC9]) + nil + bytes([FD, 0x08, FD]),
    ]
    
    for pattern in patterns:
        payload = pattern + bytes([FF])
        resp = query_raw(payload, timeout_s=3.0)
        result = classify(resp)
        print(f"  {pattern.hex()} FF -> {result}")
        time.sleep(0.1)


def test_high_index_vars():
    """
    Test Var indices near the reserved range (0xFB, 0xFC).
    These are the highest valid Var indices before FD/FE/FF.
    """
    print("\n" + "=" * 60)
    print("HIGH INDEX VARS (0xFB, 0xFC)")
    print("=" * 60)
    
    for high_var in [0xFB, 0xFC]:
        patterns = [
            bytes([high_var]),
            bytes([high_var, 0x00, FD]),
            bytes([0x00, high_var, FD]),
            bytes([high_var, high_var, FD]),
            bytes([high_var, FE]),
            bytes([0x08, high_var, FD]),
            bytes([high_var, 0x08, FD]),
            bytes([high_var, 0x00, FD, high_var, FD]),
        ]
        
        for pattern in patterns:
            payload = pattern + bytes([FF])
            resp = query_raw(payload, timeout_s=2.0)
            result = classify(resp)
            if result not in ("silent", "invalid"):
                print(f"  {pattern.hex()} FF -> {result}")
            time.sleep(0.05)


def main():
    test_fd_fe_combinations()
    test_stack_underflow()
    test_syscall8_with_embedded_special()
    test_echo_with_special()
    test_backdoor_with_special()
    test_high_index_vars()


if __name__ == "__main__":
    main()
