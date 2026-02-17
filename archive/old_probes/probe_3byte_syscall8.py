#!/usr/bin/env python3
"""
"3 leafs" - maybe literally 3 bytes for the syscall 8 argument?

The smallest terms that could be arguments:
- Var(n) = 1 byte
- (Var Var) = 3 bytes: XX YY FD
- λ.Var = 2 bytes: XX FE
- λλ.Var = 3 bytes: XX FE FE

Try all 3-byte argument combinations.
"""

import socket
import time
import itertools

HOST = "82.165.133.222"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def query(payload: bytes, timeout_s: float = 3.0) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        sock.settimeout(timeout_s)
        out = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                out += chunk
                if FF in chunk:
                    break
            except socket.timeout:
                break
        return out


def test_syscall8(arg_bytes: bytes) -> str:
    payload = bytes([0x08]) + arg_bytes + bytes([FD]) + QD + bytes([FD, FF])
    try:
        resp = query(payload)
        if not resp:
            return "empty"
        if b"Encoding failed" in resp:
            return "enc_fail"
        if b"Invalid term" in resp:
            return "invalid"
        
        resp_hex = resp.hex()
        if resp_hex == "000600fdfefefefefefefefefefdfefeff":
            return "R6_perm"
        if "000600fdfe" in resp_hex:
            return "R6"
        if "000200fdfe" in resp_hex:
            return "R2"
        if "000100fdfe" in resp_hex:
            return "R1"
        if "000000fdfe" in resp_hex:
            return "R0"
        if resp_hex.startswith("01"):
            return f"Left!={resp_hex[:20]}"
        return resp_hex[:20]
    except Exception as e:
        return f"err:{e}"


def main():
    print("=== 3-byte syscall 8 arguments ===\n")
    
    interesting = []
    
    patterns_3byte = [
        (bytes([0x00, FE, FE]), "nil"),
        (bytes([0x00, 0x00, FD]), "(0 0)"),
        (bytes([0x01, 0x00, FD]), "(1 0)"),
        (bytes([0x00, 0x01, FD]), "(0 1)"),
        (bytes([0x08, 0x00, FD]), "(8 0)"),
        (bytes([0x00, 0x08, FD]), "(0 8)"),
        (bytes([0x0E, 0x00, FD]), "(14 0)"),
        (bytes([0x00, 0x0E, FD]), "(0 14)"),
        (bytes([0xC9, 0x00, FD]), "(201 0)"),
        (bytes([0x00, 0xC9, FD]), "(0 201)"),
    ]
    
    for arg, desc in patterns_3byte:
        result = test_syscall8(arg)
        marker = "!!!" if result not in ["R6_perm", "R6", "empty", "invalid"] else ""
        if marker:
            interesting.append((arg, desc, result))
        print(f"{arg.hex():10} {desc:20} -> {result} {marker}")
    
    print("\n=== Scan (X Y FD) for X,Y in interesting values ===\n")
    
    vals = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xC9]
    
    for x, y in itertools.product(vals, vals):
        arg = bytes([x, y, FD])
        result = test_syscall8(arg)
        if result not in ["R6_perm", "R6", "empty", "invalid", "R2"]:
            print(f"{arg.hex():10} ({x} {y}) -> {result} !!!")
            interesting.append((arg, f"({x} {y})", result))
        time.sleep(0.05)
    
    print("\n=== Scan (X FE FE) for nil-like patterns ===\n")
    
    for x in range(256):
        if x in [FD, FE, FF]:
            continue
        arg = bytes([x, FE, FE])
        result = test_syscall8(arg)
        if result not in ["R6_perm", "R6", "empty", "invalid", "R2"]:
            print(f"{arg.hex():10} λλ.{x} -> {result} !!!")
            interesting.append((arg, f"λλ.{x}", result))
        time.sleep(0.02)
    
    print("\n=== Summary of interesting results ===")
    for arg, desc, result in interesting:
        print(f"{arg.hex():10} {desc:20} -> {result}")


if __name__ == "__main__":
    main()
