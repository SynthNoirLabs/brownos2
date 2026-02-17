#!/usr/bin/env python3
"""
Test the absolute smallest possible payloads.

"3 leafs" might mean the entire payload has 3 variable bytes.
Or the argument to syscall 8 is incredibly minimal.
"""

import socket
import time

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


def test(payload: bytes, desc: str) -> None:
    try:
        resp = query(payload)
        resp_str = resp.hex() if resp else "(empty)"
        if b"Encoding failed" in resp:
            resp_str = "Encoding failed!"
        elif b"Invalid term" in resp:
            resp_str = "Invalid term!"
        elif b"Permission" in resp:
            resp_str = "Permission denied (text)"
        elif b"Term too big" in resp:
            resp_str = "Term too big!"
        print(f"{payload.hex():30} {desc:40} -> {resp_str[:60]}")
    except Exception as e:
        print(f"{payload.hex():30} {desc:40} -> ERROR: {e}")
    time.sleep(0.1)


def main():
    print("=== Absolute minimum payloads for syscall 8 ===\n")
    
    tests = [
        (bytes([0x08, 0x00, FD, FF]), "syscall8(Var(0)) alone"),
        (bytes([0x08, 0x00, FE, FD, FF]), "syscall8(I) alone"),
        (bytes([0x08, 0x00, FE, FE, FD, FF]), "syscall8(nil) alone"),
        
        (bytes([0x08, 0x00, FE, FE, FD]) + QD + bytes([FD, FF]), "syscall8(nil) + QD"),
        
        (bytes([0x08, 0xC9, FD, FF]), "syscall8(Var(201)) alone"),
        (bytes([0x08, 0x0E, FD, FF]), "syscall8(Var(14)) alone"),
        
        (bytes([0x08, 0x00, 0x00, FD, FD, FF]), "(syscall8(Var(0)))(Var(0))"),
        (bytes([0x08, 0x00, FD, 0x00, FD, FF]), "((syscall8)(Var(0)))(Var(0))"),
        
        (bytes([0x08, 0x00, FD, 0x00, FE, FD, FF]), "(syscall8(Var(0)))(I)"),
        
        (bytes([0xC9, 0x00, FE, FE, FD, 0x08, FD, FF]), "(backdoor(nil))(syscall8)"),
        
        (bytes([0x00, FE, FE, 0x08, FD, FF]), "(nil)(syscall8)"),
        (bytes([0x08, 0x00, FE, FE, FD, FD, FF]), "(syscall8(nil))()? - malformed"),
    ]
    
    for payload, desc in tests:
        test(payload, desc)
    
    print("\n=== 3-byte payloads ===\n")
    
    for a in [0x00, 0x08, 0x0E, 0xC9]:
        for b in [0x00, 0x08, 0x0E, 0xC9]:
            for op in [FD, FE]:
                payload = bytes([a, b, op, FF])
                desc = f"{a:02x} {b:02x} {op:02x}"
                test(payload, desc)
    
    print("\n=== 00 FE FE prefix variations ===\n")
    
    nil_tests = [
        (bytes([0x00, FE, FE, FF]), "nil alone"),
        (bytes([0x00, FE, FE, 0x08, FD, FF]), "(nil)(syscall8)"),
        (bytes([0x08, 0x00, FE, FE, FD, FF]), "(syscall8)(nil)"),
        (bytes([0x00, FE, FE, 0x08, FD, 0x00, FE, FE, FD, FF]), "((nil)(syscall8))(nil)"),
        (bytes([0x00, FE, FE, 0x00, FE, FE, FD, FF]), "(nil)(nil)"),
        (bytes([0x00, FE, FE, 0xC9, FD, FF]), "(nil)(backdoor)"),
        (bytes([0xC9, 0x00, FE, FE, FD, FF]), "(backdoor)(nil)"),
    ]
    
    for payload, desc in nil_tests:
        test(payload, desc)


if __name__ == "__main__":
    main()
