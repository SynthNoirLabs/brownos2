#!/usr/bin/env python3
"""
Test RAW wire-level byte sequences for syscall 8.
The "combining special bytes froze my system" hint suggests parser quirks.
"""

import socket
import time

HOST = "82.165.133.222"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def query_raw(payload: bytes, timeout_s: float = 3.0) -> bytes:
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


def main():
    print("=== RAW wire-level experiments ===\n")
    
    payloads = [
        (bytes([0x08, 0x00, FE, FE, FD]) + QD + bytes([FD, FF]), "syscall8(nil) wrapped"),
        
        (bytes([0x08, 0x00, FE, FE, FD, FF]), "syscall8(nil) no-QD"),
        (bytes([0x08, 0x00, FE, FD, FF]), "syscall8(I) no-QD"),
        
        (bytes([0x08, FD, FF]), "08 FD FF (app with just Var8?)"),
        (bytes([0x08, FE, FF]), "08 FE FF (lam around Var8?)"),
        
        (bytes([FD, 0x08, 0x00, FE, FE, FD, FF]), "FD at start"),
        (bytes([FE, 0x08, 0x00, FE, FE, FD, FF]), "FE at start"),
        
        (bytes([0x08, 0xC9, 0x00, FE, FE, FD, FD, FF]), "syscall8(backdoor(nil))"),
        (bytes([0xC9, 0x00, FE, FE, FD, 0x08, FD, FF]), "backdoor(nil) 8 FD"),
        
        (bytes([0x00, FE, FE, 0x08, FD, FF]), "nil 08 FD - (nil syscall8)?"),
        
        (bytes([0xC9, 0x08, FD, 0x00, FE, FE, FD, FF]), "(backdoor syscall8) nil"),
        
        (bytes([0x08, 0xFD, 0xFE, FD, FF]), "syscall8(λ.FD)? - FD inside lambda"),
        
        (bytes([0x08, 0xFE, FD, FF]), "syscall8(FE)?"),
        (bytes([0x08, 0xFC, FD, FF]), "syscall8(Var252)?"),
    ]
    
    for payload, desc in payloads:
        try:
            resp = query_raw(payload)
            print(f"{payload.hex():50} | {desc:40} -> {resp.hex()[:60]}")
        except Exception as e:
            print(f"{payload.hex():50} | {desc:40} -> ERROR: {e}")
        time.sleep(0.15)


if __name__ == "__main__":
    main()
