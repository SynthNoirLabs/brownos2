#!/usr/bin/env python3
"""
"My record is 3 leafs IIRC" - literal interpretation

What if "3 leafs" means literally 3 variable bytes in the bytecode?
Testing the SMALLEST valid terms with exactly 3 Var nodes.
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


def test_syscall8_raw(arg_bytes: bytes) -> bytes:
    payload = bytes([0x08]) + arg_bytes + bytes([FD]) + QD + bytes([FD, FF])
    return query(payload)


def main():
    print("=== Testing 3-leaf terms LITERALLY ===\n")
    
    terms_3leaf = [
        (b'\x00\x00\x00\xfd\xfd', "((0 0) 0)"),
        (b'\x00\x00\xfd\x00\xfd', "(0 (0 0))"),
        (b'\x00\x00\x00\xfd\xfd\xfe', "λ.((0 0) 0)"),
        (b'\x00\x00\xfd\x00\xfd\xfe', "λ.(0 (0 0))"),
        (b'\x00\x01\x00\xfd\xfd', "((1 0) 0)"),
        (b'\x00\x00\x01\xfd\xfd', "((0 0) 1)"),
        (b'\x00\x01\xfd\x00\xfd', "(0 (1 0))"),
        (b'\x01\x00\xfd\x00\xfd', "(1 (0 0))"),
        (b'\x00\x00\xfd\x01\xfd', "(0 (0 1))"),
        (b'\x00\x01\xfd\x00\xfd\xfe', "λ.(0 (1 0))"),
        (b'\x01\x00\xfd\x00\xfd\xfe', "λ.(1 (0 0))"),
        (b'\x00\x00\x00\xfd\xfd\xfe\xfe', "λλ.((0 0) 0)"),
        (b'\x00\x00\xfd\x00\xfd\xfe\xfe', "λλ.(0 (0 0))"),
        (b'\x01\x00\xfd\x00\xfd\xfe\xfe', "λλ.(1 (0 0))"),
        (b'\x00\x01\xfd\x00\xfd\xfe\xfe', "λλ.(0 (1 0))"),
    ]
    
    permission_denied = "000600fdfefefefefefefefefefdfefeff"
    
    for raw, desc in terms_3leaf:
        try:
            resp = test_syscall8_raw(raw)
            marker = "!!! DIFFERENT" if resp.hex() != permission_denied else ""
            print(f"{raw.hex():20} {desc:25} -> {resp.hex()} {marker}")
        except Exception as e:
            print(f"{raw.hex():20} {desc:25} -> ERROR: {e}")
        time.sleep(0.1)
    
    print("\n=== Testing special byte combinations ===\n")
    
    special = [
        (b'\x08\x00\xfe\xfe\xfd', "syscall8(nil)"),
        (b'\x00\xfe\xfe', "nil itself"),
        (b'\xc9', "Var(201) = backdoor ref"),
        (b'\x08', "Var(8) = syscall8 ref"),
        (b'\xc9\x00\xfe\xfe\xfd', "backdoor(nil) raw"),
    ]
    
    for raw, desc in special:
        try:
            resp = test_syscall8_raw(raw)
            marker = "!!! DIFFERENT" if resp.hex() != permission_denied else ""
            print(f"{raw.hex():20} {desc:25} -> {resp.hex()} {marker}")
        except Exception as e:
            print(f"{raw.hex():20} {desc:25} -> ERROR: {e}")
        time.sleep(0.1)


if __name__ == "__main__":
    main()
