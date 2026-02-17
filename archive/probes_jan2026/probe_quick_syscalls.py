#!/usr/bin/env python3
"""Quick test of a few syscalls in the 202-252 range."""
import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
FD = 0xFD
FE = 0xFE
FF = 0xFF

nil = bytes([0x00, FE, FE])


def query(payload: bytes, timeout_s: float = 4.0) -> bytes:
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(timeout_s)
            out = b""
            while True:
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


def test_syscall(sid: int) -> str:
    payload = bytes([sid]) + nil + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    if not resp:
        return "EMPTY"
    if resp.startswith(b"Invalid"):
        return resp.decode()[:40]
    return f"RAW({len(resp)}): {resp[:30].hex()}"


print("Testing a sample of syscalls in 202-252 range:")
for sid in [202, 210, 220, 230, 240, 250, 251]:
    print(f"  {sid} (0x{sid:02X}): {test_syscall(sid)}")
    time.sleep(0.3)
