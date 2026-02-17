#!/usr/bin/env python3
"""Scan syscalls 202-252 for hidden functionality.

Known:
- 201 = backdoor (returns Left(pair))
- 252-254 = "does not exist" (Right(1))
- 255 = terminator byte

Testing range 202-252 with nil argument.
"""

import socket
import time

HOST = "82.165.133.222"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

NIL = bytes([0x00, FE, FE])
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


def test_syscall(num: int, arg: bytes = NIL) -> bytes:
    """Call syscall `num` with given argument, wrapped in QD continuation."""
    payload = bytes([num]) + arg + bytes([FD]) + QD + bytes([FD, FF])
    return query(payload)


def main():
    print("=== Scanning syscalls 202-252 ===\n")
    
    results = {}
    for n in range(202, 253):
        try:
            resp = test_syscall(n)
            results[n] = resp.hex()
            print(f"syscall({n}): {resp.hex()}")
        except Exception as e:
            results[n] = f"ERROR: {e}"
            print(f"syscall({n}): ERROR - {e}")
        time.sleep(0.1)
    
    print("\n=== Summary ===")
    by_response = {}
    for n, resp in results.items():
        by_response.setdefault(resp, []).append(n)
    
    for resp, nums in sorted(by_response.items(), key=lambda x: len(x[1]), reverse=True):
        if len(nums) <= 5:
            print(f"{resp}: {nums}")
        else:
            print(f"{resp}: {nums[:3]}... ({len(nums)} total)")


if __name__ == "__main__":
    main()
