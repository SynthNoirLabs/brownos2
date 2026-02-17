#!/usr/bin/env python3
"""
Test if syscall 8 writes directly on success (no QD needed).

Hypothesis: Maybe syscall 8 on success writes the answer directly,
and we've been getting empty output because the permission check fails
and returns Right(6) which we can't see without QD.

Let's try with a simple identity continuation and longer timeouts.
"""
from __future__ import annotations

import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF


def recv_raw(sock: socket.socket, timeout_s: float = 10.0) -> bytes:
    sock.settimeout(timeout_s)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    return out


def query(payload: bytes, timeout_s: float = 10.0) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return recv_raw(sock, timeout_s=timeout_s)


def main():
    print("=" * 60)
    print("Test syscall 8 direct output hypothesis")
    print("=" * 60)
    
    identity = bytes([0x00, FE])
    
    print("\n[1] Syscall 8 with identity continuation")
    
    test_args = [
        ("V0", bytes([0x00])),
        ("V251", bytes([0xFB])),
        ("nil", bytes([0x00, FE, FE])),
    ]
    
    for name, arg in test_args:
        program = bytes([0x08]) + arg + bytes([FD]) + identity + bytes([FD, FF])
        print(f"  syscall8({name}) with identity: ", end="")
        out = query(program)
        print(f"{out!r}")
    
    print("\n[2] Syscall 8 with 'throw away' continuation (λx.nil)")
    
    discard = bytes([0x00, FE, FE, FE])
    
    for name, arg in test_args:
        program = bytes([0x08]) + arg + bytes([FD]) + discard + bytes([FD, FF])
        print(f"  syscall8({name}) with discard: ", end="")
        out = query(program)
        print(f"{out!r}")
    
    print("\n[3] Echo V251 → identity continuation → syscall8 with identity")
    
    shifted_id = bytes([0x01, FE])
    
    inner = bytes([0x09, 0x00, FD]) + shifted_id + bytes([FD])
    cont = inner + bytes([FE])
    
    program = bytes([0x0E, 0xFB, FD]) + cont + bytes([FD, FF])
    print(f"  Payload: {program.hex()}")
    out = query(program)
    print(f"  Output: {out!r}")
    
    print("\n[4] Echo V251 → unwrap → syscall8 → identity")
    
    unwrap = bytes([0x00, 0x00, FE, FD, 0x00, FE, FE, FD])
    inner = bytes([0x09]) + unwrap + bytes([FD]) + shifted_id + bytes([FD])
    cont = inner + bytes([FE])
    
    program = bytes([0x0E, 0xFB, FD]) + cont + bytes([FD, FF])
    print(f"  Payload: {program.hex()}")
    out = query(program)
    print(f"  Output: {out!r}")
    
    print("\n[5] Double echo V249 → unwrap both → syscall8 → identity")
    
    shifted_id2 = bytes([0x02, FE])
    
    unwrap2 = bytes([0x00, 0x00, FE, FD, 0x00, FE, FE, FD])
    inner2 = bytes([0x0A]) + unwrap2 + bytes([FD]) + shifted_id2 + bytes([FD])
    
    unwrap1 = bytes([0x00, 0x00, FE, FD, 0x00, FE, FE, FD])
    outer_inner = bytes([0x0F]) + unwrap1 + bytes([FD]) + inner2 + bytes([FE, FD])
    cont = outer_inner + bytes([FE])
    
    program = bytes([0x0E, 0xF9, FD]) + cont + bytes([FD, FF])
    print(f"  Payload: {program.hex()}")
    out = query(program)
    print(f"  Output: {out!r}")
    
    print("\n[6] Try backdoor pair components with syscall 8")
    
    print("  Getting backdoor pair first...")
    QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
    bd_out = query(bytes([0xC9, 0x00, FE, FE, FD]) + QD + bytes([FD, FF]))
    print(f"  Backdoor raw: {bd_out.hex() if len(bd_out) > 0 else 'empty'}")
    
    print("\n[7] Construct a chained program:")
    print("  backdoor(nil) → get pair → apply fst → pass A to syscall8")
    
    QD_shifted1 = bytes([b + 1 if b < FD else b for b in QD])
    QD_shifted2 = bytes([b + 2 if b < FD else b for b in QD])
    
    fst = bytes([0x00, FE, 0x01, FE])
    
    get_A = bytes([0x00]) + fst + bytes([FD, 0x00, FE, FE, FD])
    inner = bytes([0x09]) + get_A + bytes([FD]) + QD_shifted1 + bytes([FD])
    cont = inner + bytes([FE])
    
    program = bytes([0xC9, 0x00, FE, FE, FD]) + cont + bytes([FD, FF])
    print(f"  Payload: {program.hex()}")
    out = query(program)
    print(f"  Output: {out!r}")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
