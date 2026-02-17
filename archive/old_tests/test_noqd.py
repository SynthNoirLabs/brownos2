#!/usr/bin/env python3
"""
Test syscall 8 without QD - maybe it outputs directly?
Or maybe we need a different continuation.
"""
from __future__ import annotations

import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def recv_raw(sock: socket.socket, timeout_s: float = 8.0) -> bytes:
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


def query(payload: bytes, timeout_s: float = 8.0) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return recv_raw(sock, timeout_s=timeout_s)


def main():
    print("=" * 60)
    print("Test syscall 8 variations")
    print("=" * 60)
    
    print("\n[1] Syscall 8 with identity continuation (λx.x)")
    identity = bytes([0x00, FE])
    program = bytes([0x08, 0x00, FD]) + identity + bytes([FD, FF])
    print(f"  Payload: {program.hex()}")
    out = query(program)
    print(f"  Output: {out!r}")
    
    print("\n[2] Syscall 8 with write continuation")
    write_cont = bytes([0x02])
    program = bytes([0x08, 0x00, FD]) + write_cont + bytes([FD, FF])
    print(f"  Payload: {program.hex()}")
    out = query(program)
    print(f"  Output: {out!r}")
    
    print("\n[3] Syscall 8 with different arguments and QD")
    
    test_args = [
        ("nil", bytes([0x00, FE, FE])),
        ("zero", bytes([0x00] + [FE]*9)),
        ("V8 (syscall 8)", bytes([0x08])),
        ("(V8 V8)", bytes([0x08, 0x08, FD])),
    ]
    
    for name, arg in test_args:
        program = bytes([0x08]) + arg + bytes([FD]) + QD + bytes([FD, FF])
        out = query(program)
        if b'\xff' in out:
            print(f"  {name}: {out[:out.index(0xff)+1].hex()}")
        else:
            print(f"  {name}: {out!r}")
    
    print("\n[4] Chain: backdoor → apply A and B → syscall 8")
    
    bd_result = query(bytes([0xC9, 0x00, FE, FE, FD]) + QD + bytes([FD, FF]))
    print(f"  Backdoor raw: {bd_result[:60].hex() if len(bd_result) > 20 else bd_result!r}")
    
    print("\n[5] Test if syscall 8 returns Left on success")
    
    program = bytes([0x08]) + bytes([0x08]) + bytes([FD]) + QD + bytes([FD, FF])
    out = query(program)
    if b'\xff' in out:
        print(f"  syscall8(V8): {out[:out.index(0xff)+1].hex()}")
    
    print("\n[6] What if we DON'T call syscall 8 but chain backdoor differently?")
    
    nil = bytes([0x00, FE, FE])
    program = bytes([0xC9]) + nil + bytes([FD]) + QD + bytes([FD, FF])
    out = query(program)
    if b'\xff' in out:
        print(f"  backdoor(nil): {out[:out.index(0xff)+1].hex()}")
    
    print("\n[7] Can we chain backdoor → extract A or B → syscall 8?")
    
    shifted_qd = bytes([b + 2 if b < FD else b for b in QD])
    
    fst = bytes([0x00, FE, 0x01, FE])
    snd = bytes([0x01, FE, 0x00, FE])
    
    prog = bytes([0xC9]) + nil + bytes([FD])
    inner = bytes([0x0A]) + bytes([0x00]) + fst + bytes([FD, FD]) + shifted_qd + bytes([FD, FE, FD, FF])
    
    print(f"  (complex chaining - skipping for now)")
    
    print("\n[8] Minimal test: what does echo return internally?")
    
    shifted_qd1 = bytes([b + 1 if b < FD else b for b in QD])
    
    prog = bytes([0x0E, 0xFC, FD]) + shifted_qd1 + bytes([FE, FD, FF])
    print(f"  echo(V252) with shifted QD as continuation: {prog.hex()}")
    out = query(prog)
    print(f"  Output: {out!r}")
    
    prog = bytes([0x04, 0xFC, FD]) + QD + bytes([FD, FF])
    out = query(prog)
    print(f"  quote(V252): {out[:50] if len(out) > 50 else out!r}")
    
    print("\n[9] What's the correct way to unwrap Left?")
    
    prog = bytes([0x0E, 0x00, FD]) + QD + bytes([FD, FF])
    out = query(prog)
    if b'\xff' in out:
        print(f"  echo(V0) with QD: {out[:out.index(0xff)+1].hex()}")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
