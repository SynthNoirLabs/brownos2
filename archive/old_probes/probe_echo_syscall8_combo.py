#!/usr/bin/env python3
"""
Test echo (0x0E) + syscall 8 combinations.

Key insight: "combining special bytes froze the system"
Echo shifts indices by +2.

What if we:
1. Echo syscall 8's reference to shift it?
2. Call syscall 8 from inside echo's continuation?
3. Use echo to create a term that unlocks syscall 8?
"""

import socket
import time

HOST = "82.165.133.222"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def query(payload: bytes, timeout_s: float = 5.0) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
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
        elif resp.hex() == "000600fdfefefefefefefefefefdfefeff":
            resp_str = "Right(6) = Permission denied"
        elif b"Term too big" in resp:
            resp_str = "Term too big!"
        print(f"{desc:60} -> {resp_str[:80]}")
    except socket.timeout:
        print(f"{desc:60} -> TIMEOUT (froze?)")
    except Exception as e:
        print(f"{desc:60} -> ERROR: {e}")
    time.sleep(0.15)


def main():
    print("=== Echo + Syscall 8 Combinations ===\n")
    
    NIL = bytes([0x00, FE, FE])
    I = bytes([0x00, FE])
    
    UNWRAP_LEFT = bytes([0x00, FE, 0x01, FE])
    
    payloads = [
        (bytes([0x0E, 0x08]) + bytes([FD]) + QD + bytes([FD, FF]),
         "echo(Var(8))"),
        
        (bytes([0x0E, 0x08, FD, 0x00, FE, 0x01, FE, FD]) + NIL + bytes([FD]) + QD + bytes([FD, FF]),
         "echo(Var(8)) >>= \\x. x(nil)"),
         
        (bytes([0x0E]) + NIL + bytes([FD, 0x00, FE, 0x01, FE, FD, 0x08]) + NIL + bytes([FD, FD]) + QD + bytes([FD, FF]),
         "echo(nil) >>= \\x. syscall8(nil)"),
         
        (bytes([0x0E, 0x08, FD, 0x00, FE, 0x0A, FD, 0x01, FE, FD]) + NIL + bytes([FD]) + QD + bytes([FD, FF]),
         "echo(Var(8)) >>= \\echoed. syscall8(nil)"),
         
        (bytes([0xC9]) + NIL + bytes([FD, 0x00, FE, 0x0E, 0x08, FD, 0x01, FE, FD]) + QD + bytes([FD, FF]),
         "backdoor(nil) >>= \\pair. echo(Var(8))"),
         
        (bytes([0xC9]) + NIL + bytes([FD, 0x00, FE, 0x08, 0x01, FD, FD, 0x01, FE, FD]) + QD + bytes([FD, FF]),
         "backdoor(nil) >>= \\pair. syscall8(pair)"),
         
        (bytes([0x0E, 0xC9]) + NIL + bytes([FD, FD]) + QD + bytes([FD, FF]),
         "echo(backdoor(nil))"),
         
        (bytes([0x0E, 0x00, FD]) + QD + bytes([FD, FF]),
         "echo((0 0))"),
         
        (bytes([0x0E, 0x00, 0x00, FD, FD]) + QD + bytes([FD, FF]),
         "echo(((0 0) 0))"),
    ]
    
    for payload, desc in payloads:
        test(payload, desc)
    
    print("\n=== Special: Echo with FD/FE byte indices ===\n")
    
    special = [
        (bytes([0x0E, 0xFB, FD]) + QD + bytes([FD, FF]),
         "echo(Var(251)) - shifts to 253=FD"),
         
        (bytes([0x0E, 0xFC, FD]) + QD + bytes([FD, FF]),
         "echo(Var(252)) - shifts to 254=FE"),
         
        (bytes([0x0E, 0xFB, FD, 0x00, FE, 0x0A, 0x01, FD, FD, 0x01, FE, FD]) + NIL + bytes([FD]) + QD + bytes([FD, FF]),
         "echo(251) >>= \\v253. syscall8(v253)"),
         
        (bytes([0x0E, 0xFC, FD, 0x00, FE, 0x0A, 0x01, FD, FD, 0x01, FE, FD]) + NIL + bytes([FD]) + QD + bytes([FD, FF]),
         "echo(252) >>= \\v254. syscall8(v254)"),
    ]
    
    for payload, desc in special:
        test(payload, desc)
    
    print("\n=== Double echo for Var(255)? ===\n")
    
    double_echo = [
        (bytes([0x0E, 0xFB, FD, 0x00, FE, 0x0E, 0x01, FD, FD, 0x01, FE, FD]) + QD + bytes([FD, FF]),
         "echo(251) >>= \\v253. echo(v253)"),
    ]
    
    for payload, desc in double_echo:
        test(payload, desc)


if __name__ == "__main__":
    main()
