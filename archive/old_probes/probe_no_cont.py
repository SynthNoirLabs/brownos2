#!/usr/bin/env python3
"""
What if we don't need a continuation at all?

The cheat sheet shows:
BrownOS[<syscall> <argument> FD <rest> FD] -> BrownOS[<rest> <result> FD]

But what if we send: <syscall> <argument> FD FF
Without the <rest>?

This might cause the VM to output the result directly.
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
PORT = 61221

FD, FE, FF = 0xFD, 0xFE, 0xFF
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


@dataclass(frozen=True)
class Var:
    i: int


@dataclass(frozen=True)
class Lam:
    body: object


@dataclass(frozen=True)
class App:
    f: object
    x: object


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError


def query(payload: bytes, timeout_s: float = 5.0) -> bytes:
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except:
                pass
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


def test(desc: str, payload: bytes) -> None:
    resp = query(payload)
    if not resp:
        print(f"{desc}: (empty)")
    elif b"Invalid term" in resp:
        print(f"{desc}: Invalid term!")
    elif b"Encoding failed" in resp:
        print(f"{desc}: Encoding failed!")
    else:
        try:
            text = resp.decode('utf-8', 'replace')
            if all(c.isprintable() or c in '\n\r\t' for c in text):
                print(f"{desc}: TEXT={text!r}")
            else:
                print(f"{desc}: hex={resp.hex()[:80]}")
        except:
            print(f"{desc}: hex={resp.hex()[:80]}")
    time.sleep(0.15)


def main():
    print("=" * 70)
    print("NO CONTINUATION TESTS")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print("\n=== Pattern: <syscall> <arg> FD FF (no continuation) ===\n")
    
    syscalls = [(1, "errstr"), (2, "write"), (4, "quote"), (5, "readdir"), 
                (6, "name"), (7, "readfile"), (8, "syscall8"), (14, "echo"),
                (42, "towel"), (201, "backdoor")]
    
    for sc, name in syscalls:
        payload = bytes([sc]) + encode_term(nil) + bytes([FD, FF])
        test(f"{name}(nil) FD FF", payload)
    
    print("\n=== Pattern: <syscall> FD FF (just syscall) ===\n")
    
    for sc, name in syscalls:
        payload = bytes([sc, FD, FF])
        test(f"{name} FD FF", payload)
    
    print("\n=== Pattern: <syscall> <arg> FF (no FD) ===\n")
    
    for sc, name in syscalls[:5]:
        payload = bytes([sc]) + encode_term(nil) + bytes([FF])
        test(f"{name}(nil) FF", payload)
    
    print("\n=== Simple raw patterns ===\n")
    
    patterns = [
        ("C9 FF", bytes([0xC9, FF])),
        ("C9 00 FF", bytes([0xC9, 0x00, FF])),
        ("C9 00 FE FE FF", bytes([0xC9, 0x00, FE, FE, FF])),
        ("C9 00 FE FE FD FF", bytes([0xC9, 0x00, FE, FE, FD, FF])),
        ("0E FF", bytes([0x0E, FF])),
        ("0E 00 FF", bytes([0x0E, 0x00, FF])),
        ("0E 00 FD FF", bytes([0x0E, 0x00, FD, FF])),
        ("08 FF", bytes([0x08, FF])),
        ("08 00 FF", bytes([0x08, 0x00, FF])),
        ("08 00 FD FF", bytes([0x08, 0x00, FD, FF])),
        ("02 FF", bytes([0x02, FF])),
        ("04 FF", bytes([0x04, FF])),
    ]
    
    for desc, payload in patterns:
        test(desc, payload)
    
    print("\n=== Test: backdoor with identity continuation ===\n")
    
    I = Lam(Var(0))
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(I) + bytes([FD, FF])
    test("backdoor(nil) I", payload)
    
    K = Lam(Lam(Var(1)))
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(K) + bytes([FD, FF])
    test("backdoor(nil) K", payload)
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(nil) + bytes([FD, FF])
    test("backdoor(nil) nil", payload)
    
    print("\n=== Test: use write (Var 2) as continuation ===\n")
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD, 0x02, FD, FF])
    test("backdoor(nil) write", payload)
    
    payload = bytes([0x0E, 0x00, FD, 0x02, FD, FF])
    test("echo(V0) write", payload)
    
    payload = bytes([0x04]) + encode_term(nil) + bytes([FD, 0x02, FD, FF])
    test("quote(nil) write", payload)


if __name__ == "__main__":
    main()
