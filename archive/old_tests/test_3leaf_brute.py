#!/usr/bin/env python3
"""
Brute force 3-leaf programs: ((Vi Vj) Vk) and (Vi (Vj Vk))
"""
from __future__ import annotations

import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE  
FF = 0xFF


def recv_raw(sock: socket.socket, timeout_s: float = 3.0) -> bytes:
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


def query(payload: bytes, timeout_s: float = 3.0) -> tuple[bytes, bool]:
    """Returns (output, timed_out)"""
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            out = recv_raw(sock, timeout_s=timeout_s)
            return out, False
    except socket.timeout:
        return b"", True
    except Exception as e:
        return str(e).encode(), False


def parse_result(data: bytes) -> str:
    """Parse and summarize the result."""
    if not data:
        return "EMPTY"
    if data == b"Invalid term!":
        return "INVALID"
    if data.startswith(b"Encoding failed"):
        return "ENCODING_FAILED"
    if FF not in data:
        return f"NO_FF: {data[:30]!r}"
    
    idx = data.index(FF)
    term_bytes = data[:idx]
    
    if len(term_bytes) < 2:
        return f"SHORT: {term_bytes.hex()}"
    
    if term_bytes[0] == 0x01:
        return "Left(...)"
    elif term_bytes[0] == 0x00:
        if len(term_bytes) >= 10:
            return f"Right({term_bytes[1:10].hex()}...)"
        return f"Right({term_bytes[1:].hex()})"
    else:
        return f"TERM: {term_bytes[:20].hex()}"


def build_3leaf_left(i: int, j: int, k: int) -> bytes:
    """Build ((Vi Vj) Vk) FF"""
    return bytes([i, j, FD, k, FD, FF])


def build_3leaf_right(i: int, j: int, k: int) -> bytes:
    """Build (Vi (Vj Vk)) FF"""
    return bytes([i, j, k, FD, FD, FF])


def main():
    print("=" * 70)
    print("3-Leaf Program Brute Force")
    print("=" * 70)
    
    syscalls = {
        1: "err",
        2: "write",
        4: "quote",
        5: "readdir",
        6: "name",
        7: "readfile",
        8: "syscall8",
        14: "echo",
        42: "towel",
        201: "backdoor",
    }
    
    interesting = [1, 2, 4, 5, 6, 7, 8, 14, 42, 201, 251, 252]
    
    print("\n[1] Testing ((V8 Varg) Vk) - syscall 8 with various args and continuations")
    print("-" * 70)
    
    results = []
    
    for j in interesting[:10]:
        for k in interesting[:10]:
            prog = build_3leaf_left(8, j, k)
            out, timeout = query(prog)
            result = "TIMEOUT" if timeout else parse_result(out)
            
            j_name = syscalls.get(j, f"V{j}")
            k_name = syscalls.get(k, f"V{k}")
            
            if result not in ["Right(03020", "Right(0302"]:
                results.append((j, k, result))
                print(f"  ((V8 {j_name}) {k_name}): {result}")
    
    print("\n[2] Testing ((V201 Varg) Vk) - backdoor with various args")
    print("-" * 70)
    
    for j in interesting[:10]:
        for k in interesting[:10]:
            prog = build_3leaf_left(201, j, k)
            out, timeout = query(prog)
            result = "TIMEOUT" if timeout else parse_result(out)
            
            j_name = syscalls.get(j, f"V{j}")
            k_name = syscalls.get(k, f"V{k}")
            
            if result not in ["Right(010200", "Right(0102"]:
                print(f"  ((V201 {j_name}) {k_name}): {result}")
    
    print("\n[3] Testing ((V14 Varg) Vk) - echo with various args")
    print("-" * 70)
    
    for j in interesting[:8]:
        for k in interesting[:8]:
            if j == 14 and k == 14:
                continue
            prog = build_3leaf_left(14, j, k)
            out, timeout = query(prog)
            result = "TIMEOUT" if timeout else parse_result(out)
            
            j_name = syscalls.get(j, f"V{j}")
            k_name = syscalls.get(k, f"V{k}")
            
            if "Left" in result or "TIMEOUT" in result or "ENCODING" in result:
                print(f"  ((V14 {j_name}) {k_name}): {result}")
    
    print("\n[4] Testing dangerous combinations (short timeout)")
    print("-" * 70)
    
    dangerous = [
        (201, 201, 201, "triple backdoor"),
        (8, 8, 8, "triple syscall8"),
        (14, 14, 14, "triple echo"),
        (201, 8, 201, "bd-sys8-bd"),
        (8, 201, 8, "sys8-bd-sys8"),
    ]
    
    for i, j, k, name in dangerous:
        prog = build_3leaf_left(i, j, k)
        out, timeout = query(prog, timeout_s=2.0)
        result = "TIMEOUT" if timeout else parse_result(out)
        print(f"  {name}: {result}")
    
    print("\n[5] Right-associative forms (Vi (Vj Vk))")
    print("-" * 70)
    
    for i in [8, 201, 14]:
        for j in interesting[:6]:
            for k in interesting[:6]:
                prog = build_3leaf_right(i, j, k)
                out, timeout = query(prog)
                result = "TIMEOUT" if timeout else parse_result(out)
                
                i_name = syscalls.get(i, f"V{i}")
                j_name = syscalls.get(j, f"V{j}")
                k_name = syscalls.get(k, f"V{k}")
                
                if result not in ["Right(030200", "Right(0302", "Right(010200", "EMPTY", "Right(01020"]:
                    print(f"  ({i_name} ({j_name} {k_name})): {result}")
    
    print("\n[6] Testing with nil and integers as args")
    print("-" * 70)
    
    nil = bytes([0x00, FE, FE])
    zero = bytes([0x00] + [FE] * 9)
    
    for i in [8, 201]:
        for arg_name, arg_bytes in [("nil", nil), ("zero", zero)]:
            for k in [4, 14, 201]:
                prog = bytes([i]) + arg_bytes + bytes([FD, k, FD, FF])
                out, timeout = query(prog)
                result = "TIMEOUT" if timeout else parse_result(out)
                
                i_name = syscalls.get(i, f"V{i}")
                k_name = syscalls.get(k, f"V{k}")
                
                print(f"  (({i_name} {arg_name}) {k_name}): {result}")
    
    print("\n" + "=" * 70)
    print("Scan complete")


if __name__ == "__main__":
    main()
