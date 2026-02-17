#!/usr/bin/env python3
"""Focused 3-leaf tests with strict timeouts."""
from __future__ import annotations
import socket
import time
import signal

HOST = "wc3.wechall.net"
PORT = 61221
FD, FE, FF = 0xFD, 0xFE, 0xFF


class TimeoutError(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutError()


def query_safe(payload: bytes, timeout_s: float = 2.0) -> tuple[bytes, str]:
    try:
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(int(timeout_s + 1))
        
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            
            out = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                out += chunk
            
            signal.alarm(0)
            return out, "OK"
    except TimeoutError:
        return b"", "TIMEOUT"
    except socket.timeout:
        signal.alarm(0)
        return b"", "SOCKET_TIMEOUT"
    except Exception as e:
        signal.alarm(0)
        return b"", f"ERROR:{e}"


def parse(data: bytes) -> str:
    if not data:
        return "EMPTY"
    if data == b"Invalid term!":
        return "INVALID"
    if b"Encoding failed" in data:
        return "ENC_FAIL"
    if FF not in data:
        return f"NO_FF"
    
    idx = data.index(FF)
    t = data[:idx]
    if len(t) < 2:
        return f"SHORT"
    if t[0] == 0x01:
        return f"Left"
    if t[0] == 0x00:
        return f"Right"
    return f"OTHER"


def main():
    print("Focused 3-leaf tests")
    print("=" * 50)
    
    syscalls = {1:"err", 2:"wr", 4:"qt", 5:"rd", 6:"nm", 7:"rf", 8:"s8", 14:"ec", 42:"tw", 201:"bd"}
    
    print("\n[1] Syscall 8 with various args/continuations")
    
    tested = set()
    for j in [1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
        for k in [1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
            key = (8, j, k)
            if key in tested:
                continue
            tested.add(key)
            
            prog = bytes([8, j, FD, k, FD, FF])
            out, status = query_safe(prog, 2.0)
            result = status if status != "OK" else parse(out)
            
            if result not in ["Right"]:
                jn = syscalls.get(j, str(j))
                kn = syscalls.get(k, str(k))
                print(f"  ((s8 {jn}) {kn}): {result}")
    
    print("\n[2] Backdoor with various args/continuations")
    
    for j in [1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
        for k in [1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
            prog = bytes([201, j, FD, k, FD, FF])
            out, status = query_safe(prog, 2.0)
            result = status if status != "OK" else parse(out)
            
            if result not in ["Right"]:
                jn = syscalls.get(j, str(j))
                kn = syscalls.get(k, str(k))
                print(f"  ((bd {jn}) {kn}): {result}")
    
    print("\n[3] Echo with args/continuations")
    
    for j in [1, 2, 4, 5, 6, 7, 8, 201]:
        for k in [1, 2, 4, 5, 6, 7, 8, 14, 201]:
            prog = bytes([14, j, FD, k, FD, FF])
            out, status = query_safe(prog, 2.0)
            result = status if status != "OK" else parse(out)
            
            if result in ["Left", "TIMEOUT", "ENC_FAIL", "SOCKET_TIMEOUT"]:
                jn = syscalls.get(j, str(j))
                kn = syscalls.get(k, str(k))
                print(f"  ((ec {jn}) {kn}): {result}")
    
    print("\n[4] Right-assoc forms")
    
    for i in [8, 201, 14]:
        for j in [4, 8, 14, 201]:
            for k in [4, 8, 14, 201]:
                prog = bytes([i, j, k, FD, FD, FF])
                out, status = query_safe(prog, 2.0)
                result = status if status != "OK" else parse(out)
                
                if result in ["Left", "TIMEOUT", "ENC_FAIL"]:
                    in_ = syscalls.get(i, str(i))
                    jn = syscalls.get(j, str(j))
                    kn = syscalls.get(k, str(k))
                    print(f"  ({in_} ({jn} {kn})): {result}")
    
    print("\n[5] High vars (V251, V252)")
    
    for i in [8, 14, 201]:
        for j in [251, 252]:
            for k in [4, 14]:
                prog = bytes([i, j, FD, k, FD, FF])
                out, status = query_safe(prog, 2.0)
                result = status if status != "OK" else parse(out)
                
                in_ = syscalls.get(i, str(i))
                kn = syscalls.get(k, str(k))
                print(f"  (({in_} V{j}) {kn}): {result}")
    
    print("\n" + "=" * 50)


if __name__ == "__main__":
    main()
