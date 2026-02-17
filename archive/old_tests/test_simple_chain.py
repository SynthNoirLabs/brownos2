#!/usr/bin/env python3
"""
Simpler chained syscall test - use raw bytes more directly.
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


def recv_raw(sock: socket.socket, timeout_s: float = 5.0) -> bytes:
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


def query(payload: bytes, retries: int = 3, timeout_s: float = 8.0) -> bytes:
    delay = 0.5
    last_err: Exception | None = None
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_raw(sock, timeout_s=timeout_s)
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed to query") from last_err


def test_basic_syscall():
    """Test a simple syscall works with our setup."""
    print("[0] Basic syscall 0x2A test")
    payload = bytes([0x2A, 0x00, FD]) + QD + bytes([FD, FF])
    out = query(payload)
    print(f"  Output: {out[:50]!r}...")
    return b'\xff' in out


def test_chained_v1():
    """
    Test: echo(nil) -> syscall 8
    
    Program structure in CPS:
    ((echo nil) (λresult. ((syscall8 result) QD)))
    
    In raw form with de Bruijn:
    - At top level: echo = 0x0E, nil = λλ0 = 00 FE FE
    - Continuation: λ. ((09 0) shifted_QD)
      - Under the lambda, syscall8 is at index 9 (was 8)
      - result is at index 0
    """
    print("\n[1] Chained: echo(nil) → syscall8 (without using echoed result)")
    
    nil = bytes([0x00, FE, FE])
    syscall8_under_lambda = bytes([0x09])
    result_var = bytes([0x00])
    
    shifted_qd = bytes([0x06, 0x01, FD, 0x01, 0x06, 0x01, FD, 0x04, FD, FE, FD, 0x03, FD, FE, FD, FE])
    
    cont = result_var + syscall8_under_lambda + result_var + bytes([FD]) + shifted_qd + bytes([FD])
    cont += bytes([FE])
    
    program = bytes([0x0E]) + nil + bytes([FD]) + cont + bytes([FD, FF])
    print(f"  Payload: {program.hex()}")
    out = query(program)
    print(f"  Output: {out!r}")
    return out


def test_direct_syscall8():
    """Direct syscall 8 with various arguments."""
    print("\n[2] Direct syscall 8 tests")
    
    tests = [
        ("nil", bytes([0x00, FE, FE])),
        ("V0", bytes([0x00])),
        ("V251", bytes([0xFB])),
        ("V252", bytes([0xFC])),
    ]
    
    for name, arg in tests:
        payload = bytes([0x08]) + arg + bytes([FD]) + QD + bytes([FD, FF])
        out = query(payload)
        ff_idx = out.find(0xFF) if 0xFF in out else -1
        if ff_idx >= 0:
            print(f"  {name}: {out[:ff_idx+1].hex()}")
        else:
            print(f"  {name}: {out!r}")


def test_echo_then_syscall():
    """
    More careful chained test.
    
    Standard CPS call: ((syscall arg) continuation)
    
    For echo → syscall8:
    ((0x0E arg) (λecho_result. ((0x08 echo_result) continuation2)))
    
    Where continuation2 must itself be a valid continuation for syscall8.
    
    Let's use QD as the inner continuation, but shifted appropriately.
    """
    print("\n[3] Chained echo → syscall8 with proper CPS")
    
    qd_bytes = list(QD)
    shifted_qd = bytes([b + 1 if b < FD else b for b in qd_bytes])
    print(f"  Original QD: {QD.hex()}")
    print(f"  Shifted QD (+1): {shifted_qd.hex()}")
    
    arg = bytes([0x00, FE, FE])
    
    inner_call = bytes([0x09, 0x00, FD]) + shifted_qd + bytes([FD])
    continuation = inner_call + bytes([FE])
    
    program = bytes([0x0E]) + arg + bytes([FD]) + continuation + bytes([FD, FF])
    print(f"  Full program: {program.hex()}")
    
    out = query(program)
    print(f"  Output: {out!r}")
    return out


def test_write_directly():
    """Test write syscall works."""
    print("\n[4] Direct write test")
    
    h_byte = Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(App(Var(7), App(Var(4), App(Var(3), Var(0)))))))))))))
    
    print("  (skipping complex encoding)")


def main():
    print("=" * 60)
    print("Simple Chained Syscall Tests")
    print("=" * 60)
    
    if not test_basic_syscall():
        print("Basic test failed!")
        return
    
    test_direct_syscall8()
    test_chained_v1()
    test_echo_then_syscall()
    
    print("\n[5] Try different echo argument with chain")
    
    arg = bytes([0xFB])
    qd_bytes = list(QD)
    shifted_qd = bytes([b + 1 if b < FD else b for b in qd_bytes])
    
    inner_call = bytes([0x09, 0x00, FD]) + shifted_qd + bytes([FD])
    continuation = inner_call + bytes([FE])
    
    program = bytes([0x0E]) + arg + bytes([FD]) + continuation + bytes([FD, FF])
    print(f"  Program (echo V251 → syscall8): {program.hex()}")
    
    out = query(program)
    print(f"  Output: {out!r}")
    
    print("\n" + "=" * 60)


class Var:
    def __init__(self, i): self.i = i
class Lam:
    def __init__(self, body): self.body = body
class App:
    def __init__(self, f, x): self.f = f; self.x = x


if __name__ == "__main__":
    main()
