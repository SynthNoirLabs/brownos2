#!/usr/bin/env python3
"""
Check all error strings and decode them properly.
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


def encode_term(term) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unknown term type: {type(term)}")


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
            deadline = time.time() + timeout_s
            while time.time() < deadline:
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


nil = Lam(Lam(Var(0)))


def make_church(n):
    expr = Var(0)
    for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def decode_string_response(data):
    """Try to decode a string response from the wire format."""
    # String format: cons-encoded list where each element is a Church-encoded byte
    # For simplicity, just show the raw hex
    return data.hex()


def test_error_strings():
    """
    Syscall 1 returns error string for given code.
    Let's check codes 0-10.
    """
    print("=" * 70)
    print("ERROR STRINGS (syscall 1)")
    print("=" * 70)
    
    # Use QD to print the result as a string
    # syscall1(n) returns Either; QD decodes Either and prints string
    
    for n in range(0, 12):
        # ((syscall1 n) QD)
        payload = bytes([0x01]) + encode_term(make_church(n)) + bytes([FD]) + QD + bytes([FD, FF])
        resp = query(payload, timeout_s=2)
        
        # Interpret the response
        print(f"  error({n}): raw={resp.hex()[:40] if resp else 'empty'} text={''.join(chr(b) if 32 <= b < 127 else '.' for b in resp)}")
        time.sleep(0.1)


def test_readdir_root():
    """
    Let's verify readdir of root still works.
    """
    print("\n" + "=" * 70)
    print("READDIR /")
    print("=" * 70)
    
    # readdir(0) = list root
    payload = bytes([0x05]) + encode_term(make_church(0)) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  readdir(0): {resp[:100]}")


def test_name_special():
    """
    Check name() for some special IDs.
    """
    print("\n" + "=" * 70)
    print("NAME SYSCALL")
    print("=" * 70)
    
    for n in [0, 1, 2, 256, 257, 512]:
        payload = bytes([0x06]) + encode_term(make_church(n)) + bytes([FD]) + QD + bytes([FD, FF])
        resp = query(payload, timeout_s=2)
        # Try to decode as string
        text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in resp)
        print(f"  name({n}): {text[:50]} (raw: {resp.hex()[:40] if resp else 'empty'})")
        time.sleep(0.1)


def test_towel_for_reference():
    """
    The towel syscall (0x2A) as reference.
    """
    print("\n" + "=" * 70)
    print("TOWEL SYSCALL (0x2A) - REFERENCE")
    print("=" * 70)
    
    payload = bytes([0x2A]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload, timeout_s=2)
    print(f"  towel: {resp}")


def test_syscall8_decode_response():
    """
    Decode syscall 8's response more carefully.
    """
    print("\n" + "=" * 70)
    print("SYSCALL 8 RESPONSE ANALYSIS")
    print("=" * 70)
    
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload, timeout_s=2)
    print(f"  syscall8(nil) via QD: {resp}")
    print(f"  hex: {resp.hex() if resp else 'empty'}")
    
    # Now try without QD - just get raw Either
    # We need a continuation that writes the raw Either
    test_term = Lam(
        App(
            App(Var(0),  # result (Either)
                Lam(App(App(Var(4), Var(0)), nil))  # Left handler: write payload
            ),
            Lam(App(App(Var(4), Var(0)), nil))  # Right handler: write error
        )
    )
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=2)
    print(f"  syscall8(nil) raw write: {resp}")
    print(f"  hex: {resp.hex() if resp else 'empty'}")
    
    # The "Permission denied" error is code 6
    # Let's see if we can get the error string
    print("\n  Error string for code 6:")
    payload = bytes([0x01]) + encode_term(make_church(6)) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload, timeout_s=2)
    print(f"  error(6): {resp}")


def main():
    test_error_strings()
    time.sleep(0.3)
    
    test_readdir_root()
    time.sleep(0.3)
    
    test_name_special()
    time.sleep(0.3)
    
    test_towel_for_reference()
    time.sleep(0.3)
    
    test_syscall8_decode_response()


if __name__ == "__main__":
    main()
