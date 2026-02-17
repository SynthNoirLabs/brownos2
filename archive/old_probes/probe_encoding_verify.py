#!/usr/bin/env python3
"""Verify integer encoding for values >= 256."""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
PORT = 61221

FD, FE, FF = 0xFD, 0xFE, 0xFF
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


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
    raise TypeError(f"Unsupported: {type(term)}")


def term_to_str(term: object) -> str:
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{term_to_str(term.body)}"
    if isinstance(term, App):
        return f"({term_to_str(term.f)} {term_to_str(term.x)})"
    return "?"


def encode_int_simple(n: int) -> object:
    """Simple bit-based encoding (only works for n < 256)."""
    expr: object = Var(0)
    for idx, weight in ((1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)):
        if n & weight:
            expr = App(Var(idx), expr)
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_int_proper(n: int) -> object:
    """Additive encoding (works for n >= 256)."""
    expr: object = Var(0)
    remaining = n
    weights = [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]
    for idx, weight in weights:
        while remaining >= weight:
            expr = App(Var(idx), expr)
            remaining -= weight
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def query(payload: bytes, timeout_s: float = 3.0) -> bytes:
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
                if FF in chunk:
                    break
            except socket.timeout:
                break
        return out


def main():
    print("=== Verify integer encoding ===\n")
    
    print("Testing simple encoding for known values:")
    for n in [0, 1, 11, 65, 88, 255]:
        term = encode_int_simple(n)
        bs = encode_term(term)
        print(f"  {n}: {bs.hex()} ({term_to_str(term)[:60]})")
    
    print("\nTesting proper encoding for values >= 256:")
    for n in [256, 257, 512, 1000]:
        term = encode_int_proper(n)
        bs = encode_term(term)
        print(f"  {n}: {bs.hex()} ({term_to_str(term)[:80]})")
    
    print("\n256 = 128 + 128 = V8(V8(V0))")
    term_256 = Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(
        App(Var(8), App(Var(8), Var(0)))
    )))))))))
    print(f"  Manual 256: {encode_term(term_256).hex()}")
    print(f"  proper 256: {encode_term(encode_int_proper(256)).hex()}")
    
    print("\nTesting name() syscall with both encodings:")
    
    for n in [0, 11, 256]:
        print(f"\n  ID {n}:")
        for enc_name, enc_fn in [("simple", encode_int_simple), ("proper", encode_int_proper)]:
            payload = bytes([0x06]) + encode_term(enc_fn(n)) + bytes([FD]) + QD + bytes([FD, FF])
            resp = query(payload)
            print(f"    {enc_name}: {resp.hex()[:60]}")
        time.sleep(0.2)


if __name__ == "__main__":
    main()
