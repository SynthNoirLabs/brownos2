#!/usr/bin/env python3
"""
SYSTEMATIC 3-LEAF SEARCH

"3 leafs" = 3 Var nodes in the AST.

The simplest 3-leaf patterns are:
1. (V V V) = two applications: ((V V) V) or (V (V V))
2. λ.(V V V) = lambda with 3 vars inside
3. etc.

Let's focus on the pattern: ((syscall8 arg) continuation)
This already has at least 2 vars (8 and continuation).
If arg is a single Var, that's 3 leafs!

So we need: ((8 V) QD) where QD is replaced by a single Var.

But QD is complex... unless we use a simpler continuation.
"""
from __future__ import annotations

import socket
import time

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    decode_byte_term,
    decode_bytes_list,
    decode_either,
    encode_term,
    parse_term,
)
from solve_brownos_answer import QD as QD_BYTES

FF = 0xFF
NIL_TERM = Lam(Lam(Var(0)))
QD_TERM = parse_term(QD_BYTES)
I_TERM = Lam(Var(0))


def recv_all(sock, timeout_s):
    sock.settimeout(timeout_s)
    out = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
    return out


def query_raw(payload, timeout_s=4.0, host="82.165.133.222"):
    with socket.create_connection((host, 61221), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return recv_all(sock, timeout_s)


def classify(resp):
    if not resp:
        return "<silent>"
    if resp.startswith(b"Invalid term!"):
        return "Invalid term!"
    if resp.startswith(b"Encoding failed!"):
        return "Encoding failed!"
    if FF not in resp:
        return f"<no FF: {resp[:50].hex()}>"
    try:
        term = parse_term(resp)
        tag, payload = decode_either(term)
        if tag == "Right":
            return f"Right({decode_byte_term(payload)})"
        else:
            try:
                return f"Left('{decode_bytes_list(payload).decode()[:40]}')"
            except:
                return "Left(<non-bytes>)"
    except Exception as e:
        return f"<parse error: {e}>"


def count_vars(term):
    if isinstance(term, Var):
        return 1
    if isinstance(term, Lam):
        return count_vars(term.body)
    if isinstance(term, App):
        return count_vars(term.f) + count_vars(term.x)
    return 0


def main():
    print("=" * 70)
    print("SYSTEMATIC 3-LEAF SEARCH")
    print("=" * 70)
    
    print("\n--- Pattern: ((8 Var(x)) Var(y)) - exactly 3 Vars ---")
    
    interesting = []
    
    for x in range(256):
        if x in (0xFD, 0xFE, 0xFF):
            continue
        for y in range(256):
            if y in (0xFD, 0xFE, 0xFF):
                continue
            
            term = App(App(Var(8), Var(x)), Var(y))
            assert count_vars(term) == 3
            
            payload = encode_term(term) + bytes([FF])
            resp = query_raw(payload, timeout_s=1.5)
            result = classify(resp)
            
            if result != "Right(6)" and result != "<silent>":
                interesting.append((x, y, result))
                print(f"  ((8 {x}) {y}): {result} ***")
            
            if x < 20 and y < 20:
                pass
            
            time.sleep(0.05)
        
        if x % 50 == 0:
            print(f"  Progress: x={x}/252...")
    
    print(f"\nInteresting results: {len(interesting)}")
    for x, y, r in interesting:
        print(f"  ((8 {x}) {y}): {r}")
    
    print("\n--- Pattern: ((x 8) y) ---")
    for x in [0, 1, 2, 8, 0xC9, 0x0E]:
        for y in [0, 1, 2, 8, 0xC9, 0x0E]:
            if x in (0xFD, 0xFE, 0xFF) or y in (0xFD, 0xFE, 0xFF):
                continue
            term = App(App(Var(x), Var(8)), Var(y))
            payload = encode_term(term) + bytes([FF])
            resp = query_raw(payload, timeout_s=1.5)
            result = classify(resp)
            if result not in ["<silent>", "Right(1)"]:
                print(f"  (({x} 8) {y}): {result}")
            time.sleep(0.05)
    
    print("\n--- Pattern: (8 (x y)) ---")
    for x in [0, 1, 2, 8, 0xC9, 0x0E]:
        for y in [0, 1, 2, 8, 0xC9, 0x0E]:
            if x in (0xFD, 0xFE, 0xFF) or y in (0xFD, 0xFE, 0xFF):
                continue
            term = App(Var(8), App(Var(x), Var(y)))
            payload = encode_term(term) + bytes([FF])
            resp = query_raw(payload, timeout_s=1.5)
            result = classify(resp)
            if result not in ["<silent>"]:
                print(f"  (8 ({x} {y})): {result}")
            time.sleep(0.05)
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
