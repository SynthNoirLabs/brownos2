#!/usr/bin/env python3
"""
FOCUSED 3-LEAF SEARCH based on hints.

Hints tell us:
1. "start with 00 FE FE" - nil is involved
2. backdoor returns A and B
3. Echo shifts indices

So 3 leafs should involve: 8, and something related to backdoor/echo.
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


def query_raw(payload, timeout_s=3.0, host="82.165.133.222"):
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


def main():
    print("=" * 70)
    print("FOCUSED 3-LEAF SEARCH")
    print("=" * 70)
    
    syscalls_of_interest = [
        (8, "syscall8"),
        (0xC9, "backdoor"),
        (0x0E, "echo"),
        (4, "quote"),
        (2, "write"),
    ]
    
    print("\n--- Pattern: ((8 x) y) with x,y from important syscalls ---")
    
    for x, xname in syscalls_of_interest:
        for y, yname in syscalls_of_interest:
            term = App(App(Var(8), Var(x)), Var(y))
            payload = encode_term(term) + bytes([FF])
            resp = query_raw(payload)
            result = classify(resp)
            print(f"  ((8 {xname}) {yname}): {result}")
            time.sleep(0.15)
    
    print("\n--- Pattern: ((C9 x) y) ---")
    for x, xname in syscalls_of_interest:
        for y, yname in syscalls_of_interest:
            term = App(App(Var(0xC9), Var(x)), Var(y))
            payload = encode_term(term) + bytes([FF])
            resp = query_raw(payload)
            result = classify(resp)
            if "silent" not in result:
                print(f"  ((C9 {xname}) {yname}): {result}")
            time.sleep(0.15)
    
    print("\n--- Pattern: ((E x) y) ---")
    for x, xname in syscalls_of_interest:
        for y, yname in syscalls_of_interest:
            term = App(App(Var(0x0E), Var(x)), Var(y))
            payload = encode_term(term) + bytes([FF])
            resp = query_raw(payload)
            result = classify(resp)
            if "silent" not in result:
                print(f"  ((E {xname}) {yname}): {result}")
            time.sleep(0.15)
    
    print("\n--- Pattern: (x (y 8)) ---")
    for x, xname in syscalls_of_interest:
        for y, yname in syscalls_of_interest:
            term = App(Var(x), App(Var(y), Var(8)))
            payload = encode_term(term) + bytes([FF])
            resp = query_raw(payload)
            result = classify(resp)
            if "silent" not in result:
                print(f"  ({xname} ({yname} 8)): {result}")
            time.sleep(0.15)
    
    print("\n--- Test with nil as one component ---")
    terms = [
        ("((8 nil) C9)", App(App(Var(8), NIL_TERM), Var(0xC9))),
        ("((8 nil) E)", App(App(Var(8), NIL_TERM), Var(0x0E))),
        ("((8 C9) nil)", App(App(Var(8), Var(0xC9)), NIL_TERM)),
        ("((8 E) nil)", App(App(Var(8), Var(0x0E)), NIL_TERM)),
        ("((C9 8) nil)", App(App(Var(0xC9), Var(8)), NIL_TERM)),
        ("((E 8) nil)", App(App(Var(0x0E), Var(8)), NIL_TERM)),
        ("(8 (C9 nil))", App(Var(8), App(Var(0xC9), NIL_TERM))),
        ("(8 (E nil))", App(Var(8), App(Var(0x0E), NIL_TERM))),
        ("(C9 (8 nil))", App(Var(0xC9), App(Var(8), NIL_TERM))),
        ("(E (8 nil))", App(Var(0x0E), App(Var(8), NIL_TERM))),
    ]
    
    for name, term in terms:
        payload = encode_term(term) + bytes([FF])
        resp = query_raw(payload)
        result = classify(resp)
        print(f"  {name}: {result}")
        time.sleep(0.15)
    
    print("\n--- Extra: Raw byte patterns with 3 Vars ---")
    patterns = [
        ("08 C9 FD E FD", bytes([0x08, 0xC9, 0xFD, 0x0E, 0xFD, 0xFF])),
        ("08 E FD C9 FD", bytes([0x08, 0x0E, 0xFD, 0xC9, 0xFD, 0xFF])),
        ("C9 08 FD E FD", bytes([0xC9, 0x08, 0xFD, 0x0E, 0xFD, 0xFF])),
        ("C9 E FD 08 FD", bytes([0xC9, 0x0E, 0xFD, 0x08, 0xFD, 0xFF])),
        ("E 08 FD C9 FD", bytes([0x0E, 0x08, 0xFD, 0xC9, 0xFD, 0xFF])),
        ("E C9 FD 08 FD", bytes([0x0E, 0xC9, 0xFD, 0x08, 0xFD, 0xFF])),
    ]
    
    for name, payload in patterns:
        resp = query_raw(payload)
        result = classify(resp)
        print(f"  {name}: {result}")
        time.sleep(0.15)
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
