#!/usr/bin/env python3
"""
Targeted 3-leaf probes using specific syscall indices.
If "3 leafs" means 3 variable references, try combinations of syscall numbers.
"""
from __future__ import annotations

import json
import socket
import time
from pathlib import Path

from solve_brownos_answer import (
    App, Lam, Var, FF, QD,
    decode_byte_term, decode_bytes_list, decode_either,
    encode_term, parse_term,
)


HOST = "wc3.wechall.net"
PORT = 61221

QD_TERM = parse_term(QD)


def query_raw(payload: bytes, timeout_s: float = 3.0) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        sock.settimeout(timeout_s)
        out = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                out += chunk
                if FF in chunk:
                    break
        except socket.timeout:
            pass
        return out


def classify_response(resp: bytes) -> tuple[str, str, bool]:
    if not resp:
        return "silent", "No response", False
    if resp.startswith(b"Invalid term!"):
        return "invalid", "Invalid term!", False
    if resp.startswith(b"Encoding failed!"):
        return "encoding_failed", "Encoding failed!", True
    if FF not in resp:
        return "no_ff", resp[:100].decode("utf-8", "replace"), True
    try:
        term = parse_term(resp)
        tag, payload = decode_either(term)
        if tag == "Right":
            code = decode_byte_term(payload)
            return "either_right", f"Right({code})", code not in (1, 6)
        bs = decode_bytes_list(payload)
        return "either_left", f"Left({len(bs)}b:{bs[:60].decode('utf-8','replace')!r})", True
    except Exception as e:
        return "other", str(e)[:80], True


def run_probe(name: str, term: object) -> dict:
    payload = encode_term(term) + bytes([FF])
    try:
        resp = query_raw(payload)
    except Exception as e:
        return {"name": name, "error": str(e)}
    
    cls, detail, interesting = classify_response(resp)
    status = "***" if interesting else ""
    print(f"  {name}: {cls} - {detail} {status}")
    if interesting:
        print(f"    Hex: {resp[:60].hex()}")
    return {"name": name, "result": detail, "interesting": interesting, "hex": resp.hex()}


def main():
    results = []
    
    # Key syscall indices
    SYS8 = 0x08    # restricted
    ECHO = 0x0E    # echo
    BD = 0xC9      # backdoor (201)
    
    print("=" * 70)
    print("3-leaf patterns with syscall indices")
    print("=" * 70)
    
    # Pattern: (Va (Vb Vc)) where a,b,c are syscall numbers
    patterns_right_assoc = [
        (BD, ECHO, SYS8),   # (backdoor (echo syscall8))
        (BD, SYS8, ECHO),   # (backdoor (syscall8 echo))
        (ECHO, BD, SYS8),   # (echo (backdoor syscall8))
        (ECHO, SYS8, BD),   # (echo (syscall8 backdoor))
        (SYS8, BD, ECHO),   # (syscall8 (backdoor echo))
        (SYS8, ECHO, BD),   # (syscall8 (echo backdoor))
    ]
    
    for a, b, c in patterns_right_assoc:
        term = App(Var(a), App(Var(b), Var(c)))
        full = App(term, QD_TERM)
        results.append(run_probe(f"({a:02x}_({b:02x}_{c:02x}))_QD", full))
    
    print("\n" + "=" * 70)
    print("3-leaf patterns: ((Va Vb) Vc) with syscalls")
    print("=" * 70)
    
    patterns_left_assoc = [
        (BD, ECHO, SYS8),
        (BD, SYS8, ECHO),
        (ECHO, BD, SYS8),
        (ECHO, SYS8, BD),
        (SYS8, BD, ECHO),
        (SYS8, ECHO, BD),
    ]
    
    for a, b, c in patterns_left_assoc:
        term = App(App(Var(a), Var(b)), Var(c))
        full = App(term, QD_TERM)
        results.append(run_probe(f"(({a:02x}_{b:02x})_{c:02x})_QD", full))
    
    print("\n" + "=" * 70)
    print("3-leaf with QD incorporated (QD as one of the leaves)")
    print("=" * 70)
    
    # What if QD itself is part of the 3-leaf structure?
    # QD internally has variables, so we need fresh patterns
    
    # Try: ((syscall8 backdoor_result) QD) but build backdoor inline
    # That would be > 3 leaves though...
    
    # Simple 3-leaf with Var(4) = quote syscall
    QUOTE = 0x04
    WRITE = 0x02
    
    more_patterns = [
        (SYS8, QUOTE, WRITE),
        (BD, QUOTE, SYS8),
        (ECHO, QUOTE, SYS8),
        (QUOTE, ECHO, SYS8),
        (WRITE, ECHO, SYS8),
    ]
    
    for a, b, c in more_patterns:
        term = App(App(Var(a), Var(b)), Var(c))
        full = App(term, QD_TERM)
        results.append(run_probe(f"(({a:02x}_{b:02x})_{c:02x})_QD_extra", full))
    
    print("\n" + "=" * 70)
    print("Try 3-leaf inside lambda (scoped indices)")
    print("=" * 70)
    
    # λ.((Va Vb) Vc) where a,b,c are relative to the lambda
    # Under 1 lambda, syscall indices shift by 1
    
    for a, b, c in [(SYS8+1, ECHO+1, BD+1), (BD+1, ECHO+1, SYS8+1)]:
        inner = App(App(Var(a), Var(b)), Var(c))
        term = Lam(inner)
        full = App(term, QD_TERM)
        results.append(run_probe(f"lam_(({a}_{b})_{c})_QD", full))
    
    print("\n" + "=" * 70)
    print("Direct byte payloads (hand-crafted minimal terms)")
    print("=" * 70)
    
    # Try some minimal hand-crafted payloads
    # 3 bytes + FD + FD + QD + FD + FF
    
    minimal_payloads = [
        # ((8 14) 201) QD - 3 leaves
        bytes([SYS8, ECHO, 0xFD, BD, 0xFD]) + QD + bytes([0xFD, FF]),
        # ((201 14) 8) QD
        bytes([BD, ECHO, 0xFD, SYS8, 0xFD]) + QD + bytes([0xFD, FF]),
        # (8 (14 201)) QD
        bytes([SYS8, ECHO, BD, 0xFD, 0xFD]) + QD + bytes([0xFD, FF]),
        # (201 (14 8)) QD
        bytes([BD, ECHO, SYS8, 0xFD, 0xFD]) + QD + bytes([0xFD, FF]),
    ]
    
    for i, payload in enumerate(minimal_payloads):
        try:
            resp = query_raw(payload)
            cls, detail, interesting = classify_response(resp)
            status = "***" if interesting else ""
            print(f"  minimal_{i}: {cls} - {detail} {status}")
            results.append({"name": f"minimal_{i}", "payload": payload.hex(), "result": detail})
        except Exception as e:
            print(f"  minimal_{i}: error - {e}")
        time.sleep(0.2)
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    interesting = [r for r in results if r.get("interesting")]
    print(f"Found {len(interesting)} interesting results")
    for r in interesting:
        print(f"  {r['name']}: {r.get('result', r.get('error', '?'))}")
    
    Path("3leaf_targeted_results.json").write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
