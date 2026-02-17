#!/usr/bin/env python3
"""
Quick 3-leaf exhaustive probe using IPv4.
"""
from __future__ import annotations

import socket
import time
import itertools

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
HOST = "82.165.133.222"  # IPv4
PORT = 61221


def query_ipv4(payload: bytes, timeout_s: float = 3.0) -> bytes:
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            sock.settimeout(timeout_s)
            out = b''
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out += chunk
                    if 0xFF in chunk:
                        break
                except socket.timeout:
                    break
            return out
    except Exception:
        return b''


def classify(resp: bytes) -> tuple[str, str]:
    if not resp:
        return ("silent", "")
    if resp.startswith(b"Invalid"):
        return ("invalid", "")
    if resp.startswith(b"Encoding failed"):
        return ("encfail", "")
    if FF not in resp:
        return ("noterm", resp[:20].hex())
    
    try:
        term = parse_term(resp)
        try:
            tag, payload = decode_either(term)
            if tag == "Right":
                code = decode_byte_term(payload)
                return ("R", str(code))
            else:
                try:
                    bs = decode_bytes_list(payload)
                    return ("L", bs.decode('utf-8', 'replace')[:80])
                except:
                    return ("L_nb", "")
        except:
            return ("term", "")
    except:
        return ("err", "")


def main():
    print("=" * 60)
    print("3-LEAF EXHAUSTIVE: ((a b) c)")
    print("=" * 60)
    
    # Key indices
    interesting = [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201, 252]
    
    found = []
    tested = 0
    
    for a, b, c in itertools.product(interesting, repeat=3):
        term = App(App(Var(a), Var(b)), Var(c))
        payload = encode_term(term) + bytes([FF])
        
        resp = query_ipv4(payload, timeout_s=2.0)
        cat, detail = classify(resp)
        
        tested += 1
        
        # Print interesting results
        if cat == "L":
            print(f"*** (({a} {b}) {c}): LEFT - {detail[:50]} ***")
            found.append(((a, b, c), detail))
        elif cat == "R" and detail not in ("1", "6", "2", "7"):
            print(f"(({a} {b}) {c}): Right({detail})")
        elif cat not in ("silent", "invalid", "R"):
            print(f"(({a} {b}) {c}): {cat}")
        
        # Progress
        if tested % 50 == 0:
            print(f"... tested {tested}...", flush=True)
        
        time.sleep(0.05)  # Rate limit
    
    print(f"\nTotal tested: {tested}")
    print(f"Found {len(found)} LEFT results")
    
    # Also test (a (b c)) pattern
    print("\n" + "=" * 60)
    print("3-LEAF RIGHT-ASSOC: (a (b c))")
    print("=" * 60)
    
    for a, b, c in itertools.product(interesting, repeat=3):
        term = App(Var(a), App(Var(b), Var(c)))
        payload = encode_term(term) + bytes([FF])
        
        resp = query_ipv4(payload, timeout_s=2.0)
        cat, detail = classify(resp)
        
        if cat == "L":
            print(f"*** ({a} ({b} {c})): LEFT - {detail[:50]} ***")
        elif cat == "R" and detail not in ("1", "6", "2", "7"):
            print(f"({a} ({b} {c})): Right({detail})")
        elif cat not in ("silent", "invalid", "R"):
            print(f"({a} ({b} {c})): {cat}")
        
        time.sleep(0.05)
    
    print("\nDone!")


if __name__ == "__main__":
    main()
