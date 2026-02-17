#!/usr/bin/env python3
"""
AUTHOR HINT: "My record is 3 leafs IIRC"

Let's enumerate ALL possible programs with exactly 3 Var nodes (leafs).

Possible structures:
- ((a b) c)  - 2 apps, 3 vars
- (a (b c))  - 2 apps, 3 vars
- λ.((a b) c) - 1 lam, 2 apps, 3 vars
- λ.(a (b c)) - 1 lam, 2 apps, 3 vars
- λ.λ.((a b) c) - 2 lams, 2 apps, 3 vars

For each structure, enumerate interesting variable indices.

Key syscalls: 8 (mystery), 14 (echo), 201 (backdoor), 2 (write), 4 (quote), etc.

The pattern ((syscall arg) cont) with 3 vars means:
- syscall = Var(a)
- arg = Var(b)  
- cont = Var(c)
"""
from __future__ import annotations

import socket
import time
import itertools
from typing import Iterator

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
NIL_TERM: object = Lam(Lam(Var(0)))
QD_TERM: object = parse_term(QD_BYTES)


def term_to_string(term: object, depth: int = 0) -> str:
    if depth > 15:
        return "..."
    if isinstance(term, Var):
        return f"{term.i}"
    if isinstance(term, Lam):
        return f"λ.{term_to_string(term.body, depth+1)}"
    if isinstance(term, App):
        return f"({term_to_string(term.f, depth+1)} {term_to_string(term.x, depth+1)})"
    return str(term)


def count_vars(term: object) -> int:
    if isinstance(term, Var):
        return 1
    if isinstance(term, Lam):
        return count_vars(term.body)
    if isinstance(term, App):
        return count_vars(term.f) + count_vars(term.x)
    return 0


def recv_all(sock: socket.socket, timeout_s: float) -> bytes:
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


def query_raw(payload: bytes, timeout_s: float = 3.0) -> bytes:
    try:
        with socket.create_connection(("wc3.wechall.net", 61221), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            return recv_all(sock, timeout_s)
    except Exception:
        return b""


def classify_response(resp: bytes) -> tuple[str, str]:
    """Returns (category, detail)."""
    if not resp:
        return ("silent", "")
    if resp.startswith(b"Invalid term!"):
        return ("invalid", "")
    if resp.startswith(b"Encoding failed!"):
        return ("encfail", "")
    if resp.startswith(b"Term too big!"):
        return ("toobig", "")
    if FF not in resp:
        return ("noterm", resp[:20].hex())
    
    try:
        term = parse_term(resp)
        try:
            tag, payload = decode_either(term)
            if tag == "Right":
                code = decode_byte_term(payload)
                return ("right", str(code))
            else:
                try:
                    bs = decode_bytes_list(payload)
                    txt = bs.decode('utf-8', 'replace')
                    return ("left", txt[:80])
                except:
                    return ("left_nb", term_to_string(payload)[:60])
        except:
            return ("term", term_to_string(term)[:60])
    except:
        return ("err", resp[:20].hex())


def test_3leaf_cps_pattern() -> None:
    """
    Test the CPS pattern ((a b) c) with 3 var indices.
    This is the standard syscall pattern.
    """
    print("=" * 70)
    print("3-LEAF CPS PATTERN: ((a b) c) FF")
    print("=" * 70)
    
    # Interesting indices to try
    # Syscalls: 1,2,4,5,6,7,8,14,42,201
    # Low indices (bound vars in lambdas): 0,1,2
    # High indices (near reserved): 250,251,252
    
    interesting = [0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 42, 201, 250, 251, 252]
    
    results = {}
    tested = 0
    
    print("\nSearching for non-trivial results...")
    
    for a, b, c in itertools.product(interesting, repeat=3):
        term = App(App(Var(a), Var(b)), Var(c))
        payload = encode_term(term) + bytes([FF])
        
        resp = query_raw(payload, timeout_s=2.0)
        cat, detail = classify_response(resp)
        
        # Only record interesting results
        if cat not in ("silent", "invalid", "right"):
            key = f"(({a} {b}) {c})"
            results[key] = (cat, detail)
            print(f"  {key}: {cat} - {detail[:50]}")
        elif cat == "right" and detail != "1" and detail != "6":
            # Non-standard error code
            key = f"(({a} {b}) {c})"
            results[key] = (cat, detail)
            print(f"  {key}: Right({detail})")
        elif cat == "left":
            # Success case!
            key = f"(({a} {b}) {c})"
            results[key] = (cat, detail)
            print(f"  *** {key}: LEFT - {detail[:50]} ***")
        
        tested += 1
        if tested % 100 == 0:
            time.sleep(0.1)
    
    print(f"\nTested {tested} combinations")
    print(f"Found {len(results)} interesting results")


def test_3leaf_right_assoc_pattern() -> None:
    """
    Test the right-associative pattern (a (b c)).
    """
    print("\n" + "=" * 70)
    print("3-LEAF RIGHT-ASSOC PATTERN: (a (b c)) FF")
    print("=" * 70)
    
    interesting = [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201, 252]
    
    results = {}
    tested = 0
    
    print("\nSearching for non-trivial results...")
    
    for a, b, c in itertools.product(interesting, repeat=3):
        term = App(Var(a), App(Var(b), Var(c)))
        payload = encode_term(term) + bytes([FF])
        
        resp = query_raw(payload, timeout_s=2.0)
        cat, detail = classify_response(resp)
        
        if cat not in ("silent", "invalid", "right") or (cat == "right" and detail not in ("1", "6")):
            key = f"({a} ({b} {c}))"
            results[key] = (cat, detail)
            if cat == "left":
                print(f"  *** {key}: LEFT - {detail[:50]} ***")
            else:
                print(f"  {key}: {cat} - {detail[:40]}")
        
        tested += 1
        if tested % 100 == 0:
            time.sleep(0.1)
    
    print(f"\nTested {tested} combinations")


def test_3leaf_with_1_lambda() -> None:
    """
    Test λ.((a b) c) - introduces 1 binder.
    This shifts all indices by 1 in interpretation.
    """
    print("\n" + "=" * 70)
    print("3-LEAF WITH 1 LAMBDA: λ.((a b) c) FF")
    print("=" * 70)
    
    # With 1 lambda, Var(0) is bound, Var(1+) are globals shifted by -1
    # So to call syscall 8, we'd use Var(9) (8+1)
    
    interesting = [0, 1, 2, 7, 8, 9, 15, 43, 202, 251, 252]
    
    results = {}
    tested = 0
    
    for a, b, c in itertools.product(interesting, repeat=3):
        inner = App(App(Var(a), Var(b)), Var(c))
        term = Lam(inner)
        payload = encode_term(term) + bytes([FF])
        
        resp = query_raw(payload, timeout_s=2.0)
        cat, detail = classify_response(resp)
        
        if cat not in ("silent", "invalid") and not (cat == "right" and detail in ("1", "6")):
            key = f"λ.(({a} {b}) {c})"
            results[key] = (cat, detail)
            print(f"  {key}: {cat} - {detail[:40]}")
        
        tested += 1
        if tested % 100 == 0:
            time.sleep(0.1)
    
    print(f"\nTested {tested} combinations")


def test_3leaf_with_2_lambdas() -> None:
    """
    Test λ.λ.((a b) c) - introduces 2 binders.
    Syscall 8 would be at Var(10).
    """
    print("\n" + "=" * 70)
    print("3-LEAF WITH 2 LAMBDAS: λ.λ.((a b) c) FF")
    print("=" * 70)
    
    # Focus on patterns where vars could reference bound args
    # Var(0) = innermost bound, Var(1) = outer bound
    # Var(2+) = globals shifted by 2
    
    interesting = [0, 1, 2, 3, 8, 9, 10, 16, 44, 203, 252]
    
    for a, b, c in itertools.product(interesting, repeat=3):
        inner = App(App(Var(a), Var(b)), Var(c))
        term = Lam(Lam(inner))
        payload = encode_term(term) + bytes([FF])
        
        resp = query_raw(payload, timeout_s=2.0)
        cat, detail = classify_response(resp)
        
        if cat not in ("silent", "invalid") and not (cat == "right" and detail in ("1", "6")):
            key = f"λ.λ.(({a} {b}) {c})"
            print(f"  {key}: {cat} - {detail[:40]}")
        
        time.sleep(0.05)


def test_key_syscall_combos() -> None:
    """
    Focus on syscall 8 specifically with various args and conts.
    """
    print("\n" + "=" * 70)
    print("SYSCALL 8 FOCUSED: ((8 arg) cont)")
    print("=" * 70)
    
    # All possible single-Var args and conts
    for arg in range(253):  # 0-252
        for cont in range(253):
            term = App(App(Var(8), Var(arg)), Var(cont))
            payload = encode_term(term) + bytes([FF])
            
            resp = query_raw(payload, timeout_s=2.0)
            cat, detail = classify_response(resp)
            
            # We're looking for anything other than Right(6) or silent
            if cat == "left":
                print(f"  *** ((8 {arg}) {cont}): LEFT - {detail[:50]} ***")
            elif cat == "right" and detail not in ("1", "6"):
                print(f"  ((8 {arg}) {cont}): Right({detail})")
            elif cat not in ("silent", "right", "invalid"):
                print(f"  ((8 {arg}) {cont}): {cat} - {detail[:30]}")
            
            # Rate limiting
            if (arg * 253 + cont) % 500 == 0:
                time.sleep(0.1)
    
    print("\nDone with syscall 8 sweep")


def test_backdoor_related_patterns() -> None:
    """
    Focus on patterns involving backdoor (201/0xC9).
    """
    print("\n" + "=" * 70)
    print("BACKDOOR-RELATED 3-LEAF PATTERNS")
    print("=" * 70)
    
    # Key indices
    syscall8 = 8
    backdoor = 201
    echo = 14
    
    # Try all combinations with these and low indices
    indices = [0, 1, 2, 4, 8, 14, 201]
    
    print("\nCPS patterns ((a b) c):")
    for a, b, c in itertools.product(indices, repeat=3):
        term = App(App(Var(a), Var(b)), Var(c))
        payload = encode_term(term) + bytes([FF])
        
        resp = query_raw(payload, timeout_s=2.5)
        cat, detail = classify_response(resp)
        
        # Print anything that's not silent/invalid/R1/R6
        if cat == "left":
            print(f"  *** (({a} {b}) {c}): LEFT - {detail[:50]} ***")
        elif cat == "right" and detail not in ("1", "2", "6", "7"):
            print(f"  (({a} {b}) {c}): Right({detail})")
        elif cat not in ("silent", "invalid", "right"):
            print(f"  (({a} {b}) {c}): {cat}")
        
        time.sleep(0.1)


def main() -> None:
    test_backdoor_related_patterns()  # Quick focused test first
    test_3leaf_cps_pattern()
    test_3leaf_right_assoc_pattern()
    test_3leaf_with_1_lambda()
    # Skip exhaustive syscall 8 sweep - too slow
    # test_key_syscall_combos()


if __name__ == "__main__":
    main()
