#!/usr/bin/env python3
"""
Analyze the backdoor (syscall 0xC9/201) response for hidden meaning.

The mail hint says: "Backdoor is ready at syscall 201; start with 00 FE FE."
The backdoor returns a pair: (A=λab.bb, B=λab.ab)

This probe:
1. Examines raw bytes of backdoor response
2. Checks if bytes encode ASCII directly
3. Analyzes the pair structure for hidden semantics
4. Tests using backdoor components in various ways
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    decode_byte_term,
    decode_bytes_list,
    decode_either,
    encode_term,
    parse_term,
    query,
)
from solve_brownos_answer import QD as QD_BYTES

FF = 0xFF
FE = 0xFE
FD = 0xFD

NIL_TERM: object = Lam(Lam(Var(0)))
QD_TERM: object = parse_term(QD_BYTES)


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


def query_raw(payload: bytes, timeout_s: float = 4.0) -> bytes:
    """Query and return raw response (don't require FF termination)."""
    with socket.create_connection(("wc3.wechall.net", 61221), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return recv_all(sock, timeout_s)


def term_to_string(term: object) -> str:
    """Human-readable term representation."""
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"(λ.{term_to_string(term.body)})"
    if isinstance(term, App):
        return f"({term_to_string(term.f)} {term_to_string(term.x)})"
    return str(term)


def analyze_backdoor_raw() -> None:
    """Call backdoor and analyze raw response."""
    print("=" * 60)
    print("BACKDOOR RAW ANALYSIS")
    print("=" * 60)
    
    # Call syscall 201 with nil argument, using QD as continuation
    # ((0xC9 nil) QD)
    payload = bytes([0xC9]) + encode_term(NIL_TERM) + bytes([FD]) + QD_BYTES + bytes([FD, FF])
    
    print(f"Payload hex: {payload.hex()}")
    print(f"Payload len: {len(payload)}")
    
    resp = query_raw(payload)
    print(f"\nResponse hex: {resp.hex()}")
    print(f"Response len: {len(resp)}")
    
    # Check for ASCII interpretation
    print("\nASCII interpretation (raw):")
    printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in resp)
    print(f"  {printable}")
    
    # Check for ASCII if we strip FD/FE/FF
    stripped = bytes(b for b in resp if b not in (FD, FE, FF))
    print(f"\nASCII interpretation (stripped FD/FE/FF):")
    printable2 = ''.join(chr(b) if 32 <= b < 127 else '.' for b in stripped)
    print(f"  {printable2}")
    
    # Parse as term
    if FF in resp:
        term = parse_term(resp)
        print(f"\nParsed term: {term_to_string(term)}")
        
        try:
            tag, payload_term = decode_either(term)
            print(f"Either tag: {tag}")
            print(f"Payload: {term_to_string(payload_term)}")
            
            # The payload should be a Scott pair: λs. s A B
            # Where A = λa.λb. b b and B = λa.λb. a b
            if isinstance(payload_term, Lam):
                pair_body = payload_term.body
                print(f"Pair body: {term_to_string(pair_body)}")
                
                # Try to extract A and B
                if isinstance(pair_body, App) and isinstance(pair_body.f, App):
                    selector = pair_body.f.f
                    a_term = pair_body.f.x
                    b_term = pair_body.x
                    print(f"\nSelector: {term_to_string(selector)}")
                    print(f"A term: {term_to_string(a_term)}")
                    print(f"B term: {term_to_string(b_term)}")
                    
                    # Encode A and B separately
                    a_bytes = encode_term(a_term)
                    b_bytes = encode_term(b_term)
                    print(f"\nA bytes: {a_bytes.hex()}")
                    print(f"B bytes: {b_bytes.hex()}")
                    
                    # Check ASCII
                    print(f"A ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in a_bytes)}")
                    print(f"B ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in b_bytes)}")
                    
        except Exception as e:
            print(f"Decode error: {e}")


def extract_pair_components(pair_term: object) -> tuple[object, object]:
    """
    Extract A and B from a Scott pair.
    Scott pair: λs. s A B = λ. (V0 A) B under 1 lambda
    But the actual structure may be: λ.λ. ((V1 A) B) (two lambdas)
    """
    # Strip lambdas until we get to the application
    cur = pair_term
    depth = 0
    while isinstance(cur, Lam):
        cur = cur.body
        depth += 1
    
    print(f"  Pair has {depth} leading lambdas")
    print(f"  Core: {term_to_string(cur)}")
    
    # cur should be ((selector A) B)
    if isinstance(cur, App) and isinstance(cur.f, App):
        selector = cur.f.f
        a_term = cur.f.x
        b_term = cur.x
        print(f"  Selector: {term_to_string(selector)}")
        print(f"  A: {term_to_string(a_term)}")
        print(f"  B: {term_to_string(b_term)}")
        return a_term, b_term
    
    raise ValueError(f"Unexpected pair structure: {term_to_string(cur)}")


def test_backdoor_components_as_syscall8_args() -> None:
    """Test using backdoor components as arguments to syscall 8."""
    print("\n" + "=" * 60)
    print("BACKDOOR COMPONENTS AS SYSCALL 8 ARGUMENTS")
    print("=" * 60)
    
    # First get backdoor result
    backdoor_payload = bytes([0xC9]) + encode_term(NIL_TERM) + bytes([FD]) + QD_BYTES + bytes([FD, FF])
    resp = query_raw(backdoor_payload)
    
    if FF not in resp:
        print("ERROR: No FF in backdoor response")
        return
    
    term = parse_term(resp)
    tag, pair_term = decode_either(term)
    
    if tag != "Left":
        print(f"ERROR: Backdoor returned {tag}")
        return
    
    # Extract A and B from the pair
    a_term, b_term = extract_pair_components(pair_term)
    
    print(f"A = {term_to_string(a_term)}")
    print(f"B = {term_to_string(b_term)}")
    
    # Test passing A, B, pair, and combinations to syscall 8
    test_cases = [
        ("A", a_term),
        ("B", b_term),
        ("pair", pair_term),
        ("A applied to B", App(a_term, b_term)),
        ("B applied to A", App(b_term, a_term)),
        ("A applied to nil", App(a_term, NIL_TERM)),
        ("B applied to nil", App(b_term, NIL_TERM)),
    ]
    
    for name, arg in test_cases:
        # ((0x08 arg) QD)
        payload = bytes([0x08]) + encode_term(arg) + bytes([FD]) + QD_BYTES + bytes([FD, FF])
        
        try:
            resp = query(payload, timeout_s=4.0)
            result_term = parse_term(resp)
            result_tag, result_payload = decode_either(result_term)
            
            if result_tag == "Right":
                code = decode_byte_term(result_payload)
                print(f"{name}: Right({code})")
            else:
                try:
                    bs = decode_bytes_list(result_payload)
                    print(f"{name}: Left('{bs.decode()}')")
                except:
                    print(f"{name}: Left(<non-bytes>)")
        except Exception as e:
            print(f"{name}: ERROR - {e}")
        
        time.sleep(0.2)


def test_backdoor_as_continuation() -> None:
    """Test using backdoor components as continuation for syscall 8."""
    print("\n" + "=" * 60)
    print("BACKDOOR COMPONENTS AS CONTINUATION")
    print("=" * 60)
    
    # Get backdoor components
    backdoor_payload = bytes([0xC9]) + encode_term(NIL_TERM) + bytes([FD]) + QD_BYTES + bytes([FD, FF])
    resp = query_raw(backdoor_payload)
    term = parse_term(resp)
    _, pair_term = decode_either(term)
    
    a_term, b_term = extract_pair_components(pair_term)
    
    # Test using A and B as continuations
    # ((0x08 nil) A) - what happens if A is the continuation?
    for name, cont in [("A", a_term), ("B", b_term), ("pair", pair_term)]:
        payload = bytes([0x08]) + encode_term(NIL_TERM) + bytes([FD]) + encode_term(cont) + bytes([FD, FF])
        
        try:
            resp = query_raw(payload, timeout_s=4.0)
            if not resp:
                print(f"syscall8 with {name} as continuation: <silent>")
            elif FF in resp:
                result = parse_term(resp)
                print(f"syscall8 with {name} as continuation: {term_to_string(result)}")
            else:
                print(f"syscall8 with {name} as continuation: {resp[:50].hex()}...")
        except Exception as e:
            print(f"syscall8 with {name} as continuation: ERROR - {e}")
        
        time.sleep(0.2)


def test_nested_backdoor() -> None:
    """Test nesting backdoor calls or using backdoor result recursively."""
    print("\n" + "=" * 60)
    print("NESTED BACKDOOR TESTS")
    print("=" * 60)
    
    # Get backdoor pair
    backdoor_payload = bytes([0xC9]) + encode_term(NIL_TERM) + bytes([FD]) + QD_BYTES + bytes([FD, FF])
    resp = query_raw(backdoor_payload)
    term = parse_term(resp)
    _, pair_term = decode_either(term)
    
    a_term, b_term = extract_pair_components(pair_term)
    
    # What if we call backdoor with the pair/A/B as argument?
    print("\nCalling backdoor with various non-nil arguments:")
    for name, arg in [("A", a_term), ("B", b_term), ("pair", pair_term)]:
        payload = bytes([0xC9]) + encode_term(arg) + bytes([FD]) + QD_BYTES + bytes([FD, FF])
        
        try:
            resp = query(payload, timeout_s=4.0)
            result = parse_term(resp)
            tag, payload_term = decode_either(result)
            
            if tag == "Right":
                code = decode_byte_term(payload_term)
                print(f"backdoor({name}): Right({code})")
            else:
                print(f"backdoor({name}): Left({term_to_string(payload_term)[:100]})")
        except Exception as e:
            print(f"backdoor({name}): ERROR - {e}")
        
        time.sleep(0.2)


def analyze_3_leafs_interpretation() -> None:
    """
    Author hint: "My record is 3 leafs IIRC"
    
    In lambda calculus, a "leaf" is typically a variable (Var).
    "3 leafs" could mean:
    - A term with exactly 3 Var nodes
    - 3 applications of something
    - A very minimal program
    
    Let's enumerate all possible 3-leaf terms and test them.
    """
    print("\n" + "=" * 60)
    print("3 LEAFS INTERPRETATION")
    print("=" * 60)
    
    # Minimal 3-var terms:
    # ((V_a V_b) V_c) - 3 vars, 2 apps
    # (V_a (V_b V_c)) - 3 vars, 2 apps
    # λ.((V_a V_b) V_c) - 3 vars under 1 lambda
    
    # With syscall semantics ((syscall arg) cont):
    # - 3 leaves = syscall, arg, cont all being single Vars
    
    # What if the answer is just: ((Var(X) Var(Y)) Var(Z)) for specific X,Y,Z?
    # The backdoor hint says "start with 00 FE FE" which is nil
    
    # Test minimal patterns
    print("\nMinimal 3-leaf patterns with syscall 8:")
    
    # Pattern: ((8 nil) QD) is what we've been doing
    # But what if arg should be something simpler?
    
    # Try: ((8 V_i) QD) for various i
    print("\n((8 Var(i)) QD) for interesting i values:")
    for i in [0, 1, 8, 14, 42, 201, 252]:
        payload = bytes([0x08, i, FD]) + QD_BYTES + bytes([FD, FF])
        try:
            resp = query(payload, timeout_s=3.0)
            result = parse_term(resp)
            tag, p = decode_either(result)
            if tag == "Right":
                code = decode_byte_term(p)
                print(f"  i={i}: Right({code})")
            else:
                print(f"  i={i}: Left(...)")
        except Exception as e:
            print(f"  i={i}: ERROR - {e}")
        time.sleep(0.15)
    
    # What about using a raw Var as continuation instead of QD?
    print("\n((8 nil) Var(i)) for interesting i:")
    for i in [0, 1, 2, 4, 8, 14, 42, 201]:
        # ((8 nil) V_i)
        payload = bytes([0x08]) + encode_term(NIL_TERM) + bytes([FD, i, FD, FF])
        try:
            resp = query_raw(payload, timeout_s=3.0)
            if not resp:
                print(f"  i={i}: <silent>")
            elif FF in resp:
                result = parse_term(resp)
                print(f"  i={i}: {term_to_string(result)[:60]}")
            else:
                print(f"  i={i}: {resp[:30].hex()}")
        except Exception as e:
            print(f"  i={i}: ERROR - {e}")
        time.sleep(0.15)


def main() -> None:
    analyze_backdoor_raw()
    test_backdoor_components_as_syscall8_args()
    test_backdoor_as_continuation()
    test_nested_backdoor()
    analyze_3_leafs_interpretation()


if __name__ == "__main__":
    main()
