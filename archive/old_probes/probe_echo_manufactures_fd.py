#!/usr/bin/env python3
"""
DEFINITIVE TEST: Use echo's +2 shift to manufacture terms with FD/FE/FF indices.

KEY INSIGHT from agent analysis:
- Echo returns Left(input) where input's de Bruijn indices ARE shifted by +2
- So echo(Var(251)) returns Left(Var(253)) - a term containing the FD byte!
- Double echo: Var(251) → Left(Var(253)) → Left(Left(Var(255)))
- This is how you manufacture "special byte" terms that cannot be directly authored

AUTHOR HINTS:
1. "Why would an OS need echo?" → To manufacture special bytes
2. "Combining special bytes" → Use echo-manufactured bytes with syscall 8
3. "Start with 00 FE FE" → The argument should contain nil-like structure
4. "3 leafs" → Minimal construction using echo/backdoor

STRATEGY:
1. Use echo to create Var(253) (FD byte) 
2. Extract from Left wrapper
3. Feed to syscall 8 or use as part of a special construction
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
)
from solve_brownos_answer import QD as QD_BYTES

FF = 0xFF
FE = 0xFE
FD = 0xFD

NIL_TERM: object = Lam(Lam(Var(0)))  # λλ.0 = nil = 00 FE FE
QD_TERM: object = parse_term(QD_BYTES)
I_TERM: object = Lam(Var(0))  # Identity: λx.x


def term_to_string(term: object) -> str:
    """Human-readable term representation."""
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"(λ.{term_to_string(term.body)})"
    if isinstance(term, App):
        return f"({term_to_string(term.f)} {term_to_string(term.x)})"
    return str(term)


def shift(term: object, delta: int, cutoff: int = 0) -> object:
    """De Bruijn shift (increase free vars >= cutoff by delta)."""
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    raise TypeError(f"Unsupported term node: {type(term)}")


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


def query_raw(payload: bytes, timeout_s: float = 4.0, host: str = "82.165.133.222") -> bytes:
    """Query using IPv4 address directly to avoid DNS/IPv6 issues."""
    with socket.create_connection((host, 61221), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return recv_all(sock, timeout_s)


def classify_response(resp: bytes) -> str:
    """Classify response for quick display."""
    if not resp:
        return "<silent>"
    if resp.startswith(b"Invalid term!"):
        return "Invalid term!"
    if resp.startswith(b"Encoding failed!"):
        return "Encoding failed!"
    if resp.startswith(b"Term too big!"):
        return "Term too big!"
    if FF not in resp:
        return f"<no FF: {resp[:50].hex()}>"
    
    try:
        term = parse_term(resp)
        tag, payload = decode_either(term)
        if tag == "Right":
            code = decode_byte_term(payload)
            return f"Right({code})"
        else:
            try:
                bs = decode_bytes_list(payload)
                return f"Left('{bs.decode()[:50]}')"
            except:
                return f"Left(<non-bytes>)"
    except Exception as e:
        return f"<parse error: {e}>"


def test_echo_shift_verification() -> None:
    """
    Verify that echo actually shifts indices by +2.
    
    Test: echo(Var(k)) should behave like accessing global k+2 when extracted.
    """
    print("=" * 70)
    print("PHASE 1: Verify echo shifts indices by +2")
    print("=" * 70)
    
    # Build: ((0x0E Var(k)) (λe. ((e (λx.((x nil) QD')) (λy.((y nil) QD')))))
    # This extracts the payload from Either and applies it to nil, then QD
    # If echo(Var(k)) gives us access to global k+2, we should see different behavior
    
    for k in [4, 5, 6, 7]:  # These are: quote, ?, name, readfile
        print(f"\n--- Testing echo(Var({k})) ---")
        
        # Direct call: ((Var(k) nil) QD)
        direct = App(App(Var(k), NIL_TERM), QD_TERM)
        direct_payload = encode_term(direct) + bytes([FF])
        
        # Echo call: ((0x0E Var(k)) (λe. ((e (λx.((x nil_s) QD_s)) same))))
        # Inside λe: e is at Var(0), globals shift by +1
        # e is Either: Left(payload) or Right(err)
        # Apply e to left_handler and right_handler
        # left_handler = λpayload. ((payload nil_shifted) qd_shifted)
        
        # Actually simpler: extract and call
        # ((0x0E Var(k)) (λe. (((e I I) nil_s) qd_s)))
        e = Var(0)
        unwrapped = App(App(e, I_TERM), I_TERM)  # e I I extracts from Either
        nil_shifted = shift(NIL_TERM, 1)
        qd_shifted = shift(QD_TERM, 1)
        body = App(App(unwrapped, nil_shifted), qd_shifted)
        cont = Lam(body)
        
        echo_call = App(App(Var(0x0E), Var(k)), cont)
        echo_payload = encode_term(echo_call) + bytes([FF])
        
        direct_resp = query_raw(direct_payload)
        time.sleep(0.15)
        echo_resp = query_raw(echo_payload)
        
        print(f"  Direct Var({k}) with nil: {classify_response(direct_resp)}")
        print(f"  Echo(Var({k})) extracted:  {classify_response(echo_resp)}")
        
        # If echo shifts by +2, echo(Var(k)) extracted should act like Var(k+2)
        # Let's also test direct Var(k+2) for comparison
        if k + 2 <= 252:  # Can encode
            direct_k2 = App(App(Var(k + 2), NIL_TERM), QD_TERM)
            direct_k2_payload = encode_term(direct_k2) + bytes([FF])
            time.sleep(0.15)
            direct_k2_resp = query_raw(direct_k2_payload)
            print(f"  Direct Var({k+2}) with nil: {classify_response(direct_k2_resp)}")
        
        time.sleep(0.2)


def test_manufacture_fd() -> None:
    """
    Use echo to manufacture Var(253) - the FD byte that cannot be directly encoded.
    
    echo(Var(251)) should give us access to something at index 253.
    """
    print("\n" + "=" * 70)
    print("PHASE 2: Manufacture Var(253) using echo")
    print("=" * 70)
    
    # echo(Var(251)) → Left(Var(253)) internally (after +2 shift)
    # When we extract and use it, we're accessing global 253
    
    print("\nTesting echo(Var(251)) - should access index 253 (FD byte)")
    
    # Build: ((0x0E Var(251)) (λe. (((e I I) nil_s) qd_s)))
    e = Var(0)
    unwrapped = App(App(e, I_TERM), I_TERM)
    nil_shifted = shift(NIL_TERM, 1)
    qd_shifted = shift(QD_TERM, 1)
    body = App(App(unwrapped, nil_shifted), qd_shifted)
    cont = Lam(body)
    
    echo_251 = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(echo_251) + bytes([FF])
    resp = query_raw(payload)
    print(f"  echo(Var(251)) → extract → call: {classify_response(resp)}")
    
    # Try 250, 249 for comparison
    for k in [250, 249, 248]:
        e = Var(0)
        unwrapped = App(App(e, I_TERM), I_TERM)
        nil_shifted = shift(NIL_TERM, 1)
        qd_shifted = shift(QD_TERM, 1)
        body = App(App(unwrapped, nil_shifted), qd_shifted)
        cont = Lam(body)
        
        echo_k = App(App(Var(0x0E), Var(k)), cont)
        payload = encode_term(echo_k) + bytes([FF])
        time.sleep(0.15)
        resp = query_raw(payload)
        print(f"  echo(Var({k})) → extract → call: {classify_response(resp)}")
    
    time.sleep(0.3)


def test_echo_to_syscall8() -> None:
    """
    Use echo-manufactured high-index term as argument to syscall 8.
    
    Strategy: Get the Left(Var(253)) from echo, feed that entire thing to syscall 8.
    Or: Extract the Var(253) and feed to syscall 8.
    """
    print("\n" + "=" * 70)
    print("PHASE 3: Feed echo-manufactured terms to syscall 8")
    print("=" * 70)
    
    # Approach A: Feed the raw echo result to syscall 8
    # Build: ((0x0E Var(251)) (λe. ((Var(9) e) qd_s)))
    # Var(9) inside λe = syscall 8 (shifted by 1)
    
    print("\nApproach A: Feed raw echo(Var(251)) result to syscall 8")
    e = Var(0)
    syscall8_shifted = Var(8 + 1)  # syscall 8 is at global 8, +1 inside lambda
    qd_shifted = shift(QD_TERM, 1)
    body = App(App(syscall8_shifted, e), qd_shifted)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"  syscall8(echo(251) raw): {classify_response(resp)}")
    
    # Approach B: Extract from Either first, then feed to syscall 8
    # Build: ((0x0E Var(251)) (λe. ((Var(9) (e I I)) qd_s)))
    print("\nApproach B: Extract from echo(Var(251)), feed to syscall 8")
    e = Var(0)
    unwrapped = App(App(e, I_TERM), I_TERM)
    syscall8_shifted = Var(9)
    qd_shifted = shift(QD_TERM, 1)
    body = App(App(syscall8_shifted, unwrapped), qd_shifted)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"  syscall8(extract(echo(251))): {classify_response(resp)}")
    
    # Approach C: Double echo - Var(249) → 251 → 253 after two echoes
    print("\nApproach C: Double echo to manufacture Var(253)")
    
    # First echo: ((0x0E Var(249)) (λe1. second_echo))
    # Second echo: ((0x0E (e1 I I)) (λe2. use e2))
    # But we need to shift properly inside nested lambdas
    
    # Inner continuation (after second echo): λe2. ((Var(10) e2) qd_ss)
    # Var(10) = syscall 8 after 2 shifts
    e2 = Var(0)
    syscall8_ss = Var(8 + 2)  # +2 for two lambda wrappers
    qd_ss = shift(QD_TERM, 2)
    inner_body = App(App(syscall8_ss, e2), qd_ss)
    inner_cont = Lam(inner_body)
    
    # Middle part: λe1. ((0x0F (e1 I I)) inner_cont_s)
    # 0x0F = echo syscall shifted by 1
    e1 = Var(0)
    echo_s = Var(0x0E + 1)  # echo shifted by 1
    unwrap1 = App(App(e1, shift(I_TERM, 1)), shift(I_TERM, 1))
    inner_cont_s = shift(inner_cont, 1)
    middle_body = App(App(echo_s, unwrap1), inner_cont_s)
    middle_cont = Lam(middle_body)
    
    # Full: ((0x0E Var(249)) middle_cont)
    program = App(App(Var(0x0E), Var(249)), middle_cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"  syscall8(double_echo(249)): {classify_response(resp)}")
    
    time.sleep(0.3)


def test_echo_nil_combination() -> None:
    """
    Combine echo with nil as per "start with 00 FE FE" hint.
    
    Ideas:
    1. echo(nil) - does it produce special bytes?
    2. nil applied to echo result
    3. Use nil as the term to echo, but with syscall 8
    """
    print("\n" + "=" * 70)
    print("PHASE 4: Combine echo with nil (00 FE FE)")
    print("=" * 70)
    
    # Test 1: echo(nil) and feed to syscall 8
    print("\nTest 1: echo(nil) → syscall 8")
    e = Var(0)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    body = App(App(syscall8_s, e), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"  syscall8(echo(nil)): {classify_response(resp)}")
    
    # Test 2: Apply nil to echo-extracted term, then syscall 8
    print("\nTest 2: (echo(Var(251)) I I) nil → syscall 8")
    e = Var(0)
    unwrapped = App(App(e, I_TERM), I_TERM)
    nil_s = shift(NIL_TERM, 1)
    with_nil = App(unwrapped, nil_s)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    body = App(App(syscall8_s, with_nil), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"  syscall8((extract(echo(251))) nil): {classify_response(resp)}")
    
    # Test 3: Build a term that starts with 00 FE FE bytes
    # The hint says "start with 00 FE FE" - maybe the ARGUMENT to syscall 8 
    # needs to START with these bytes in the wire format
    
    # 00 FE FE = Var(0) wrapped in 2 lambdas = nil = λλ.0
    # So we need syscall 8's argument to be nil or start with nil
    print("\nTest 3: syscall8(nil)")
    program = App(App(Var(8), NIL_TERM), QD_TERM)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"  syscall8(nil): {classify_response(resp)}")
    
    time.sleep(0.3)


def test_raw_byte_injection() -> None:
    """
    Try to inject raw 00 FE FE bytes at the start of the program.
    
    The hint might mean the PROGRAM should start with these bytes, not just the argument.
    """
    print("\n" + "=" * 70)
    print("PHASE 5: Raw byte injection tests")
    print("=" * 70)
    
    # Test 1: Program literally starting with 00 FE FE
    # 00 FE FE = nil = λλ.0
    # Then add syscall 8 call after
    
    print("\nTest 1: Program = nil (just nil by itself)")
    payload = bytes([0x00, 0xFE, 0xFE, 0xFF])
    resp = query_raw(payload)
    print(f"  Just nil (00 FE FE FF): {classify_response(resp)}")
    if resp:
        print(f"    Raw response: {resp.hex()}")
    
    # Test 2: nil applied to syscall 8 stuff
    # (nil syscall8_term) doesn't make sense...
    # But what about ((syscall8 nil) QD) with bytes rearranged?
    
    print("\nTest 2: Examine byte layout of ((8 nil) QD)")
    program = App(App(Var(8), NIL_TERM), QD_TERM)
    normal_bytes = encode_term(program)
    print(f"  Normal encoding: {normal_bytes.hex()}")
    
    # The encoding is: 8 00 FE FE FD QD FD FF
    # What if we put 00 FE FE at the front?
    # 00 FE FE 08 FD QD FD FF = (nil 8) QD... which is ((λλ.0) 8) QD
    
    print("\nTest 3: Try (nil Var(8)) QD = ((λλ.0) 8) QD")
    nil_applied_8 = App(NIL_TERM, Var(8))
    program = App(nil_applied_8, QD_TERM)
    payload = encode_term(program) + bytes([FF])
    print(f"  Encoding: {payload.hex()}")
    resp = query_raw(payload)
    print(f"  Result: {classify_response(resp)}")
    
    time.sleep(0.3)


def test_backdoor_to_syscall8() -> None:
    """
    Use backdoor (syscall 201) output directly with syscall 8.
    
    Backdoor returns pair (A, B) where:
    - A = λab.bb (self-apply second)
    - B = λab.ab (apply first to second)
    
    From Oracle analysis: These can produce ω but not Y combinator.
    But maybe the RAW BYTES of the backdoor response matter.
    """
    print("\n" + "=" * 70)
    print("PHASE 6: Backdoor output to syscall 8")
    print("=" * 70)
    
    # First get backdoor response to see the raw bytes
    print("\nStep 1: Get backdoor response")
    backdoor_call = App(App(Var(0xC9), NIL_TERM), QD_TERM)
    payload = encode_term(backdoor_call) + bytes([FF])
    resp = query_raw(payload)
    print(f"  Backdoor result: {classify_response(resp)}")
    print(f"  Raw bytes: {resp.hex() if resp else '<empty>'}")
    
    # Now use the backdoor result directly as argument to syscall 8
    # Build: ((0xC9 nil) (λpair. ((8 pair) qd_s)))
    print("\nStep 2: Feed backdoor pair to syscall 8")
    pair = Var(0)
    syscall8_s = Var(9)  # 8 + 1 for lambda wrapper
    qd_s = shift(QD_TERM, 1)
    body = App(App(syscall8_s, pair), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0xC9), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"  syscall8(backdoor_pair): {classify_response(resp)}")
    
    # Use extracted A and B
    print("\nStep 3: Use pair eliminator on backdoor, feed result to syscall 8")
    # Build: ((0xC9 nil) (λpair. ((8 (pair A_selector)) qd_s)))
    # pair with A_selector = pair (λa.λb.a) = first element = A
    
    # A_selector = λa.λb.a = Lam(Lam(Var(1)))
    fst_selector = Lam(Lam(Var(1)))
    snd_selector = Lam(Lam(Var(0)))
    
    for name, selector in [("A (first)", fst_selector), ("B (second)", snd_selector)]:
        pair = Var(0)
        selected = App(pair, shift(selector, 1))
        syscall8_s = Var(9)
        qd_s = shift(QD_TERM, 1)
        body = App(App(syscall8_s, selected), qd_s)
        cont = Lam(body)
        
        program = App(App(Var(0xC9), NIL_TERM), cont)
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload)
        print(f"  syscall8({name} from backdoor): {classify_response(resp)}")
        time.sleep(0.15)
    
    time.sleep(0.3)


def test_three_leafs_minimal() -> None:
    """
    "My record is 3 leafs" - try minimal 3-leaf constructions.
    
    A leaf in lambda calculus is either:
    - A variable (Var)
    - A lambda with a single-node body
    
    3 leafs could mean:
    - (V V V) = ((V V) V) or (V (V V))
    - λ.V with something
    - etc.
    """
    print("\n" + "=" * 70)
    print("PHASE 7: Minimal 3-leaf constructions")
    print("=" * 70)
    
    # 3 variables in application structure
    cases = [
        ("((8 8) QD)", App(App(Var(8), Var(8)), QD_TERM)),
        ("((8 QD) 8)", App(App(Var(8), QD_TERM), Var(8))),
        ("(8 (8 QD))", App(Var(8), App(Var(8), QD_TERM))),
        ("(8 (QD 8))", App(Var(8), App(QD_TERM, Var(8)))),
        
        # With identity
        ("((8 I) QD)", App(App(Var(8), I_TERM), QD_TERM)),
        ("((8 nil) QD)", App(App(Var(8), NIL_TERM), QD_TERM)),
        
        # With backdoor
        ("((8 201) QD)", App(App(Var(8), Var(0xC9)), QD_TERM)),
        ("((201 8) QD)", App(App(Var(0xC9), Var(8)), QD_TERM)),
        
        # Mixed syscalls
        ("((8 (14 nil)) QD)", App(App(Var(8), App(Var(0x0E), NIL_TERM)), QD_TERM)),  # 14=echo
        ("((14 8) QD)", App(App(Var(0x0E), Var(8)), QD_TERM)),  # echo of syscall 8
    ]
    
    for name, term in cases:
        payload = encode_term(term) + bytes([FF])
        resp = query_raw(payload)
        print(f"  {name}: {classify_response(resp)}")
        time.sleep(0.12)


def main() -> None:
    print("BROWNOS SYSCALL 8 - ECHO BYTE MANUFACTURING PROBE")
    print("=" * 70)
    print("Testing the hypothesis that echo's +2 index shift")
    print("allows manufacturing terms with FD/FE/FF byte indices")
    print("=" * 70)
    
    test_echo_shift_verification()
    test_manufacture_fd()
    test_echo_to_syscall8()
    test_echo_nil_combination()
    test_raw_byte_injection()
    test_backdoor_to_syscall8()
    test_three_leafs_minimal()
    
    print("\n" + "=" * 70)
    print("PROBE COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
