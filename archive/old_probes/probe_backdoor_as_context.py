#!/usr/bin/env python3
"""
HYPOTHESIS: The backdoor combinators are meant to be used as CONTEXT,
not as arguments to syscall 8.

A = λab.bb (self-application)
B = λab.ab (application)

What if:
1. We need to CALL syscall 8 FROM WITHIN a computation involving A/B?
2. The permission check looks at the calling context, not the argument?
3. A and B together form a Y combinator or similar that grants access?

Let's try:
- Using A as the continuation for syscall 8
- Nesting syscall 8 calls inside A/B applications
- Building evaluation contexts with A/B
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
FE = 0xFE
FD = 0xFD

NIL_TERM: object = Lam(Lam(Var(0)))
QD_TERM: object = parse_term(QD_BYTES)


def term_to_string(term: object, depth: int = 0) -> str:
    if depth > 20:
        return "..."
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{term_to_string(term.body, depth+1)}"
    if isinstance(term, App):
        return f"({term_to_string(term.f, depth+1)} {term_to_string(term.x, depth+1)})"
    return str(term)


def shift(term: object, delta: int, cutoff: int = 0) -> object:
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    return term


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
    with socket.create_connection(("wc3.wechall.net", 61221), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return recv_all(sock, timeout_s)


def classify_response(resp: bytes) -> str:
    if not resp:
        return "<silent>"
    if resp.startswith(b"Invalid term!"):
        return "Invalid!"
    if resp.startswith(b"Encoding failed!"):
        return "EncFail!"
    if FF not in resp:
        return f"<noFF:{resp[:30].hex()}>"
    
    try:
        term = parse_term(resp)
        tag, payload = decode_either(term)
        if tag == "Right":
            code = decode_byte_term(payload)
            return f"R{code}"
        else:
            try:
                bs = decode_bytes_list(payload)
                txt = bs.decode('utf-8', 'replace')[:40]
                return f"L'{txt}'"
            except:
                return f"L<{term_to_string(payload)[:40]}>"
    except:
        try:
            term = parse_term(resp)
            return f"<{term_to_string(term)[:40]}>"
        except:
            return "<err>"


def get_backdoor_components() -> tuple[object, object, object]:
    """Get A, B, and the pair from backdoor."""
    backdoor_payload = bytes([0xC9]) + encode_term(NIL_TERM) + bytes([FD]) + QD_BYTES + bytes([FD, FF])
    resp = query_raw(backdoor_payload)
    term = parse_term(resp)
    _, pair_term = decode_either(term)
    
    cur = pair_term
    while isinstance(cur, Lam):
        cur = cur.body
    a_term = cur.f.x  # λab.bb
    b_term = cur.x    # λab.ab
    
    return a_term, b_term, pair_term


def test_syscall8_inside_backdoor_application() -> None:
    """
    What if we call syscall 8 from INSIDE an application of A or B?
    
    Like: A (syscall 8 nil) QD
    or:   B (syscall 8 nil) QD
    
    These would evaluate syscall 8 in a special context.
    """
    print("=" * 60)
    print("SYSCALL 8 INSIDE BACKDOOR APPLICATION")
    print("=" * 60)
    
    A, B, pair = get_backdoor_components()
    print(f"A = {term_to_string(A)}")
    print(f"B = {term_to_string(B)}")
    
    # Remember: A x y = y y, B x y = x y
    
    # Test: A (syscall8 nil) QD
    # = QD QD = apply QD to itself
    # This doesn't help syscall 8...
    
    # Test: B (syscall8 nil) QD  
    # = (syscall8 nil) QD = normal call
    
    # What about: B syscall8 nil then apply to QD?
    # B 8 nil = 8 nil, then (8 nil) QD = normal
    
    # Hmm. Let me think differently.
    # What if the syscall 8 result needs to be PROCESSED by A or B?
    
    # ((0x08 nil) (λresult. (A result) something))
    
    print("\nTest: syscall8 result processed by A/B")
    
    # ((0x08 nil) (λr. ((A r) QD)))
    # Inside λr: r=V0, globals shift +1, so 0x08->9, etc.
    # A needs to be available... let's put it in scope
    
    # Actually, we need to get A first, then use it.
    # Let's build: 
    # ((0xC9 nil) (λpair. let A = fst pair in ((0x08 nil) (λr. ((A r) QD)))))
    
    # This is getting complex. Let me try simpler patterns first.
    
    # What if we just try: (A (B syscall8)) or similar combinator applications?
    
    print("\nCombinator-wrapped syscall 8:")
    
    syscall8 = Var(8)
    
    tests = [
        # Use A and B to wrap syscall 8 in various ways
        ("(A syscall8) nil QD", App(App(App(A, syscall8), NIL_TERM), QD_TERM)),
        ("(B syscall8) nil QD", App(App(App(B, syscall8), NIL_TERM), QD_TERM)),
        ("A (syscall8 nil) QD", App(App(A, App(syscall8, NIL_TERM)), QD_TERM)),
        ("B (syscall8 nil) QD", App(App(B, App(syscall8, NIL_TERM)), QD_TERM)),
        # What about using the pair itself?
        ("pair syscall8 nil", App(App(pair, syscall8), NIL_TERM)),
    ]
    
    for name, term in tests:
        payload = encode_term(term) + bytes([FF])
        resp = query_raw(payload, timeout_s=4.0)
        result = classify_response(resp)
        print(f"  {name}: {result}")
        time.sleep(0.2)


def test_chained_backdoor_syscall8() -> None:
    """
    What if we need to call backdoor first, THEN syscall 8,
    passing the backdoor result through somehow?
    """
    print("\n" + "=" * 60)
    print("CHAINED: BACKDOOR THEN SYSCALL 8")
    print("=" * 60)
    
    # ((0xC9 nil) (λpair. ((0x08 pair) QD)))
    # Call backdoor, then pass pair to syscall 8
    
    print("\nBackdoor → syscall8 chain:")
    
    # Build continuation that calls syscall 8 with the backdoor result
    # Inside λpair: pair=V0, globals at +1
    pair = Var(0)
    qd_shifted = shift(QD_TERM, 1)
    syscall8_shifted = Var(9)  # 8 + 1
    body = App(App(syscall8_shifted, pair), qd_shifted)
    cont = Lam(body)
    
    program = App(App(Var(0xC9), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload, timeout_s=4.0)
    print(f"  ((0xC9 nil) λp.((8 p) QD)): {classify_response(resp)}")
    
    time.sleep(0.2)
    
    # What about using fst/snd on the pair?
    # fst = λp. p (λa.λb.a)
    # snd = λp. p (λa.λb.b)
    
    # pair (λa.λb.a) = ((λs. s A B) (λa.λb.a)) = (λa.λb.a) A B = A
    # pair (λa.λb.b) = ((λs. s A B) (λa.λb.b)) = (λa.λb.b) A B = B
    
    fst_selector = Lam(Lam(Var(1)))  # λa.λb.a
    snd_selector = Lam(Lam(Var(0)))  # λa.λb.b
    
    # ((0xC9 nil) (λpair. ((0x08 (pair fst)) QD)))
    for name, selector in [("fst (=A)", fst_selector), ("snd (=B)", snd_selector)]:
        pair = Var(0)
        qd_s = shift(QD_TERM, 1)
        selected = App(pair, selector)
        body = App(App(Var(9), selected), qd_s)
        cont = Lam(body)
        program = App(App(Var(0xC9), NIL_TERM), cont)
        
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload, timeout_s=4.0)
        print(f"  syscall8(pair {name}): {classify_response(resp)}")
        time.sleep(0.2)


def test_y_combinator_with_syscall8() -> None:
    """
    A = λab.bb (self-application)
    This is reminiscent of the ω combinator: ω = λx.xx
    
    Y combinator uses self-application for recursion.
    What if A and B together are meant to build a fixed-point?
    
    Y = λf. (λx. f(x x)) (λx. f(x x))
    
    With A (which does y y), we can get self-application.
    """
    print("\n" + "=" * 60)
    print("FIXED-POINT / Y-COMBINATOR IDEAS")
    print("=" * 60)
    
    A, B, pair = get_backdoor_components()
    
    # A x y = y y
    # So (A anything syscall8) = syscall8 syscall8
    
    print("Test: (A _ syscall8) = syscall8 syscall8")
    program = App(App(A, NIL_TERM), Var(8))
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload, timeout_s=4.0)
    print(f"  Result: {classify_response(resp)}")
    
    time.sleep(0.2)
    
    # B x y = x y
    # (B syscall8 nil) = syscall8 nil
    print("\nTest: (B syscall8 nil) QD = (syscall8 nil) QD")
    b_syscall_nil = App(App(B, Var(8)), NIL_TERM)
    program = App(b_syscall_nil, QD_TERM)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload, timeout_s=4.0)
    print(f"  Result: {classify_response(resp)}")
    
    time.sleep(0.2)
    
    # What about: (B (A x y)) z = (y y) z ?
    # Hmm, this is getting circular.
    
    # Let me try: use A to make syscall8 call itself
    # ((A nil syscall8) something) = ((syscall8 syscall8) something)
    # syscall8 applied to syscall8 is weird...
    
    print("\nTest: ((A nil syscall8) nil) QD")
    inner = App(App(A, NIL_TERM), Var(8))  # syscall8 syscall8
    call = App(inner, NIL_TERM)  # (syscall8 syscall8) nil
    program = App(call, QD_TERM)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload, timeout_s=4.0)
    print(f"  Result: {classify_response(resp)}")


def test_backdoor_pair_as_environment() -> None:
    """
    The backdoor returns a PAIR (A, B).
    What if we need to "install" this pair as an environment for syscall 8?
    
    In some capability systems, you pass credentials as a hidden argument.
    """
    print("\n" + "=" * 60)
    print("BACKDOOR PAIR AS CAPABILITY/ENVIRONMENT")
    print("=" * 60)
    
    A, B, pair = get_backdoor_components()
    
    # What if syscall 8's real signature is: syscall8 capability arg cont?
    # And the capability should be A, B, or the pair?
    
    # Test: ((syscall8 A) nil) QD  
    # Reinterpret: syscall8 takes A as first arg, nil as second?
    
    tests = [
        ("((8 A) nil) QD - A as first arg", App(App(App(Var(8), A), NIL_TERM), QD_TERM)),
        ("((8 B) nil) QD - B as first arg", App(App(App(Var(8), B), NIL_TERM), QD_TERM)),
        ("((8 pair) nil) QD", App(App(App(Var(8), pair), NIL_TERM), QD_TERM)),
        
        # Or maybe it's: syscall8 (A, B) as a tuple-like structure?
        # Build a proper pair: λs. s A B
        ("((8 (λs.sAB)) nil) QD", App(App(Var(8), Lam(App(App(Var(0), A), B))), QD_TERM)),
    ]
    
    for name, term in tests:
        payload = encode_term(term) + bytes([FF])
        resp = query_raw(payload, timeout_s=4.0)
        result = classify_response(resp)
        print(f"  {name}: {result}")
        time.sleep(0.2)


def test_backdoor_output_as_program() -> None:
    """
    What if the backdoor output IS the program to run?
    
    The backdoor returns Left(pair). What if we should
    EVALUATE that pair as a program itself?
    """
    print("\n" + "=" * 60)
    print("BACKDOOR OUTPUT AS PROGRAM")
    print("=" * 60)
    
    A, B, pair = get_backdoor_components()
    
    # pair = λs. s A B
    # If we apply pair to syscall8: pair syscall8 = syscall8 A B
    # = ((syscall8 A) B) = syscall8 with A as arg, B as cont?
    
    print("Test: pair syscall8 = syscall8 A B")
    program = App(pair, Var(8))  # pair syscall8
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload, timeout_s=4.0)
    print(f"  Result: {classify_response(resp)}")
    
    time.sleep(0.2)
    
    # What about pair echo?
    print("\nTest: pair echo = echo A B")
    program = App(pair, Var(0x0E))
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload, timeout_s=4.0)
    print(f"  Result: {classify_response(resp)}")
    
    time.sleep(0.2)
    
    # Or pair applied to various syscalls
    for syscall_num in [1, 2, 4, 5, 6, 7, 42, 201]:
        program = App(pair, Var(syscall_num))
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload, timeout_s=3.0)
        result = classify_response(resp)
        if result not in ["<silent>", "R1"]:
            print(f"  pair Var({syscall_num}): {result}")
        time.sleep(0.15)


def test_minimal_term_analysis() -> None:
    """
    The author said "3 leafs". Let me enumerate the most minimal
    terms and see which ones produce interesting results.
    """
    print("\n" + "=" * 60)
    print("MINIMAL TERM ENUMERATION")
    print("=" * 60)
    
    # The most minimal complete programs that might do something:
    # With 3 vars: ((a b) c)
    
    # Syscall pattern: ((syscall arg) cont)
    # If syscall=8, arg=?, cont=?
    
    # What are the most interesting values for arg and cont?
    # - QD is a complex continuation
    # - nil is simple
    # - Var(i) for small i
    
    # What if arg and cont should be Vars pointing to something?
    
    A, B, pair = get_backdoor_components()
    
    print("\n3-leaf patterns with backdoor components embedded:")
    
    # The backdoor components A and B are terms, not Vars
    # But we could try minimal applications
    
    # ((8 A) B) - syscall 8 with A as arg, B as cont
    tests = [
        ("((8 A) B)", App(App(Var(8), A), B)),
        ("((8 B) A)", App(App(Var(8), B), A)),
        ("((8 nil) A)", App(App(Var(8), NIL_TERM), A)),
        ("((8 nil) B)", App(App(Var(8), NIL_TERM), B)),
        ("((8 A) A)", App(App(Var(8), A), A)),
        ("((8 B) B)", App(App(Var(8), B), B)),
    ]
    
    for name, term in tests:
        payload = encode_term(term) + bytes([FF])
        resp = query_raw(payload, timeout_s=4.0)
        result = classify_response(resp)
        print(f"  {name}: {result}")
        time.sleep(0.2)


def main() -> None:
    test_syscall8_inside_backdoor_application()
    test_chained_backdoor_syscall8()
    test_y_combinator_with_syscall8()
    test_backdoor_pair_as_environment()
    test_backdoor_output_as_program()
    test_minimal_term_analysis()


if __name__ == "__main__":
    main()
