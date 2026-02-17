#!/usr/bin/env python3
"""
OBSERVATION: When using backdoor combinators A or B as continuations,
we get <silent> responses instead of Right(6).

This is DIFFERENT from the normal error path!

Let's investigate what happens when A or B is the continuation.

A = λab.bb  (takes result, ignores it, applies second arg to itself)
B = λab.ab  (takes result, applies first arg to second)

If syscall 8 returns Right(6) and passes it to A:
  A Right(6) ??? = ??? ???
  
But A needs TWO arguments. So (A Right(6)) is a partial application.
Maybe we need to supply the second argument?
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
    if depth > 30:
        return "..."
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{term_to_string(term.body, depth+1)}"
    if isinstance(term, App):
        return f"({term_to_string(term.f, depth+1)} {term_to_string(term.x, depth+1)})"
    return str(term)


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


def query_raw(payload: bytes, timeout_s: float = 5.0) -> bytes:
    with socket.create_connection(("wc3.wechall.net", 61221), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return recv_all(sock, timeout_s)


def get_backdoor_components() -> tuple[object, object]:
    """Get A and B from backdoor."""
    backdoor_payload = bytes([0xC9]) + encode_term(NIL_TERM) + bytes([FD]) + QD_BYTES + bytes([FD, FF])
    resp = query_raw(backdoor_payload)
    term = parse_term(resp)
    _, pair_term = decode_either(term)
    
    cur = pair_term
    while isinstance(cur, Lam):
        cur = cur.body
    a_term = cur.f.x
    b_term = cur.x
    
    return a_term, b_term


def analyze_syscall8_with_a_continuation() -> None:
    """
    Analyze what happens with ((8 arg) A).
    
    A = λa.λb. b b
    
    If syscall 8 returns result R and passes to A:
    A R = λb. b b  (partial application, waiting for b)
    
    The program then continues... what?
    If our full program is ((8 arg) A), then after syscall 8:
    - result R is passed to A
    - A R = λb. b b
    - But this is the final value, there's nothing to apply it to
    - So the program "finishes" with λb. b b, which produces no output
    
    But wait - maybe we need to supply that second argument!
    """
    print("=" * 60)
    print("ANALYZING SYSCALL 8 WITH A/B AS CONTINUATION")
    print("=" * 60)
    
    A, B = get_backdoor_components()
    print(f"A = {term_to_string(A)}")
    print(f"B = {term_to_string(B)}")
    
    # ((8 arg) A) second_arg
    # = (A result) second_arg
    # = (λb. b b) second_arg  [assuming result is absorbed]
    # = second_arg second_arg
    
    # Wait, that's not right either. Let me trace more carefully.
    # A = λa.λb. b b
    # (A result) = (λa.λb. b b) result = λb. b b  [a is bound to result but not used]
    # ((A result) x) = (λb. b b) x = x x
    
    # So if second_arg is QD, then (A result) QD = QD QD
    # QD applied to QD = ??
    
    print("\n((8 nil) A) QD - does QD QD do something?")
    program = App(App(App(Var(8), NIL_TERM), A), QD_TERM)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"  Raw hex: {resp.hex()}")
    print(f"  Raw ascii: {resp.decode('utf-8', 'replace')[:100]}")
    
    time.sleep(0.3)
    
    # What about ((8 nil) B) QD?
    # B = λa.λb. a b
    # (B result) = λb. result b
    # ((B result) QD) = result QD
    # = Right(6) applied to QD
    # Right(6) = λl.λr. r 6
    # (Right(6) QD) = (λl.λr. r 6) QD = λr. r 6
    # This is still a partial application...
    
    print("\n((8 nil) B) QD")
    program = App(App(App(Var(8), NIL_TERM), B), QD_TERM)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"  Raw hex: {resp.hex()}")
    print(f"  Raw ascii: {resp.decode('utf-8', 'replace')[:100]}")
    
    time.sleep(0.3)
    
    # What about (((8 nil) B) QD) QD?
    # = (Right(6) QD) QD
    # = (λr. r 6) QD
    # = QD 6
    # QD applied to 6 should print 6!
    
    print("\n(((8 nil) B) QD) QD - should print the error code?")
    inner = App(App(App(Var(8), NIL_TERM), B), QD_TERM)
    program = App(inner, QD_TERM)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"  Raw hex: {resp.hex()}")
    if FF in resp:
        term = parse_term(resp)
        print(f"  Parsed: {term_to_string(term)}")


def test_different_second_args() -> None:
    """
    Test ((8 nil) A) x for various x.
    
    ((8 nil) A) x = (A result) x = x x
    
    So this applies x to itself! What if x is something interesting?
    """
    print("\n" + "=" * 60)
    print("((8 nil) A) x = x x  FOR VARIOUS x")
    print("=" * 60)
    
    A, B = get_backdoor_components()
    
    test_values = [
        ("QD", QD_TERM),
        ("nil", NIL_TERM),
        ("I (λx.x)", Lam(Var(0))),
        ("A", A),
        ("B", B),
        ("Var(0)", Var(0)),
        ("Var(1)", Var(1)),
        ("Var(2)", Var(2)),
        ("Var(4)", Var(4)),
        ("Var(8)", Var(8)),
    ]
    
    for name, x in test_values:
        # ((8 nil) A) x
        inner = App(App(Var(8), NIL_TERM), A)
        program = App(inner, x)
        payload = encode_term(program) + bytes([FF])
        
        resp = query_raw(payload, timeout_s=5.0)
        
        if not resp:
            result = "<silent>"
        elif resp.startswith(b"Invalid term!"):
            result = "Invalid!"
        elif FF in resp:
            try:
                term = parse_term(resp)
                result = term_to_string(term)[:60]
            except:
                result = f"<parse error: {resp[:30].hex()}>"
        else:
            result = resp.decode('utf-8', 'replace')[:60]
        
        print(f"  x={name}: {result}")
        time.sleep(0.2)


def test_b_continuation_variations() -> None:
    """
    Test ((8 nil) B) x y for various x, y.
    
    ((8 nil) B) = B result = λb. result b
    ((8 nil) B) x = result x
    (((8 nil) B) x) y = (result x) y = ... depends on result
    
    If result is Right(6):
    Right(6) = λl.λr. r 6
    Right(6) x = λr. r 6
    Right(6) x y = y 6
    
    So (((8 nil) B) x) y = y 6 (y applied to the error code 6)
    
    If y = QD, then QD 6 should print 6.
    """
    print("\n" + "=" * 60)
    print("(((8 nil) B) x) y = y 6  FOR VARIOUS x, y")
    print("=" * 60)
    
    A, B = get_backdoor_components()
    
    # (((8 nil) B) anything) QD should print 6
    for name, x in [("nil", NIL_TERM), ("Var(0)", Var(0)), ("QD", QD_TERM)]:
        inner1 = App(App(Var(8), NIL_TERM), B)  # (8 nil) B
        inner2 = App(inner1, x)  # ((8 nil) B) x
        program = App(inner2, QD_TERM)  # (((8 nil) B) x) QD
        
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload, timeout_s=5.0)
        
        if not resp:
            result = "<silent>"
        elif FF in resp:
            try:
                term = parse_term(resp)
                result = term_to_string(term)[:80]
            except:
                result = f"<parse error: {resp[:30].hex()}>"
        else:
            result = resp.decode('utf-8', 'replace')[:80]
        
        print(f"  (((8 nil) B) {name}) QD: {result}")
        time.sleep(0.2)


def test_a_with_special_syscalls() -> None:
    """
    ((syscall arg) A) x = x x
    
    What if syscall is NOT 8? What about other syscalls?
    This pattern essentially ignores the syscall result.
    
    But wait - maybe A is meant to trigger some special behavior
    when used as continuation for syscall 8 specifically?
    """
    print("\n" + "=" * 60)
    print("((syscall nil) A) QD FOR VARIOUS SYSCALLS")
    print("=" * 60)
    
    A, B = get_backdoor_components()
    
    for syscall_num in [1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
        program = App(App(App(Var(syscall_num), NIL_TERM), A), QD_TERM)
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload, timeout_s=4.0)
        
        if not resp:
            result = "<silent>"
        elif resp.startswith(b"Invalid"):
            result = "Invalid!"
        elif FF in resp:
            try:
                term = parse_term(resp)
                # Try to decode as Either
                tag, pay = decode_either(term)
                if tag == "Right":
                    code = decode_byte_term(pay)
                    result = f"R{code}"
                else:
                    try:
                        bs = decode_bytes_list(pay)
                        result = f"L'{bs.decode()[:30]}'"
                    except:
                        result = f"L<non-bytes>"
            except:
                result = term_to_string(parse_term(resp))[:50]
        else:
            result = resp.decode('utf-8', 'replace')[:50]
        
        print(f"  syscall {syscall_num}: {result}")
        time.sleep(0.2)


def test_echo_with_a_b_continuation() -> None:
    """
    What about echo (0x0E) with A or B as continuation?
    
    Echo returns Left(input). If we pass to A:
    A Left(x) = λb. b b (ignoring the result)
    
    But with B:
    B Left(x) = λb. Left(x) b = λb. (λl.λr. l x) b
    """
    print("\n" + "=" * 60)
    print("ECHO WITH A/B CONTINUATION")
    print("=" * 60)
    
    A, B = get_backdoor_components()
    
    # ((0x0E x) A) QD for various x
    for name, x in [("nil", NIL_TERM), ("Var(8)", Var(8)), ("A", A)]:
        program = App(App(App(Var(0x0E), x), A), QD_TERM)
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload, timeout_s=4.0)
        
        if not resp:
            result = "<silent>"
        elif FF in resp:
            try:
                term = parse_term(resp)
                result = term_to_string(term)[:60]
            except:
                result = f"<err>"
        else:
            result = resp[:50].hex()
        
        print(f"  ((echo {name}) A) QD: {result}")
        time.sleep(0.2)


def test_nested_ab_patterns() -> None:
    """
    What if we need to nest A and B in a specific way?
    
    The author said "3 leafs" - A has 2 leaves (V0 V0), B has 2 (V1 V0).
    Combined with syscall 8 (1 leaf), we get 5 leaves.
    
    But if the "3 leafs" is the WHOLE PROGRAM, not counting A/B...
    
    Minimal: ((8 nil) A) - 8, nil has 1 leaf, A counted as 1?
    Wait, nil = λλV0 = 1 leaf.
    """
    print("\n" + "=" * 60)
    print("NESTED A/B PATTERNS")
    print("=" * 60)
    
    A, B = get_backdoor_components()
    
    patterns = [
        # Various nestings
        ("A A B", App(App(A, A), B)),
        ("A B A", App(App(A, B), A)),
        ("B A A", App(App(B, A), A)),
        ("B A B", App(App(B, A), B)),
        ("A (B A)", App(A, App(B, A))),
        ("A (B B)", App(A, App(B, B))),
        ("B (A A)", App(B, App(A, A))),
        ("B (A B)", App(B, App(A, B))),
        # Triple nesting
        ("(A A) A", App(App(A, A), A)),
        ("(B B) B", App(App(B, B), B)),
        ("(A B) B", App(App(A, B), B)),
        ("(B A) A", App(App(B, A), A)),
    ]
    
    for name, term in patterns:
        # Evaluate and see result
        program = App(term, QD_TERM)  # Apply to QD to see what we get
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload, timeout_s=4.0)
        
        if not resp:
            result = "<silent>"
        elif FF in resp:
            try:
                t = parse_term(resp)
                result = term_to_string(t)[:50]
            except:
                result = "<err>"
        else:
            result = resp[:30].hex()
        
        print(f"  ({name}) QD: {result}")
        time.sleep(0.15)


def main() -> None:
    analyze_syscall8_with_a_continuation()
    test_different_second_args()
    test_b_continuation_variations()
    test_a_with_special_syscalls()
    test_echo_with_a_b_continuation()
    test_nested_ab_patterns()


if __name__ == "__main__":
    main()
