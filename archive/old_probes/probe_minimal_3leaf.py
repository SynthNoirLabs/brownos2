#!/usr/bin/env python3
"""
Author hint: "My record is 3 leafs IIRC"

In lambda calculus AST, a "leaf" is a Var node.
"3 leafs" = exactly 3 Var nodes in the term.

Let's enumerate ALL possible structures with exactly 3 leaves
and test them against the server.

Possible structures with 3 Vars:
1. ((Va Vb) Vc) - 2 apps
2. (Va (Vb Vc)) - 2 apps  
3. λ.((Va Vb) Vc) - 1 lam, 2 apps
4. λ.(Va (Vb Vc)) - 1 lam, 2 apps
5. λ.λ.((Va Vb) Vc) - 2 lams, 2 apps
6. etc.

The mail hint says "start with 00 FE FE" which is nil = λ.λ.V0.
That's only 1 leaf. So maybe the answer STARTS with nil as an argument?

Or maybe "3 leafs" in bytecode terms? Let's check:
- 00 FE FE = [Var(0), Lam, Lam] = nil, 1 leaf
- Actually the bytecode is postfix, so "00 FE FE" parses as λλV0

Let me think about what makes syscall 8 succeed.
All our attempts return Right(6) = Permission denied.

What if the permission check looks at:
- The CALLER (what context called syscall 8)?
- The STRUCTURE of the argument?
- Some CAPABILITY/TOKEN embedded in the argument?
"""
from __future__ import annotations

import itertools
import socket
import time
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
FE = 0xFE
FD = 0xFD

NIL_TERM: object = Lam(Lam(Var(0)))
QD_TERM: object = parse_term(QD_BYTES)


def term_to_string(term: object) -> str:
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{term_to_string(term.body)}"
    if isinstance(term, App):
        return f"({term_to_string(term.f)} {term_to_string(term.x)})"
    return str(term)


def count_leaves(term: object) -> int:
    """Count Var nodes (leaves) in a term."""
    if isinstance(term, Var):
        return 1
    if isinstance(term, Lam):
        return count_leaves(term.body)
    if isinstance(term, App):
        return count_leaves(term.f) + count_leaves(term.x)
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
    if resp.startswith(b"Term too big!"):
        return "TooBig!"
    if FF not in resp:
        return f"<noFF:{resp[:20].hex()}>"
    
    try:
        term = parse_term(resp)
        tag, payload = decode_either(term)
        if tag == "Right":
            code = decode_byte_term(payload)
            return f"R{code}"
        else:
            try:
                bs = decode_bytes_list(payload)
                txt = bs.decode('utf-8', 'replace')[:30]
                return f"L'{txt}'"
            except:
                return "L<nb>"
    except:
        return "<err>"


def generate_3leaf_terms(max_var: int = 255, max_lambdas: int = 2) -> Iterator[tuple[str, object]]:
    """Generate all 3-leaf term structures."""
    
    # Structure 1: ((Va Vb) Vc) - no lambdas
    for a, b, c in itertools.product(range(max_var + 1), repeat=3):
        term = App(App(Var(a), Var(b)), Var(c))
        yield (f"(({a} {b}) {c})", term)
    
    # Structure 2: (Va (Vb Vc)) - no lambdas
    for a, b, c in itertools.product(range(max_var + 1), repeat=3):
        term = App(Var(a), App(Var(b), Var(c)))
        yield (f"({a} ({b} {c}))", term)


def generate_3leaf_with_lambdas(var_range: range, lam_count: int) -> Iterator[tuple[str, object]]:
    """Generate 3-leaf terms with specific lambda count."""
    
    def wrap_lambdas(term: object, n: int) -> object:
        for _ in range(n):
            term = Lam(term)
        return term
    
    for a, b, c in itertools.product(var_range, repeat=3):
        # ((Va Vb) Vc)
        term1 = wrap_lambdas(App(App(Var(a), Var(b)), Var(c)), lam_count)
        yield (f"λ^{lam_count}.(({a} {b}) {c})", term1)
        
        # (Va (Vb Vc))
        term2 = wrap_lambdas(App(Var(a), App(Var(b), Var(c))), lam_count)
        yield (f"λ^{lam_count}.({a} ({b} {c}))", term2)


def test_minimal_programs() -> None:
    """
    Test the most minimal possible programs.
    
    The simplest valid program is just a Var: sends [i, FF] for Var(i).
    With 3 leafs, we have patterns like:
    - ((a b) c) FF
    - (a (b c)) FF
    """
    print("=" * 60)
    print("MINIMAL 3-LEAF PROGRAMS (no QD, direct output)")
    print("=" * 60)
    
    # Test raw 3-leaf programs without QD
    # These are just: term FF
    
    interesting_vars = [0, 1, 2, 4, 6, 7, 8, 14, 42, 201]
    
    print("\nStructure: ((a b) c) FF - direct evaluation")
    tested = 0
    found_interesting = []
    
    for a in interesting_vars:
        for b in interesting_vars:
            for c in interesting_vars:
                # ((a b) c) - this is the CPS pattern: ((syscall arg) cont)
                term = App(App(Var(a), Var(b)), Var(c))
                payload = encode_term(term) + bytes([FF])
                
                resp = query_raw(payload, timeout_s=2.0)
                result = classify_response(resp)
                
                # Only print interesting results
                if result not in ["<silent>", "R1", "Invalid!"]:
                    print(f"  (({a} {b}) {c}): {result}")
                    found_interesting.append(((a, b, c), result))
                
                tested += 1
                if tested % 50 == 0:
                    time.sleep(0.1)  # Rate limit
    
    print(f"\nTested {tested} combinations")
    print(f"Found {len(found_interesting)} interesting results")


def test_syscall8_with_structured_args() -> None:
    """
    All our syscall 8 tests pass simple arguments (nil, ints, strings).
    What if syscall 8 expects a very specific STRUCTURE?
    
    Like: a tuple, a function, or a specific combinator?
    """
    print("\n" + "=" * 60)
    print("SYSCALL 8 WITH STRUCTURED ARGUMENTS")
    print("=" * 60)
    
    # Get backdoor components for use as structured args
    backdoor_payload = bytes([0xC9]) + encode_term(NIL_TERM) + bytes([FD]) + QD_BYTES + bytes([FD, FF])
    resp = query_raw(backdoor_payload)
    term = parse_term(resp)
    _, pair_term = decode_either(term)
    
    # Extract pair body
    cur = pair_term
    while isinstance(cur, Lam):
        cur = cur.body
    a_term = cur.f.x  # λab.bb
    b_term = cur.x    # λab.ab
    
    # I combinator
    i_term = Lam(Var(0))  # λx.x
    
    # K combinator (like True)
    k_term = Lam(Lam(Var(1)))  # λx.λy.x
    
    # S combinator (partial)
    # s_term = λx.λy.λz. (x z) (y z)
    
    structured_args = [
        ("I (identity)", i_term),
        ("K (const/true)", k_term),
        ("backdoor A", a_term),
        ("backdoor B", b_term),
        ("backdoor pair", pair_term),
        ("(A A)", App(a_term, a_term)),
        ("(B B)", App(b_term, b_term)),
        ("(A B)", App(a_term, b_term)),
        ("(B A)", App(b_term, a_term)),
        ("(I I)", App(i_term, i_term)),
        ("(K I)", App(k_term, i_term)),
        ("(A I)", App(a_term, i_term)),
        ("(B I)", App(b_term, i_term)),
        ("(I A)", App(i_term, a_term)),
        ("(I B)", App(i_term, b_term)),
        # Nested structures
        ("((A B) A)", App(App(a_term, b_term), a_term)),
        ("((B A) B)", App(App(b_term, a_term), b_term)),
        ("(A (B A))", App(a_term, App(b_term, a_term))),
        ("(B (A B))", App(b_term, App(a_term, b_term))),
    ]
    
    for name, arg in structured_args:
        call = App(App(Var(8), arg), QD_TERM)
        payload = encode_term(call) + bytes([FF])
        resp = query_raw(payload, timeout_s=3.0)
        result = classify_response(resp)
        print(f"  syscall8({name}): {result}")
        time.sleep(0.15)


def test_echo_then_syscall8() -> None:
    """
    What if the RESULT of echo (the Either term) is what syscall 8 wants?
    Not the unwrapped payload, but the Either structure itself?
    """
    print("\n" + "=" * 60)
    print("ECHO RESULT AS SYSCALL 8 ARGUMENT")
    print("=" * 60)
    
    # Build: ((0x0E x) (λe. ((0x08 e) QD_shifted)))
    # This passes the Either result directly to syscall 8
    
    test_inputs = [
        ("nil", NIL_TERM),
        ("Var(0)", Var(0)),
        ("Var(8)", Var(8)),
        ("Var(201)", Var(201)),
        ("I", Lam(Var(0))),
    ]
    
    def shift(term: object, delta: int, cutoff: int = 0) -> object:
        if isinstance(term, Var):
            return Var(term.i + delta) if term.i >= cutoff else term
        if isinstance(term, Lam):
            return Lam(shift(term.body, delta, cutoff + 1))
        if isinstance(term, App):
            return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
        return term
    
    for name, input_term in test_inputs:
        # ((0x0E input) (λe. ((0x08 e) QD_shifted)))
        e = Var(0)
        qd_shifted = shift(QD_TERM, 1)
        body = App(App(Var(9), e), qd_shifted)  # Var(9) = 0x08 + 1 shift
        cont = Lam(body)
        program = App(App(Var(0x0E), input_term), cont)
        
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload, timeout_s=3.0)
        result = classify_response(resp)
        print(f"  echo({name}) → syscall8: {result}")
        time.sleep(0.15)


def test_double_echo_syscall8() -> None:
    """
    What about echo(echo(x)) as argument to syscall 8?
    """
    print("\n" + "=" * 60)
    print("DOUBLE ECHO AS SYSCALL 8 ARGUMENT")  
    print("=" * 60)
    
    def shift(term: object, delta: int, cutoff: int = 0) -> object:
        if isinstance(term, Var):
            return Var(term.i + delta) if term.i >= cutoff else term
        if isinstance(term, Lam):
            return Lam(shift(term.body, delta, cutoff + 1))
        if isinstance(term, App):
            return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
        return term
    
    # ((0x0E x) (λe1. ((0x0E e1) (λe2. ((0x08 e2) QD)))))
    for name, x in [("nil", NIL_TERM), ("Var(0)", Var(0))]:
        # Inner continuation: λe2. ((0x08 e2) QD)
        qd_shifted_2 = shift(QD_TERM, 2)  # Under 2 lambdas
        inner_body = App(App(Var(10), Var(0)), qd_shifted_2)  # Var(10) = 8 + 2
        inner_cont = Lam(inner_body)
        
        # Middle: λe1. ((0x0E e1) inner_cont)
        middle_body = App(App(Var(15), Var(0)), inner_cont)  # Var(15) = 0x0E + 1
        middle_cont = Lam(middle_body)
        
        # Outer: ((0x0E x) middle_cont)
        program = App(App(Var(0x0E), x), middle_cont)
        
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload, timeout_s=3.0)
        result = classify_response(resp)
        print(f"  echo(echo({name})) → syscall8: {result}")
        time.sleep(0.15)


def test_raw_bytecode_patterns() -> None:
    """
    Test raw bytecode patterns that might have special meaning.
    
    The mail says "start with 00 FE FE" - let's try variations.
    """
    print("\n" + "=" * 60)
    print("RAW BYTECODE PATTERNS")
    print("=" * 60)
    
    patterns = [
        ("00 FE FE (nil)", bytes([0x00, 0xFE, 0xFE])),
        ("00 FE FE + QD", bytes([0x00, 0xFE, 0xFE]) + QD_BYTES + bytes([0xFD])),
        ("08 00 FE FE FD (syscall8 nil)", bytes([0x08, 0x00, 0xFE, 0xFE, 0xFD])),
        ("C9 00 FE FE FD (backdoor nil)", bytes([0xC9, 0x00, 0xFE, 0xFE, 0xFD])),
        # What if 00 FE FE is the START of a longer pattern?
        ("00 FE FE 00 FE FE FD", bytes([0x00, 0xFE, 0xFE, 0x00, 0xFE, 0xFE, 0xFD])),
        ("00 FE FE 01 FD", bytes([0x00, 0xFE, 0xFE, 0x01, 0xFD])),
        # Try patterns suggested by "3 leafs"
        ("00 00 FD 00 FD", bytes([0x00, 0x00, 0xFD, 0x00, 0xFD])),  # ((V0 V0) V0)
        ("08 00 FE FE FD 02 FD", bytes([0x08, 0x00, 0xFE, 0xFE, 0xFD, 0x02, 0xFD])),  # ((8 nil) write)
    ]
    
    for name, raw in patterns:
        payload = raw + bytes([0xFF])
        resp = query_raw(payload, timeout_s=3.0)
        result = classify_response(resp)
        print(f"  {name}: {result}")
        time.sleep(0.15)


def main() -> None:
    test_syscall8_with_structured_args()
    test_echo_then_syscall8()
    test_double_echo_syscall8()
    test_raw_bytecode_patterns()
    # test_minimal_programs()  # This is very slow, skip for now


if __name__ == "__main__":
    main()
