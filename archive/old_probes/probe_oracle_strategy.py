#!/usr/bin/env python3
"""
Oracle's strategy: Project B from backdoor using FALSE (00 FE FE),
then call syscall 8 THROUGH B (not just with B as argument).

The permission check might be about PROVENANCE - syscall 8 expects
to be called via a capability from the backdoor, not just passed one.
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

HOST = "82.165.133.222"
PORT = 61221

NIL_TERM: object = Lam(Lam(Var(0)))
QD_TERM: object = parse_term(QD_BYTES)

FALSE_TERM: object = Lam(Lam(Var(0)))
TRUE_TERM: object = Lam(Lam(Var(1)))


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


def query_raw(payload: bytes, timeout_s: float = 5.0) -> bytes:
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
    except Exception as e:
        return b''


def classify(resp: bytes) -> str:
    if not resp:
        return "<silent>"
    if resp.startswith(b"Invalid"):
        return "Invalid!"
    if resp.startswith(b"Encoding failed"):
        return "EncFail!"
    if FF not in resp:
        return f"<noFF:{resp[:30].hex()}>"
    
    try:
        term = parse_term(resp)
        try:
            tag, payload = decode_either(term)
            if tag == "Right":
                code = decode_byte_term(payload)
                return f"Right({code})"
            else:
                try:
                    bs = decode_bytes_list(payload)
                    return f"Left('{bs.decode()[:50]}')"
                except:
                    return f"Left(<{term_to_string(payload)[:40]}>)"
        except:
            return term_to_string(term)[:50]
    except:
        return f"<err:{resp[:20].hex()}>"


def test_project_b_call_8_through_it():
    """
    Oracle's main strategy:
    ((201 nil) (λpair. let b = pair FALSE in ((b 8) nil) QD))
    
    This projects B from the pair, then calls syscall 8 THROUGH B.
    B x y = x y, so ((B 8) nil) = (8 nil) = syscall 8 with nil.
    
    But the key is: the call goes THROUGH B, which came from the backdoor.
    If there's provenance checking, this might work.
    """
    print("=" * 60)
    print("ORACLE STRATEGY: Project B, call 8 through it")
    print("=" * 60)
    
    # Build: ((201 nil) (λpair. (((pair FALSE) 8) nil) QD_shifted))
    # Inside λpair:
    #   pair = V0
    #   Globals at +1 (so syscall 8 is V9, etc.)
    # After (pair FALSE):
    #   We get B = λab.ab
    # Then ((B 8) nil):
    #   = ((λab.ab 8) nil)
    #   = (8 nil)
    # Then ((8 nil) QD_shifted)
    
    # Wait, that's not calling 8 "through" B in a meaningful way...
    # Let me think again.
    
    # B = λab.ab
    # (B x) = λb. x b
    # ((B x) y) = x y
    
    # So ((B 8) nil) reduces to (8 nil), which is just normal syscall 8.
    # If the permission check is at reduction time, this is identical.
    
    # BUT: if the check is at INVOCATION time and looks at the closure
    # that's being applied, then B (from backdoor) being in the call chain
    # might matter.
    
    # Let's try it anyway.
    
    pair = Var(0)
    false_sel = Lam(Lam(Var(0)))
    b_projected = App(pair, false_sel)
    
    syscall8_shifted = Var(9)
    qd_shifted = shift(QD_TERM, 1)
    
    call_through_b = App(App(b_projected, syscall8_shifted), NIL_TERM)
    body = App(call_through_b, qd_shifted)
    cont = Lam(body)
    
    program = App(App(Var(201), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    
    print(f"Program: ((201 nil) (λp. (((p FALSE) 8) nil) QD))")
    resp = query_raw(payload)
    print(f"Result: {classify(resp)}")
    
    time.sleep(0.3)
    
    # Also try with TRUE to get A
    print("\n--- With TRUE (projects A instead) ---")
    true_sel = Lam(Lam(Var(1)))
    a_projected = App(pair, true_sel)
    
    call_through_a = App(App(a_projected, syscall8_shifted), NIL_TERM)
    body_a = App(call_through_a, qd_shifted)
    cont_a = Lam(body_a)
    
    program_a = App(App(Var(201), NIL_TERM), cont_a)
    payload_a = encode_term(program_a) + bytes([FF])
    
    print(f"Program: ((201 nil) (λp. (((p TRUE) 8) nil) QD))")
    resp_a = query_raw(payload_a)
    print(f"Result: {classify(resp_a)}")


def test_b_as_continuation_for_8():
    """
    What if B should be the CONTINUATION for syscall 8?
    
    ((8 arg) B) where B comes from the backdoor.
    
    B = λab.ab, so B result = λb. result b
    This is a partial application waiting for another arg.
    """
    print("\n" + "=" * 60)
    print("B AS CONTINUATION FOR SYSCALL 8")
    print("=" * 60)
    
    # ((201 nil) (λpair. let b = pair FALSE in ((8 nil) b) then ???))
    # The problem is: after ((8 nil) b), we get (b result) = λb2. result b2
    # We need to supply another arg to see output.
    
    # Let's try: ((201 nil) (λpair. (((8 nil) (pair FALSE)) QD)))
    pair = Var(0)
    false_sel = Lam(Lam(Var(0)))
    b_projected = App(pair, false_sel)
    
    syscall8_shifted = Var(9)
    qd_shifted = shift(QD_TERM, 1)
    
    call_8_with_b_cont = App(App(syscall8_shifted, NIL_TERM), b_projected)
    body = App(call_8_with_b_cont, qd_shifted)
    cont = Lam(body)
    
    program = App(App(Var(201), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    
    print(f"Program: ((201 nil) (λp. (((8 nil) (p FALSE)) QD)))")
    resp = query_raw(payload)
    print(f"Result: {classify(resp)}")
    
    time.sleep(0.3)
    
    # Also: what about passing B as the arg to syscall 8?
    # ((8 (pair FALSE)) QD)
    print("\n--- B as argument to syscall 8 ---")
    call_8_with_b_arg = App(App(syscall8_shifted, b_projected), qd_shifted)
    cont2 = Lam(call_8_with_b_arg)
    
    program2 = App(App(Var(201), NIL_TERM), cont2)
    payload2 = encode_term(program2) + bytes([FF])
    
    print(f"Program: ((201 nil) (λp. ((8 (p FALSE)) QD)))")
    resp2 = query_raw(payload2)
    print(f"Result: {classify(resp2)}")


def test_echo_then_syscall8():
    """
    Oracle suggested using echo (14) to "preserve and observe".
    
    Wrap result with: λr. ((14 r) QD)
    This echoes the result, then prints via QD.
    """
    print("\n" + "=" * 60)
    print("ECHO-WRAPPED CONTINUATION")
    print("=" * 60)
    
    # cont = λr. ((14 r) QD_shifted)
    r = Var(0)
    echo_shifted = Var(15)
    qd_shifted = shift(QD_TERM, 1)
    
    echo_r = App(App(echo_shifted, r), qd_shifted)
    echo_cont = Lam(echo_r)
    
    # ((8 nil) echo_cont)
    program = App(App(Var(8), NIL_TERM), echo_cont)
    payload = encode_term(program) + bytes([FF])
    
    print(f"Program: ((8 nil) (λr. ((14 r) QD)))")
    resp = query_raw(payload)
    print(f"Result: {classify(resp)}")
    
    time.sleep(0.3)
    
    # Now with backdoor-projected B:
    # ((201 nil) (λpair. ((8 (pair FALSE)) (λr. ((14 r) QD)))))
    print("\n--- With backdoor-projected B as arg ---")
    
    pair = Var(0)
    false_sel = Lam(Lam(Var(0)))
    b_projected = App(pair, false_sel)
    
    syscall8_shifted = Var(9)
    echo_shifted2 = Var(15)
    qd_shifted2 = shift(QD_TERM, 2)
    
    r2 = Var(0)
    inner_echo = App(App(Var(16), r2), shift(QD_TERM, 2))
    inner_cont = Lam(inner_echo)
    
    call_8 = App(App(syscall8_shifted, b_projected), inner_cont)
    outer_cont = Lam(call_8)
    
    program2 = App(App(Var(201), NIL_TERM), outer_cont)
    payload2 = encode_term(program2) + bytes([FF])
    
    print(f"Program: ((201 nil) (λp. ((8 (p FALSE)) (λr. ((14 r) QD)))))")
    resp2 = query_raw(payload2)
    print(f"Result: {classify(resp2)}")


def test_pass_full_pair():
    """
    What if syscall 8 wants the FULL PAIR, not just A or B?
    """
    print("\n" + "=" * 60)
    print("FULL PAIR TO SYSCALL 8")
    print("=" * 60)
    
    # ((201 nil) (λpair. ((8 pair) QD)))
    pair = Var(0)
    syscall8_shifted = Var(9)
    qd_shifted = shift(QD_TERM, 1)
    
    call_8 = App(App(syscall8_shifted, pair), qd_shifted)
    cont = Lam(call_8)
    
    program = App(App(Var(201), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    
    print(f"Program: ((201 nil) (λp. ((8 p) QD)))")
    resp = query_raw(payload)
    print(f"Result: {classify(resp)}")


def test_minimal_3_leaf():
    """
    If the minimal solution is "3 leafs", let's try the absolute minimum
    while incorporating backdoor.
    
    Backdoor: ((201 nil) cont) - that's already 3 leaves (201, nil's V0, cont's structure)
    
    Wait, nil = λλV0 has 1 leaf.
    ((201 nil) cont) with cont = V2 would be:
    - Var(201): 1 leaf
    - nil: 1 leaf
    - Var(2): 1 leaf
    Total: 3 leaves!
    
    So ((201 nil) 2) might be the pattern!
    """
    print("\n" + "=" * 60)
    print("MINIMAL 3-LEAF WITH BACKDOOR")
    print("=" * 60)
    
    # ((201 nil) Var(i)) for various i
    for i in [0, 1, 2, 4, 8, 14, 42]:
        term = App(App(Var(201), NIL_TERM), Var(i))
        payload = encode_term(term) + bytes([FF])
        resp = query_raw(payload, timeout_s=3.0)
        result = classify(resp)
        print(f"  ((201 nil) V{i}): {result}")
        time.sleep(0.15)


def test_syscall8_applied_to_pair():
    """
    The pair is λs. s A B.
    What if we apply syscall 8 AS s?
    
    pair 8 = 8 A B = ((8 A) B)
    
    This means syscall 8 gets A as argument and B as continuation!
    """
    print("\n" + "=" * 60)
    print("PAIR APPLIED TO SYSCALL 8: pair 8 = ((8 A) B)")
    print("=" * 60)
    
    # ((201 nil) (λpair. (pair 8) then QD))
    # Wait, (pair 8) = ((8 A) B). The result of that needs to go to QD.
    
    # Let me build: ((201 nil) (λpair. ((pair 8) (λres. (res QD)))))
    # Hmm, that's getting complicated.
    
    # Simpler: ((201 nil) (λpair. (pair 8)))
    # Then apply QD outside?
    # ((((201 nil) (λpair. (pair 8))) ???) QD)
    
    # Actually let's just try: ((201 nil) (λpair. ((pair 8))))
    # And see if there's output
    
    pair = Var(0)
    syscall8_shifted = Var(9)
    
    pair_applied_to_8 = App(pair, syscall8_shifted)
    cont = Lam(pair_applied_to_8)
    
    program = App(App(Var(201), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    
    print(f"Program: ((201 nil) (λp. (p 8)))")
    resp = query_raw(payload)
    print(f"Result: {classify(resp)}")
    
    time.sleep(0.3)
    
    # Also try wrapping with echo:
    # ((201 nil) (λpair. ((14 (pair 8)) QD)))
    print("\n--- With echo wrapper ---")
    echo_shifted = Var(15)
    qd_shifted = shift(QD_TERM, 1)
    
    inner = App(pair, syscall8_shifted)
    echoed = App(App(echo_shifted, inner), qd_shifted)
    cont2 = Lam(echoed)
    
    program2 = App(App(Var(201), NIL_TERM), cont2)
    payload2 = encode_term(program2) + bytes([FF])
    
    print(f"Program: ((201 nil) (λp. ((14 (p 8)) QD)))")
    resp2 = query_raw(payload2)
    print(f"Result: {classify(resp2)}")


def main():
    test_project_b_call_8_through_it()
    test_b_as_continuation_for_8()
    test_echo_then_syscall8()
    test_pass_full_pair()
    test_minimal_3_leaf()
    test_syscall8_applied_to_pair()


if __name__ == "__main__":
    main()
