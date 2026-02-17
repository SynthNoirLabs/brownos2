#!/usr/bin/env python3
"""
INVESTIGATION: echo(syscall8) returns Left(<non-bytes>)

This means echo successfully wraps the syscall 8 reference.
The question is: what's inside that Left wrapper?

Strategy:
1. Echo syscall 8, then examine the result
2. Try to APPLY the echoed syscall 8 to arguments
3. See if the echoed version behaves differently
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
I_TERM: object = Lam(Var(0))


def shift(term: object, delta: int, cutoff: int = 0) -> object:
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
    with socket.create_connection((host, 61221), timeout=timeout_s) as sock:
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
        return "Invalid term!"
    if resp.startswith(b"Encoding failed!"):
        return "Encoding failed!"
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


def term_to_string(term: object) -> str:
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"(λ.{term_to_string(term.body)})"
    if isinstance(term, App):
        return f"({term_to_string(term.f)} {term_to_string(term.x)})"
    return str(term)


def main():
    print("=" * 70)
    print("ECHO(SYSCALL8) INVESTIGATION")
    print("=" * 70)
    
    print("\n--- Phase 1: Basic echo tests ---")
    
    for syscall_num in [4, 6, 7, 8, 14, 0xC9]:
        program = App(App(Var(0x0E), Var(syscall_num)), QD_TERM)
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload)
        print(f"echo(Var({syscall_num})): {classify_response(resp)}")
        if resp and FF in resp:
            try:
                term = parse_term(resp)
                tag, inner = decode_either(term)
                if tag == "Left":
                    print(f"  Parsed inner: {term_to_string(inner)[:100]}")
            except Exception as e:
                print(f"  Parse error: {e}")
        time.sleep(0.15)
    
    print("\n--- Phase 2: Extract and use echoed syscall 8 ---")
    
    # Build: ((0x0E Var(8)) (λe. (((e I I) arg) qd_s)))
    # Extract the echoed syscall 8 and apply it to an argument
    
    for arg_name, arg in [("nil", NIL_TERM), ("I", I_TERM), ("Var(8)", Var(8))]:
        e = Var(0)
        unwrapped = App(App(e, I_TERM), I_TERM)
        arg_s = shift(arg, 1) if isinstance(arg, (Lam, App)) else Var(arg.i + 1) if isinstance(arg, Var) and arg.i >= 0 else arg
        if isinstance(arg, Var):
            arg_s = Var(arg.i + 1) if arg.i >= 0 else arg
        elif isinstance(arg, (Lam, App)):
            arg_s = shift(arg, 1)
        else:
            arg_s = arg
        qd_s = shift(QD_TERM, 1)
        body = App(App(unwrapped, arg_s), qd_s)
        cont = Lam(body)
        
        program = App(App(Var(0x0E), Var(8)), cont)
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload)
        print(f"extract(echo(8))({arg_name}): {classify_response(resp)}")
        time.sleep(0.15)
    
    print("\n--- Phase 3: Double extract pattern ---")
    
    # What if we echo the result of extracting an echo?
    # ((0x0E Var(8)) (λe1. ((0x0F (e1 I I)) (λe2. ((e2 I I) arg) qd))))
    
    e2 = Var(0)
    nil_ss = shift(NIL_TERM, 2)
    qd_ss = shift(QD_TERM, 2)
    inner_body = App(App(App(App(e2, shift(I_TERM, 2)), shift(I_TERM, 2)), nil_ss), qd_ss)
    inner_cont = Lam(inner_body)
    
    e1 = Var(0)
    echo_s = Var(0x0E + 1)
    unwrap1 = App(App(e1, shift(I_TERM, 1)), shift(I_TERM, 1))
    inner_cont_s = shift(inner_cont, 1)
    middle_body = App(App(echo_s, unwrap1), inner_cont_s)
    middle_cont = Lam(middle_body)
    
    program = App(App(Var(0x0E), Var(8)), middle_cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"echo(extract(echo(8))) then use: {classify_response(resp)}")
    
    print("\n--- Phase 4: Use echoed syscall directly (don't extract) ---")
    
    # What if we DON'T extract, but apply the Left wrapper directly?
    # ((0x0E Var(8)) (λe. ((e arg) qd_s)))
    # This applies the Either directly
    
    for arg_name, arg in [("nil", NIL_TERM), ("I", I_TERM)]:
        e = Var(0)
        arg_s = shift(arg, 1)
        qd_s = shift(QD_TERM, 1)
        body = App(App(e, arg_s), qd_s)
        cont = Lam(body)
        
        program = App(App(Var(0x0E), Var(8)), cont)
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload)
        print(f"echo(8) applied directly to {arg_name}: {classify_response(resp)}")
        time.sleep(0.15)
    
    print("\n--- Phase 5: Chain echo to syscall 8 as continuation ---")
    
    # Instead of calling syscall 8 with a value, what if we use
    # the echoed syscall 8 AS the continuation?
    
    # Try: ((other_syscall arg) echoed_8)
    # Build: ((0x0E Var(8)) (λe8. ((syscall arg) e8)))
    
    for syscall, sarg in [(0x07, Var(0)), (0x06, NIL_TERM), (0xC9, NIL_TERM)]:
        e8 = Var(0)
        syscall_s = Var(syscall + 1)
        if isinstance(sarg, Var):
            sarg_s = Var(sarg.i + 1)
        else:
            sarg_s = shift(sarg, 1)
        body = App(App(syscall_s, sarg_s), e8)
        cont = Lam(body)
        
        program = App(App(Var(0x0E), Var(8)), cont)
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload)
        print(f"(syscall_{syscall} arg) with echo(8) as cont: {classify_response(resp)}")
        time.sleep(0.15)
    
    print("\n--- Phase 6: Use backdoor result with echoed syscall 8 ---")
    
    # Get backdoor pair, then use echoed syscall 8 somehow
    # ((0xC9 nil) (λpair. ((0x0F pair) (λe. use e with syscall 8))))
    
    # Actually let's try: echo the pair, then feed to syscall 8
    pair = Var(0)
    echo_s = Var(0x0E + 1)
    syscall8_ss = Var(8 + 2)
    qd_ss = shift(QD_TERM, 2)
    
    e = Var(0)
    inner_body = App(App(syscall8_ss, e), qd_ss)
    inner_cont = Lam(inner_body)
    
    middle_body = App(App(echo_s, pair), shift(inner_cont, 1))
    middle_cont = Lam(middle_body)
    
    program = App(App(Var(0xC9), NIL_TERM), middle_cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8(echo(backdoor_pair)): {classify_response(resp)}")
    
    print("\n--- Phase 7: What about applying backdoor pair TO syscall 8? ---")
    
    # pair = λs. s A B
    # pair Var(8) = Var(8) A B = syscall8 applied to A and B!
    
    pair = Var(0)
    syscall8_s = Var(8 + 1)
    qd_s = shift(QD_TERM, 1)
    
    # (pair syscall8) = syscall8 A B
    pair_of_8 = App(pair, syscall8_s)
    body = App(pair_of_8, qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0xC9), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"(backdoor_pair syscall8) then QD: {classify_response(resp)}")
    
    # Also try: ((pair syscall8) nil) qd - to complete the syscall call
    pair = Var(0)
    syscall8_s = Var(9)
    nil_s = shift(NIL_TERM, 1)
    qd_s = shift(QD_TERM, 1)
    
    pair_of_8 = App(pair, syscall8_s)
    call_with_nil = App(pair_of_8, nil_s)
    body = App(call_with_nil, qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0xC9), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"((backdoor_pair syscall8) nil) then QD: {classify_response(resp)}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
