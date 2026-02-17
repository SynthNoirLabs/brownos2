#!/usr/bin/env python3
"""
TOKEN HYPOTHESIS: Syscall 8 expects a "token" that includes special bytes.

FACTS:
1. echo(Var(n)) returns Left(Var(n+2))
2. Var(253/254/255) cannot be SERIALIZED (Encoding failed!)
3. But they CAN BE USED in computation
4. Syscall 8 always returns Right(6) for normal inputs

HYPOTHESIS:
Syscall 8 checks if its argument is a specific structure that CONTAINS
a Var(253), Var(254), or Var(255). This structure can ONLY be created
at runtime via echo - you can't encode it directly.

The backdoor returns A and B. Maybe the "token" is (A something) or (B something)
where "something" involves the echo-manufactured special indices.

"3 leafs" might mean: A term with 3 Var nodes, where at least one is 253+.
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
NIL_TERM = Lam(Lam(Var(0)))
QD_TERM = parse_term(QD_BYTES)
I_TERM = Lam(Var(0))


def shift(term, delta, cutoff=0):
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    raise TypeError(f"Unsupported: {type(term)}")


def recv_all(sock, timeout_s):
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


def query_raw(payload, timeout_s=4.0, host="82.165.133.222"):
    with socket.create_connection((host, 61221), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return recv_all(sock, timeout_s)


def classify(resp):
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
            return f"Right({decode_byte_term(payload)})"
        else:
            try:
                return f"Left('{decode_bytes_list(payload).decode()[:40]}')"
            except:
                return "Left(<non-bytes>)"
    except Exception as e:
        return f"<parse error: {e}>"


def main():
    print("=" * 70)
    print("TOKEN HYPOTHESIS: Build special structures with echo")
    print("=" * 70)
    
    print("\n--- Test 1: Build (backdoor_A Var(253)) ---")
    
    A_TERM = Lam(Lam(App(Var(0), Var(0))))
    B_TERM = Lam(Lam(App(Var(1), Var(0))))
    
    e = Var(0)
    extracted = App(App(e, I_TERM), I_TERM)
    a_s = shift(A_TERM, 1)
    token = App(a_s, extracted)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    body = App(App(syscall8_s, token), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8((A Var(253))): {classify(resp)}")
    
    print("\n--- Test 2: Build (backdoor_B Var(253)) ---")
    e = Var(0)
    extracted = App(App(e, I_TERM), I_TERM)
    b_s = shift(B_TERM, 1)
    token = App(b_s, extracted)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    body = App(App(syscall8_s, token), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8((B Var(253))): {classify(resp)}")
    
    print("\n--- Test 3: Build (Var(253) A) ---")
    e = Var(0)
    extracted = App(App(e, I_TERM), I_TERM)
    a_s = shift(A_TERM, 1)
    token = App(extracted, a_s)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    body = App(App(syscall8_s, token), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8((Var(253) A)): {classify(resp)}")
    
    print("\n--- Test 4: Build (Var(253) B) ---")
    e = Var(0)
    extracted = App(App(e, I_TERM), I_TERM)
    b_s = shift(B_TERM, 1)
    token = App(extracted, b_s)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    body = App(App(syscall8_s, token), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8((Var(253) B)): {classify(resp)}")
    
    print("\n--- Test 5: Build pair(Var(253), something) ---")
    def make_pair(fst, snd):
        return Lam(App(App(Var(0), fst), snd))
    
    e = Var(0)
    extracted = App(App(e, I_TERM), I_TERM)
    nil_s = shift(NIL_TERM, 1)
    pair_term = make_pair(extracted, nil_s)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    body = App(App(syscall8_s, pair_term), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8(pair(Var(253), nil)): {classify(resp)}")
    
    print("\n--- Test 6: Build Left(Var(253)) and give to syscall 8 ---")
    def make_left(x):
        return Lam(Lam(App(Var(1), x)))
    
    e = Var(0)
    extracted = App(App(e, I_TERM), I_TERM)
    left_term = make_left(extracted)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    body = App(App(syscall8_s, left_term), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8(Left(Var(253))): {classify(resp)}")
    
    print("\n--- Test 7: What about the raw Left wrapper from echo? ---")
    e = Var(0)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    body = App(App(syscall8_s, e), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8(Left(Var(253)) as raw Either): {classify(resp)}")
    
    print("\n--- Test 8: Use backdoor's A and B from server ---")
    pair_var = Var(0)
    fst = Lam(Lam(Var(1)))
    snd = Lam(Lam(Var(0)))
    a_from_pair = App(pair_var, shift(fst, 1))
    b_from_pair = App(pair_var, shift(snd, 1))
    
    e1 = Var(0)
    extracted1 = App(App(e1, shift(I_TERM, 1)), shift(I_TERM, 1))
    pair_s = Var(1)
    a_part = App(pair_s, shift(shift(fst, 1), 1))
    token = App(a_part, extracted1)
    syscall8_ss = Var(10)
    qd_ss = shift(QD_TERM, 2)
    inner_body = App(App(syscall8_ss, token), qd_ss)
    inner_cont = Lam(inner_body)
    
    echo_s = Var(0x0F)
    middle_body = App(App(echo_s, Var(251 + 1)), shift(inner_cont, 1))
    middle_cont = Lam(middle_body)
    
    program = App(App(Var(0xC9), NIL_TERM), middle_cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"get backdoor pair, then syscall8((A Var(253))): {classify(resp)}")
    
    print("\n--- Test 9: Echo inside backdoor continuation ---")
    pair = Var(0)
    fst_selector = Lam(Lam(Var(1)))
    
    echo_s = Var(0x0E + 1)
    echo_251_s = App(echo_s, Var(251 + 1))
    
    e1 = Var(0)
    extracted = App(App(e1, shift(I_TERM, 2)), shift(I_TERM, 2))
    pair_ss = Var(2)
    a_from_pair_ss = App(pair_ss, shift(shift(fst_selector, 1), 1))
    token = App(a_from_pair_ss, extracted)
    syscall8_sss = Var(11)
    qd_sss = shift(QD_TERM, 3)
    deepest = App(App(syscall8_sss, token), qd_sss)
    inner_cont = Lam(deepest)
    
    middle_body = App(echo_251_s, shift(inner_cont, 1))
    middle_cont = Lam(middle_body)
    
    program = App(App(Var(0xC9), NIL_TERM), middle_cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"backdoor → echo(251) → syscall8((A extracted)): {classify(resp)}")
    
    print("\n--- Test 10: CRITICAL - Apply pair TO Var(253) ---")
    e = Var(0)
    extracted = App(App(e, I_TERM), I_TERM)
    
    inner_pair = Var(0)
    applied_to_extracted = App(inner_pair, Var(1))
    syscall8_ss = Var(10)
    qd_ss = shift(QD_TERM, 2)
    inner_body = App(applied_to_extracted, qd_ss)
    inner_cont = Lam(inner_body)
    
    middle_body = App(App(Var(0xCA), NIL_TERM), shift(inner_cont, 1))
    middle_cont = Lam(middle_body)
    
    program = App(App(Var(0x0E), Var(251)), middle_cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"echo(251) → backdoor → (pair Var(253)): {classify(resp)}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
