#!/usr/bin/env python3
"""
USE UNSERIALIZABLE VARS IN COMPUTATION

KEY INSIGHT: echo(Var(251)) creates Var(253) internally, but:
- We can't QUOTE it (encoding fails)
- But we CAN USE it in computation!

The trick: use the Var(253) as input to a syscall whose OUTPUT is encodable.

For example:
- echo(Var(251)) → Left(Var(253))
- Extract → Var(253)
- Call syscall 8 with it: syscall8(Var(253))
- syscall 8 returns Right(something) which IS encodable
- Quote THAT result

We need a continuation that:
1. Doesn't try to quote the high-index var directly
2. Uses it as syscall input
3. Quotes the syscall's result
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
    print("USE HIGH-INDEX VARS WITHOUT QUOTING THEM")
    print("=" * 70)
    
    # The key is: call syscall with the extracted high-index var,
    # then use QD on the RESULT of the syscall (not on the var itself)
    
    # Build: ((0x0E Var(251)) (λe. ((syscall (e I I)) QD_s)))
    # Here: (e I I) extracts Var(253)
    #       syscall(Var(253)) produces a result
    #       QD outputs the result
    
    print("\n--- Test 1: Use extracted Var(253) as arg to syscall 8 ---")
    
    e = Var(0)
    extracted = App(App(e, I_TERM), I_TERM)
    syscall8_s = Var(8 + 1)
    qd_s = shift(QD_TERM, 1)
    body = App(App(syscall8_s, extracted), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8(extract(echo(251))): {classify(resp)}")
    if resp:
        print(f"  Raw: {resp[:60].hex()}")
    
    print("\n--- Test 2: Use extracted Var(253) as arg to other syscalls ---")
    
    for syscall_num in [6, 7, 0xC9]:
        e = Var(0)
        extracted = App(App(e, I_TERM), I_TERM)
        syscall_s = Var(syscall_num + 1)
        qd_s = shift(QD_TERM, 1)
        body = App(App(syscall_s, extracted), qd_s)
        cont = Lam(body)
        
        program = App(App(Var(0x0E), Var(251)), cont)
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload)
        print(f"syscall{syscall_num}(extract(echo(251))): {classify(resp)}")
        time.sleep(0.15)
    
    print("\n--- Test 3: Double echo chain, use result with syscall 8 ---")
    
    e2 = Var(0)
    i_ss = shift(I_TERM, 2)
    extracted2 = App(App(e2, i_ss), i_ss)
    syscall8_ss = Var(8 + 2)
    qd_ss = shift(QD_TERM, 2)
    inner_body = App(App(syscall8_ss, extracted2), qd_ss)
    inner_cont = Lam(inner_body)
    
    e1 = Var(0)
    i_s = shift(I_TERM, 1)
    extracted1 = App(App(e1, i_s), i_s)
    echo_s = Var(0x0E + 1)
    inner_cont_s = shift(inner_cont, 1)
    middle_body = App(App(echo_s, extracted1), inner_cont_s)
    middle_cont = Lam(middle_body)
    
    program = App(App(Var(0x0E), Var(251)), middle_cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"double_echo(251) → Var(255) → syscall8: {classify(resp)}")
    if resp:
        print(f"  Raw: {resp[:60].hex()}")
    
    print("\n--- Test 4: What if Var(253) IS THE KEY for syscall 8? ---")
    
    e = Var(0)
    extracted = App(App(e, I_TERM), I_TERM)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    body = App(App(syscall8_s, extracted), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8(Var(253)): {classify(resp)}")
    
    print("\n--- Test 5: What if Var(254) or Var(255) is the key? ---")
    
    for start_k in [252, 251, 250]:
        result_k = start_k + 2
        
        e = Var(0)
        extracted = App(App(e, I_TERM), I_TERM)
        syscall8_s = Var(9)
        qd_s = shift(QD_TERM, 1)
        body = App(App(syscall8_s, extracted), qd_s)
        cont = Lam(body)
        
        program = App(App(Var(0x0E), Var(start_k)), cont)
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload)
        print(f"syscall8(Var({result_k})) via echo({start_k}): {classify(resp)}")
        time.sleep(0.15)
    
    print("\n--- Test 6: Apply Var(253) directly (it might be a function) ---")
    
    e = Var(0)
    extracted = App(App(e, I_TERM), I_TERM)
    nil_s = shift(NIL_TERM, 1)
    applied = App(extracted, nil_s)
    qd_s = shift(QD_TERM, 1)
    body = App(applied, qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"(Var(253) nil) → QD: {classify(resp)}")
    if resp:
        print(f"  Raw: {resp[:60].hex()}")
    
    print("\n--- Test 7: Use Var(253) with backdoor ---")
    
    backdoor = Var(0xC9)
    
    e = Var(0)
    extracted = App(App(e, I_TERM), I_TERM)
    backdoor_s = Var(0xC9 + 1)
    qd_s = shift(QD_TERM, 1)
    body = App(App(backdoor_s, extracted), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"backdoor(Var(253)): {classify(resp)}")
    if resp:
        print(f"  Raw: {resp[:60].hex()}")
    
    print("\n--- Test 8: What's at Var(253)? Try different operations ---")
    
    for i in range(0, 10):
        small_arg = Var(i)
        
        e = Var(0)
        extracted = App(App(e, I_TERM), I_TERM)
        arg_s = Var(i + 1)
        applied = App(extracted, arg_s)
        qd_s = shift(QD_TERM, 1)
        body = App(applied, qd_s)
        cont = Lam(body)
        
        program = App(App(Var(0x0E), Var(251)), cont)
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload)
        print(f"(Var(253) Var({i})): {classify(resp)}")
        time.sleep(0.1)
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
