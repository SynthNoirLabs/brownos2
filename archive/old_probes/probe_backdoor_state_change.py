#!/usr/bin/env python3
"""
STATE CHANGE HYPOTHESIS: Backdoor modifies permissions.

What if calling backdoor(nil) changes some internal state, and
THEN syscall 8 works with a normal argument?

The backdoor returns a pair (A, B). What if:
1. The pair needs to be applied to something
2. That application changes state
3. Then syscall 8 works

Or: What if we need to apply syscall 8 inside the backdoor continuation?
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
    print("STATE CHANGE HYPOTHESIS: Call backdoor, then syscall 8")
    print("=" * 70)
    
    print("\n--- Test 1: Call backdoor(nil) THEN syscall 8 ---")
    pair = Var(0)
    syscall8_s = Var(9)
    nil_s = shift(NIL_TERM, 1)
    qd_s = shift(QD_TERM, 1)
    
    syscall8_call = App(App(syscall8_s, nil_s), qd_s)
    cont = Lam(syscall8_call)
    
    program = App(App(Var(0xC9), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"backdoor(nil) → syscall8(nil): {classify(resp)}")
    
    print("\n--- Test 2: Apply pair to syscall 8, then call ---")
    pair = Var(0)
    syscall8_s = Var(9)
    applied = App(pair, syscall8_s)
    nil_s = shift(NIL_TERM, 1)
    qd_s = shift(QD_TERM, 1)
    call = App(App(applied, nil_s), qd_s)
    cont = Lam(call)
    
    program = App(App(Var(0xC9), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"backdoor(nil) → (pair syscall8)(nil): {classify(resp)}")
    
    print("\n--- Test 3: Apply pair to some value, then use result with syscall 8 ---")
    pair = Var(0)
    nil_s = shift(NIL_TERM, 1)
    applied = App(pair, nil_s)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    call = App(App(syscall8_s, applied), qd_s)
    cont = Lam(call)
    
    program = App(App(Var(0xC9), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"backdoor(nil) → syscall8(pair nil): {classify(resp)}")
    
    print("\n--- Test 4: Chain backdoor calls ---")
    pair1 = Var(0)
    backdoor_ss = Var(0xCB)
    nil_ss = shift(NIL_TERM, 2)
    syscall8_ss = Var(10)
    qd_ss = shift(QD_TERM, 2)
    
    pair2 = Var(0)
    inner_call = App(App(syscall8_ss, pair2), qd_ss)
    inner_cont = Lam(inner_call)
    
    middle_body = App(App(backdoor_ss, nil_ss), shift(inner_cont, 1))
    middle_cont = Lam(middle_body)
    
    program = App(App(Var(0xC9), NIL_TERM), middle_cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"backdoor → backdoor → syscall8(pair2): {classify(resp)}")
    
    print("\n--- Test 5: Use A and B from backdoor as handlers ---")
    pair = Var(0)
    fst = Lam(Lam(Var(1)))
    snd = Lam(Lam(Var(0)))
    
    a_val = App(pair, shift(fst, 1))
    b_val = App(pair, shift(snd, 1))
    
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    
    applied = App(App(a_val, b_val), nil_s)
    call = App(App(syscall8_s, applied), qd_s)
    cont = Lam(call)
    
    program = App(App(Var(0xC9), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8((A B) nil): {classify(resp)}")
    
    print("\n--- Test 6: What if the pair is the continuation? ---")
    pair = Var(0)
    syscall8_s = Var(9)
    nil_s = shift(NIL_TERM, 1)
    
    call = App(App(syscall8_s, nil_s), pair)
    cont = Lam(call)
    
    program = App(App(Var(0xC9), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8(nil)(pair): {classify(resp)}")
    
    print("\n--- Test 7: Extract A, use as continuation to syscall 8 ---")
    pair = Var(0)
    fst = Lam(Lam(Var(1)))
    a_val = App(pair, shift(fst, 1))
    
    syscall8_s = Var(9)
    nil_s = shift(NIL_TERM, 1)
    call = App(App(syscall8_s, nil_s), a_val)
    cont = Lam(call)
    
    program = App(App(Var(0xC9), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8(nil)(A): {classify(resp)}")
    
    print("\n--- Test 8: Extract B, use as continuation to syscall 8 ---")
    pair = Var(0)
    snd = Lam(Lam(Var(0)))
    b_val = App(pair, shift(snd, 1))
    
    syscall8_s = Var(9)
    nil_s = shift(NIL_TERM, 1)
    call = App(App(syscall8_s, nil_s), b_val)
    cont = Lam(call)
    
    program = App(App(Var(0xC9), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8(nil)(B): {classify(resp)}")
    
    print("\n--- Test 9: What if BOTH backdoor and echo are needed? ---")
    pair = Var(0)
    echo_s = Var(0x0F)
    
    e = Var(0)
    extracted = App(App(e, shift(I_TERM, 2)), shift(I_TERM, 2))
    pair_ss = Var(2)
    fst_ss = shift(shift(Lam(Lam(Var(1))), 1), 1)
    a_val_ss = App(pair_ss, fst_ss)
    
    token = App(a_val_ss, extracted)
    syscall8_sss = Var(11)
    qd_sss = shift(QD_TERM, 3)
    inner_call = App(App(syscall8_sss, token), qd_sss)
    inner_cont = Lam(inner_call)
    
    echo_call = App(App(echo_s, Var(252)), shift(inner_cont, 1))
    middle_cont = Lam(echo_call)
    
    program = App(App(Var(0xC9), NIL_TERM), middle_cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"backdoor → echo(252) → syscall8((A Var(254))): {classify(resp)}")
    
    print("\n--- Test 10: Try the pair as the ARGUMENT with different continuation ---")
    pair = Var(0)
    syscall8_s = Var(9)
    
    call = App(syscall8_s, pair)
    cont = Lam(App(call, shift(QD_TERM, 1)))
    
    program = App(App(Var(0xC9), NIL_TERM), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8(pair) then QD: {classify(resp)}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
