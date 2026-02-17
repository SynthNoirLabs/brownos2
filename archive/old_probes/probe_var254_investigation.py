#!/usr/bin/env python3
"""
VAR(254) INVESTIGATION

DISCOVERY: (Var(254) Var(254)) returns Right(1) = "Syscall does not exist"
This means Var(254) is being treated as a syscall reference!

Var(254) = 0xFE in the internal representation
0xFE is the Lambda marker in the wire format, but internally it's a valid index

Questions:
1. What happens if we call Var(254) as a syscall with different arguments?
2. What about Var(253) and Var(255)?
3. Can we use echo to access these as actual syscalls?
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
QD_TERM = parse_term(QD_BYTES)
NIL = Lam(Lam(Var(0)))
I = Lam(Var(0))


def shift(term, delta, cutoff=0):
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    return term


def short_show(term, depth=10):
    if depth <= 0:
        return "..."
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"(λ.{short_show(term.body, depth-1)})"
    if isinstance(term, App):
        return f"({short_show(term.f, depth-1)} {short_show(term.x, depth-1)})"
    return repr(term)


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
        return f"<no FF: {resp[:40].hex()}>"
    try:
        term = parse_term(resp)
        tag, payload = decode_either(term)
        if tag == "Right":
            return f"Right({decode_byte_term(payload)})"
        else:
            try:
                bs = decode_bytes_list(payload)
                return f"Left('{bs.decode()[:40]}')"
            except:
                return f"Left({short_show(payload)})"
    except Exception as e:
        return f"<parse error: {e}>"


def main():
    print("=" * 70)
    print("VAR(254) AS SYSCALL INVESTIGATION")
    print("=" * 70)
    
    print("\n--- Phase 1: Call Var(253/254/255) as syscalls ---")
    
    for target_idx in [252, 253, 254, 255]:
        if target_idx <= 252:
            start = target_idx
            echoes = 0
        elif target_idx == 253:
            start = 251
            echoes = 1
        elif target_idx == 254:
            start = 252
            echoes = 1
        else:
            start = 251
            echoes = 2
        
        print(f"\n--- Testing Var({target_idx}) via {echoes} echo(s) from {start} ---")
        
        if echoes == 0:
            for arg_name, arg in [("nil", NIL), ("I", I), ("Var(0)", Var(0))]:
                e = Var(0)
                extracted = App(App(e, I), I)
                arg_s = shift(arg, 1) if isinstance(arg, (Lam, App)) else Var(arg.i + 1) if isinstance(arg, Var) else arg
                if isinstance(arg, Var):
                    arg_s = Var(arg.i + 1)
                else:
                    arg_s = shift(arg, 1)
                qd_s = shift(QD_TERM, 1)
                
                call_extracted = App(App(extracted, arg_s), qd_s)
                cont = Lam(call_extracted)
                
                program = App(App(Var(0x0E), Var(start)), cont)
                payload = encode_term(program) + bytes([FF])
                resp = query_raw(payload)
                print(f"  (Var({target_idx}) {arg_name}): {classify(resp)}")
                time.sleep(0.12)
        
        elif echoes == 1:
            for arg_name, arg in [("nil", NIL), ("I", I), ("self", None)]:
                e = Var(0)
                extracted = App(App(e, I), I)
                
                if arg is None:
                    arg_s = extracted
                elif isinstance(arg, Var):
                    arg_s = Var(arg.i + 1)
                else:
                    arg_s = shift(arg, 1)
                
                qd_s = shift(QD_TERM, 1)
                call_extracted = App(App(extracted, arg_s), qd_s)
                cont = Lam(call_extracted)
                
                program = App(App(Var(0x0E), Var(start)), cont)
                payload = encode_term(program) + bytes([FF])
                resp = query_raw(payload)
                print(f"  (Var({target_idx}) {arg_name}): {classify(resp)}")
                time.sleep(0.12)
        
        elif echoes == 2:
            e2 = Var(0)
            i_ss = shift(I, 2)
            extracted2 = App(App(e2, i_ss), i_ss)
            nil_ss = shift(NIL, 2)
            qd_ss = shift(QD_TERM, 2)
            inner_call = App(App(extracted2, nil_ss), qd_ss)
            inner_cont = Lam(inner_call)
            
            e1 = Var(0)
            i_s = shift(I, 1)
            extracted1 = App(App(e1, i_s), i_s)
            echo_s = Var(0x0E + 1)
            inner_cont_s = shift(inner_cont, 1)
            middle_call = App(App(echo_s, extracted1), inner_cont_s)
            middle_cont = Lam(middle_call)
            
            program = App(App(Var(0x0E), Var(start)), middle_cont)
            payload = encode_term(program) + bytes([FF])
            resp = query_raw(payload)
            print(f"  (Var({target_idx}) nil): {classify(resp)}")
            time.sleep(0.15)
    
    print("\n" + "=" * 70)
    print("Phase 2: What if Var(254) is a REAL hidden syscall?")
    print("=" * 70)
    
    e = Var(0)
    extracted = App(App(e, I), I)
    nil_s = shift(NIL, 1)
    qd_s = shift(QD_TERM, 1)
    
    call_254_nil = App(App(extracted, nil_s), qd_s)
    cont = Lam(call_254_nil)
    
    program = App(App(Var(0x0E), Var(252)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"(Var(254) nil) QD: {classify(resp)}")
    
    from solve_brownos_answer import encode_byte_term
    arg_0 = encode_byte_term(0)
    
    e = Var(0)
    extracted = App(App(e, I), I)
    arg_s = shift(arg_0, 1)
    qd_s = shift(QD_TERM, 1)
    
    call_254_arg = App(App(extracted, arg_s), qd_s)
    cont = Lam(call_254_arg)
    
    program = App(App(Var(0x0E), Var(252)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"(Var(254) byte_0) QD: {classify(resp)}")
    
    print("\n" + "=" * 70)
    print("Phase 3: Use Var(254) as argument to syscall 8")
    print("=" * 70)
    
    e = Var(0)
    extracted = App(App(e, I), I)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    
    call_s8 = App(App(syscall8_s, extracted), qd_s)
    cont = Lam(call_s8)
    
    program = App(App(Var(0x0E), Var(252)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"syscall8(Var(254)): {classify(resp)}")
    
    print("\n" + "=" * 70)
    print("Phase 4: Apply Var(254) to syscall 8")
    print("=" * 70)
    
    e = Var(0)
    extracted = App(App(e, I), I)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    
    applied = App(extracted, syscall8_s)
    
    call_applied = App(applied, qd_s)
    cont = Lam(call_applied)
    
    program = App(App(Var(0x0E), Var(252)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"(Var(254) syscall8) QD: {classify(resp)}")
    
    nil_s = shift(NIL, 1)
    call_full = App(App(applied, nil_s), qd_s)
    cont = Lam(call_full)
    
    program = App(App(Var(0x0E), Var(252)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"((Var(254) syscall8) nil) QD: {classify(resp)}")
    
    print("\n" + "=" * 70)
    print("Phase 5: Backdoor then Var(254)")
    print("=" * 70)
    
    pair = Var(0)
    fst = Lam(Lam(Var(1)))
    snd = Lam(Lam(Var(0)))
    
    e1 = Var(0)
    extracted1 = App(App(e1, shift(I, 2)), shift(I, 2))
    pair_ss = Var(2)
    
    call_254_pair = App(extracted1, pair_ss)
    qd_sss = shift(QD_TERM, 3)
    inner_body = App(call_254_pair, qd_sss)
    inner_cont = Lam(inner_body)
    
    echo_s = Var(0x0E + 1)
    echo_call = App(App(echo_s, Var(253)), shift(inner_cont, 1))
    middle_cont = Lam(echo_call)
    
    program = App(App(Var(0xC9), NIL), middle_cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"backdoor → echo(252) → (Var(254) pair): {classify(resp)}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
