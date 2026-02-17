#!/usr/bin/env python3
"""
METIS INSIGHTS PROBE

Testing specific hypotheses from agent analysis:

1. "00 FE FE" reinterpretation:
   - Currently: nil = λλ.0 (postfix notation)
   - Alternative: What if bytes are interpreted differently?
   - Or: What if we need echo-manufactured FE bytes?

2. "3 leafs" minimal terms:
   - λ.(0 (0 0)) = omega-like
   - λλ.(1 (0 0))
   - Combinations with syscall indices

3. Echo transforming the syscall itself:
   - echo(syscall8) instead of echo(arg)
   - Use echoed syscall reference
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
    call_syscall,
)
from solve_brownos_answer import QD as QD_BYTES

FF = 0xFF
FE = 0xFE
FD = 0xFD
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
                return f"Left('{decode_bytes_list(payload).decode()[:30]}')"
            except:
                return f"Left({short_show(payload)})"
    except Exception as e:
        return f"<parse error: {e}>"


def main():
    print("=" * 70)
    print("METIS INSIGHTS PROBE")
    print("=" * 70)
    
    print("\n" + "=" * 70)
    print("PHASE 1: 3-Leaf Minimal Terms with syscall 8")
    print("=" * 70)
    
    three_leaf_terms = [
        ("λ.(0 (0 0)) - omega body", Lam(App(Var(0), App(Var(0), Var(0))))),
        ("λ.((0 0) 0) - left assoc", Lam(App(App(Var(0), Var(0)), Var(0)))),
        ("λλ.(1 (0 0))", Lam(Lam(App(Var(1), App(Var(0), Var(0)))))),
        ("λλ.(0 (1 0))", Lam(Lam(App(Var(0), App(Var(1), Var(0)))))),
        ("λλ.(0 (0 1))", Lam(Lam(App(Var(0), App(Var(0), Var(1)))))),
        ("λλ.((1 0) 0)", Lam(Lam(App(App(Var(1), Var(0)), Var(0))))),
        ("λλ.((0 1) 0)", Lam(Lam(App(App(Var(0), Var(1)), Var(0))))),
        ("λλ.((0 0) 1)", Lam(Lam(App(App(Var(0), Var(0)), Var(1))))),
    ]
    
    for name, term in three_leaf_terms:
        try:
            out = call_syscall(0x08, term)
            tag, payload = decode_either(out)
            if tag == "Right":
                code = decode_byte_term(payload)
                result = f"Right({code})"
            else:
                result = f"Left(...)"
        except Exception as e:
            result = f"error: {e}"
        print(f"  syscall8({name}): {result}")
        time.sleep(0.15)
    
    print("\n" + "=" * 70)
    print("PHASE 2: Echo the syscall reference itself")
    print("=" * 70)
    
    e = Var(0)
    extracted = App(App(e, I), I)
    syscall8_s = Var(9)
    nil_s = shift(NIL, 1)
    qd_s = shift(QD_TERM, 1)
    
    call_extracted = App(App(extracted, nil_s), qd_s)
    cont = Lam(call_extracted)
    
    program = App(App(Var(0x0E), Var(8)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"echo(Var(8)) → extract → call with nil: {classify(resp)}")
    
    e = Var(0)
    extracted = App(App(e, I), I)
    arg_s = shift(NIL, 1)
    applied = App(extracted, arg_s)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    call_s8 = App(App(syscall8_s, applied), qd_s)
    cont = Lam(call_s8)
    
    program = App(App(Var(0x0E), Var(8)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"echo(Var(8)) → extract → syscall8(extracted nil): {classify(resp)}")
    
    print("\n" + "=" * 70)
    print("PHASE 3: Use echo-manufactured Var(254) in self-application")
    print("=" * 70)
    
    e = Var(0)
    extracted = App(App(e, I), I)
    self_app = App(extracted, extracted)
    qd_s = shift(QD_TERM, 1)
    body = App(self_app, qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(252)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload, timeout_s=2.0)
    print(f"echo(252) → (Var(254) Var(254)): {classify(resp)}")
    
    e = Var(0)
    extracted = App(App(e, I), I)
    syscall8_s = Var(9)
    self_app = App(extracted, extracted)
    qd_s = shift(QD_TERM, 1)
    body = App(App(syscall8_s, self_app), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(252)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload, timeout_s=2.0)
    print(f"syscall8((Var(254) Var(254))): {classify(resp)}")
    
    print("\n" + "=" * 70)
    print("PHASE 4: Combine backdoor with echo")
    print("=" * 70)
    
    pair = Var(0)
    fst = Lam(Lam(Var(1)))
    snd = Lam(Lam(Var(0)))
    
    a_val = App(pair, shift(fst, 1))
    
    e1 = Var(0)
    extracted1 = App(App(e1, shift(I, 2)), shift(I, 2))
    pair_ss = Var(2)
    a_ss = App(pair_ss, shift(shift(fst, 1), 1))
    
    combined = App(a_ss, extracted1)
    syscall8_sss = Var(11)
    qd_sss = shift(QD_TERM, 3)
    inner_body = App(App(syscall8_sss, combined), qd_sss)
    inner_cont = Lam(inner_body)
    
    echo_s = Var(0x0E + 1)
    echo_call = App(App(echo_s, Var(252)), shift(inner_cont, 1))
    middle_cont = Lam(echo_call)
    
    program = App(App(Var(0xC9), NIL), middle_cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"backdoor → echo(252) → syscall8((A Var(254))): {classify(resp)}")
    
    print("\n" + "=" * 70)
    print("PHASE 5: Hidden id 256 investigation")
    print("=" * 70)
    
    from solve_brownos_answer import encode_byte_term
    id_256 = encode_byte_term(256)
    
    try:
        out = call_syscall(0x06, id_256)
        tag, payload = decode_either(out)
        if tag == "Left":
            try:
                name = decode_bytes_list(payload).decode()
                print(f"name(256): '{name}'")
            except:
                print(f"name(256): Left({short_show(payload)})")
        else:
            print(f"name(256): Right({decode_byte_term(payload)})")
    except Exception as e:
        print(f"name(256): error: {e}")
    
    try:
        out = call_syscall(0x08, id_256)
        tag, payload = decode_either(out)
        if tag == "Right":
            print(f"syscall8(id_256): Right({decode_byte_term(payload)})")
        else:
            print(f"syscall8(id_256): Left(...)")
    except Exception as e:
        print(f"syscall8(id_256): error: {e}")
    
    print("\n" + "=" * 70)
    print("PHASE 6: Raw byte patterns")
    print("=" * 70)
    
    raw_patterns = [
        ("00 FE FE FF (nil)", bytes([0x00, 0xFE, 0xFE, 0xFF])),
        ("FE FE 00 FF (λλ then Var0?)", bytes([0xFE, 0xFE, 0x00, 0xFF])),
        ("08 00 FE FE FD FF (syscall8 nil)", bytes([0x08, 0x00, 0xFE, 0xFE, 0xFD, 0xFF])),
        ("00 FE FE 08 FD FF ((nil) 8)", bytes([0x00, 0xFE, 0xFE, 0x08, 0xFD, 0xFF])),
        ("08 08 FD FF ((8) 8)", bytes([0x08, 0x08, 0xFD, 0xFF])),
        ("08 08 08 FD FD FF (((8 8) 8))", bytes([0x08, 0x08, 0x08, 0xFD, 0xFD, 0xFF])),
    ]
    
    for name, payload in raw_patterns:
        resp = query_raw(payload)
        print(f"  {name}: {classify(resp)}")
        time.sleep(0.1)
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
