#!/usr/bin/env python3
"""Debug the double echo chain step by step."""
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
                return f"Left('{decode_bytes_list(payload).decode()[:30]}')"
            except:
                return "Left(<non-bytes>)"
    except Exception as e:
        return f"<parse error: {e}>"


def main():
    print("=" * 60)
    print("DEBUG: Echo chain step by step")
    print("=" * 60)
    
    print("\n--- Step 1: Single echo, just output the raw Either ---")
    program = App(App(Var(0x0E), Var(251)), QD_TERM)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"echo(Var(251)) with QD: {classify(resp)}")
    if resp and FF in resp:
        print(f"  Raw: {resp.hex()}")
        try:
            term = parse_term(resp)
            tag, inner = decode_either(term)
            print(f"  Inner term (should be Var(253)): {inner}")
        except Exception as e:
            print(f"  Parse error: {e}")
    
    print("\n--- Step 2: Echo then extract (should give Var(253)) ---")
    e = Var(0)
    extracted = App(App(e, I_TERM), I_TERM)
    qd_s = shift(QD_TERM, 1)
    body = App(extracted, qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"echo(251) → extract → output: {classify(resp)}")
    if resp:
        print(f"  Raw: {resp.hex()}")
    
    print("\n--- Step 3: Extract and then echo that result ---")
    e1 = Var(0)
    extracted1 = App(App(e1, I_TERM), I_TERM)
    echo_s = Var(0x0E + 1)
    qd_s = shift(QD_TERM, 1)
    middle_body = App(App(echo_s, extracted1), qd_s)
    middle_cont = Lam(middle_body)
    
    program = App(App(Var(0x0E), Var(251)), middle_cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"echo(251) → extract → echo: {classify(resp)}")
    if resp:
        print(f"  Raw: {resp.hex()}")
    
    print("\n--- Step 4: What if we DON'T extract, just pass the Either to echo? ---")
    e1 = Var(0)
    echo_s = Var(0x0E + 1)
    qd_s = shift(QD_TERM, 1)
    body = App(App(echo_s, e1), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"echo(251) → echo(the Either) directly: {classify(resp)}")
    if resp:
        print(f"  Raw: {resp.hex()}")
    
    print("\n--- Step 5: Verify extraction actually works ---")
    e = Var(0)
    extracted = App(App(e, I_TERM), I_TERM)
    nil_s = shift(NIL_TERM, 1)
    call = App(extracted, nil_s)
    qd_s = shift(QD_TERM, 1)
    body = App(call, qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(8)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"echo(8) → extract → call with nil: {classify(resp)}")
    if resp:
        print(f"  Raw: {resp.hex()}")
    
    print("\n--- Step 6: Can we echo a high-index var that causes trouble? ---")
    for k in [251, 252]:
        program = App(App(Var(0x0E), Var(k)), QD_TERM)
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload)
        print(f"echo(Var({k})): {classify(resp)}")
        if resp and FF in resp:
            try:
                term = parse_term(resp)
                tag, inner = decode_either(term)
                print(f"  Contains: {inner}")
            except:
                pass
        time.sleep(0.15)
    
    print("\n--- Step 7: Quote the extracted high-index var ---")
    e = Var(0)
    extracted = App(App(e, I_TERM), I_TERM)
    quote_s = Var(4 + 1)
    qd_s = shift(QD_TERM, 1)
    body = App(App(quote_s, extracted), qd_s)
    cont = Lam(body)
    
    program = App(App(Var(0x0E), Var(251)), cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"echo(251) → extract → quote: {classify(resp)}")
    if resp:
        print(f"  Raw: {resp.hex()}")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
