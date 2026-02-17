#!/usr/bin/env python3
"""
RUNTIME DOUBLE ECHO - Manufacture Var(255) (the FF byte)

CONFIRMED: echo(Var(n)) returns Left(Var(n+2))

So:
- echo(Var(251)) → Left(Var(253))  [FD byte]
- echo(Var(252)) → Left(Var(254))  [FE byte]

To get Var(255), we need to echo something that's already Var(253).
We can't ENCODE Var(253), but we can COMPUTE it at runtime!

Strategy:
1. echo(Var(251)) → Left(Var(253))
2. Extract Var(253) from the Left
3. Echo THAT (at runtime, not encoding time)
4. Get Left(Var(255))
5. Feed to syscall 8

The key is that the second echo happens IN EVALUATION, not encoding.
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


def test_runtime_double_echo():
    print("=" * 70)
    print("RUNTIME DOUBLE ECHO - Manufacturing Var(255)")
    print("=" * 70)
    
    print("\nGoal: echo(Var(251)) → extract → echo again → get Var(255)")
    print()
    
    # Build: ((0x0E Var(251)) (λe1. ((0x0F (e1 I I)) cont2)))
    # Where cont2 = λe2. ... use e2 which contains Var(255)
    #
    # Inside λe1: e1 = Var(0), globals shift by +1
    #   (e1 I I) extracts Var(253) from Left(Var(253))
    #   0x0F = echo shifted by 1
    #   We echo the extracted Var(253)
    #
    # Inside λe2: e2 = Var(0), globals shift by +2 from top
    #   e2 is Left(Var(255))
    #   We can extract and use it

    # Let's first verify the structure works
    print("--- Test 1: Verify double echo chain works ---")
    
    # Innermost: use the double-echoed result with syscall 8
    # λe2. ((syscall8_ss (e2 I I)) qd_ss)
    e2 = Var(0)
    i_ss = shift(I_TERM, 2)  # I shifted by 2
    extracted2 = App(App(e2, i_ss), i_ss)
    syscall8_ss = Var(8 + 2)
    qd_ss = shift(QD_TERM, 2)
    inner_body = App(App(syscall8_ss, extracted2), qd_ss)
    inner_cont = Lam(inner_body)
    
    # Middle: echo the extracted result
    # λe1. ((echo_s (e1 I I)) inner_cont_s)
    e1 = Var(0)
    i_s = shift(I_TERM, 1)
    extracted1 = App(App(e1, i_s), i_s)
    echo_s = Var(0x0E + 1)
    inner_cont_s = shift(inner_cont, 1)
    middle_body = App(App(echo_s, extracted1), inner_cont_s)
    middle_cont = Lam(middle_body)
    
    # Outer: echo Var(251)
    program = App(App(Var(0x0E), Var(251)), middle_cont)
    
    payload = encode_term(program) + bytes([FF])
    print(f"Encoded bytes: {payload.hex()}")
    resp = query_raw(payload)
    print(f"Result: {classify_response(resp)}")
    
    if resp and FF in resp:
        try:
            term = parse_term(resp)
            print(f"Parsed term: {term}")
        except Exception as e:
            print(f"Parse error: {e}")
    
    print("\n--- Test 2: What does Var(255) reference? ---")
    # Var(255) should be a global at index 255
    # What's at that index? Let's try to see what the server does
    
    # Actually, FF = end marker. If we try to access Var(255), it might:
    # 1. Be an undefined global (error)
    # 2. Be a special hidden value
    # 3. Cause parsing issues (FF is end marker in wire format)
    
    # The interesting thing is: when we EVALUATE Var(255), it looks up
    # index 255 in the global environment. The encoding issue is only
    # for SERIALIZATION.
    
    print("\n--- Test 3: Try extracting and using Var(255) with different syscalls ---")
    
    for syscall in [6, 7, 8, 0xC9]:
        e2 = Var(0)
        i_ss = shift(I_TERM, 2)
        extracted2 = App(App(e2, i_ss), i_ss)
        syscall_ss = Var(syscall + 2)
        qd_ss = shift(QD_TERM, 2)
        inner_body = App(App(syscall_ss, extracted2), qd_ss)
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
        print(f"syscall_{syscall}(Var(255)): {classify_response(resp)}")
        time.sleep(0.15)
    
    print("\n--- Test 4: Different starting points for double echo ---")
    
    for start in [250, 251, 252]:
        final_index = start + 4  # +2 from each echo
        
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
        
        program = App(App(Var(0x0E), Var(start)), middle_cont)
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload)
        print(f"double_echo(Var({start})) → Var({final_index}): {classify_response(resp)}")
        time.sleep(0.15)
    
    print("\n--- Test 5: Triple echo - push even further ---")
    
    # Can we get Var(257) or beyond? Probably wraps or errors
    
    # λe3. use extracted e3
    e3 = Var(0)
    i_sss = shift(I_TERM, 3)
    extracted3 = App(App(e3, i_sss), i_sss)
    syscall8_sss = Var(8 + 3)
    qd_sss = shift(QD_TERM, 3)
    deepest_body = App(App(syscall8_sss, extracted3), qd_sss)
    deepest_cont = Lam(deepest_body)
    
    # λe2. echo extracted2
    e2 = Var(0)
    i_ss = shift(I_TERM, 2)
    extracted2 = App(App(e2, i_ss), i_ss)
    echo_ss = Var(0x0E + 2)
    deepest_s = shift(deepest_cont, 2)
    inner_body = App(App(echo_ss, extracted2), deepest_s)
    inner_cont = Lam(inner_body)
    
    # λe1. echo extracted1
    e1 = Var(0)
    i_s = shift(I_TERM, 1)
    extracted1 = App(App(e1, i_s), i_s)
    echo_s = Var(0x0E + 1)
    inner_s = shift(inner_cont, 1)
    middle_body = App(App(echo_s, extracted1), inner_s)
    middle_cont = Lam(middle_body)
    
    # Outer: echo Var(249)
    program = App(App(Var(0x0E), Var(249)), middle_cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"triple_echo(Var(249)) → Var(255): {classify_response(resp)}")
    
    # Try starting at 251 for Var(257)
    program = App(App(Var(0x0E), Var(251)), middle_cont)
    payload = encode_term(program) + bytes([FF])
    resp = query_raw(payload)
    print(f"triple_echo(Var(251)) → Var(257): {classify_response(resp)}")
    
    print("\n--- Test 6: Use double-echoed result as argument differently ---")
    
    # Instead of extracting and calling syscall, what if we use the
    # Left(Var(255)) directly with syscall 8?
    
    # λe2. syscall8(e2) - don't extract
    e2 = Var(0)
    syscall8_ss = Var(8 + 2)
    qd_ss = shift(QD_TERM, 2)
    inner_body = App(App(syscall8_ss, e2), qd_ss)  # e2 is Left(Var(255))
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
    print(f"syscall8(Left(Var(255))) without extract: {classify_response(resp)}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    test_runtime_double_echo()
