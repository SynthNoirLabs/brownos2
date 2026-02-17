#!/usr/bin/env python3
"""
DIVERGENT TERMS PROBE - Testing "froze my whole system" hint

The author mentioned "combining special bytes" caused the system to freeze.
This suggests creating divergent (non-terminating) terms might reveal something.

Backdoor returns:
- A = λab.bb (self-apply second arg) 
- B = λab.ab (apply first to second)

Key combinations:
- (A A) → λb.bb = ω
- (ω ω) = Ω = diverges forever
- (A B) → λb.bb = ω  
- (B A) → λb.(λab.bb)b = λb.bb = ω

The "freeze" might:
1. Expose a race condition or timing-based check
2. Bypass a permission check that has a timeout
3. Trigger an error handler that grants access
4. Create a side-effect during infinite evaluation
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

A_TERM = Lam(Lam(App(Var(0), Var(0))))
B_TERM = Lam(Lam(App(Var(1), Var(0))))
OMEGA = Lam(App(Var(0), Var(0)))


def shift(term, delta, cutoff=0):
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    return term


def short_show(term, depth=8):
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
    start = time.time()
    with socket.create_connection((host, 61221), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        resp = recv_all(sock, timeout_s)
    elapsed = time.time() - start
    return resp, elapsed


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
                return f"Left('{bs.decode()[:30]}')"
            except:
                return f"Left({short_show(payload)})"
    except Exception as e:
        return f"<parse error: {e}>"


def main():
    print("=" * 70)
    print("DIVERGENT TERMS PROBE - 'Froze my system' investigation")
    print("=" * 70)
    
    print("\n--- Phase 1: Build Ω (omega-omega) and related divergent terms ---")
    
    omega_omega = App(OMEGA, OMEGA)
    print(f"Ω = (ω ω) = {short_show(omega_omega)}")
    print("Encoded:", encode_term(omega_omega).hex())
    
    print("\n--- Phase 2: Test divergent terms with syscall 8 ---")
    print("(Using short timeouts to detect hangs)")
    
    divergent_tests = [
        ("ω (λ.(0 0))", OMEGA),
        ("(A A) = ω", App(A_TERM, A_TERM)),
        ("(A B)", App(A_TERM, B_TERM)),
        ("(B A)", App(B_TERM, A_TERM)),
        ("(B B)", App(B_TERM, B_TERM)),
    ]
    
    for name, term in divergent_tests:
        program = App(App(Var(8), term), QD_TERM)
        payload = encode_term(program) + bytes([FF])
        resp, elapsed = query_raw(payload, timeout_s=2.0)
        result = classify(resp)
        print(f"  syscall8({name}): {result} [{elapsed:.2f}s]")
        time.sleep(0.2)
    
    print("\n--- Phase 3: Test Ω directly (might hang) ---")
    
    program = App(App(Var(8), omega_omega), QD_TERM)
    payload = encode_term(program) + bytes([FF])
    resp, elapsed = query_raw(payload, timeout_s=3.0)
    result = classify(resp)
    print(f"  syscall8(Ω): {result} [{elapsed:.2f}s]")
    
    print("\n--- Phase 4: Divergent term AS continuation ---")
    
    program = App(App(Var(8), NIL), OMEGA)
    payload = encode_term(program) + bytes([FF])
    resp, elapsed = query_raw(payload, timeout_s=2.0)
    result = classify(resp)
    print(f"  (syscall8 nil) ω: {result} [{elapsed:.2f}s]")
    
    program = App(App(Var(8), NIL), omega_omega)
    payload = encode_term(program) + bytes([FF])
    resp, elapsed = query_raw(payload, timeout_s=3.0)
    result = classify(resp)
    print(f"  (syscall8 nil) Ω: {result} [{elapsed:.2f}s]")
    
    print("\n--- Phase 5: Divergent with backdoor pair ---")
    
    pair = Var(0)
    fst = Lam(Lam(Var(1)))
    snd = Lam(Lam(Var(0)))
    
    a_val = App(pair, shift(fst, 1))
    b_val = App(pair, shift(snd, 1))
    
    omega_from_ab = App(a_val, b_val)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    call = App(App(syscall8_s, omega_from_ab), qd_s)
    cont = Lam(call)
    
    program = App(App(Var(0xC9), NIL), cont)
    payload = encode_term(program) + bytes([FF])
    resp, elapsed = query_raw(payload, timeout_s=3.0)
    result = classify(resp)
    print(f"  backdoor → syscall8((A B)): {result} [{elapsed:.2f}s]")
    
    omega_omega_ab = App(App(a_val, a_val), App(a_val, a_val))
    call2 = App(App(syscall8_s, omega_omega_ab), qd_s)
    cont2 = Lam(call2)
    
    program = App(App(Var(0xC9), NIL), cont2)
    payload = encode_term(program) + bytes([FF])
    resp, elapsed = query_raw(payload, timeout_s=3.0)
    result = classify(resp)
    print(f"  backdoor → syscall8(((A A) (A A))): {result} [{elapsed:.2f}s]")
    
    print("\n--- Phase 6: Echo + divergent ---")
    
    e = Var(0)
    extracted = App(App(e, I), I)
    self_app = App(extracted, extracted)
    syscall8_s = Var(9)
    qd_s = shift(QD_TERM, 1)
    call = App(App(syscall8_s, self_app), qd_s)
    cont = Lam(call)
    
    program = App(App(Var(0x0E), OMEGA), cont)
    payload = encode_term(program) + bytes([FF])
    resp, elapsed = query_raw(payload, timeout_s=3.0)
    result = classify(resp)
    print(f"  echo(ω) → syscall8((extracted extracted)): {result} [{elapsed:.2f}s]")
    
    print("\n--- Phase 7: Test if syscall 8 with divergent arg times out differently ---")
    
    results = []
    for i in range(3):
        program = App(App(Var(8), NIL), QD_TERM)
        payload = encode_term(program) + bytes([FF])
        resp, elapsed = query_raw(payload, timeout_s=2.0)
        results.append(("nil", elapsed))
        
        program = App(App(Var(8), omega_omega), QD_TERM)
        payload = encode_term(program) + bytes([FF])
        resp, elapsed = query_raw(payload, timeout_s=2.0)
        results.append(("Ω", elapsed))
        
        time.sleep(0.2)
    
    print("Timing comparison:")
    nil_times = [r[1] for r in results if r[0] == "nil"]
    omega_times = [r[1] for r in results if r[0] == "Ω"]
    print(f"  nil avg: {sum(nil_times)/len(nil_times):.3f}s")
    print(f"  Ω avg: {sum(omega_times)/len(omega_times):.3f}s")
    
    if abs(sum(nil_times)/len(nil_times) - sum(omega_times)/len(omega_times)) > 0.5:
        print("  *** TIMING DIFFERENCE DETECTED! ***")
    else:
        print("  No significant timing difference")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
