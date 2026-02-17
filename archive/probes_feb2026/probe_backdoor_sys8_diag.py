#!/usr/bin/env python3
"""
probe_backdoor_sys8_diag.py — Diagnose WHY backdoor→sys8(A) returns EMPTY
while sys8(A_inline)(QD) returns Right(6).

Either:
1. The backdoor-extracted A is different from inline A (kernel-minted)
2. The CPS chain has a de Bruijn index error (most likely)
3. sys8 actually succeeds with backdoor-extracted A

We need to verify the CPS chain is correct by testing with echo instead of sys8.
"""

import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE
FF = 0xFF
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


@dataclass(frozen=True)
class V:
    i: int


@dataclass(frozen=True)
class L:
    body: object


@dataclass(frozen=True)
class Ap:
    f: object
    x: object


def parse_term(data):
    stack = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            stack.append(Ap(f, x))
        elif b == FE:
            stack.append(L(stack.pop()))
        else:
            stack.append(V(b))
    return stack[0] if stack else None


def enc(term):
    if isinstance(term, V):
        if term.i > 0xFC:
            raise ValueError(f"V({term.i}) too large")
        return bytes([term.i])
    if isinstance(term, L):
        return enc(term.body) + bytes([FE])
    if isinstance(term, Ap):
        return enc(term.f) + enc(term.x) + bytes([FD])
    raise TypeError(f"Unknown: {type(term)}")


def sh(term, delta, cutoff=0):
    if isinstance(term, V):
        return V(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, L):
        return L(sh(term.body, delta, cutoff + 1))
    if isinstance(term, Ap):
        return Ap(sh(term.f, delta, cutoff), sh(term.x, delta, cutoff))
    return term


def show(term, depth=0):
    if depth > 8:
        return "..."
    if isinstance(term, V):
        return f"V{term.i}"
    if isinstance(term, L):
        return f"λ.{show(term.body, depth + 1)}"
    if isinstance(term, Ap):
        return f"({show(term.f, depth + 1)} {show(term.x, depth + 1)})"
    return "?"


def recv_all(sock, timeout_s=5.0):
    sock.settimeout(timeout_s)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    return out


def q(payload, timeout_s=6.0):
    delay = 0.4
    for attempt in range(3):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s)
        except Exception as e:
            if attempt == 2:
                return b""
            time.sleep(delay)
            delay *= 2
    return b""


def desc(resp):
    if not resp:
        return "EMPTY"
    try:
        text = resp.decode("ascii", errors="strict")
        if any(text.startswith(p) for p in ["Invalid", "Encoding", "Term"]):
            return f"ERROR: {text.strip()}"
    except:
        pass
    if FF not in resp:
        return f"NO_FF: {resp[:40].hex()}"
    try:
        term = parse_term(resp)
        return f"TERM: {show(term)}"
    except Exception as e:
        return f"PARSE_ERR: {e}"


def a2(f, x, y):
    """App(App(f, x), y)"""
    return Ap(Ap(f, x), y)


nil_t = L(L(V(0)))
qd_t = parse_term(QD + bytes([FF]))


def main():
    print("=" * 70)
    print("DIAGNOSTIC: Why does backdoor→sys8(A) return EMPTY?")
    print("=" * 70)

    # DIAGNOSTIC 1: Verify the CPS chain works with ECHO instead of sys8
    # If echo(A) returns Left(A) through the chain, the chain is correct.
    # If it returns EMPTY, the chain has a de Bruijn error.
    print("\n--- D1: backdoor→extract_A→ECHO(A)→QD (verify CPS chain) ---")

    # Same chain as T3 but with echo (V(14)) instead of sys8 (V(8))
    # Under 4 lambdas: echo = V(14+4) = V(18)
    qd_s4 = sh(qd_t, 4)
    inner_echo = a2(V(18), V(1), qd_s4)  # echo(a)(QD_shifted)
    destr = L(L(inner_echo))  # λa.λb. echo(a)(QD)
    left_h = L(Ap(V(0), destr))  # λpair. pair(destr)
    right_h = L(sh(nil_t, 2))  # λerr. nil
    dispatch = a2(V(0), left_h, right_h)  # result(left)(right)
    cont = L(dispatch)  # λresult. ...
    full = a2(V(0xC9), nil_t, cont)  # backdoor(nil)(cont)

    try:
        payload = enc(full) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        print(f"  Term: {show(full)}")
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # DIAGNOSTIC 2: Verify echo(A_inline)(QD) works directly
    print("\n--- D2: echo(A_inline)(QD) — direct baseline ---")
    A_b = bytes([0x00, 0x00, FD, FE, FE])
    payload = bytes([0x0E]) + A_b + bytes([FD]) + QD + bytes([FD, FF])
    resp = q(payload)
    print(f"  Result: {desc(resp)}")
    print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    time.sleep(0.5)

    # DIAGNOSTIC 3: Simpler CPS chain — backdoor→quote(A)→QD
    # This should show us A's bytecode if the chain works
    print("\n--- D3: backdoor→extract_A→quote(A)→QD (simpler chain) ---")

    # Under 4 lambdas: quote = V(4+4) = V(8)
    inner_quote = a2(V(8), V(1), qd_s4)  # quote(a)(QD_shifted)
    destr_q = L(L(inner_quote))
    left_hq = L(Ap(V(0), destr_q))
    dispatch_q = a2(V(0), left_hq, right_h)
    cont_q = L(dispatch_q)
    full_q = a2(V(0xC9), nil_t, cont_q)

    try:
        payload = enc(full_q) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
        if resp and FF in resp:
            term = parse_term(resp)
            # If this is Left(bytes), decode the bytes
            if isinstance(term, L) and isinstance(term.body, L):
                body = term.body.body
                if isinstance(body, Ap) and isinstance(body.f, V):
                    tag = "Left" if body.f.i == 1 else "Right"
                    print(f"  Either: {tag}")
                    if tag == "Left":
                        # Try to decode as byte list
                        print(f"  Payload term: {show(body.x)}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # DIAGNOSTIC 4: Even simpler — backdoor→just return pair via QD
    print("\n--- D4: backdoor(nil)(QD) — baseline, should return Left(pair) ---")
    payload = bytes([0xC9]) + bytes([0x00, FE, FE]) + bytes([FD]) + QD + bytes([FD, FF])
    resp = q(payload)
    print(f"  Result: {desc(resp)}")
    print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    time.sleep(0.5)

    # DIAGNOSTIC 5: Backdoor → just pass pair to echo → QD
    # This tests: backdoor(nil)(λresult. result(λpair. echo(pair)(QD))(λerr. nil))
    print("\n--- D5: backdoor→Left handler→echo(pair)→QD ---")

    # Under 2 lambdas (result, pair): echo = V(14+2) = V(16)
    qd_s2 = sh(qd_t, 2)
    echo_pair = a2(V(16), V(0), qd_s2)  # echo(pair)(QD)
    left_h5 = L(echo_pair)  # λpair. echo(pair)(QD)
    right_h5 = L(sh(nil_t, 2))
    dispatch_5 = a2(V(0), left_h5, right_h5)
    cont_5 = L(dispatch_5)
    full_5 = a2(V(0xC9), nil_t, cont_5)

    try:
        payload = enc(full_5) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # DIAGNOSTIC 6: Backdoor → destruct pair → echo(A) → QD
    # Simpler pair destruction: pair(λa.λb. echo(a)(QD))
    print("\n--- D6: backdoor→pair(λa.λb. echo(a)(QD)) ---")

    # Under 3 lambdas (result, a, b): echo = V(14+3) = V(17)
    # Wait — the Left handler receives the pair, then we apply pair to destructor
    # Under 2 lambdas (result, pair): pair = V(0)
    # destructor = λa.λb. echo(a)(QD)
    # Under 4 lambdas (result, pair, a, b): echo = V(14+4) = V(18), a = V(1)
    inner_echo6 = a2(V(18), V(1), qd_s4)  # echo(a)(QD)
    destr6 = L(L(inner_echo6))  # λa.λb. echo(a)(QD)
    pair_apply6 = Ap(V(0), destr6)  # pair(destructor)
    left_h6 = L(pair_apply6)  # λpair. pair(destructor)
    right_h6 = L(sh(nil_t, 2))
    dispatch_6 = a2(V(0), left_h6, right_h6)
    cont_6 = L(dispatch_6)
    full_6 = a2(V(0xC9), nil_t, cont_6)

    try:
        payload = enc(full_6) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # DIAGNOSTIC 7: Verify pair destruction works at all
    # Direct: pair(echo)(QD) where pair is inline
    # pair = λf.f(A)(B), pair(echo) = echo(A)(B)
    # echo(A) = Left(A), then B gets Left(A)
    # B = λa.λb.(a b), so B(Left(A)) = λb.(Left(A) b)
    # Then QD gets that: QD(λb.(Left(A) b))
    print("\n--- D7: pair_inline(echo)(QD) — verify pair destruction ---")
    A_t = L(L(Ap(V(0), V(0))))
    B_t = L(L(Ap(V(1), V(0))))
    A_s1 = sh(A_t, 1)
    B_s1 = sh(B_t, 1)
    pair_t = L(a2(V(0), A_s1, B_s1))
    full_7 = a2(pair_t, V(0x0E), qd_t)

    try:
        payload = enc(full_7) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # DIAGNOSTIC 8: The SIMPLEST possible chain
    # backdoor(nil)(λr. r(λx. x)(λx. x))
    # If backdoor returns Left(pair), then Left(pair)(λx.x)(λx.x) = (λx.x)(pair) = pair
    # Then pair is the final result... but nobody writes it.
    # Let's use QD directly: backdoor(nil)(λr. QD(r))
    # Under 1 lambda: QD shifted by 1
    print("\n--- D8: backdoor(nil)(λr. QD_shifted(r)) ---")
    qd_s1 = sh(qd_t, 1)
    cont_8 = L(Ap(qd_s1, V(0)))  # λr. QD(r)
    full_8 = a2(V(0xC9), nil_t, cont_8)

    try:
        payload = enc(full_8) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # DIAGNOSTIC 9: Even simpler — what does QD do with the backdoor result?
    # QD is a continuation. backdoor(nil)(QD) should work.
    # This is the BASELINE we already know works.
    print("\n--- D9: backdoor(nil)(QD) — known baseline ---")
    payload = bytes([0xC9, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])
    resp = q(payload)
    print(f"  Result: {desc(resp)}")
    print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    time.sleep(0.5)

    # DIAGNOSTIC 10: Check if the Either dispatch is correct
    # Left(x) = λl.λr. l(x) — so Left(x)(f)(g) = f(x)
    # Right(y) = λl.λr. r(y) — so Right(y)(f)(g) = g(y)
    # Test: backdoor(nil)(λresult. result(λpair. QD_s2(pair))(λerr. nil))
    print("\n--- D10: backdoor→Left dispatch→QD(pair) ---")
    qd_s2_10 = sh(qd_t, 2)
    left_h10 = L(Ap(qd_s2_10, V(0)))  # λpair. QD(pair)
    right_h10 = L(sh(nil_t, 2))
    dispatch_10 = a2(V(0), left_h10, right_h10)
    cont_10 = L(dispatch_10)
    full_10 = a2(V(0xC9), nil_t, cont_10)

    try:
        payload = enc(full_10) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # DIAGNOSTIC 11: Check pair destruction with QD
    # backdoor→Left dispatch→pair(λa.λb. QD(a))
    print("\n--- D11: backdoor→pair(λa.λb. QD_s4(a)) ---")
    qd_s4_11 = sh(qd_t, 4)
    inner_11 = Ap(qd_s4_11, V(1))  # QD(a) under 4 lambdas
    destr_11 = L(L(inner_11))  # λa.λb. QD(a)
    left_h11 = L(Ap(V(0), destr_11))  # λpair. pair(destr)
    right_h11 = L(sh(nil_t, 2))
    dispatch_11 = a2(V(0), left_h11, right_h11)
    cont_11 = L(dispatch_11)
    full_11 = a2(V(0xC9), nil_t, cont_11)

    try:
        payload = enc(full_11) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    print("\n" + "=" * 70)
    print("DIAGNOSTIC COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
