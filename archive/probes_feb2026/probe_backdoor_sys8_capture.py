#!/usr/bin/env python3
"""
probe_backdoor_sys8_capture.py — Call sys8 with backdoor-extracted A/B
and capture the result with a proper write-capable continuation.

Previous tests showed backdoor->sys8(A) returns EMPTY = possibly SUCCESS.
We need to capture what sys8 actually returns.
"""

import socket
import time
import hashlib
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE
FF = 0xFF
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ROUNDS = 56154


@dataclass(frozen=True)
class V:
    i: int


@dataclass(frozen=True)
class L:
    body: object


@dataclass(frozen=True)
class A:
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
            stack.append(A(f, x))
        elif b == FE:
            body = stack.pop()
            stack.append(L(body))
        else:
            stack.append(V(b))
    return stack[0] if stack else None


def encode(term):
    if isinstance(term, V):
        if term.i > 0xFC:
            raise ValueError(f"V({term.i}) too large to encode")
        return bytes([term.i])
    if isinstance(term, L):
        return encode(term.body) + bytes([FE])
    if isinstance(term, A):
        return encode(term.f) + encode(term.x) + bytes([FD])
    raise TypeError(f"Unknown: {type(term)}")


def shift(term, delta, cutoff=0):
    if isinstance(term, V):
        return V(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, L):
        return L(shift(term.body, delta, cutoff + 1))
    if isinstance(term, A):
        return A(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    return term


def show(term, depth=0):
    if depth > 6:
        return "..."
    if isinstance(term, V):
        return f"V{term.i}"
    if isinstance(term, L):
        return f"λ.{show(term.body, depth + 1)}"
    if isinstance(term, A):
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


def describe(resp):
    if not resp:
        return "EMPTY"
    try:
        text = resp.decode("ascii", errors="strict")
        if (
            text.startswith("Invalid")
            or text.startswith("Encoding")
            or text.startswith("Term")
        ):
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


def check_answer(candidate):
    cur = candidate.encode("utf-8")
    for _ in range(ROUNDS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET


# Constants
nil_b = bytes([0x00, FE, FE])
A_b = bytes([0x00, 0x00, FD, FE, FE])  # λa.λb.(b b)
B_b = bytes([0x01, 0x00, FD, FE, FE])  # λa.λb.(a b)

nil_t = L(L(V(0)))
A_t = L(L(A(V(0), V(0))))  # λa.λb.(b b)
B_t = L(L(A(V(1), V(0))))  # λa.λb.(a b)

qd_t = parse_term(QD + bytes([FF]))


def app2(f, x, y):
    return A(A(f, x), y)


def main():
    print("=" * 70)
    print("BACKDOOR → SYS8 CAPTURE PROBE")
    print("=" * 70)

    # ===== TEST 1: Direct sys8(A_inline)(QD) =====
    print("\n--- T1: sys8(A_inline)(QD) ---")
    payload = bytes([0x08]) + A_b + bytes([FD]) + QD + bytes([FD, FF])
    resp = q(payload)
    print(f"  {describe(resp)}")
    print(f"  Raw: {resp.hex() if resp else 'EMPTY'}")
    time.sleep(0.5)

    # ===== TEST 2: Direct sys8(B_inline)(QD) =====
    print("\n--- T2: sys8(B_inline)(QD) ---")
    payload = bytes([0x08]) + B_b + bytes([FD]) + QD + bytes([FD, FF])
    resp = q(payload)
    print(f"  {describe(resp)}")
    print(f"  Raw: {resp.hex() if resp else 'EMPTY'}")
    time.sleep(0.5)

    # ===== TEST 3: Backdoor CPS → extract A → sys8(A) → QD =====
    # Chain: ((C9 nil) (λresult. ((result (λpair. ((pair (λa.λb. ((sys8 a) QD))) ))) (λerr. nil))))
    print("\n--- T3: backdoor→extract_A→sys8(A)→QD ---")

    # Under 4 lambdas (result=0, pair=0, a=1, b=0 relative):
    # result binder (depth 1): result=V(0)
    # left handler (depth 2): pair=V(0)
    # destructor (depth 3,4): a=V(1), b=V(0)
    # sys8 at depth 4 = V(8+4) = V(12)
    qd_s4 = shift(qd_t, 4)
    inner = app2(V(12), V(1), qd_s4)  # sys8(a)(QD_shifted)
    destr = L(L(inner))  # λa.λb. sys8(a)(QD)
    left_h = L(A(V(0), destr))  # λpair. pair(destr)
    right_h = L(shift(nil_t, 2))  # λerr. nil
    dispatch = app2(V(0), left_h, right_h)  # result(left)(right)
    cont = L(dispatch)  # λresult. ...
    full = app2(V(0xC9), nil_t, cont)  # backdoor(nil)(cont)

    try:
        payload = encode(full) + bytes([FF])
        print(f"  Payload size: {len(payload)} bytes")
        resp = q(payload, timeout_s=8.0)
        print(f"  {describe(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== TEST 4: Same but extract B =====
    print("\n--- T4: backdoor→extract_B→sys8(B)→QD ---")
    inner_b = app2(V(12), V(0), qd_s4)  # sys8(b)(QD_shifted)
    destr_b = L(L(inner_b))
    left_hb = L(A(V(0), destr_b))
    dispatch_b = app2(V(0), left_hb, right_h)
    cont_b = L(dispatch_b)
    full_b = app2(V(0xC9), nil_t, cont_b)

    try:
        payload = encode(full_b) + bytes([FF])
        resp = q(payload, timeout_s=8.0)
        print(f"  {describe(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== TEST 5: Backdoor → sys8(whole_pair) → QD =====
    print("\n--- T5: backdoor→sys8(whole_pair)→QD ---")
    qd_s2 = shift(qd_t, 2)
    sys8_pair = app2(V(10), V(0), qd_s2)  # sys8(pair)(QD) under 2 lambdas
    left_h5 = L(sys8_pair)  # λpair. sys8(pair)(QD)
    right_h5 = L(shift(nil_t, 2))
    dispatch_5 = app2(V(0), left_h5, right_h5)
    cont_5 = L(dispatch_5)
    full_5 = app2(V(0xC9), nil_t, cont_5)

    try:
        payload = encode(full_5) + bytes([FF])
        resp = q(payload, timeout_s=8.0)
        print(f"  {describe(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== TEST 6: sys8(g(251))(QD) and sys8(g(252))(QD) =====
    print("\n--- T6: sys8(g(251/252))(QD) ---")
    for gi in [251, 252]:
        payload = bytes([0x08, gi, FD]) + QD + bytes([FD, FF])
        resp = q(payload)
        print(f"  sys8(g({gi}))(QD): {describe(resp)}")
        time.sleep(0.5)

    # ===== TEST 7: Custom write(quote(result)) continuation =====
    # backdoor→extract_A→sys8(A)→(λr. quote(r)(λq. write(q)(λ_. nil)))
    print("\n--- T7: backdoor→sys8(A)→write(quote(result)) ---")

    # Build custom continuation for sys8 result
    # Under 5 lambdas (result, pair, a, b, sys8_result):
    #   quote = V(4+5) = V(9), sys8_result = V(0)
    # Under 6 lambdas (+ quoted):
    #   write = V(2+6) = V(8), quoted = V(0)
    # Under 7 lambdas (+ _):
    #   nil shifted by 7
    nil_s7 = shift(nil_t, 7)
    write_k = L(nil_s7)  # λ_. nil
    write_call = app2(V(8), V(0), write_k)  # write(quoted)(λ_.nil)
    quote_k = L(write_call)  # λquoted. write(quoted)(λ_.nil)
    quote_call = app2(V(9), V(0), quote_k)  # quote(sys8_result)(λquoted...)
    custom_cont = L(quote_call)  # λsys8_result. quote(result)(...)

    # Under 4 lambdas: sys8 = V(12), a = V(1)
    inner_custom = app2(V(12), V(1), custom_cont)
    destr_custom = L(L(inner_custom))
    left_custom = L(A(V(0), destr_custom))
    right_custom = L(shift(nil_t, 2))
    dispatch_custom = app2(V(0), left_custom, right_custom)
    cont_custom = L(dispatch_custom)
    full_custom = app2(V(0xC9), nil_t, cont_custom)

    try:
        payload = encode(full_custom) + bytes([FF])
        print(f"  Payload size: {len(payload)} bytes")
        resp = q(payload, timeout_s=8.0)
        print(f"  {describe(resp)}")
        print(f"  Raw: {resp[:100].hex() if resp else 'EMPTY'}")
        if resp:
            try:
                text = resp.decode("ascii", errors="replace")
                print(f"  Text: {text[:200]}")
            except:
                pass
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== TEST 8: ((pair_inline sys8) QD) =====
    print("\n--- T8: ((pair_inline sys8) QD) ---")
    # pair = λf.f(A)(B) with A,B shifted by 1
    A_s1 = shift(A_t, 1)
    B_s1 = shift(B_t, 1)
    pair_t = L(app2(V(0), A_s1, B_s1))
    full_8 = A(app2(pair_t, V(0x08)), qd_t)  # ((pair sys8) QD) — wait, this is wrong
    # Actually: ((pair sys8) QD) = App(App(pair, sys8), QD)
    full_8 = app2(pair_t, V(0x08), qd_t)

    try:
        payload = encode(full_8) + bytes([FF])
        resp = q(payload, timeout_s=8.0)
        print(f"  {describe(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== TEST 9: Raw bytecode variants =====
    print("\n--- T9: Raw bytecode variants ---")
    tests = [
        (
            "sys8(nil)(QD) baseline",
            bytes([0x08]) + nil_b + bytes([FD]) + QD + bytes([FD, FF]),
        ),
        ("sys8(A)(B) no QD", bytes([0x08]) + A_b + bytes([FD]) + B_b + bytes([FD, FF])),
        ("sys8(B)(A) no QD", bytes([0x08]) + B_b + bytes([FD]) + A_b + bytes([FD, FF])),
        ("sys8(A)(A) no QD", bytes([0x08]) + A_b + bytes([FD]) + A_b + bytes([FD, FF])),
        ("sys8(B)(B) no QD", bytes([0x08]) + B_b + bytes([FD]) + B_b + bytes([FD, FF])),
    ]
    for label, payload in tests:
        resp = q(payload)
        print(f"  {label}: {describe(resp)}")
        time.sleep(0.5)

    # ===== TEST 10: Backdoor → sys8(A) with IDENTITY continuation =====
    # If sys8 succeeds, it returns Left(answer). Identity just passes it through.
    # Then we need something to observe it.
    # Chain: backdoor(nil)(λr. r(λp. p(λa.λb. sys8(a)(λres. write_either(res))))(λe.nil))
    print("\n--- T10: backdoor→sys8(A)→identity→observe ---")

    # Simpler: backdoor(nil)(λr. r(λp. p(λa.λb. echo(sys8_result_via_a)))(λe.nil))
    # Actually let's try: backdoor→extract A→sys8(A)→(λres. echo(res)(QD_shifted))
    # echo wraps in Left, then QD serializes
    # Under 5 lambdas: echo = V(14+5) = V(19), res = V(0)
    qd_s5 = shift(qd_t, 5)
    echo_res = app2(V(19), V(0), qd_s5)  # echo(res)(QD)
    echo_cont = L(echo_res)  # λres. echo(res)(QD)

    inner_10 = app2(V(12), V(1), echo_cont)  # sys8(a)(echo_cont)
    destr_10 = L(L(inner_10))
    left_10 = L(A(V(0), destr_10))
    right_10 = L(shift(nil_t, 2))
    dispatch_10 = app2(V(0), left_10, right_10)
    cont_10 = L(dispatch_10)
    full_10 = app2(V(0xC9), nil_t, cont_10)

    try:
        payload = encode(full_10) + bytes([FF])
        print(f"  Payload size: {len(payload)} bytes")
        resp = q(payload, timeout_s=8.0)
        print(f"  {describe(resp)}")
        print(f"  Raw: {resp[:100].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    print("\n" + "=" * 70)
    print("PROBE COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
