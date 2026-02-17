#!/usr/bin/env python3
"""
probe_either_dispatch.py — Test Either dispatch in isolation.

The issue: backdoor(nil)(λr. r(left)(right)) returns EMPTY for ALL left handlers.
But backdoor(nil)(QD) works fine.

Hypothesis: The Either dispatch r(left)(right) is wrong because the backdoor
continuation doesn't receive Left(pair) — it receives something else.

Let's test what the backdoor continuation actually receives.
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
    return Ap(Ap(f, x), y)


nil_t = L(L(V(0)))
qd_t = parse_term(QD + bytes([FF]))


def main():
    print("=" * 70)
    print("EITHER DISPATCH DIAGNOSTIC")
    print("=" * 70)

    # ===== E1: echo(nil)(QD) — baseline, returns Left(nil) =====
    print("\n--- E1: echo(nil)(QD) — returns Left(nil) ---")
    payload = bytes([0x0E, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])
    resp = q(payload)
    print(f"  {desc(resp)}")
    time.sleep(0.5)

    # ===== E2: echo(nil)(λresult. result(λx. QD_s2(x))(λe. nil_s2)) =====
    # This should dispatch Left(nil) and apply QD to nil
    print("\n--- E2: echo(nil)(λr. r(λx. QD_s2(x))(λe. nil_s2)) ---")
    qd_s2 = sh(qd_t, 2)
    nil_s2 = sh(nil_t, 2)
    left_h = L(Ap(qd_s2, V(0)))  # λx. QD(x)
    right_h = L(nil_s2)  # λe. nil
    dispatch = a2(V(0), left_h, right_h)
    cont = L(dispatch)
    full = a2(V(0x0E), nil_t, cont)

    try:
        payload = enc(full) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== E3: echo(nil)(λresult. QD_s1(result)) =====
    # Just apply QD to the result directly (no Either dispatch)
    print("\n--- E3: echo(nil)(λr. QD_s1(r)) — no dispatch ---")
    qd_s1 = sh(qd_t, 1)
    cont3 = L(Ap(qd_s1, V(0)))
    full3 = a2(V(0x0E), nil_t, cont3)

    try:
        payload = enc(full3) + bytes([FF])
        resp = q(payload, timeout_s=8.0)
        print(f"  {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== E4: Manually construct Left(nil) and dispatch it =====
    # Left(nil) = λl.λr. l(nil) = L(L(Ap(V(1), nil_shifted_2)))
    print("\n--- E4: Manual Left(nil) dispatched with QD ---")
    nil_s2_inner = sh(nil_t, 2)
    left_nil = L(L(Ap(V(1), nil_s2_inner)))  # Left(nil)
    # Apply: Left(nil)(λx. QD(x))(λe. nil)
    # Under 0 lambdas: QD not shifted
    left_h4 = L(Ap(qd_t, V(0)))  # λx. QD(x)
    right_h4 = L(nil_t)  # λe. nil
    full4 = a2(left_nil, left_h4, right_h4)

    try:
        payload = enc(full4) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== E5: echo(nil) then dispatch with write =====
    # echo(nil)(λresult. result(λx. write_s2(x)(λ_. nil_s3))(λe. nil_s2))
    # Left(nil)(λx. write(x)(λ_.nil))(λe. nil) = (λx. write(x)(λ_.nil))(nil) = write(nil)(λ_.nil)
    # write(nil) writes nothing (nil = empty byte list), returns Left(something)
    print("\n--- E5: echo(nil)(λr. r(λx. write(x)(λ_.nil))(λe. nil)) ---")
    # Under 3 lambdas (result, x, _): write = V(2+3) = V(5)
    nil_s3 = sh(nil_t, 3)
    write_call = a2(
        V(5), V(1), L(nil_s3)
    )  # write(x)(λ_.nil) — x is V(1) under 2 lambdas?
    # Wait, let me be more careful.
    # Under 1 lambda (result): result = V(0)
    # left_handler = λx. write(x)(λ_.nil)
    # Under 2 lambdas (result, x): write = V(2+2) = V(4), x = V(0)
    nil_s3_v = sh(nil_t, 3)
    write_inner = a2(V(4), V(0), L(nil_s3_v))  # write(x)(λ_.nil)
    left_h5 = L(write_inner)  # λx. write(x)(λ_.nil)
    nil_s2_v = sh(nil_t, 2)
    right_h5 = L(nil_s2_v)
    dispatch5 = a2(V(0), left_h5, right_h5)
    cont5 = L(dispatch5)
    full5 = a2(V(0x0E), nil_t, cont5)

    try:
        payload = enc(full5) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== E6: Simplest Either dispatch test =====
    # Construct Left(42_byte_term) manually and dispatch
    # Left(x)(f)(g) = f(x)
    # Test: Left(Var(42))(echo)(QD) = echo(Var(42))(QD) = Left(Var(42)) via QD
    print("\n--- E6: Left(V42)(echo)(QD) — manual Either dispatch ---")
    v42_s2 = V(44)  # Var(42) shifted by 2 under Left's lambdas
    left_v42 = L(L(Ap(V(1), v42_s2)))  # Left(Var(42))
    full6 = a2(left_v42, V(0x0E), qd_t)  # Left(V42)(echo)(QD)

    try:
        payload = enc(full6) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== E7: Test if CPS continuation receives the result correctly =====
    # echo(nil)(λr. echo_s1(r)(QD_s1))
    # echo returns Left(nil) to continuation
    # continuation: λr. echo(r)(QD) — echo the result again
    # echo(Left(nil))(QD) = Left(Left(nil)) via QD
    print("\n--- E7: echo(nil)(λr. echo(r)(QD)) — double echo ---")
    qd_s1_v = sh(qd_t, 1)
    # Under 1 lambda: echo = V(15), r = V(0)
    double_echo = a2(V(15), V(0), qd_s1_v)
    cont7 = L(double_echo)
    full7 = a2(V(0x0E), nil_t, cont7)

    try:
        payload = enc(full7) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== E8: backdoor(nil)(λr. echo_s1(r)(QD_s1)) =====
    # Same as E7 but with backdoor instead of echo
    # backdoor returns Left(pair) to continuation
    # continuation: λr. echo(r)(QD) — echo the result
    # echo(Left(pair))(QD) = Left(Left(pair)) via QD
    print("\n--- E8: backdoor(nil)(λr. echo(r)(QD)) — echo the backdoor result ---")
    # Under 1 lambda: echo = V(15), r = V(0)
    echo_bd = a2(V(15), V(0), qd_s1_v)
    cont8 = L(echo_bd)
    full8 = a2(V(0xC9), nil_t, cont8)

    try:
        payload = enc(full8) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  {desc(resp)}")
        print(f"  Raw: {resp[:100].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== E9: backdoor(nil)(λr. r(echo_s1)(QD_s1)) =====
    # Dispatch the Either: Left(pair)(echo)(QD) = echo(pair)(QD)
    # echo(pair) = Left(pair), then QD serializes Left(pair)
    # Wait — echo(pair)(QD) is a CPS call: echo with arg=pair, cont=QD
    # echo returns Left(pair) to QD. QD serializes Left(pair).
    print("\n--- E9: backdoor(nil)(λr. r(echo)(QD)) — Either dispatch with echo ---")
    # Under 1 lambda: echo = V(15), r = V(0)
    dispatch9 = a2(V(0), V(15), qd_s1_v)  # r(echo)(QD)
    cont9 = L(dispatch9)
    full9 = a2(V(0xC9), nil_t, cont9)

    try:
        payload = enc(full9) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  {desc(resp)}")
        print(f"  Raw: {resp[:100].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== E10: backdoor(nil)(λr. r(sys8)(QD)) =====
    # Either dispatch: Left(pair)(sys8)(QD) = sys8(pair)(QD)
    # Wait no! Left(pair)(sys8)(QD) = sys8(pair) — QD is bound to r but unused!
    # Left = λl.λr. l(pair)
    # Left(sys8) = λr. sys8(pair)
    # Left(sys8)(QD) = sys8(pair) — NO CONTINUATION!
    # This is wrong. The Either dispatch loses the second argument.

    # Actually wait: Left(x) = λl.λr. l(x)
    # Left(x)(f) = (λl.λr. l(x))(f) = λr. f(x)
    # Left(x)(f)(g) = f(x) — g is DISCARDED
    # So Left(pair)(sys8)(QD) = sys8(pair) — sys8 with pair as arg, NO continuation!
    # That's why we get EMPTY — sys8 is called without a continuation.

    # THE BUG IS: Either dispatch uses the FIRST arg as the handler, not as a CPS continuation.
    # Left(x)(left_handler)(right_handler) = left_handler(x)
    # The left_handler receives x and must provide its OWN continuation.

    # So the correct pattern is:
    # backdoor(nil)(λr. r(λpair. sys8(pair)(QD_s2))(λerr. nil_s2))
    # left_handler = λpair. sys8(pair)(QD)
    # This calls sys8 with pair as arg and QD as continuation.

    # But wait — this is EXACTLY what T6 in the previous probe tested!
    # And T6 returned Right(6) = PermDenied. So the dispatch IS working for T6.

    # Let me re-test T6 to confirm:
    print("\n--- E10: backdoor→r(λp. sys8(p)(QD))(λe. nil) — re-test T6 ---")
    qd_s2_v = sh(qd_t, 2)
    nil_s2_v = sh(nil_t, 2)
    # Under 2 lambdas (result, pair): sys8 = V(10), pair = V(0)
    sys8_pair_qd = a2(V(10), V(0), qd_s2_v)
    left_h10 = L(sys8_pair_qd)  # λpair. sys8(pair)(QD)
    right_h10 = L(nil_s2_v)
    dispatch10 = a2(V(0), left_h10, right_h10)
    cont10 = L(dispatch10)
    full10 = a2(V(0xC9), nil_t, cont10)

    try:
        payload = enc(full10) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== E11: backdoor→r(λp. pair(sys8)(QD))(λe. nil) =====
    # This is: left_handler(pair) where left_handler = λp. ((p sys8) QD)
    # = pair(sys8)(QD) = ((λf.f(A)(B)) sys8)(QD) = (sys8(A)(B))(QD)
    # sys8(A)(B) is a CPS call: sys8 with arg=A, cont=B
    # sys8 returns result to B: B(result) = λb.(result b)
    # Then QD(λb.(result b)) — QD serializes the partial application
    print("\n--- E11: backdoor→r(λp. ((p sys8) QD))(λe. nil) — pair as destructor ---")
    # Under 2 lambdas: sys8 = V(10), pair = V(0)
    pair_sys8 = Ap(V(0), V(10))  # pair(sys8)
    pair_sys8_qd = Ap(pair_sys8, qd_s2_v)  # (pair(sys8))(QD)
    left_h11 = L(pair_sys8_qd)
    dispatch11 = a2(V(0), left_h11, right_h10)
    cont11 = L(dispatch11)
    full11 = a2(V(0xC9), nil_t, cont11)

    try:
        payload = enc(full11) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  {desc(resp)}")
        print(f"  Raw: {resp[:100].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== E12: backdoor→r(λp. ((p echo) QD))(λe. nil) =====
    # pair(echo)(QD) = echo(A)(B) then QD
    # echo(A) returns Left(A) to B
    # B(Left(A)) = λb.(Left(A) b) — partial
    # QD(λb.(Left(A) b)) — serializes
    print("\n--- E12: backdoor→r(λp. ((p echo) QD))(λe. nil) ---")
    # Under 2 lambdas: echo = V(16)
    pair_echo = Ap(V(0), V(16))
    pair_echo_qd = Ap(pair_echo, qd_s2_v)
    left_h12 = L(pair_echo_qd)
    dispatch12 = a2(V(0), left_h12, right_h10)
    cont12 = L(dispatch12)
    full12 = a2(V(0xC9), nil_t, cont12)

    try:
        payload = enc(full12) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  {desc(resp)}")
        print(f"  Raw: {resp[:100].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    print("\n" + "=" * 70)
    print("DIAGNOSTIC COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
