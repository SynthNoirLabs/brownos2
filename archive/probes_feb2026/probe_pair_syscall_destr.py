#!/usr/bin/env python3
"""
probe_pair_syscall_destr.py — Use raw syscalls as pair destructors.

KEY INSIGHT: pair = λf.f(A)(B). When f is a raw syscall global:
  pair(sys8) = sys8(A)(B) — sys8 with arg=A, continuation=B
  pair(echo) = echo(A)(B) — echo with arg=A, continuation=B
  pair(quote) = quote(A)(B) — quote with arg=A, continuation=B

When f is a lambda, beta reduction may diverge because A is the mockingbird.

So the correct approach is:
  backdoor(nil)(λresult. result(λpair. pair(sys8))(λerr. nil))

This gives: sys8(A)(B) where B is the continuation.
B = λa.λb.(a b), so B(sys8_result) = λb.(sys8_result b)
If sys8 returns Left(answer), then Left(answer)(b) = ... hmm, that's partial.

Actually we need to OBSERVE the result. Let's chain:
  pair(sys8) gives sys8(A)(B)
  sys8 returns result to B
  B(result) = λb.(result b) — this is a function, not observable

We need a DIFFERENT approach. What if we use the pair differently?

Actually, from the double_question probe:
  ((pair sys8) QD) = Right(6) = PermDenied

But that was with INLINE pair. Let's try with BACKDOOR-extracted pair:
  backdoor(nil)(λresult. result(λpair. ((pair sys8) QD_shifted))(λerr. nil))
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


def check_answer(candidate):
    cur = candidate.encode("utf-8")
    for _ in range(ROUNDS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET


nil_t = L(L(V(0)))
qd_t = parse_term(QD + bytes([FF]))


def main():
    print("=" * 70)
    print("PAIR DESTRUCTION VIA RAW SYSCALLS")
    print("=" * 70)

    # ===== T1: backdoor→Left dispatch→pair(sys8)→then QD =====
    # Chain: backdoor(nil)(λresult. result(λpair. ((pair sys8) QD_s2))(λerr. nil))
    # Under 2 lambdas (result, pair): sys8 = V(8+2) = V(10), pair = V(0)
    print("\n--- T1: backdoor→pair(sys8)→QD ---")
    # pair(sys8) = sys8(A)(B) — sys8 with A as arg, B as continuation
    # Then QD gets applied to the result of B(sys8_result)
    # Actually: ((pair sys8) QD) = (sys8(A)(B))(QD) — that's wrong!
    # pair(sys8) = sys8(A)(B) which is a CPS call
    # sys8(A)(B) means: call sys8 with arg A, continuation B
    # B receives the result: B(result) = λb.(result b) — a function
    # Then QD(λb.(result b)) — QD tries to serialize this function

    # Actually we want: pair(sys8)(QD) = ((pair sys8) QD)
    # pair = λf.f(A)(B)
    # pair(sys8) = sys8(A)(B) — this is the CPS call, B is the continuation
    # sys8 returns result to B: B(result) = λb.(result b)
    # Then QD is applied to that: QD(λb.(result b))
    # QD = quote then write, so it serializes the function λb.(result b)

    # Hmm, this is what the double_question probe already tested!
    # ((pair sys8) QD) returned Right(6) with inline pair.
    # Let's test with backdoor-extracted pair.

    qd_s2 = sh(qd_t, 2)
    # pair(sys8) then QD: ((pair sys8) QD)
    # Under 2 lambdas: pair=V(0), sys8=V(10)
    pair_sys8_qd = a2(Ap(V(0), V(10)), qd_s2, sh(nil_t, 2))  # Hmm wait
    # Actually: ((pair sys8) QD) = App(App(pair, sys8), QD)
    # = a2(V(0), V(10), qd_s2)
    pair_sys8_qd = a2(V(0), V(10), qd_s2)
    left_h1 = L(pair_sys8_qd)  # λpair. ((pair sys8) QD)
    right_h1 = L(sh(nil_t, 2))
    dispatch_1 = a2(V(0), left_h1, right_h1)
    cont_1 = L(dispatch_1)
    full_1 = a2(V(0xC9), nil_t, cont_1)

    try:
        payload = enc(full_1) + bytes([FF])
        print(f"  Payload ({len(payload)}b): {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== T2: backdoor→pair(echo)→QD =====
    # pair(echo) = echo(A)(B) — echo returns Left(A), B gets Left(A)
    # B(Left(A)) = λb.(Left(A) b) — a function
    # QD serializes that function
    print("\n--- T2: backdoor→pair(echo)→QD ---")
    # Under 2 lambdas: echo = V(14+2) = V(16)
    pair_echo_qd = a2(V(0), V(16), qd_s2)
    left_h2 = L(pair_echo_qd)
    dispatch_2 = a2(V(0), left_h2, right_h1)
    cont_2 = L(dispatch_2)
    full_2 = a2(V(0xC9), nil_t, cont_2)

    try:
        payload = enc(full_2) + bytes([FF])
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== T3: backdoor→pair(quote)→QD =====
    # pair(quote) = quote(A)(B) — quote serializes A, B gets Left(bytecode)
    print("\n--- T3: backdoor→pair(quote)→QD ---")
    # Under 2 lambdas: quote = V(4+2) = V(6)
    pair_quote_qd = a2(V(0), V(6), qd_s2)
    left_h3 = L(pair_quote_qd)
    dispatch_3 = a2(V(0), left_h3, right_h1)
    cont_3 = L(dispatch_3)
    full_3 = a2(V(0xC9), nil_t, cont_3)

    try:
        payload = enc(full_3) + bytes([FF])
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== T4: Use sys8 as pair destructor with QD as the "third" arg =====
    # pair = λf.f(A)(B)
    # pair(sys8) = sys8(A)(B) — CPS: sys8 with arg=A, cont=B
    # B(result) = λb.(result b) — partial application
    # We need to capture this. What if we wrap differently?

    # What about: pair(λf. sys8(f)(QD)) — but this is a lambda, won't work

    # What about using the pair TWICE?
    # pair(pair) = pair(A)(B) = A(B) = (λa.λb.bb)(B) = λb.bb = mockingbird!
    # Then QD(mockingbird) serializes it
    print("\n--- T4: backdoor→pair(pair)→QD (pair applied to itself) ---")
    # Under 2 lambdas: pair = V(0)
    pair_pair_qd = a2(Ap(V(0), V(0)), qd_s2, sh(nil_t, 2))  # Hmm
    # Actually: ((pair pair) QD) but pair is the same pair...
    # pair(pair) = pair(A)(B) = A(B) = mockingbird(B) = λb.bb applied to B... diverges?
    # Let's just try: ((pair pair) QD)
    pair_pair_qd = a2(V(0), V(0), qd_s2)  # Hmm, this is pair(pair)(QD) but pair=V(0)
    # Wait, V(0) is the pair variable. pair(pair) means applying pair to itself.
    # But pair is under 2 lambdas (result, pair). pair = V(0).
    # pair(pair) = V(0)(V(0)) = pair applied to pair
    # = (λf.f(A)(B))(pair) = pair(A)(B) = A(B) = (λa.λb.bb)(B) = λb.bb
    # Then QD(λb.bb) serializes the mockingbird
    left_h4 = L(a2(V(0), V(0), qd_s2))
    dispatch_4 = a2(V(0), left_h4, right_h1)
    cont_4 = L(dispatch_4)
    full_4 = a2(V(0xC9), nil_t, cont_4)

    try:
        payload = enc(full_4) + bytes([FF])
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== T5: What if we need to use the BACKDOOR output as sys8's continuation? =====
    # sys8(nil)(pair) — sys8 with nil arg, pair as continuation
    # pair receives sys8's result: pair(result) = result(A)(B)
    # If result = Right(6): Right(6)(A)(B) = B(6) = λb.(6 b) — partial
    # If result = Left(x): Left(x)(A)(B) = A(x) = (λa.λb.bb)(x) = λb.bb — mockingbird!
    # Then we need to observe this...
    print("\n--- T5: backdoor→sys8(nil)(pair)→QD ---")
    # Chain: backdoor(nil)(λresult. result(λpair. sys8(nil)(λr. pair(r)(QD)))(λerr. nil))
    # Hmm, this is getting complex. Let me try simpler:
    # backdoor(nil)(λresult. result(λpair. QD(sys8_inline(nil)(pair)))(λerr. nil))
    # Under 2 lambdas: sys8=V(10), nil needs shift
    nil_s2 = sh(nil_t, 2)
    # sys8(nil)(pair) under 2 lambdas: sys8=V(10), nil shifted, pair=V(0)
    sys8_nil_pair = a2(V(10), nil_s2, V(0))  # sys8(nil)(pair)
    # Then QD(result_of_that)
    qd_of_result = Ap(qd_s2, sys8_nil_pair)  # QD(sys8(nil)(pair))
    left_h5 = L(qd_of_result)
    dispatch_5 = a2(V(0), left_h5, right_h1)
    cont_5 = L(dispatch_5)
    full_5 = a2(V(0xC9), nil_t, cont_5)

    try:
        payload = enc(full_5) + bytes([FF])
        print(f"  Payload ({len(payload)}b): {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== T6: What about sys8 with pair as ARGUMENT and QD as continuation? =====
    # backdoor(nil)(λresult. result(λpair. sys8(pair)(QD))(λerr. nil))
    print("\n--- T6: backdoor→sys8(pair)(QD) ---")
    sys8_pair_qd = a2(V(10), V(0), qd_s2)  # sys8(pair)(QD)
    left_h6 = L(sys8_pair_qd)
    dispatch_6 = a2(V(0), left_h6, right_h1)
    cont_6 = L(dispatch_6)
    full_6 = a2(V(0xC9), nil_t, cont_6)

    try:
        payload = enc(full_6) + bytes([FF])
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== T7: The CRITICAL test — pair(sys8) with backdoor pair =====
    # From double_question: ((pair_inline sys8) QD) = Right(6)
    # But what about ((backdoor_pair sys8) QD)?
    # pair(sys8) = sys8(A)(B) — sys8 with kernel-minted A, continuation B
    # If kernel-minted A is different from inline A, sys8 might succeed!
    # Then B(Left(answer)) = λb.(Left(answer) b) — partial
    # Then QD(λb.(Left(answer) b)) — serializes the partial application

    # We already tested this in T1. Let me also try without the Either dispatch:
    print("\n--- T7: backdoor(nil)(λr. ((r(λp. ((p sys8) QD_s3))) (λe. nil))) ---")
    # Under 1 lambda (result): result = V(0)
    # Left handler: λpair. ((pair sys8) QD)
    # Under 2 lambdas: pair=V(0), sys8=V(10)
    # But wait — the Either dispatch is: result(left_handler)(right_handler)
    # Left(x)(f)(g) = f(x)
    # So left_handler receives x (the pair), not the whole Left

    # Let me verify: is the Either dispatch correct?
    # Left(pair) = λl.λr. l(pair)
    # Left(pair)(left_handler)(right_handler) = left_handler(pair)
    # So left_handler = λpair. ... and pair = the actual pair term
    # This is what we've been doing. Let me verify T1 is correct.

    # T1 chain: backdoor(nil)(λresult. result(λpair. pair(sys8)(QD))(λerr. nil))
    # = backdoor(nil)(λresult. result(λpair. ((pair sys8) QD))(λerr. nil))
    # Under 1 lambda: result=V(0)
    # Under 2 lambdas: pair=V(0), sys8=V(10), QD shifted by 2
    # pair(sys8)(QD) = ((V(0) V(10)) QD_s2)
    # This looks correct!

    # Let me try a COMPLETELY DIFFERENT approach:
    # Don't use Either dispatch at all. Just apply the backdoor result to sys8 and QD.
    # backdoor(nil) returns Left(pair) = λl.λr. l(pair)
    # If we apply Left(pair) to sys8: Left(pair)(sys8) = (λl.λr. l(pair))(sys8) = λr. sys8(pair)
    # Then apply QD: (λr. sys8(pair))(QD) = sys8(pair)(QD) — wait, that's wrong
    # Actually: Left(pair)(sys8)(QD) = sys8(pair) — sys8 applied to pair, no continuation!
    # Hmm, that's not CPS.

    # Actually: Left(pair) = λl.λr. l(pair)
    # Left(pair)(sys8) = (λr. sys8(pair))
    # Left(pair)(sys8)(QD) = sys8(pair)(QD) — wait, that IS wrong
    # No: Left(pair)(sys8)(QD) = ((λl.λr. l(pair))(sys8))(QD) = (λr. sys8(pair))(QD) = sys8(pair)
    # So QD is bound to r but never used! sys8(pair) is called with NO continuation.

    # Hmm, that means the Either dispatch is:
    # result(left_handler)(right_handler) where result = Left(pair)
    # = left_handler(pair) — right_handler is IGNORED
    # So left_handler receives the pair directly. This is correct.

    # The issue might be that pair(sys8) = sys8(A)(B) and B is the continuation,
    # but B(result) = λb.(result b) which is a function, and QD tries to serialize it.
    # QD = quote then write. quote(λb.(result b)) should work...

    # Let me try the simplest possible test:
    # backdoor(nil)(λr. r(λp. p(V(10)))(λe. nil))
    # This is: Left(pair)(λp. p(sys8))(λe. nil) = (λp. p(sys8))(pair) = pair(sys8)
    # = sys8(A)(B) — CPS call, B is continuation
    # sys8 returns result to B. B(result) = λb.(result b)
    # This is the final value. Nobody writes it. So we get EMPTY.
    # We need to WRAP this so QD can observe it.

    # Better: backdoor(nil)(λr. r(λp. ((p V(10)) QD_s2))(λe. nil))
    # = pair(sys8)(QD) = ((sys8(A)(B)) QD)
    # Wait: pair(sys8) = sys8(A)(B). This is a CPS call.
    # sys8(A)(B) means sys8 is called with arg A and continuation B.
    # sys8 evaluates, produces result, calls B(result).
    # B(result) = λb.(result b). This is a function.
    # Then QD is applied to this function: QD(λb.(result b))
    # QD = quote then write. It quotes the function and writes the bytecode.

    # So ((pair sys8) QD) should produce output! And it DID in the double_question probe.
    # It returned Right(6) = PermDenied.

    # So T1 should also work. Let me check if T1's payload is correct.
    print("  (Verifying T1 payload construction...)")

    # Let me rebuild T1 step by step and print the term
    # backdoor(nil)(λresult. result(λpair. ((pair sys8) QD_s2))(λerr. nil_s2))

    # Step 1: QD shifted by 2
    qd_s2_v = sh(qd_t, 2)
    print(f"  QD_s2: {show(qd_s2_v)}")

    # Step 2: ((pair sys8) QD_s2) under 2 lambdas
    # pair = V(0), sys8 = V(10)
    inner_t1 = a2(V(0), V(10), qd_s2_v)
    print(f"  inner: {show(inner_t1)}")

    # Step 3: λpair. inner
    left_t1 = L(inner_t1)
    print(f"  left_handler: {show(left_t1)}")

    # Step 4: λerr. nil_s2
    nil_s2_v = sh(nil_t, 2)
    right_t1 = L(nil_s2_v)
    print(f"  right_handler: {show(right_t1)}")

    # Step 5: result(left)(right) under 1 lambda
    dispatch_t1 = a2(V(0), left_t1, right_t1)
    print(f"  dispatch: {show(dispatch_t1)}")

    # Step 6: λresult. dispatch
    cont_t1 = L(dispatch_t1)

    # Step 7: backdoor(nil)(cont)
    full_t1 = a2(V(0xC9), nil_t, cont_t1)
    print(f"  full term: {show(full_t1)}")

    try:
        payload = enc(full_t1) + bytes([FF])
        print(f"  Payload ({len(payload)}b): {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== T8: SIMPLEST chain — no Either dispatch =====
    # backdoor(nil) returns Left(pair)
    # Apply Left(pair) directly to sys8 and QD:
    # ((Left(pair) sys8) QD) = sys8(pair) — but QD is lost!
    # This is wrong. Let me think again...

    # Actually the CPS convention is:
    # ((syscall arg) continuation) → continuation(result)
    # So backdoor(nil)(k) → k(Left(pair))
    # k = λresult. ...
    # result = Left(pair) = λl.λr. l(pair)
    # result(f)(g) = f(pair)

    # So to get pair(sys8)(QD):
    # k = λresult. ((result (λpair. ((pair sys8_s2) QD_s2))) (λerr. nil_s2))
    # = λresult. result(λpair. pair(sys8)(QD))(λerr. nil)

    # This is exactly T1/T7. Let me try a DIFFERENT approach:
    # What if we DON'T destruct the pair, but pass the WHOLE Left(pair) to sys8?
    # sys8(Left(pair))(QD)
    # k = λresult. ((sys8_s1 result) QD_s1)
    print("\n--- T8: backdoor→sys8(Left(pair))(QD) — pass whole Either to sys8 ---")
    qd_s1 = sh(qd_t, 1)
    # Under 1 lambda: sys8 = V(9), result = V(0)
    sys8_whole = a2(V(9), V(0), qd_s1)
    cont_8 = L(sys8_whole)
    full_8 = a2(V(0xC9), nil_t, cont_8)

    try:
        payload = enc(full_8) + bytes([FF])
        print(f"  Payload ({len(payload)}b): {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        print(f"  Result: {desc(resp)}")
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== T9: What about using backdoor result as sys8's CONTINUATION? =====
    # sys8(nil)(Left(pair)) — sys8 with nil arg, Left(pair) as continuation
    # sys8 returns Right(6) to Left(pair)
    # Left(pair)(Right(6)) = ... hmm, Left(pair) is λl.λr. l(pair)
    # Left(pair) applied to Right(6): (λl.λr. l(pair))(Right(6)) = λr. Right(6)(pair)
    # That's a function. Not useful.

    # What about: sys8(nil)(pair) — pair as continuation
    # sys8 returns Right(6) to pair
    # pair(Right(6)) = (λf.f(A)(B))(Right(6)) = Right(6)(A)(B)
    # Right(6) = λl.λr. r(6)
    # Right(6)(A)(B) = B(6) = (λa.λb.(a b))(6) = λb.(6 b)
    # That's a partial application. Not directly useful.

    # But what if sys8 SUCCEEDS and returns Left(answer)?
    # pair(Left(answer)) = Left(answer)(A)(B) = A(answer)
    # A = λa.λb.(b b), so A(answer) = λb.(b b) = mockingbird!
    # The answer is LOST. A ignores its argument.

    # Hmm. So pair as continuation loses the answer.
    # We need a DIFFERENT continuation that captures the answer.

    # ===== T10: Try ALL syscalls as pair destructor =====
    print("\n--- T10: backdoor→pair(syscall_N)→QD for various N ---")

    syscalls_to_test = [
        (0, "exception"),
        (1, "errorString"),
        (2, "write"),
        (4, "quote"),
        (5, "readdir"),
        (6, "name"),
        (7, "readfile"),
        (8, "solution"),
        (14, "echo"),
        (42, "towel"),
        (201, "backdoor"),
    ]

    for sc_num, sc_name in syscalls_to_test:
        # backdoor(nil)(λr. r(λp. ((p sc) QD_s2))(λe. nil_s2))
        # Under 2 lambdas: sc = V(sc_num + 2)
        sc_shifted = V(sc_num + 2)
        inner = a2(V(0), sc_shifted, qd_s2_v)
        left_h = L(inner)
        right_h = L(nil_s2_v)
        disp = a2(V(0), left_h, right_h)
        cont = L(disp)
        full = a2(V(0xC9), nil_t, cont)

        try:
            payload = enc(full) + bytes([FF])
            resp = q(payload, timeout_s=8.0)
            result = desc(resp)
            print(f"  pair({sc_name}={sc_num}): {result}")
        except Exception as e:
            print(f"  pair({sc_name}={sc_num}): ERROR: {e}")
        time.sleep(0.5)

    print("\n" + "=" * 70)
    print("PROBE COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
