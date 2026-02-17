#!/usr/bin/env python3
"""
probe_hidden_syscall.py — Two angles:

ANGLE 1: Hidden syscall sweep. Test syscall numbers we haven't tried,
especially in ranges near known syscalls and high values.

ANGLE 2: Backdoor pair extraction → sys8 with PROPER CPS chain.
The pair is Church-style: pair(destructor)(dummy) = destructor(A)(B).
We need to extract A and B and pass them to sys8 with a working observer.

ANGLE 3: What if sys8 needs the BACKDOOR GLOBAL (g(201)) as argument,
not the pair it returns? Or what if sys8 needs to be called FROM WITHIN
the backdoor's CPS chain?
"""

import socket
import time
import sys
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE
FF = 0xFF

QD_HEX = "0500fd000500fd03fdfefd02fdfefdfe"


@dataclass(frozen=True)
class Var:
    i: int


@dataclass(frozen=True)
class Lam:
    body: object


@dataclass(frozen=True)
class App:
    f: object
    x: object


def encode_term(term):
    if isinstance(term, Var):
        if term.i > 0xFC:
            raise ValueError(f"Cannot encode Var({term.i})")
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError


def parse_term(data):
    stack = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            stack.append(Lam(stack.pop()))
        else:
            stack.append(Var(b))
    return stack[0] if len(stack) == 1 else None


def shift(term, d, c=0):
    if isinstance(term, Var):
        return Var(term.i + d) if term.i >= c else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, d, c + 1))
    if isinstance(term, App):
        return App(shift(term.f, d, c), shift(term.x, d, c))
    raise TypeError


QD = parse_term(bytes.fromhex(QD_HEX) + bytes([FF]))
nil = Lam(Lam(Var(0)))
I = Lam(Var(0))


def send_raw(payload, timeout_s=8.0):
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            sock.settimeout(timeout_s)
            out = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out += chunk
                except socket.timeout:
                    break
            return out
    except Exception as e:
        return f"ERROR: {e}".encode()


novel_list = []


def test(label, term_or_bytes, timeout_s=8.0):
    if isinstance(term_or_bytes, bytes):
        payload = term_or_bytes
    else:
        payload = encode_term(term_or_bytes) + bytes([FF])

    if len(payload) > 2000:
        print(f"[TOOBIG      ] {label} ({len(payload)} bytes)")
        return "TOOBIG"

    time.sleep(0.45)
    resp = send_raw(payload, timeout_s)
    rh = resp.hex() if resp else "EMPTY"
    rt = resp.decode("utf-8", "replace") if resp else ""

    is_perm = "Permission denied" in rt
    is_r6 = "00030200fdfd" in rh
    is_empty = len(resp) == 0
    is_invalid = "Invalid term" in rt
    is_enc = "Encoding failed" in rt
    is_toobig = "Term too big" in rt
    is_error = rt.startswith("ERROR:")
    # Check for Left (success) — starts with 01 ... FE FE (Left = λl.λr. l(x))
    is_left = (
        len(resp) > 4
        and resp[0] != 0x00
        and rh != "EMPTY"
        and not is_perm
        and not is_r6
        and not is_invalid
        and not is_enc
        and not is_toobig
        and not is_error
    )

    status = (
        "PERM_DENIED"
        if is_perm
        else "RIGHT6_RAW"
        if is_r6
        else "EMPTY"
        if is_empty
        else "INVALID"
        if is_invalid
        else "ENC_FAIL"
        if is_enc
        else "TOO_BIG"
        if is_toobig
        else "CONN_ERR"
        if is_error
        else "*** NOVEL ***"
    )

    print(f"[{status:12s}] {label}")
    if resp and not is_empty:
        print(f"  Resp hex: {rh[:80]}")
    if status == "*** NOVEL ***":
        print(f"  !!! POSSIBLE BREAKTHROUGH !!!")
        print(f"  Full hex: {rh}")
        print(f"  Full text: {repr(rt[:200])}")
        # Try to parse as Either
        try:
            term = parse_term(resp)
            if term and isinstance(term, Lam) and isinstance(term.body, Lam):
                body = term.body.body
                if isinstance(body, App) and isinstance(body.f, Var):
                    if body.f.i == 1:
                        print(f"  DECODED: Left(...)")
                    elif body.f.i == 0:
                        print(f"  DECODED: Right(...)")
        except:
            pass
        novel_list.append((label, rh, rt))
    sys.stdout.flush()
    return status


# ================================================================
print("=" * 70)
print("ANGLE 1: Hidden syscall sweep")
print("Test syscall numbers not previously tested with QD observer")
print("=" * 70)

# Known syscalls: 0,1,2,4,5,6,7,8,14,42,201
# Test a range of unknown ones
for sc in [3, 9, 10, 11, 12, 13, 15, 16, 100, 128, 200, 202, 203, 204, 205, 250]:
    term = App(App(Var(sc), nil), QD)
    test(f"syscall({sc})(nil)(QD)", term)

# ================================================================
print()
print("=" * 70)
print("ANGLE 2: Backdoor → extract pair → sys8 with proper observer")
print("=" * 70)

# The backdoor returns Left(pair) where pair = λf.λg. f(A)(B)
# We need: bd(nil)(λeither. either(λpair. BODY)(λerr. nil))
# where BODY uses pair to extract A and B, then calls sys8

# Test 1: Extract A via pair(QD)(nil) — this should print A's bytecode
# bd(nil)(λe. e(λp. p(QD_s2)(nil_s2))(λerr. nil_s2))
# Under λe: depth 1
# Under λe.λp: depth 2 — QD needs +2 shift, nil needs +2 shift
QD_s2 = shift(QD, 2)
nil_s2 = shift(nil, 2)  # nil is closed, shift doesn't change it

# left_handler = λp. p(QD_s2)(nil_s2)
# = λ. App(App(Var(0), QD_s2), nil_s2)
left_handler = Lam(App(App(Var(0), QD_s2), nil_s2))

# right_handler = λerr. nil_s2
right_handler = Lam(nil_s2)

# continuation = λe. e(left_handler)(right_handler)
# = λ. App(App(Var(0), left_handler), right_handler)
continuation = Lam(App(App(Var(0), left_handler), right_handler))

# Full term: bd(nil)(continuation)
bd_extract_A = App(App(Var(201), nil), continuation)
test("bd→pair(QD)(nil) = QD(A)(B) → print A bytecode", bd_extract_A)

# Test 2: Extract A, then pass to sys8
# bd(nil)(λe. e(λp. p(λa.λb. sys8(a)(QD_s4))(nil_s2))(λerr. nil_s2))
# Under λe.λp.λa.λb: depth 4
# sys8 = Var(8+4) = Var(12)
# QD needs +4 shift
QD_s4 = shift(QD, 4)
nil_s4 = shift(nil, 4)

# inner = λa.λb. sys8(a)(QD_s4)
# Under λa: Var(0)=a, sys8=Var(8+3)=Var(11)... wait
# Actually under λe.λp.λa: depth 3, sys8=Var(8+3)=Var(11)
# Under λe.λp.λa.λb: depth 4, sys8=Var(8+4)=Var(12), a=Var(1)
inner_sys8_a = Lam(Lam(App(App(Var(12), Var(1)), QD_s4)))

# left_handler2 = λp. p(inner_sys8_a)(nil_s2)
left_handler2 = Lam(App(App(Var(0), inner_sys8_a), nil_s2))

continuation2 = Lam(App(App(Var(0), left_handler2), right_handler))
bd_sys8_A = App(App(Var(201), nil), continuation2)
test("bd→pair(λa.λb.sys8(a)(QD))(nil) = sys8(A)(QD)", bd_sys8_A)

# Test 3: Same but sys8(B) instead of sys8(A)
# inner = λa.λb. sys8(b)(QD_s4)
# Under depth 4: b=Var(0), sys8=Var(12)
inner_sys8_b = Lam(Lam(App(App(Var(12), Var(0)), QD_s4)))
left_handler3 = Lam(App(App(Var(0), inner_sys8_b), nil_s2))
continuation3 = Lam(App(App(Var(0), left_handler3), right_handler))
bd_sys8_B = App(App(Var(201), nil), continuation3)
test("bd→pair(λa.λb.sys8(b)(QD))(nil) = sys8(B)(QD)", bd_sys8_B)

# Test 4: sys8(pair) — pass the entire pair to sys8
# bd(nil)(λe. e(λp. sys8(p)(QD_s2))(λerr. nil_s2))
# Under λe.λp: depth 2, sys8=Var(10), p=Var(0)
left_handler4 = Lam(App(App(Var(10), Var(0)), QD_s2))
continuation4 = Lam(App(App(Var(0), left_handler4), right_handler))
bd_sys8_pair = App(App(Var(201), nil), continuation4)
test("bd→sys8(pair)(QD)", bd_sys8_pair)

# Test 5: sys8(A(B)) — A applied to B = ω (little omega)
# inner = λa.λb. sys8(a(b))(QD_s4)
# Under depth 4: a=Var(1), b=Var(0), sys8=Var(12)
inner_sys8_ab = Lam(Lam(App(App(Var(12), App(Var(1), Var(0))), QD_s4)))
left_handler5 = Lam(App(App(Var(0), inner_sys8_ab), nil_s2))
continuation5 = Lam(App(App(Var(0), left_handler5), right_handler))
bd_sys8_ab = App(App(Var(201), nil), continuation5)
test("bd→sys8(A(B))(QD) = sys8(ω)(QD)", bd_sys8_ab, timeout_s=5.0)

# ================================================================
print()
print("=" * 70)
print("ANGLE 3: sys8 called FROM WITHIN backdoor CPS chain")
print("What if the backdoor sets some VM state that unlocks sys8?")
print("=" * 70)

# Test 6: bd(nil)(λe. sys8(nil)(QD_s1))
# Call sys8 INSIDE the backdoor's continuation, ignoring the result
QD_s1 = shift(QD, 1)
bd_then_sys8 = App(App(Var(201), nil), Lam(App(App(Var(9), nil), QD_s1)))
test("bd(nil)(λ_. sys8(nil)(QD)) — sys8 inside bd cont", bd_then_sys8)

# Test 7: bd(nil)(λe. e(λp. sys8(nil)(QD_s2))(λerr. sys8(nil)(QD_s2)))
# Call sys8 in BOTH branches of the Either
left_h7 = Lam(App(App(Var(10), shift(nil, 2)), QD_s2))
right_h7 = Lam(App(App(Var(10), shift(nil, 2)), QD_s2))
cont7 = Lam(App(App(Var(0), left_h7), right_h7))
bd_both_sys8 = App(App(Var(201), nil), cont7)
test("bd(nil)(λe. e(λ_.sys8(nil)(QD))(λ_.sys8(nil)(QD)))", bd_both_sys8)

# Test 8: What if we need to pass the ENTIRE Either (not unwrapped) to sys8?
# bd(nil)(λe. sys8(e)(QD_s1))
bd_sys8_either = App(App(Var(201), nil), Lam(App(App(Var(9), Var(0)), QD_s1)))
test("bd(nil)(λe. sys8(e)(QD)) — sys8 with raw Either", bd_sys8_either)

# Test 9: What if sys8 needs g(201) (the backdoor global) as argument?
test("sys8(g(201))(QD)", App(App(Var(8), Var(201)), QD))

# Test 10: What if we chain: echo(g(201)) → sys8?
# echo(g(201))(λleft. sys8(left)(QD_s1))
echo_bd_sys8 = App(App(Var(14), Var(201)), Lam(App(App(Var(9), Var(0)), QD_s1)))
test("echo(g(201))(λl. sys8(l)(QD))", echo_bd_sys8)

print()
print("=" * 70)
print(f"SUMMARY: {len(novel_list)} novel responses")
print("=" * 70)
if novel_list:
    for label, hx, tx in novel_list:
        print(f"  {label}")
        print(f"    Hex: {hx[:80]}")
else:
    print("  No novel responses found.")
