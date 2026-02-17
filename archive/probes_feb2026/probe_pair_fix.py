#!/usr/bin/env python3
"""
probe_pair_fix.py - Fix backdoor pair extraction (Church-style pair)

The backdoor pair is: Lam(Lam(App(App(Var(1), A), B)))
= λfirst.λsecond. first(A)(B)  [Church-style]

Destructor goes FIRST: pair(destructor)(dummy) = destructor(A)(B)
Previous attempts failed because they used Scott-style: pair(destructor) [only 1 arg]
"""

import socket
import time
import sys

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FF,
    FD,
    FE,
    encode_term,
    parse_term,
    decode_either,
    decode_bytes_list,
    decode_byte_term,
    encode_byte_term,
    encode_bytes_list,
)

HOST = "wc3.wechall.net"
PORT = 61221
QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
QD = parse_term(QD_BYTES + bytes([FF]))
nil = Lam(Lam(Var(0)))


def shift(term, d, c=0):
    """Shift free variables >= c by d."""
    if isinstance(term, Var):
        return Var(term.i + d) if term.i >= c else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, d, c + 1))
    if isinstance(term, App):
        return App(shift(term.f, d, c), shift(term.x, d, c))


def send_raw(payload, timeout_s=5.0):
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


def run_test(label, term):
    payload = encode_term(term) + bytes([FF])
    print(f"\n--- {label} ---")
    print(f"  Payload hex ({len(payload)}B): {payload.hex()[:160]}")
    sys.stdout.flush()
    time.sleep(0.45)
    resp = send_raw(payload)
    if not resp:
        print("  Result: EMPTY")
        return "EMPTY"
    resp_hex = resp.hex()
    print(f"  Resp hex: {resp_hex[:120]}")
    try:
        txt = resp.decode("utf-8", "replace")
        if txt.strip():
            print(f"  Resp text: {repr(txt[:100])}")
    except:
        pass
    # Try parse
    if FF in resp:
        try:
            t = parse_term(resp)
            tag, pl = decode_either(t)
            if tag == "Right":
                try:
                    code = decode_byte_term(pl)
                    print(f"  Decoded: Right({code})")
                    return f"Right({code})"
                except:
                    print(f"  Decoded: Right(?)")
                    return "Right(?)"
            else:
                print(f"  Decoded: Left(...)")
                try:
                    bs = decode_bytes_list(pl)
                    print(f"  Left text: {bs.decode('utf-8', 'replace')}")
                except:
                    print(f"  Left payload: {pl}")
                return "Left"
        except Exception as e:
            print(f"  Parse err: {e}")
    try:
        txt = resp.decode("utf-8", "replace")
        if "Permission denied" in txt:
            return "PERM_DENIED"
        if "Invalid" in txt:
            return "INVALID"
    except:
        pass
    print("  *** NOVEL ***")
    return "NOVEL"


# ================================================================
# PHASE 0: Baseline — confirm backdoor(nil)(QD) works
# ================================================================
print("=" * 70)
print("PHASE 0: Baseline")
print("=" * 70)

# bd(nil)(QD) — should return Left(pair)
t0 = App(App(Var(201), nil), QD)
run_test("T0: bd(nil)(QD) baseline", t0)

# ================================================================
# PHASE 1: Church-style pair extraction — destructor FIRST
# ================================================================
print("\n" + "=" * 70)
print("PHASE 1: Church-style — pair(destructor)(dummy)")
print("=" * 70)

# T1: bd(nil)(λe. e(λp. p(λa.λb. write("A!")(λ_. nil))(nil))(λerr. write("E!")(λ_. nil)))
#
# Lambda depth tracking:
# depth 0: globals at face value. bd=Var(201)
# λe (depth 1): e=Var(0), globals +1
# Left handler = λp (depth 2): p=Var(0), e=Var(1), globals +2
#   pair application: p(destructor)(dummy)
#   destructor = λa (depth 3) . λb (depth 4): a=Var(1), b=Var(0), globals +4
#     write = g(2) at depth 4 = Var(2+4) = Var(6)
#     "A!" string needs shift +4
#     body: App(App(Var(6), shift(encode_bytes_list(b"A!"), 4)), Lam(shift(nil, 5)))
#   dummy = nil at depth 2 = shift(nil, 2)
# Right handler = λerr (depth 2): err=Var(0), globals +2
#   write = g(2) at depth 2 = Var(4)

a_str = encode_bytes_list(b"A!")
e_str = encode_bytes_list(b"E!")

# destructor at depth 4: λa.λb. write("A!")(λ_.nil)
inner_body_1 = App(App(Var(6), shift(a_str, 4)), Lam(shift(nil, 5)))
destructor_1 = Lam(Lam(inner_body_1))

# At depth 2: p(destructor)(nil)
pair_call_1 = App(App(Var(0), shift(destructor_1, 2)), shift(nil, 2))
left_h_1 = Lam(pair_call_1)  # λp. ...

# Right handler at depth 2: λerr. write("E!")(λ_.nil)
right_body_1 = App(App(Var(4), shift(e_str, 2)), Lam(shift(nil, 3)))
right_h_1 = Lam(right_body_1)

# At depth 1: e(left_h)(right_h)
dispatch_1 = App(App(Var(0), shift(left_h_1, 1)), shift(right_h_1, 1))
cont_1 = Lam(dispatch_1)

t1 = App(App(Var(201), nil), cont_1)
run_test("T1: Church pair(λa.λb.write('A!')...)(nil)", t1)

# ================================================================
# T2: Opposite — Scott-style pair(nil)(destructor) for comparison
# ================================================================
print("\n" + "=" * 70)
print("PHASE 2: Scott-style — pair(dummy)(destructor)")
print("=" * 70)

ok2_str = encode_bytes_list(b"S!")
inner_body_2 = App(App(Var(6), shift(ok2_str, 4)), Lam(shift(nil, 5)))
destructor_2 = Lam(Lam(inner_body_2))

# At depth 2: p(nil)(destructor) — dummy first, destructor second
pair_call_2 = App(App(Var(0), shift(nil, 2)), shift(destructor_2, 2))
left_h_2 = Lam(pair_call_2)

dispatch_2 = App(App(Var(0), shift(left_h_2, 1)), shift(right_h_1, 1))
cont_2 = Lam(dispatch_2)

t2 = App(App(Var(201), nil), cont_2)
run_test("T2: Scott pair(nil)(λa.λb.write('S!')...)", t2)

# ================================================================
# PHASE 3: Extract A with quote — Church-style
# ================================================================
print("\n" + "=" * 70)
print("PHASE 3: Extract A and B with quote")
print("=" * 70)

# T3: bd(nil)(λe. e(λp. p(λa.λb. quote(a)(QD))(nil))(λerr. QD(err)))
# At depth 4: quote = g(4) = Var(8), a = Var(1), QD shifted +4
qd4 = shift(QD, 4)
quote_a_body = App(App(Var(8), Var(1)), qd4)
destr_qa = Lam(Lam(quote_a_body))

pair_call_3 = App(App(Var(0), shift(destr_qa, 2)), shift(nil, 2))
left_h_3 = Lam(pair_call_3)

# Right: λerr. QD(err) at depth 2
qd2 = shift(QD, 2)
right_h_3 = Lam(App(qd2, Var(0)))

dispatch_3 = App(App(Var(0), shift(left_h_3, 1)), shift(right_h_3, 1))
cont_3 = Lam(dispatch_3)
t3 = App(App(Var(201), nil), cont_3)
run_test("T3: Church extract A via quote", t3)

# T4: Extract B — same but quote(b) where b=Var(0) at depth 4
quote_b_body = App(App(Var(8), Var(0)), qd4)
destr_qb = Lam(Lam(quote_b_body))

pair_call_4 = App(App(Var(0), shift(destr_qb, 2)), shift(nil, 2))
left_h_4 = Lam(pair_call_4)

dispatch_4 = App(App(Var(0), shift(left_h_4, 1)), shift(right_h_3, 1))
cont_4 = Lam(dispatch_4)
t4 = App(App(Var(201), nil), cont_4)
run_test("T4: Church extract B via quote", t4)

# T5: Scott-style extract A for comparison
pair_call_5 = App(App(Var(0), shift(nil, 2)), shift(destr_qa, 2))
left_h_5 = Lam(pair_call_5)
dispatch_5 = App(App(Var(0), shift(left_h_5, 1)), shift(right_h_3, 1))
cont_5 = Lam(dispatch_5)
t5 = App(App(Var(201), nil), cont_5)
run_test("T5: Scott extract A via quote (comparison)", t5)

# ================================================================
# PHASE 4: sys8 with extracted A and B
# ================================================================
print("\n" + "=" * 70)
print("PHASE 4: sys8 with extracted A and B")
print("=" * 70)

# T6: bd(nil)(λe. e(λp. p(λa.λb. sys8(a)(QD))(nil))(λerr. QD(err)))
# At depth 4: sys8 = g(8) = Var(12), a = Var(1)
sys8_a_body = App(App(Var(12), Var(1)), qd4)
destr_s8a = Lam(Lam(sys8_a_body))

pair_call_6 = App(App(Var(0), shift(destr_s8a, 2)), shift(nil, 2))
left_h_6 = Lam(pair_call_6)
dispatch_6 = App(App(Var(0), shift(left_h_6, 1)), shift(right_h_3, 1))
cont_6 = Lam(dispatch_6)
t6 = App(App(Var(201), nil), cont_6)
run_test("T6: Church sys8(A)(QD)", t6)

# T7: sys8(B)
sys8_b_body = App(App(Var(12), Var(0)), qd4)
destr_s8b = Lam(Lam(sys8_b_body))

pair_call_7 = App(App(Var(0), shift(destr_s8b, 2)), shift(nil, 2))
left_h_7 = Lam(pair_call_7)
dispatch_7 = App(App(Var(0), shift(left_h_7, 1)), shift(right_h_3, 1))
cont_7 = Lam(dispatch_7)
t7 = App(App(Var(201), nil), cont_7)
run_test("T7: Church sys8(B)(QD)", t7)

# ================================================================
# PHASE 5: pair(sys8)(nil) = sys8(A)(B) — B as continuation!
# ================================================================
print("\n" + "=" * 70)
print("PHASE 5: pair(sys8)(nil) — B becomes continuation")
print("=" * 70)

# T8: bd(nil)(λe. e(λp. p(sys8)(nil))(λerr. QD(err)))
# At depth 2: sys8 = g(8) = Var(10)
pair_call_8 = App(App(Var(0), Var(10)), shift(nil, 2))
left_h_8 = Lam(pair_call_8)
dispatch_8 = App(App(Var(0), shift(left_h_8, 1)), shift(right_h_3, 1))
cont_8 = Lam(dispatch_8)
t8 = App(App(Var(201), nil), cont_8)
run_test("T8: pair(sys8)(nil) = sys8(A)(B)", t8)

# T9: pair(QD)(nil) = QD(A)(B) — observe A directly
pair_call_9 = App(App(Var(0), shift(QD, 2)), shift(nil, 2))
left_h_9 = Lam(pair_call_9)
dispatch_9 = App(App(Var(0), shift(left_h_9, 1)), shift(right_h_3, 1))
cont_9 = Lam(dispatch_9)
t9 = App(App(Var(201), nil), cont_9)
run_test("T9: pair(QD)(nil) = QD(A)(B)", t9)

# ================================================================
# PHASE 6: pair(echo)(nil) and pair(backdoor)(nil)
# ================================================================
print("\n" + "=" * 70)
print("PHASE 6: pair with other syscalls")
print("=" * 70)

# T10: pair(echo)(nil) = echo(A)(B) — echo with A, B as continuation
# At depth 2: echo = g(14) = Var(16)
pair_call_10 = App(App(Var(0), Var(16)), shift(nil, 2))
left_h_10 = Lam(pair_call_10)
dispatch_10 = App(App(Var(0), shift(left_h_10, 1)), shift(right_h_3, 1))
cont_10 = Lam(dispatch_10)
t10 = App(App(Var(201), nil), cont_10)
run_test("T10: pair(echo)(nil) = echo(A)(B)", t10)

# T11: pair(backdoor)(nil) = backdoor(A)(B)
# At depth 2: backdoor = g(201) = Var(203)
pair_call_11 = App(App(Var(0), Var(203)), shift(nil, 2))
left_h_11 = Lam(pair_call_11)
dispatch_11 = App(App(Var(0), shift(left_h_11, 1)), shift(right_h_3, 1))
cont_11 = Lam(dispatch_11)
t11 = App(App(Var(201), nil), cont_11)
run_test("T11: pair(backdoor)(nil) = backdoor(A)(B)", t11)

# ================================================================
# PHASE 7: A(B) and B(A) combinations with observation
# ================================================================
print("\n" + "=" * 70)
print("PHASE 7: A(B) and B(A) with QD observation")
print("=" * 70)

# T12: bd(nil)(λe. e(λp. p(λa.λb. a(b)(QD))(nil))(λerr. QD(err)))
# At depth 4: a=Var(1), b=Var(0), QD shifted +4
ab_qd = App(App(Var(1), Var(0)), qd4)
destr_ab = Lam(Lam(ab_qd))
pair_call_12 = App(App(Var(0), shift(destr_ab, 2)), shift(nil, 2))
left_h_12 = Lam(pair_call_12)
dispatch_12 = App(App(Var(0), shift(left_h_12, 1)), shift(right_h_3, 1))
cont_12 = Lam(dispatch_12)
t12 = App(App(Var(201), nil), cont_12)
run_test("T12: Church A(B)(QD)", t12)

# T13: B(A)(QD)
ba_qd = App(App(Var(0), Var(1)), qd4)
destr_ba = Lam(Lam(ba_qd))
pair_call_13 = App(App(Var(0), shift(destr_ba, 2)), shift(nil, 2))
left_h_13 = Lam(pair_call_13)
dispatch_13 = App(App(Var(0), shift(left_h_13, 1)), shift(right_h_3, 1))
cont_13 = Lam(dispatch_13)
t13 = App(App(Var(201), nil), cont_13)
run_test("T13: Church B(A)(QD)", t13)

# ================================================================
print("\n" + "=" * 70)
print("ALL TESTS COMPLETE")
print("=" * 70)
