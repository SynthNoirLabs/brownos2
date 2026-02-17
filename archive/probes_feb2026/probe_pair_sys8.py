#!/usr/bin/env python3
"""
probe_pair_sys8.py — Use the PROVEN Church-style pair extraction pattern
to feed backdoor components A and B into sys8 and other syscalls.

Working pattern from probe_parse_verify.py Test A:
  bd(nil)(λe. e(λp. p(DESTRUCTOR)(DUMMY))(λerr. nil))

Pair structure (confirmed):
  pair = λf.λs. (f A) B   (Church-style: destructor is 1st arg)
  A = λa.λb. b(b)         (self-apply 2nd, ignore 1st)
  B = λa.λb. a(b)         (apply 1st to 2nd)

So pair(D)(X) = D(A)(B).
"""

import socket
import time

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
)

HOST = "wc3.wechall.net"
PORT = 61221
QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
nil = Lam(Lam(Var(0)))


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


def term_to_str(t, depth=0):
    if isinstance(t, Var):
        return f"V{t.i}"
    if isinstance(t, Lam):
        return f"L({term_to_str(t.body, depth + 1)})"
    if isinstance(t, App):
        return f"({term_to_str(t.f, depth)} {term_to_str(t.x, depth)})"
    return str(t)


def shift(term, d, c=0):
    if isinstance(term, Var):
        return Var(term.i + d) if term.i >= c else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, d, c + 1))
    if isinstance(term, App):
        return App(shift(term.f, d, c), shift(term.x, d, c))


QD_term = parse_term(QD_BYTES + bytes([FF]))

test_num = 0


def run_test(name, desc, destructor_at_depth2, dummy_at_depth2=None):
    """Run a test using the proven Church-style pair extraction pattern.

    destructor_at_depth2: the destructor term, already shifted for depth 2
    dummy_at_depth2: the dummy term, already shifted for depth 2 (default: nil shifted +2)
    """
    global test_num
    test_num += 1

    if dummy_at_depth2 is None:
        dummy_at_depth2 = shift(nil, 2)

    # left_handler = λp. p(destructor)(dummy)  [p = Var(0) at depth 2]
    lh_body = App(App(Var(0), destructor_at_depth2), dummy_at_depth2)
    left_handler = Lam(lh_body)

    # right_handler = λerr. nil  [nil shifted for depth 2]
    right_handler = Lam(shift(nil, 2))

    # continuation = λe. e(left_handler)(right_handler)  [e = Var(0) at depth 1]
    cont_body = App(App(Var(0), left_handler), right_handler)
    continuation = Lam(cont_body)

    # full = bd(nil)(continuation)
    full = App(App(Var(201), nil), continuation)
    payload = encode_term(full) + bytes([FF])

    if len(payload) > 2000:
        print(
            f"\n  T{test_num} [{name}]: SKIPPED — payload {len(payload)}B > 2KB limit"
        )
        return None

    print(f"\n  T{test_num} [{name}]: {desc}")
    print(f"    Payload: {len(payload)}B")
    time.sleep(0.45)
    resp = send_raw(payload)

    resp_hex = resp.hex() if resp else "EMPTY"
    resp_len = len(resp)
    print(f"    Response: {resp_hex[:120]} ({resp_len}B)")

    # Classify result
    if resp_len == 0:
        print(f"    => EMPTY")
        return "EMPTY"

    # Try text decode
    try:
        txt = resp.decode("utf-8", "replace")
        if txt.startswith("Permission denied"):
            print(f"    => PERMISSION DENIED (text)")
            return "DENIED_TEXT"
        if txt.startswith("Invalid"):
            print(f"    => {txt.strip()}")
            return "INVALID"
        if all(32 <= c < 127 or c in (10, 13) for c in resp):
            print(f"    => TEXT: {repr(txt[:80])}")
            return f"TEXT:{txt}"
    except:
        pass

    # Try parse as term
    if FF in resp:
        try:
            t = parse_term(resp)
            ts = term_to_str(t)
            print(f"    => TERM: {ts[:120]}")

            # Try decode as Either
            try:
                tag, payload_t = decode_either(t)
                print(f"    => Either: {tag}({term_to_str(payload_t)[:80]})")

                # If Right, try to decode error code
                if tag == "Right":
                    # Right payload is a byte term (9 lambdas + bitset)
                    from solve_brownos_answer import decode_byte_term

                    try:
                        code = decode_byte_term(payload_t)
                        err_names = {
                            0: "Exception",
                            1: "NotImpl",
                            2: "InvalidArg",
                            3: "NoSuchFile",
                            4: "NotDir",
                            5: "NotFile",
                            6: "PermDenied",
                            7: "RateLimit",
                        }
                        print(f"    => ERROR CODE {code}: {err_names.get(code, '???')}")
                        return f"RIGHT_{code}"
                    except:
                        print(f"    => Right (can't decode code)")
                        return "RIGHT_?"

                # If Left, try to decode as byte list
                if tag == "Left":
                    try:
                        bs = decode_bytes_list(payload_t)
                        print(f"    => LEFT DATA: {bs[:80]}")
                        return f"LEFT:{bs}"
                    except:
                        print(f"    => Left (not a byte list)")
                        return f"LEFT_TERM"

            except Exception as e:
                print(f"    => Not an Either: {e}")

            return f"TERM:{ts[:60]}"
        except Exception as e:
            print(f"    => Parse error: {e}")

    # Raw hex
    print(f"    => RAW HEX")
    return f"RAW:{resp_hex[:40]}"


# ================================================================
print("=" * 70)
print("PHASE 1: pair(sys8)(nil) = sys8(A)(B)")
print("  sys8 with A as arg, B as continuation")
print("  B(result) = λb. result(b) — partial apply, likely EMPTY")
print("=" * 70)

# At depth 2: sys8 = g(8) = Var(8+2) = Var(10)
run_test("sys8_raw", "pair(sys8)(nil) = sys8(A)(B)", Var(10))

# ================================================================
print("\n" + "=" * 70)
print("PHASE 2: pair(λa.λb. sys8(a)(QD))(nil) — sys8(A) with QD obs")
print("  Destructor extracts A, feeds to sys8 with QD continuation")
print("=" * 70)

# Destructor at depth 0: λa.λb. sys8(a)(QD)
# Inside λa.λb (depth 2 from destructor's own lambdas):
#   a = Var(1), b = Var(0)
#   But this destructor will be placed at depth 2 (inside λe.λp)
#   So we build it at depth 0, then shift +2
# At depth 0: sys8 = Var(8), QD globals start at their natural indices
# body: App(App(Var(8), Var(1)), QD_term)  — sys8(a)(QD)
# But QD_term references globals at depth 0. Inside λa.λb, depth = 2.
# So QD needs shift +2 for the destructor's own lambdas.
# Then the whole destructor gets shifted +2 for placement at depth 2.
# Total shift for QD globals: +2 (own lambdas) + 2 (placement) = +4

# Build destructor at depth 0:
qd_in_destr = shift(QD_term, 2)  # shift for λa.λb
destr_body_2 = App(
    App(Var(8 + 2), Var(1)), qd_in_destr
)  # sys8=Var(10) at depth 2 of destructor
destr_2 = Lam(Lam(destr_body_2))  # λa.λb. sys8(a)(QD)
# Now shift +2 for placement inside λe.λp
destr_2_shifted = shift(destr_2, 2)
run_test("sys8_A_QD", "pair(λa.λb. sys8(a)(QD))(nil) → sys8(A)(QD)", destr_2_shifted)

# ================================================================
print("\n" + "=" * 70)
print("PHASE 3: pair(λa.λb. sys8(b)(QD))(nil) — sys8(B) with QD obs")
print("  Destructor extracts B, feeds to sys8 with QD continuation")
print("=" * 70)

# Same as Phase 2 but sys8(b) where b = Var(0) at depth 2 of destructor
destr_body_3 = App(App(Var(8 + 2), Var(0)), qd_in_destr)  # sys8(b)(QD)
destr_3 = Lam(Lam(destr_body_3))
destr_3_shifted = shift(destr_3, 2)
run_test("sys8_B_QD", "pair(λa.λb. sys8(b)(QD))(nil) → sys8(B)(QD)", destr_3_shifted)

# ================================================================
print("\n" + "=" * 70)
print("PHASE 4: pair(λa.λb. sys8(a(b))(QD))(nil) — sys8(A(B))")
print("  A(B) = (λa.λb.b(b))(B) = λb.b(b) — mockingbird again")
print("=" * 70)

# a(b) at depth 2 of destructor: App(Var(1), Var(0))
destr_body_4 = App(App(Var(8 + 2), App(Var(1), Var(0))), qd_in_destr)
destr_4 = Lam(Lam(destr_body_4))
destr_4_shifted = shift(destr_4, 2)
run_test(
    "sys8_AB_QD", "pair(λa.λb. sys8(a(b))(QD))(nil) → sys8(A(B))(QD)", destr_4_shifted
)

# ================================================================
print("\n" + "=" * 70)
print("PHASE 5: pair(λa.λb. sys8(b(a))(QD))(nil) — sys8(B(A))")
print("  B(A) = (λa.λb.a(b))(A) = λb.A(b) = λb.(λx.λy.y(y))(b) = λb.λy.y(y)")
print("=" * 70)

# b(a) at depth 2 of destructor: App(Var(0), Var(1))
destr_body_5 = App(App(Var(8 + 2), App(Var(0), Var(1))), qd_in_destr)
destr_5 = Lam(Lam(destr_body_5))
destr_5_shifted = shift(destr_5, 2)
run_test(
    "sys8_BA_QD", "pair(λa.λb. sys8(b(a))(QD))(nil) → sys8(B(A))(QD)", destr_5_shifted
)

# ================================================================
print("\n" + "=" * 70)
print("PHASE 6: pair(echo)(nil) = echo(A)(B)")
print("  echo = g(14). echo(A) returns Left(A), B is continuation")
print("  B(Left(A)) = (λa.λb.a(b))(Left(A)) = λb. Left(A)(b) — partial")
print("=" * 70)

# At depth 2: echo = g(14) = Var(14+2) = Var(16)
run_test("echo_raw", "pair(echo)(nil) = echo(A)(B)", Var(16))

# ================================================================
print("\n" + "=" * 70)
print("PHASE 7: pair(backdoor)(nil) = backdoor(A)(B)")
print("  backdoor = g(201). backdoor(A) with B as continuation")
print("  backdoor expects nil as arg — A is not nil, may error")
print("=" * 70)

# At depth 2: backdoor = g(201) = Var(201+2) = Var(203)
run_test("bd_raw", "pair(backdoor)(nil) = backdoor(A)(B)", Var(203))

# ================================================================
print("\n" + "=" * 70)
print("PHASE 8: pair(λa.λb. quote(a)(QD))(nil) — quote A, write bytecode")
print("  Verify we can extract A's bytecode via quote instead of QD directly")
print("  At depth 4: quote = g(4) = Var(8)")
print("=" * 70)

# Destructor: λa.λb. quote(a)(QD)
# At depth 2 of destructor: quote = g(4) = Var(4+2) = Var(6), a = Var(1)
# QD shifted +2 for destructor lambdas
destr_body_8 = App(App(Var(4 + 2), Var(1)), qd_in_destr)  # quote(a)(QD)
destr_8 = Lam(Lam(destr_body_8))
destr_8_shifted = shift(destr_8, 2)
run_test("quote_A_QD", "pair(λa.λb. quote(a)(QD))(nil) → quote(A)(QD)", destr_8_shifted)

# ================================================================
print("\n" + "=" * 70)
print("PHASE 9: pair(λa.λb. quote(b)(QD))(nil) — quote B, write bytecode")
print("=" * 70)

destr_body_9 = App(App(Var(4 + 2), Var(0)), qd_in_destr)  # quote(b)(QD)
destr_9 = Lam(Lam(destr_body_9))
destr_9_shifted = shift(destr_9, 2)
run_test("quote_B_QD", "pair(λa.λb. quote(b)(QD))(nil) → quote(B)(QD)", destr_9_shifted)

# ================================================================
print("\n" + "=" * 70)
print("PHASE 10: pair(λa.λb. echo(a)(QD))(nil) — echo(A) with QD")
print("  echo(A) = Left(A), QD(Left(A)) should print Left(A) bytecode")
print("=" * 70)

# At depth 2 of destructor: echo = g(14) = Var(14+2) = Var(16)
destr_body_10 = App(App(Var(14 + 2), Var(1)), qd_in_destr)  # echo(a)(QD)
destr_10 = Lam(Lam(destr_body_10))
destr_10_shifted = shift(destr_10, 2)
run_test("echo_A_QD", "pair(λa.λb. echo(a)(QD))(nil) → echo(A)(QD)", destr_10_shifted)

# ================================================================
print("\n" + "=" * 70)
print("PHASE 11: pair(λa.λb. sys8(pair(a,b))(QD))(nil)")
print("  Reconstruct the pair and pass it to sys8")
print("  pair(a,b) = λf.λs. f(a)(b) — Church pair")
print("=" * 70)

# At depth 2 of destructor: a=Var(1), b=Var(0)
# pair(a,b) at depth 2: λf.λs. f(a_shifted)(b_shifted)
# Inside pair's λf.λs (depth 4 from destructor): f=Var(1), s=Var(0)
# a at depth 4 = Var(1+2) = Var(3), b at depth 4 = Var(0+2) = Var(2)
pair_ab = Lam(Lam(App(App(Var(1), Var(3)), Var(2))))
# sys8(pair_ab)(QD) at depth 2 of destructor
destr_body_11 = App(App(Var(8 + 2), pair_ab), qd_in_destr)
destr_11 = Lam(Lam(destr_body_11))
destr_11_shifted = shift(destr_11, 2)
run_test(
    "sys8_pair_QD",
    "pair(λa.λb. sys8(pair(a,b))(QD))(nil) → sys8(pair(A,B))(QD)",
    destr_11_shifted,
)

# ================================================================
print("\n" + "=" * 70)
print("PHASE 12: pair(λa.λb. sys8(a)(λr. r(QD)(QD)))(nil)")
print("  sys8(A) with Either-destructuring continuation")
print("  If Left(x): QD(x) prints x. If Right(e): QD(e) prints e.")
print("=" * 70)

# Continuation for sys8: λr. r(QD)(QD) — applies Either to QD twice
# At depth 2 of destructor: a=Var(1)
# sys8 = Var(10) at depth 2
# The continuation λr. r(QD)(QD) is at depth 3 of destructor (inside λa.λb.λr)
# Inside λr: r=Var(0), QD needs shift +3 from depth 0
qd_in_cont = shift(QD_term, 3)  # shift for λa.λb.λr
either_cont = Lam(App(App(Var(0), qd_in_cont), shift(QD_term, 3)))
destr_body_12 = App(App(Var(8 + 2), Var(1)), either_cont)
destr_12 = Lam(Lam(destr_body_12))
destr_12_shifted = shift(destr_12, 2)
run_test(
    "sys8_A_either_QD", "pair(λa.λb. sys8(a)(λr. r(QD)(QD)))(nil)", destr_12_shifted
)

# ================================================================
print("\n" + "=" * 70)
print("PHASE 13: pair(λa.λb. sys8(b)(λr. r(QD)(QD)))(nil)")
print("  sys8(B) with Either-destructuring continuation")
print("=" * 70)

destr_body_13 = App(App(Var(8 + 2), Var(0)), either_cont)
destr_13 = Lam(Lam(destr_body_13))
destr_13_shifted = shift(destr_13, 2)
run_test(
    "sys8_B_either_QD", "pair(λa.λb. sys8(b)(λr. r(QD)(QD)))(nil)", destr_13_shifted
)

# ================================================================
print("\n" + "=" * 70)
print("PHASE 14: Baseline — pair(QD)(nil) = QD(A)(B)")
print("  Should match probe_parse_verify.py Test A: prints A's bytecode")
print("=" * 70)

qd_at_2 = shift(QD_term, 2)
run_test("baseline_QD", "pair(QD)(nil) = QD(A)(B) — should print A bytecode", qd_at_2)

# ================================================================
# Summary
# ================================================================
print("\n" + "=" * 70)
print("ALL PHASES COMPLETE")
print("=" * 70)
