#!/usr/bin/env python3
"""
probe_var255.py — Create Var(255) = 0xFF (END marker) via double echo.

HYPOTHESIS: The "freeze" hint means creating Var(255) = 0xFF at runtime.
- echo(g(251)) → Left(Var(253))  [+2 shift: 251→253]
- Unwrap Left, feed to echo again → Left(Var(255))  [+2 shift: 253→255]
- Var(255) = 0xFF = END marker — this could crash/confuse the VM!

The key: we can't encode Var(253) in bytecode, but we CAN pass it through
CPS chains without re-encoding. The runtime value Var(253) exists as a
lambda calculus term, and echo will shift it to Var(255).

Then: feed Var(255) to sys8 and see what happens.
"""

import socket
import sys
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
DELAY = 0.5


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


def enc(term):
    if isinstance(term, Var):
        if term.i > 0xFC:
            raise ValueError(f"Var({term.i}) cannot be encoded")
        return bytes([term.i])
    if isinstance(term, Lam):
        return enc(term.body) + bytes([FE])
    if isinstance(term, App):
        return enc(term.f) + enc(term.x) + bytes([FD])
    raise TypeError


def sh(term, delta, cutoff=0):
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(sh(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(sh(term.f, delta, cutoff), sh(term.x, delta, cutoff))
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
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    return stack[0] if len(stack) == 1 else None


nil = Lam(Lam(Var(0)))
QD = parse_term(QD_BYTES + bytes([FF]))

# Syscall globals
ECHO = 14
SYS8 = 8
WRITE = 2
QUOTE = 4
ERRORSTR = 1


def send_raw(payload_bytes, timeout_s=8.0):
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload_bytes)
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
        return f"ERROR:{e}".encode()


def run_test(label, term, timeout_s=8.0):
    try:
        payload = enc(term) + bytes([FF])
    except ValueError as e:
        print(f"  [ENC_ERROR] {label}: {e}")
        return "ENC_ERROR"

    if len(payload) > 2000:
        print(f"  [TOO_BIG ] {label}: {len(payload)} bytes")
        return "TOO_BIG"

    print(f"  Sending {label} ({len(payload)}B)...", end=" ", flush=True)
    time.sleep(DELAY)
    resp = send_raw(payload, timeout_s)

    if not resp:
        print("EMPTY")
        return "EMPTY"
    if resp.startswith(b"ERROR:"):
        print(f"{resp.decode()}")
        return "ERROR"
    if b"Invalid term" in resp:
        print("INVALID")
        return "INVALID"

    resp_hex = resp.hex()
    print(f"hex={resp_hex[:80]}")

    # Try to decode as Either
    term_parsed = parse_term(resp)
    if term_parsed:
        if isinstance(term_parsed, Lam) and isinstance(term_parsed.body, Lam):
            body = term_parsed.body.body
            if isinstance(body, App) and isinstance(body.f, Var):
                if body.f.i == 0:
                    print(f"    → Right(...)")
                elif body.f.i == 1:
                    print(f"    → Left(...)")

    return resp_hex


def main():
    print("=" * 72)
    print("probe_var255.py — Creating Var(255) = 0xFF via double echo")
    print("=" * 72)
    print()

    # ===== TEST 1: Double echo to create Var(255) =====
    # echo(g(251)) → Left(Var(253))
    # Unwrap Left → Var(253)
    # echo(Var(253)) → Left(Var(255))
    # Unwrap Left → Var(255)
    # Feed Var(255) to sys8
    #
    # CPS chain:
    # echo(g(251))(λr1.                          # depth 1: r1=V0
    #   r1(λp1.                                   # depth 2: p1=V0 = Var(253) at runtime
    #     echo(p1)(λr2.                           # depth 3: r2=V0, echo=V(14+3)=V17, p1=V1
    #       r2(λp2.                               # depth 4: p2=V0 = Var(255) at runtime!
    #         sys8(p2)(QD_s4)                     # depth 4: sys8=V(8+4)=V12
    #       )(λe. nil_s4)                         # depth 4
    #     )
    #   )(λe. nil_s2)                             # depth 2
    # )

    print("--- TEST 1: echo(g251)→unwrap→echo(V253)→unwrap→sys8(V255)(QD) ---")

    qd_s4 = sh(QD, 4)
    nil_s4 = sh(nil, 4)
    nil_s2 = sh(nil, 2)

    # Inner: λp2. sys8(p2)(QD_s4) — depth 4
    inner_left = Lam(App(App(Var(12), Var(0)), qd_s4))  # sys8=V(8+4)=V12
    # Inner: λe. nil_s4 — depth 4
    inner_right = Lam(nil_s4)
    # λr2. r2(inner_left)(inner_right) — depth 3
    inner_cont = Lam(App(App(Var(0), inner_left), inner_right))
    # λp1. echo(p1)(inner_cont) — depth 2, echo=V(14+2)=V16, p1=V0
    outer_left = Lam(App(App(Var(16), Var(0)), inner_cont))
    # λe. nil_s2 — depth 2
    outer_right = Lam(nil_s2)
    # λr1. r1(outer_left)(outer_right) — depth 1
    cont = Lam(App(App(Var(0), outer_left), outer_right))
    # echo(g(251))(cont) — depth 0
    test1 = App(App(Var(ECHO), Var(251)), cont)

    run_test("T1: double_echo→sys8(V255)", test1)
    print()

    # ===== TEST 2: Same but with write observer instead of QD =====
    print("--- TEST 2: echo→echo→sys8(V255)→errorString→write ---")

    # depth 4: λp2. sys8(p2)(λres. res(λleft. write(left)(λ_. nil))(λerr. errorStr(err)(λesr. esr(λes. write(es)(λ_. nil))(λ_. nil))))
    # This is complex. Let's simplify: just use write(quote(result)) as observer

    # depth 4: λp2. sys8(p2)(λres. write(quote(res))(λ_. nil))
    # Under 5 lambdas from depth 4:
    # sys8 = V(8+4) = V12
    # Under λres (depth 5): res=V0, quote=V(4+5)=V9, write=V(2+5)=V7
    # Under λ_ (depth 6): nil shifted by 6
    nil_s6 = sh(nil, 6)
    write_done = Lam(nil_s6)  # λ_. nil at depth 6
    # λres. quote(res)(λqr. qr(λbytes. write(bytes)(write_done))(λ_. nil))
    # Actually simpler: λres. write(quote(res)) — but quote returns Either...
    # Let's just use QD shifted

    # Actually, let's try a simpler approach: just observe with QD
    # But also try with a longer timeout in case it hangs

    print("  (Using longer timeout=15s in case of freeze)")
    run_test("T2: double_echo→sys8(V255) [15s timeout]", test1, timeout_s=15.0)
    print()

    # ===== TEST 3: Create Var(255) and just return it (no sys8) =====
    print("--- TEST 3: echo→echo→extract V255 (no sys8, just observe) ---")

    # echo(g(251))(λr1. r1(λp1. echo(p1)(λr2. r2(λp2. write(quote(p2)))(λe. nil)))(λe. nil))
    # But quote(Var(255)) will fail with "Encoding failed!" since 255=0xFF
    # Let's try anyway

    # depth 4: λp2. quote(p2)(λqr. qr(λbytes. write(bytes)(λ_. nil))(λ_. nil))
    # quote = V(4+4) = V8
    nil_s5 = sh(nil, 5)
    nil_s6 = sh(nil, 6)
    nil_s7 = sh(nil, 7)

    # depth 7: λ_. nil
    d7_done = Lam(nil_s7)
    # depth 6: λbytes. write(bytes)(d7_done), write=V(2+6)=V8
    d6_write = Lam(App(App(Var(8), Var(0)), d7_done))
    # depth 6: λ_. nil
    d6_nil = Lam(nil_s6)
    # depth 5: λqr. qr(d6_write)(d6_nil)
    d5_dispatch = Lam(App(App(Var(0), d6_write), d6_nil))
    # depth 4: λp2. quote(p2)(d5_dispatch), quote=V(4+4)=V8
    d4_quote_p2 = Lam(App(App(Var(8), Var(0)), d5_dispatch))
    # depth 4: λe. nil
    d4_nil = Lam(nil_s4)
    # depth 3: λr2. r2(d4_quote_p2)(d4_nil)
    d3_dispatch = Lam(App(App(Var(0), d4_quote_p2), d4_nil))
    # depth 2: λp1. echo(p1)(d3_dispatch), echo=V(14+2)=V16
    d2_echo_p1 = Lam(App(App(Var(16), Var(0)), d3_dispatch))
    # depth 2: λe. nil
    d2_nil = Lam(nil_s2)
    # depth 1: λr1. r1(d2_echo_p1)(d2_nil)
    d1_dispatch = Lam(App(App(Var(0), d2_echo_p1), d2_nil))
    # depth 0: echo(g(251))(d1_dispatch)
    test3 = App(App(Var(ECHO), Var(251)), d1_dispatch)

    run_test("T3: double_echo→quote(V255)→write", test3)
    print()

    # ===== TEST 4: Create Var(254) via double echo and feed to sys8 =====
    print("--- TEST 4: echo(g250)→echo→sys8(V254) ---")

    # echo(g(250)) → Left(Var(252))
    # echo(Var(252)) → Left(Var(254))
    # sys8(Var(254))

    # Same structure as test1 but with g(250) instead of g(251)
    inner_left4 = Lam(App(App(Var(12), Var(0)), qd_s4))
    inner_right4 = Lam(nil_s4)
    inner_cont4 = Lam(App(App(Var(0), inner_left4), inner_right4))
    outer_left4 = Lam(App(App(Var(16), Var(0)), inner_cont4))
    outer_right4 = Lam(nil_s2)
    cont4 = Lam(App(App(Var(0), outer_left4), outer_right4))
    test4 = App(App(Var(ECHO), Var(250)), cont4)

    run_test("T4: double_echo(g250)→sys8(V254)", test4)
    print()

    # ===== TEST 5: Triple echo to create Var(255) from g(249) =====
    print("--- TEST 5: triple echo(g249)→V251→V253→V255→sys8 ---")

    # echo(g(249)) → Left(Var(251))
    # echo(Var(251)) → Left(Var(253))
    # echo(Var(253)) → Left(Var(255))
    # sys8(Var(255))

    qd_s6 = sh(QD, 6)
    nil_s6_t = sh(nil, 6)
    nil_s4_t = sh(nil, 4)
    nil_s2_t = sh(nil, 2)

    # Innermost (depth 6): λp3. sys8(p3)(QD_s6), sys8=V(8+6)=V14
    d6_sys8 = Lam(App(App(Var(14), Var(0)), qd_s6))
    d6_nil = Lam(nil_s6_t)
    # depth 5: λr3. r3(d6_sys8)(d6_nil)
    d5_r3 = Lam(App(App(Var(0), d6_sys8), d6_nil))
    # depth 4: λp2. echo(p2)(d5_r3), echo=V(14+4)=V18
    d4_echo = Lam(App(App(Var(18), Var(0)), d5_r3))
    d4_nil = Lam(nil_s4_t)
    # depth 3: λr2. r2(d4_echo)(d4_nil)
    d3_r2 = Lam(App(App(Var(0), d4_echo), d4_nil))
    # depth 2: λp1. echo(p1)(d3_r2), echo=V(14+2)=V16
    d2_echo = Lam(App(App(Var(16), Var(0)), d3_r2))
    d2_nil = Lam(nil_s2_t)
    # depth 1: λr1. r1(d2_echo)(d2_nil)
    d1_r1 = Lam(App(App(Var(0), d2_echo), d2_nil))
    # depth 0: echo(g(249))(d1_r1)
    test5 = App(App(Var(ECHO), Var(249)), d1_r1)

    run_test("T5: triple_echo(g249)→sys8(V255)", test5, timeout_s=15.0)
    print()

    # ===== TEST 6: Var(255) applied to sys8 (reversed) =====
    print("--- TEST 6: V255(sys8)(QD) — Var(255) in function position ---")

    # echo(g(251))→unwrap→echo(V253)→unwrap→V255
    # Then: V255(sys8)(QD) — apply V255 as a function

    # depth 4: λp2. p2(sys8_s4)(QD_s4)
    # p2=V0, sys8=V(8+4)=V12
    d4_apply = Lam(App(App(Var(0), Var(12)), qd_s4))
    d4_nil_t6 = Lam(nil_s4)
    d3_r2_t6 = Lam(App(App(Var(0), d4_apply), d4_nil_t6))
    d2_echo_t6 = Lam(App(App(Var(16), Var(0)), d3_r2_t6))
    d2_nil_t6 = Lam(nil_s2)
    d1_r1_t6 = Lam(App(App(Var(0), d2_echo_t6), d2_nil_t6))
    test6 = App(App(Var(ECHO), Var(251)), d1_r1_t6)

    run_test("T6: V255(sys8)(QD) — V255 as function", test6, timeout_s=15.0)
    print()

    # ===== TEST 7: Just create Var(255) and apply to nil =====
    print("--- TEST 7: V255(nil)(QD) — see what V255 does ---")

    # depth 4: λp2. p2(nil_s4)(QD_s4)
    d4_apply7 = Lam(App(App(Var(0), nil_s4), qd_s4))
    d4_nil7 = Lam(nil_s4)
    d3_r2_7 = Lam(App(App(Var(0), d4_apply7), d4_nil7))
    d2_echo_7 = Lam(App(App(Var(16), Var(0)), d3_r2_7))
    d2_nil_7 = Lam(nil_s2)
    d1_r1_7 = Lam(App(App(Var(0), d2_echo_7), d2_nil_7))
    test7 = App(App(Var(ECHO), Var(251)), d1_r1_7)

    run_test("T7: V255(nil)(QD) — V255 applied to nil", test7, timeout_s=15.0)
    print()

    # ===== TEST 8: Var(253) applied to sys8 (without second echo) =====
    print("--- TEST 8: V253(sys8)(QD) — Var(253)=FD as function ---")

    # echo(g(251))→unwrap→V253(sys8)(QD)
    # depth 2: λp1. p1(sys8_s2)(QD_s2)
    qd_s2 = sh(QD, 2)
    d2_apply8 = Lam(App(App(Var(0), Var(10)), qd_s2))  # sys8=V(8+2)=V10
    d2_nil_8 = Lam(nil_s2)
    d1_r1_8 = Lam(App(App(Var(0), d2_apply8), d2_nil_8))
    test8 = App(App(Var(ECHO), Var(251)), d1_r1_8)

    run_test("T8: V253(sys8)(QD) — V253 as function", test8, timeout_s=15.0)
    print()

    # ===== TEST 9: Var(253) applied to nil =====
    print("--- TEST 9: V253(nil)(QD) — see what V253 does ---")

    d2_apply9 = Lam(App(App(Var(0), nil_s2), qd_s2))
    d2_nil_9 = Lam(nil_s2)
    d1_r1_9 = Lam(App(App(Var(0), d2_apply9), d2_nil_9))
    test9 = App(App(Var(ECHO), Var(251)), d1_r1_9)

    run_test("T9: V253(nil)(QD) — V253 applied to nil", test9, timeout_s=15.0)
    print()

    # ===== TEST 10: What if Var(253) IS a global? =====
    # If the VM has globals beyond 252, Var(253) might be a hidden syscall!
    # echo(g(251)) creates Var(253) at runtime
    # If Var(253) is a global, then V253(nil)(QD) would invoke it
    print("--- TEST 10: V253 as potential hidden global (already tested in T9) ---")
    print("  (See T9 result above)")
    print()

    print("=" * 72)
    print("DONE")
    print("=" * 72)


if __name__ == "__main__":
    main()
