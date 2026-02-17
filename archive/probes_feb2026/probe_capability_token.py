#!/usr/bin/env python3
"""
probe_capability_token.py — Test echo→sys8 direct application patterns.

Tests patterns that have NOT been tested before:
- echo(g(N))(sys8)(QD/nil) — direct application of echo result to sys8
- sys8(echo(g(N)))(QD) — sys8 with echo result as argument
- sys8(nil)(echo(g(N))) — echo result as continuation
- Zero-arg and partial application of sys8
- 3-leaf minimal programs with echo
- Backdoor + echo + sys8 combinations
"""

import socket
import sys
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221
FD, FE, FF = 0xFD, 0xFE, 0xFF
QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
DELAY = 0.45


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
            stack.append(Lam(stack.pop()))
        else:
            stack.append(Var(b))
    return stack[0] if len(stack) == 1 else None


nil = Lam(Lam(Var(0)))
QD = parse_term(QD_BYTES + bytes([FF]))

# Known Right(6) and Right(1) QD output hex
RIGHT6_HEX = "00030200fdfdfefefefefefefefefefdfefeff"
RIGHT1_HEX = "000100fdfefefefefefefefefefdfefeff"
RIGHT2_HEX = "000200fdfefefefefefefefefefdfefeff"


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


def run_test(label, payload_bytes, timeout_s=8.0):
    if len(payload_bytes) > 2000:
        print(f"  [{label}] TOO_BIG: {len(payload_bytes)} bytes")
        return "TOO_BIG"
    hex_preview = payload_bytes.hex()[:60]
    print(
        f"  [{label}] ({len(payload_bytes)}B, bc={hex_preview})...", end=" ", flush=True
    )
    time.sleep(DELAY)
    resp = send_raw(payload_bytes, timeout_s)
    if not resp:
        print("EMPTY")
        return "EMPTY"
    if resp.startswith(b"ERROR:"):
        print(resp.decode())
        return "ERROR"
    if b"Invalid term" in resp:
        print("INVALID_TERM")
        return "INVALID"
    if b"Term too big" in resp:
        print("TERM_TOO_BIG")
        return "TERM_TOO_BIG"
    resp_hex = resp.hex()
    if resp_hex == RIGHT6_HEX:
        print("Right(6) = PermDenied")
        return "RIGHT6"
    if resp_hex == RIGHT1_HEX:
        print("Right(1) = NotImpl")
        return "RIGHT1"
    if resp_hex == RIGHT2_HEX:
        print("Right(2) = InvalidArg")
        return "RIGHT2"
    # Anything else is potentially interesting!
    print(f"*** INTERESTING *** hex={resp_hex[:120]}")
    t = parse_term(resp)
    if t:
        print(f"    Parsed: {t}")
    return resp_hex


def run_test_term(label, term, timeout_s=8.0):
    try:
        payload = enc(term) + bytes([FF])
    except ValueError as e:
        print(f"  [{label}] ENC_ERROR: {e}")
        return "ENC_ERROR"
    return run_test(label, payload, timeout_s)


results = {}


def test(label, payload_or_term, timeout_s=8.0):
    if isinstance(payload_or_term, bytes):
        r = run_test(label, payload_or_term, timeout_s)
    else:
        r = run_test_term(label, payload_or_term, timeout_s)
    results[label] = r
    return r


def main():
    print("=" * 72)
    print("probe_capability_token.py — Echo→Sys8 Direct Application Patterns")
    print("=" * 72)
    print()

    # ===== CATEGORY A: Direct application of echo result to sys8 =====
    print("=== CATEGORY A: echo(g(N))(sys8)(QD/nil) — direct application ===")
    print("  echo(g(N)) returns Left(g(N)) = λl.λr.l(g(N))")
    print("  Applied to sys8: Left(g(N))(sys8)(QD) → sys8(g(N))(QD)")
    print("  But lazy evaluation might change behavior!")
    print()

    # A1: echo(g(251))(sys8)(QD)
    a1 = bytes([0x0E, 0xFB, FD, 0x08, FD]) + QD_BYTES + bytes([FD, FF])
    test("A1:echo(g251)(sys8)(QD)", a1)

    # A2: echo(g(252))(sys8)(QD)
    a2 = bytes([0x0E, 0xFC, FD, 0x08, FD]) + QD_BYTES + bytes([FD, FF])
    test("A2:echo(g252)(sys8)(QD)", a2)

    # A3: echo(g(251))(sys8)(nil) — THE 3-LEAF TEST
    a3 = bytes([0x0E, 0xFB, FD, 0x08, FD, 0x00, FE, FE, FD, FF])
    test("A3:echo(g251)(sys8)(nil) [3-LEAF]", a3)

    # A4: echo(g(252))(sys8)(nil)
    a4 = bytes([0x0E, 0xFC, FD, 0x08, FD, 0x00, FE, FE, FD, FF])
    test("A4:echo(g252)(sys8)(nil) [3-LEAF]", a4)

    # A5-A7: Control tests with lower globals
    for n, label in [(0xFA, "250"), (0xF9, "249"), (0xF8, "248")]:
        bc = bytes([0x0E, n, FD, 0x08, FD]) + QD_BYTES + bytes([FD, FF])
        test(f"A{5 + 0xFA - n}:echo(g{label})(sys8)(QD)", bc)

    # A8: echo(nil)(sys8)(QD) — control with nil
    a8 = bytes([0x0E, 0x00, FE, FE, FD, 0x08, FD]) + QD_BYTES + bytes([FD, FF])
    test("A8:echo(nil)(sys8)(QD)", a8)

    print()

    # ===== CATEGORY B: sys8(echo(g(N)))(QD) =====
    print("=== CATEGORY B: sys8(echo(g(N)))(QD) — echo result as sys8 arg ===")
    print()

    # B1: sys8(echo(g(251)))(QD)
    b1 = bytes([0x08, 0x0E, 0xFB, FD, FD]) + QD_BYTES + bytes([FD, FF])
    test("B1:sys8(echo(g251))(QD)", b1)

    # B2: sys8(echo(g(252)))(QD)
    b2 = bytes([0x08, 0x0E, 0xFC, FD, FD]) + QD_BYTES + bytes([FD, FF])
    test("B2:sys8(echo(g252))(QD)", b2)

    # B3: sys8(echo(nil))(QD) — control
    b3 = bytes([0x08, 0x0E, 0x00, FE, FE, FD, FD]) + QD_BYTES + bytes([FD, FF])
    test("B3:sys8(echo(nil))(QD)", b3)

    print()

    # ===== CATEGORY C: Echo result as sys8 continuation =====
    print("=== CATEGORY C: sys8(nil)(echo(g(N))) — echo as continuation ===")
    print()

    # C1: sys8(nil)(echo(g(251)))
    c1 = bytes([0x08, 0x00, FE, FE, FD, 0x0E, 0xFB, FD, FD, FF])
    test("C1:sys8(nil)(echo(g251))", c1)

    # C2: sys8(nil)(echo(g(252)))
    c2 = bytes([0x08, 0x00, FE, FE, FD, 0x0E, 0xFC, FD, FD, FF])
    test("C2:sys8(nil)(echo(g252))", c2)

    # C3: sys8(g(251))(echo(g(252)))
    c3 = bytes([0x08, 0xFB, FD, 0x0E, 0xFC, FD, FD, FF])
    test("C3:sys8(g251)(echo(g252))", c3)

    print()

    # ===== CATEGORY D: Zero-arg and partial application =====
    print("=== CATEGORY D: Zero-arg and partial application of sys8 ===")
    print()

    # D1: sys8 alone (just Var(8))
    test("D1:sys8_alone", bytes([0x08, FF]))

    # D2: sys8(sys8) — self-application
    test("D2:sys8(sys8)", bytes([0x08, 0x08, FD, FF]))

    # D3: sys8(echo)
    test("D3:sys8(echo)", bytes([0x08, 0x0E, FD, FF]))

    # D4: sys8(backdoor)
    test("D4:sys8(backdoor)", bytes([0x08, 0xC9, FD, FF]))

    # D5: sys8(sys8)(QD)
    d5 = bytes([0x08, 0x08, FD]) + QD_BYTES + bytes([FD, FF])
    test("D5:sys8(sys8)(QD)", d5)

    # D6: sys8(echo)(QD)
    d6 = bytes([0x08, 0x0E, FD]) + QD_BYTES + bytes([FD, FF])
    test("D6:sys8(echo)(QD)", d6)

    # D7: sys8(backdoor)(QD)
    d7 = bytes([0x08, 0xC9, FD]) + QD_BYTES + bytes([FD, FF])
    test("D7:sys8(backdoor)(QD)", d7)

    print()

    # ===== CATEGORY E: 3-leaf minimal programs with echo =====
    print("=== CATEGORY E: 3-leaf minimal programs ===")
    print()

    # E1: echo(sys8)(nil)
    test("E1:echo(sys8)(nil)", bytes([0x0E, 0x08, FD, 0x00, FE, FE, FD, FF]))

    # E2: echo(sys8)(QD)
    e2 = bytes([0x0E, 0x08, FD]) + QD_BYTES + bytes([FD, FF])
    test("E2:echo(sys8)(QD)", e2)

    # E3: sys8(echo)(nil)
    test("E3:sys8(echo)(nil)", bytes([0x08, 0x0E, FD, 0x00, FE, FE, FD, FF]))

    # E4: echo(g(251))(echo)(QD) — echo result applied to echo again
    e4 = bytes([0x0E, 0xFB, FD, 0x0E, FD]) + QD_BYTES + bytes([FD, FF])
    test("E4:echo(g251)(echo)(QD)", e4)

    # E5: echo(g(251))(backdoor)(QD)
    e5 = bytes([0x0E, 0xFB, FD, 0xC9, FD]) + QD_BYTES + bytes([FD, FF])
    test("E5:echo(g251)(backdoor)(QD)", e5)

    # E6: echo(g(251))(quote)(QD) — echo result applied to quote
    e6 = bytes([0x0E, 0xFB, FD, 0x04, FD]) + QD_BYTES + bytes([FD, FF])
    test("E6:echo(g251)(quote)(QD)", e6)

    print()

    # ===== CATEGORY F: Backdoor + echo + sys8 =====
    print("=== CATEGORY F: Backdoor + echo + sys8 combinations ===")
    print()

    # F1: backdoor(nil)(sys8) — backdoor result directly to sys8
    test("F1:backdoor(nil)(sys8)", bytes([0xC9, 0x00, FE, FE, FD, 0x08, FD, FF]))

    # F2: backdoor(nil)(echo) — backdoor result to echo
    test("F2:backdoor(nil)(echo)", bytes([0xC9, 0x00, FE, FE, FD, 0x0E, FD, FF]))

    # F3: echo(backdoor(nil))(sys8)(QD) — echo the backdoor result, apply to sys8
    f3 = (
        bytes([0x0E, 0xC9, 0x00, FE, FE, FD, FD, 0x08, FD]) + QD_BYTES + bytes([FD, FF])
    )
    test("F3:echo(bd(nil))(sys8)(QD)", f3)

    # F4: sys8(backdoor(nil))(QD) — sys8 with backdoor result as arg
    f4 = bytes([0x08, 0xC9, 0x00, FE, FE, FD, FD]) + QD_BYTES + bytes([FD, FF])
    test("F4:sys8(bd(nil))(QD)", f4)

    # F5: backdoor(nil)(λpair. sys8(pair)(QD_s1))
    qd_s1 = sh(QD, 1)
    f5_inner = Lam(App(App(Var(9), Var(0)), qd_s1))  # sys8=V(8+1)=V9
    f5 = App(App(Var(201), nil), f5_inner)
    test("F5:bd(nil)(λp.sys8(p)(QD))", f5)

    # F6: backdoor(nil)(λpair. echo(pair)(sys8_s1)(QD_s1))
    # Under λpair: echo=V(14+1)=V15, sys8=V(8+1)=V9
    f6_inner = Lam(App(App(App(Var(15), Var(0)), Var(9)), qd_s1))
    f6 = App(App(Var(201), nil), f6_inner)
    test("F6:bd(nil)(λp.echo(p)(sys8)(QD))", f6)

    # F7: backdoor(nil)(λpair. pair(sys8_s1)(nil_s1))
    # Under λpair: pair=V0, sys8=V9, nil shifted by 1
    nil_s1 = sh(nil, 1)
    f7_inner = Lam(App(App(Var(0), Var(9)), nil_s1))
    f7 = App(App(Var(201), nil), f7_inner)
    test("F7:bd(nil)(λp.p(sys8)(nil))", f7)

    print()

    # ===== CATEGORY G: Systematic sweep of echo(g(N))(sys8)(QD) for ALL N =====
    print("=== CATEGORY G: Sweep echo(g(N))(sys8)(QD) for N=0..252 ===")
    print("  (Testing every global through echo→sys8 pipeline)")
    print()

    interesting_g = []
    for n in range(253):
        bc = bytes([0x0E, n, FD, 0x08, FD]) + QD_BYTES + bytes([FD, FF])
        label = f"G:echo(g{n})(sys8)(QD)"
        r = run_test(label, bc)
        results[label] = r
        if r not in ("RIGHT6", "EMPTY", "RIGHT1", "RIGHT2", "ERROR"):
            interesting_g.append((n, r))

    if interesting_g:
        print(f"\n  *** INTERESTING GLOBALS: {interesting_g} ***")
    else:
        print(f"\n  All 253 globals: standard results only")

    print()

    # ===== SUMMARY =====
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)

    breakthroughs = []
    for label, r in results.items():
        if r not in (
            "RIGHT6",
            "RIGHT1",
            "RIGHT2",
            "EMPTY",
            "ERROR",
            "INVALID",
            "TOO_BIG",
            "ENC_ERROR",
            "TERM_TOO_BIG",
        ):
            breakthroughs.append((label, r))

    if breakthroughs:
        print(f"\n*** {len(breakthroughs)} BREAKTHROUGH(S) FOUND! ***")
        for label, r in breakthroughs:
            print(f"  {label}: {r}")
    else:
        print("\nNo breakthroughs. All tests returned standard results.")

    # Count by result type
    from collections import Counter

    counts = Counter(results.values())
    print(f"\nResult distribution:")
    for result_type, count in counts.most_common():
        print(f"  {result_type}: {count}")

    print(f"\nTotal tests: {len(results)}")
    print("=" * 72)


if __name__ == "__main__":
    main()
