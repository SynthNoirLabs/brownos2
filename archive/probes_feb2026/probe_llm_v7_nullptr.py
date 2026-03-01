#!/usr/bin/env python3
"""
Test LLM v7 nullptr bypass theory.
Core idea: beta reduction shifts V252 past 253 boundary, reducer drops it to NULL.
sys8(NULL) might fail open.
"""

from __future__ import annotations
import socket, time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221
FD, FE, FF = 0xFD, 0xFE, 0xFF
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


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


nil = Lam(Lam(Var(0)))
I = Lam(Var(0))


def encode_term(t):
    if isinstance(t, Var):
        assert t.i <= 0xFC, f"Var({t.i}) > 252"
        return bytes([t.i])
    if isinstance(t, Lam):
        return encode_term(t.body) + bytes([FE])
    if isinstance(t, App):
        return encode_term(t.f) + encode_term(t.x) + bytes([FD])
    raise TypeError


def shift(t, n, c=0):
    if isinstance(t, Var):
        return Var(t.i + n) if t.i >= c else t
    if isinstance(t, Lam):
        return Lam(shift(t.body, n, c + 1))
    if isinstance(t, App):
        return App(shift(t.f, n, c), shift(t.x, n, c))
    return t


def encode_bytes_list(bs):
    cur = nil
    for b in reversed(bs):
        expr = Var(0)
        for idx, w in (
            (1, 1),
            (2, 2),
            (3, 4),
            (4, 8),
            (5, 16),
            (6, 32),
            (7, 64),
            (8, 128),
        ):
            if b & w:
                expr = App(Var(idx), expr)
        bt = expr
        for _ in range(9):
            bt = Lam(bt)
        cur = Lam(Lam(App(App(Var(1), shift(bt, 2)), shift(cur, 2))))
    return cur


def query(payload, timeout_s=10.0):
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
                    if FF in chunk:
                        break
                except socket.timeout:
                    break
            return out
    except Exception as e:
        return b"ERR:" + str(e).encode()


def classify(r):
    if len(r) == 0:
        return "EMPTY"
    if r.startswith(b"ERR:"):
        return r.decode()
    h = r.hex()
    try:
        text = r.decode("ascii")
        if "Encoding failed" in text:
            return "ENCODING_FAILED"
        if "Invalid term" in text:
            return "INVALID_TERM"
        return f"TEXT={text!r}"
    except:
        pass
    if "00030200fdfd" in h:
        return "RIGHT(6)"
    if "000200fdfd" in h and "00030200" not in h:
        return "RIGHT(2)"
    if "00010000fdfd" in h:
        return "RIGHT(1)"
    if h.startswith("01") and h.endswith("fefeff"):
        return f"*** LEFT *** hex={h[:80]} [{len(r)}b]"
    if b"\x42" in r[:5] or b"B" in r[:5]:
        return f"*** MARKER 'B' *** hex={h[:40]}"
    if b"L" == r[:1]:
        return f"*** MARKER 'L' *** hex={h[:40]}"
    if b"R" == r[:1]:
        return f"*** MARKER 'R' *** hex={h[:40]}"
    return f"HEX={h[:80]} [{len(r)}b]"


def test(name, payload_bytes):
    time.sleep(0.45)
    r = query(payload_bytes)
    c = classify(r)
    mark = (
        " <<<< BREAKTHROUGH"
        if "LEFT" in c or "MARKER 'B'" in c or "MARKER 'L'" in c
        else ""
    )
    print(f"  {name}: {c}{mark}")
    if "HEX" in c:
        try:
            print(f"    raw: {r[:60]!r}")
        except:
            pass
    return c


def main():
    marker = encode_bytes_list(b"\x42")

    print("=" * 70)
    print("PROBE 1: (λx.λd. sys8(x)(SAFE_OBS)) V252 I")
    print("  V252 shifts +1 under λd → V253 → reducer drops → NULL?")
    print("  If sys8(NULL) fails open → prints 'B'")
    print("=" * 70)

    # func = λx. λdummy. ((sys8 x) SAFE_OBS)
    # Under 2 lambdas: sys8=g8=Var(10), write=g2=Var(4)
    # x=Var(1), dummy=Var(0)
    # SAFE_OBS inside: λresult. write([0x42])(nil) — under 3 total lambdas: write=Var(5)
    safe_inner = Lam(App(App(Var(5), shift(marker, 3)), nil))
    func1 = Lam(Lam(App(App(Var(10), Var(1)), safe_inner)))
    term1 = App(App(func1, Var(252)), I)
    test(
        "(λx.λd.sys8(x)(OBS)) V252 I [PROBE 1: shift +1]",
        encode_term(term1) + bytes([FF]),
    )

    print()
    print("=" * 70)
    print("PROBE 2: (λx.λd1.λd2. sys8(x)(SAFE_OBS)) V251 I I")
    print("  V251 shifts +2 under λd1.λd2 → V253 → NULL?")
    print("=" * 70)

    # Under 3 lambdas: sys8=g8=Var(11), write=g2=Var(5)
    # x=Var(2), d1=Var(1), d2=Var(0)
    safe_inner2 = Lam(App(App(Var(6), shift(marker, 4)), nil))
    func2 = Lam(Lam(Lam(App(App(Var(11), Var(2)), safe_inner2))))
    term2 = App(App(App(func2, Var(251)), I), I)
    test(
        "(λx.λd1.λd2.sys8(x)(OBS)) V251 I I [PROBE 2: shift +2]",
        encode_term(term2) + bytes([FF]),
    )

    print()
    print("=" * 70)
    print("PROBE 3: Same pattern but with sys1 (error_string) instead of sys8")
    print("  If shift-drop gives NULL: sys1(NULL)(OBS) → Right(2)? EMPTY? Other?")
    print("=" * 70)

    # sys1=g1=Var(3) under 2 lambdas
    safe_inner3 = Lam(App(App(Var(5), shift(marker, 3)), nil))
    func3 = Lam(Lam(App(App(Var(3), Var(1)), safe_inner3)))
    term3 = App(App(func3, Var(252)), I)
    test(
        "(λx.λd.sys1(x)(OBS)) V252 I [sys1 with shift-dropped arg]",
        encode_term(term3) + bytes([FF]),
    )

    print()
    print("=" * 70)
    print("PROBE 4: Control — same structure but V200 (stays < 253)")
    print("  V200 shifts to V201 under λd — should work normally")
    print("=" * 70)

    safe_inner4 = Lam(App(App(Var(5), shift(marker, 3)), nil))
    func4 = Lam(Lam(App(App(Var(10), Var(1)), safe_inner4)))
    term4 = App(App(func4, Var(200)), I)
    test(
        "(λx.λd.sys8(x)(OBS)) V200 I [CONTROL: no overflow, Right(6)]",
        encode_term(term4) + bytes([FF]),
    )

    # And V250 (shifts to V251, still < 253)
    term4b = App(App(func4, Var(250)), I)
    test(
        "(λx.λd.sys8(x)(OBS)) V250 I [CONTROL: shifts to 251, still valid]",
        encode_term(term4b) + bytes([FF]),
    )

    # V251 (shifts to V252, still < 253)
    term4c = App(App(func4, Var(251)), I)
    test(
        "(λx.λd.sys8(x)(OBS)) V251 I [CONTROL: shifts to 252, boundary]",
        encode_term(term4c) + bytes([FF]),
    )

    print()
    print("=" * 70)
    print("PROBE 5: Broader shift amounts — V250 under 3 lambdas → 253")
    print("=" * 70)

    safe_inner5 = Lam(App(App(Var(6), shift(marker, 4)), nil))
    func5 = Lam(Lam(Lam(App(App(Var(11), Var(2)), safe_inner5))))
    term5 = App(App(App(func5, Var(250)), I), I)
    test(
        "(λx.λd1.λd2.sys8(x)(OBS)) V250 I I [shift +3 → 253]",
        encode_term(term5) + bytes([FF]),
    )

    # V249 under 4 lambdas → 253
    safe_inner6 = Lam(App(App(Var(7), shift(marker, 5)), nil))
    func6 = Lam(Lam(Lam(Lam(App(App(Var(12), Var(3)), safe_inner6)))))
    term6 = App(App(App(App(func6, Var(249)), I), I), I)
    test(
        "(λx.λd1.λd2.λd3.sys8(x)(OBS)) V249 I I I [shift +4 → 253]",
        encode_term(term6) + bytes([FF]),
    )

    print()
    print("=" * 70)
    print("PROBE 6: Use QD instead of SAFE_OBS (for comparison)")
    print("=" * 70)

    shifted_qd_2 = bytes.fromhex("0700fd000700fd05fdfefd04fdfefdfe")
    func7_body = bytes([0x0A, 0x01, FD]) + shifted_qd_2 + bytes([FD, FE, FE])
    term7 = func7_body + bytes([0xFC, FD]) + encode_term(I) + bytes([FD, FF])
    test("(λx.λd.sys8(x)(QD↑2)) V252 I [QD version]", term7)

    print()
    print("Done. Any 'MARKER B' or 'LEFT' = BREAKTHROUGH.")


if __name__ == "__main__":
    main()
