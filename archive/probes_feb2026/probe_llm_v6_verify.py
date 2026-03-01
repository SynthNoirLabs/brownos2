#!/usr/bin/env python3
"""
Test LLM v6 proposals:
1. V253 "App instruction" theory — test V253(SAFE_OBS)(nil) vs V253(nil)(SAFE_OBS)
2. "Stack underflow" — V253 evaluated alone
3. De Bruijn down-shift bug — does (λx.λy.x)(g42)(I) return sys42 or sys43?
4. Manual V253 creation via beta reduction (pre-2018 path)
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


def cons(h, t):
    return Lam(Lam(App(App(Var(1), shift(h, 2)), shift(t, 2))))


def encode_byte_term(n):
    expr = Var(0)
    for idx, w in ((1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)):
        if n & w:
            expr = App(Var(idx), expr)
    for _ in range(9):
        expr = Lam(expr)
    return expr


def encode_bytes_list(bs):
    cur = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


def query(payload, timeout_s=8.0):
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
    if "00020100fdfd" in h:
        return "RIGHT(3)"
    if "000200fdfd" in h:
        return "RIGHT(2)"
    if "00010000fdfd" in h:
        return "RIGHT(1)"
    if "0000fdfefefefefefefefefefd" in h:
        return "RIGHT(0)"
    return f"HEX={h[:80]} [{len(r)}b]"


def test(name, payload):
    time.sleep(0.4)
    r = query(payload)
    c = classify(r)
    print(f"  {name}: {c}")
    if "HEX" in c or "OTHER" in c:
        try:
            print(f"    text: {r[:50]!r}")
        except:
            pass
    return c


def main():
    # Safe observer: writes "B" regardless of result
    # Under 1 lambda: write=g2=Var(3)
    marker = encode_bytes_list(b"\x42")
    SAFE_OBS = Lam(App(App(Var(3), shift(marker, 1)), nil))

    print("=" * 70)
    print("PROBE 1: V253 argument ordering")
    print("  LLM claims V253 'executes App instruction' and pops stack")
    print("  Test: V253(SAFE_OBS)(nil) vs V253(nil)(SAFE_OBS)")
    print("=" * 70)

    # echo(251)(λleft. left(λv253. v253(SAFE_OBS↑3)(nil))(λe.nil))
    # Under 3 lambdas (echo handler + left handler + v253 handler):
    # write=g2=Var(5), safe_obs under 3 lams
    safe_s3 = Lam(App(App(Var(6), shift(marker, 4)), nil))

    # λv253. ((v253 SAFE_OBS) nil)
    inner_a = Lam(App(App(Var(0), shift(safe_s3, 1)), nil))
    l_handler_a = Lam(App(App(Var(0), shift(inner_a, 1)), Lam(nil)))
    term_a = App(App(Var(14), Var(251)), l_handler_a)
    test("V253(SAFE_OBS)(nil) [LLM's Probe 1 order]", encode_term(term_a) + bytes([FF]))

    # Already tested: V253(nil)(SAFE_OBS) → EMPTY (from v4 verify)
    # But let's reconfirm
    inner_b = Lam(App(App(Var(0), nil), shift(safe_s3, 1)))
    l_handler_b = Lam(App(App(Var(0), shift(inner_b, 1)), Lam(nil)))
    term_b = App(App(Var(14), Var(251)), l_handler_b)
    test(
        "V253(nil)(SAFE_OBS) [previous order, reconfirm]",
        encode_term(term_b) + bytes([FF]),
    )

    # What about just V253 alone, no arguments?
    inner_c = Lam(Var(0))  # λv253. v253 — just return it
    l_handler_c = Lam(App(App(Var(0), shift(inner_c, 1)), Lam(nil)))
    # Then apply result to SAFE_OBS
    term_c = App(App(App(Var(14), Var(251)), l_handler_c), SAFE_OBS)
    test(
        "extract V253 → apply to SAFE_OBS [V253 as function, 1 arg]",
        encode_term(term_c) + bytes([FF]),
    )

    print()
    print("=" * 70)
    print("PROBE 3: De Bruijn down-shift bug test")
    print("  (λx.λy.x)(g42)(I)(nil)(QD)")
    print("  Correct: g42(nil)(QD) → towel output")
    print("  Buggy (no down-shift): g43(nil)(QD) → Right(1) Not Implemented")
    print("=" * 70)

    # (λx.λy.x) = K combinator = Lam(Lam(Var(1)))
    K = Lam(Lam(Var(1)))

    # K(g42)(I) should reduce to g42
    # Then g42(nil)(QD) should print towel string
    term_k42 = App(
        App(App(App(K, Var(42)), I), nil),
        Lam(App(App(Var(4), App(Var(6), Var(0))), nil)),
    )
    test(
        "K(g42)(I)(nil)(write∘quote) [correct=towel, buggy=NotImpl]",
        encode_term(term_k42) + bytes([FF]),
    )

    # Also test K(g8)(I)(nil)(QD) — should give sys8's Right(6) if shift is correct
    term_k8 = App(App(K, Var(8)), I)
    test(
        "K(g8)(I)(nil)(QD) [correct=Right(6), buggy=Right(1)]",
        encode_term(
            App(App(term_k8, nil), Lam(App(App(Var(4), App(Var(6), Var(0))), nil)))
        )
        + bytes([FF]),
    )

    # Test with higher index near boundary: K(g252)(I)
    # Correct: g252(nil)(QD) → Right(1) Not Implemented
    # Buggy: g253(nil)(QD) → ??? (out of bounds)
    term_k252 = App(App(K, Var(252)), I)
    test(
        "K(g252)(I)(nil)(QD) [correct=Right(1), buggy=OOB g253]",
        encode_term(
            App(App(term_k252, nil), Lam(App(App(Var(4), App(Var(6), Var(0))), nil)))
        )
        + bytes([FF]),
    )

    print()
    print("=" * 70)
    print("PROBE 4: Manual V253 via beta reduction (pre-2018 path)")
    print("  (λx.λl.λr.(l x))(V251) = Left(V253) via shifting")
    print("  Does this work identically to echo(251)?")
    print("=" * 70)

    # Manual Left constructor: λx. λl.λr. (l x)
    # De Bruijn: Lam(Lam(Lam(App(Var(1), Var(2)))))
    manual_left = Lam(Lam(Lam(App(Var(1), Var(2)))))

    # Apply to Var(251): should beta-reduce to Left(Var(253))
    manual_echo_251 = App(manual_left, Var(251))

    # Use QD to observe: should give "Encoding failed!" (same as echo(251)(QD))
    test(
        "manual_Left(V251)(QD) [should = echo(251)(QD)]",
        encode_term(manual_echo_251) + bytes([FD]) + QD + bytes([FD, FF]),
    )

    # Compare with actual echo(251)(QD)
    test(
        "echo(V251)(QD) [control — same expected result]",
        bytes([0x0E, 0xFB, FD]) + QD + bytes([FD, FF]),
    )

    # Use EITHER_OBS instead of QD to see if it's Left
    EITHER_OBS = Lam(
        App(
            App(
                Var(0),
                Lam(App(App(Var(4), shift(encode_bytes_list(b"L"), 2)), nil)),
                Lam(App(App(Var(4), shift(encode_bytes_list(b"R"), 2)), nil)),
            )
        )
    )

    test(
        "manual_Left(V251)(EITHER_OBS) [should print 'L']",
        encode_term(App(manual_echo_251, EITHER_OBS)) + bytes([FF]),
    )

    test(
        "echo(V251)(EITHER_OBS) [control — should also print 'L']",
        encode_term(App(App(Var(14), Var(251)), EITHER_OBS)) + bytes([FF]),
    )

    print()
    print("Done.")


if __name__ == "__main__":
    main()
