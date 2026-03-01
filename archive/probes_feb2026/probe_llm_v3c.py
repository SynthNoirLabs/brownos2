#!/usr/bin/env python3
"""
Test LLM v3c proposals + verify Right(3) string length threshold.
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


def encode_term(t):
    if isinstance(t, Var):
        assert t.i <= 0xFC, f"Var({t.i}) too large"
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


def query(payload, timeout_s=5.0):
    for attempt in range(3):
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
            if attempt < 2:
                time.sleep(0.3 * (attempt + 1))
            else:
                return b""
    return b""


def classify(data):
    if len(data) == 0:
        return "EMPTY"
    try:
        text = data.decode("ascii")
        if "Invalid term" in text:
            return "INVALID_TERM"
        if "Term too big" in text:
            return "TERM_TOO_BIG"
        if "Encoding failed" in text:
            return "ENCODING_FAILED"
        return f"TEXT:{text!r}"
    except:
        pass
    h = data.hex()
    if "00030200fdfd" in h:
        return "RIGHT(6)"
    if "00020100fdfd" in h:
        return "RIGHT(3)"
    if "000200fdfd" in h:
        return "RIGHT(2)"
    if "00010000fdfd" in h:
        return "RIGHT(1)"
    if "0100fdfefefefefefefefefefd" in h:
        return "RIGHT(0)"
    return f"OTHER:{h[:60]}... [{len(data)}b]"


def cps(sc, arg):
    return bytes([sc]) + encode_term(arg) + bytes([FD]) + QD + bytes([FD, FF])


def test(name, payload):
    time.sleep(0.35)
    r = query(payload)
    c = classify(r)
    mark = " ***" if "OTHER" in c or "TEXT" in c else ""
    print(f"  {name}: {c}{mark}")
    if "OTHER" in c:
        print(f"    raw: {r[:40].hex()}")
    return c


def main():
    print("=" * 70)
    print("TEST 1: Find exact Right(3) threshold — string length boundary")
    print("=" * 70)

    for length in range(1, 10):
        data = bytes([65] * length)  # "AAA..." strings
        label = f"sys8('{chr(65)}'*{length})"
        test(label, cps(0x08, encode_bytes_list(data)))

    print()
    print("  Now test 3-char strings with varied content:")
    for s in [b"abc", b"\x00\x00\x00", b"\x01\x02\x03", b"AAA", b"sh\x00"]:
        test(f"sys8({s!r})", cps(0x08, encode_bytes_list(s)))

    print()
    print("=" * 70)
    print("TEST 2: LLM Probe 1 — bytecode password '\\x00\\xFE\\xFE'")
    print("=" * 70)

    test(
        "sys8('\\x00\\xFE\\xFE') [nil bytecode as string]",
        cps(0x08, encode_bytes_list(b"\x00\xfe\xfe")),
    )
    test(
        "sys8('\\x00\\xFD\\xFE') [mixed markers]",
        cps(0x08, encode_bytes_list(b"\x00\xfd\xfe")),
    )
    test(
        "sys8('\\xFD\\xFE\\xFF') [all markers]",
        cps(0x08, encode_bytes_list(b"\xfd\xfe\xff")),
    )

    print()
    print("=" * 70)
    print("TEST 3: LLM Probe 2 — write/error_string with list of raw primitives")
    print("=" * 70)

    # sys2(cons(g(8), nil)) — write iterates list, hits non-9-lambda element
    test(
        "sys2(cons(Var(8), nil))  [write list with raw primitive]",
        cps(0x02, cons(Var(8), nil)),
    )

    # sys2(cons(g(201), nil))
    test("sys2(cons(Var(201), nil))", cps(0x02, cons(Var(201), nil)))

    # sys7(cons(g(8), nil)) — readfile with list arg
    test("sys7(cons(Var(8), nil))  [readfile with list]", cps(0x07, cons(Var(8), nil)))

    print()
    print("=" * 70)
    print("TEST 4: Church numeral correction")
    print("  NOTE: BrownOS int(3) = λ^9.(V2(V1(V0))) is NOT Church 3!")
    print("  Church 3 = λf.λx.f(f(f(x))) — only 2 lambdas")
    print("=" * 70)

    # Actual Church numeral 3: λf.λx. f(f(f(x)))
    church3 = Lam(Lam(App(Var(1), App(Var(1), App(Var(1), Var(0))))))

    # church3(sys8)(nil) = sys8(sys8(sys8(nil)))
    # Under 2 lambdas of church3: sys8 = Var(10), nil shifts too
    # After beta reduction: sys8(sys8(sys8(nil)))
    # This is a dynamically constructed nested call
    # We need: ((church3 sys8) nil) then QD
    # = App(App(church3, Var(8)), nil) applied to QD
    inner = App(App(church3, Var(8)), nil)
    test(
        "church3(sys8)(nil)(QD) = sys8(sys8(sys8(nil)))",
        encode_term(inner) + bytes([FD]) + QD + bytes([FD, FF]),
    )

    # Also test: church3 applied to echo
    inner2 = App(App(church3, Var(14)), nil)
    test(
        "church3(echo)(nil)(QD) = echo(echo(echo(nil)))",
        encode_term(inner2) + bytes([FD]) + QD + bytes([FD, FF]),
    )

    # BrownOS int(3) applied to sys8 — to show it's different
    # int(3)(sys8) = partially applied 8-lambda term (9 - 1 = 8 lambdas left)
    int3 = encode_byte_term(3)
    test(
        "brownos_int3(sys8)(QD) [NOT church — 9 lambdas]",
        encode_term(App(int3, Var(8))) + bytes([FD]) + QD + bytes([FD, FF]),
    )

    print()
    print("=" * 70)
    print("TEST 5: Misc novel attempts")
    print("=" * 70)

    # The string "BrownOS" — mentioned by LLM earlier
    test("sys8('BrownOS')", cps(0x08, encode_bytes_list(b"BrownOS")))

    # The string "dloser" — author username
    test("sys8('dloser')", cps(0x08, encode_bytes_list(b"dloser")))

    # Empty string (nil directly, not cons wrapped)
    test("sys8(nil) [direct nil, not byte list]", cps(0x08, nil))

    print()
    print("Done.")


if __name__ == "__main__":
    main()
