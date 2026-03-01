#!/usr/bin/env python3
"""Fixed v6 probes — correct de Bruijn indices and payload structure."""

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
K = Lam(Lam(Var(1)))


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
        if "choke" in text.lower() or "towel" in text.lower():
            return f"TOWEL={text!r}"
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
    return f"HEX={h[:80]} [{len(r)}b]"


def cps(syscall_byte, arg_term):
    return (
        bytes([syscall_byte])
        + encode_term(arg_term)
        + bytes([FD])
        + QD
        + bytes([FD, FF])
    )


def test(name, payload):
    time.sleep(0.4)
    r = query(payload)
    c = classify(r)
    print(f"  {name}: {c}")
    if "HEX" in c:
        try:
            print(f"    text: {r[:50]!r}")
        except:
            pass
    return c


def main():
    print("=" * 70)
    print("PROBE 3 FIXED: De Bruijn down-shift bug test")
    print("  Use standard CPS: ((K(g42)(I) nil) QD)")
    print("  K(g42)(I) reduces to g42, then g42(nil)(QD) = towel")
    print("=" * 70)

    # K(g42)(I) as the "syscall function" in CPS position
    # ((K(g42)(I)) nil) QD → ((g42) nil) QD → towel output
    k_g42_i = App(App(K, Var(42)), I)
    payload = (
        encode_term(k_g42_i) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    )
    test("((K(g42)(I) nil) QD) [should=towel if shift correct]", payload)

    k_g8_i = App(App(K, Var(8)), I)
    payload2 = (
        encode_term(k_g8_i) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    )
    test("((K(g8)(I) nil) QD) [should=Right(6) if shift correct]", payload2)

    # Boundary test: K(g251)(I) → g251 → then g251(nil)(QD)
    k_g251_i = App(App(K, Var(251)), I)
    payload3 = (
        encode_term(k_g251_i) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    )
    test("((K(g251)(I) nil) QD) [g251→Right(1) if correct]", payload3)

    # Critical: K(g252)(I) → should give g252(nil)(QD)
    k_g252_i = App(App(K, Var(252)), I)
    payload4 = (
        encode_term(k_g252_i) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    )
    test("((K(g252)(I) nil) QD) [g252→Right(1) if correct, OOB if buggy]", payload4)

    # Control: g42(nil)(QD) directly — should print towel
    test("g42(nil)(QD) [direct control — towel]", cps(0x2A, nil))

    # Control: g8(nil)(QD) directly — should print Right(6)
    test("g8(nil)(QD) [direct control — Right(6)]", cps(0x08, nil))

    print()
    print("=" * 70)
    print("PROBE 4 FIXED: Manual Left(V251) via beta reduction")
    print("  manual_left = λx.λl.λr.(l x)")
    print("  Applied to V251 → should equal Left(V253)")
    print("=" * 70)

    manual_left = Lam(Lam(Lam(App(Var(1), Var(2)))))
    manual_echo = App(manual_left, Var(251))

    # Apply to QD: App(manual_echo, QD)
    # Correct: encode_term(manual_echo) + QD + bytes([FD, FF])
    payload5 = encode_term(manual_echo) + QD + bytes([FD, FF])
    test("manual_Left(V251)(QD) [should=ENCODING_FAILED like echo]", payload5)

    # Control: echo(251)(QD)
    payload6 = bytes([0x0E, 0xFB, FD]) + QD + bytes([FD, FF])
    test("echo(V251)(QD) [control]", payload6)

    # Use safe either observer: λr. r(λx.write("L")(nil))(λx.write("R")(nil))
    L_marker = encode_bytes_list(b"L")
    R_marker = encode_bytes_list(b"R")
    either_obs = Lam(
        App(
            App(Var(0), Lam(App(App(Var(4), shift(L_marker, 2)), nil))),
            Lam(App(App(Var(4), shift(R_marker, 2)), nil)),
        )
    )

    payload7 = encode_term(App(manual_echo, either_obs)) + bytes([FF])
    test("manual_Left(V251)(EITHER_OBS) [should print 'L']", payload7)

    payload8 = encode_term(App(App(Var(14), Var(251)), either_obs)) + bytes([FF])
    test("echo(V251)(EITHER_OBS) [control — should print 'L']", payload8)

    print()
    print("Done.")


if __name__ == "__main__":
    main()
