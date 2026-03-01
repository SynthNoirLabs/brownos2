#!/usr/bin/env python3
"""Quick tests for LLM v8 non-CPS proposals."""

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


def cps(sc, arg):
    return bytes([sc]) + encode_term(arg) + bytes([FD]) + QD + bytes([FD, FF])


def test(name, payload):
    time.sleep(0.4)
    r = query(payload)
    if len(r) == 0:
        print(f"  {name}: EMPTY")
    else:
        h = r.hex()
        try:
            text = r.decode("ascii")
            print(f"  {name}: TEXT={text!r}")
            return
        except:
            pass
        if "00030200fdfd" in h:
            print(f"  {name}: RIGHT(6)")
        elif "00020100fdfd" in h:
            print(f"  {name}: RIGHT(3)")
        elif "000200fdfd" in h:
            print(f"  {name}: RIGHT(2)")
        elif "00010000fdfd" in h:
            print(f"  {name}: RIGHT(1)")
        elif h.startswith("01"):
            print(f"  {name}: LEFT response! hex={h[:80]} [{len(r)}b]")
            try:
                from solve_brownos_answer import (
                    parse_term as pt,
                    decode_either,
                    decode_bytes_list,
                )

                term = pt(r)
                tag, payload_t = decode_either(term)
                if tag == "Left":
                    bs = decode_bytes_list(payload_t)
                    print(f"    *** DECODED: {bs!r} ***")
            except Exception as e:
                print(f"    decode error: {e}")
        else:
            print(f"  {name}: HEX={h[:80]} [{len(r)}b]")
            print(f"    raw: {r[:50]!r}")


def main():
    int8 = encode_byte_term(8)

    print("=" * 70)
    print("PROBE 1: error_string(int(8)) — error code 8")
    print("  Known codes: 0=Exception 1=NotImpl 2=InvalidArg 3=NoSuchFile")
    print("  4=NotDir 5=NotFile 6=PermDenied 7=RateLimit. Code 8 = ???")
    print("=" * 70)

    test("sys1(int(8))(QD) [error code 8]", cps(0x01, int8))
    test("sys1(int(9))(QD) [error code 9]", cps(0x01, encode_byte_term(9)))
    test("sys1(int(10))(QD) [error code 10]", cps(0x01, encode_byte_term(10)))
    test("sys1(int(0))(QD) [control: code 0]", cps(0x01, encode_byte_term(0)))

    print()
    print("=" * 70)
    print("PROBE 2: readfile(int(8)) — file ID 8")
    print("  ID 8 is NOT in the filesystem tree (gap between 6 and 9)")
    print("=" * 70)

    test("sys7(int(8))(QD) [readfile id 8]", cps(0x07, int8))
    test("sys6(int(8))(QD) [name id 8]", cps(0x06, int8))
    test("sys5(int(8))(QD) [readdir id 8]", cps(0x05, int8))

    print()
    print("=" * 70)
    print("PROBE 3: sys2(cons(g8, nil)) — write with raw primitive in list")
    print("  Already tested → Right(2). Reconfirming.")
    print("=" * 70)

    test(
        "sys2(cons(Var(8), nil))(QD) [write raw prim list]",
        cps(0x02, Lam(Lam(App(App(Var(1), Var(10)), shift(nil, 2))))),
    )

    print()
    print("=" * 70)
    print("PROBE 4: backdoor → readfile(8) chain")
    print("=" * 70)

    shifted_qd = bytes.fromhex("0600fd000600fd04fdfefd03fdfefdfe")
    inner = (
        bytes([0x08])
        + encode_term(shift(int8, 1))
        + bytes([FD])
        + shifted_qd
        + bytes([FD])
    )
    payload4 = bytes([0xC9, 0x00, FE, FE, FD]) + inner + bytes([FE, FD, FF])
    test("backdoor(nil)(λ_.sys7(int(8))(QD↑1)) [elevated readfile]", payload4)

    print()
    print("Done.")


if __name__ == "__main__":
    main()
