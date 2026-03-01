#!/usr/bin/env python3
"""Verify which strings actually return Right(3) vs Right(6)."""

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
    except:
        return b""


def classify_detailed(data):
    if len(data) == 0:
        return "EMPTY", ""
    h = data.hex()
    if "00030200fdfd" in h:
        return "RIGHT(6)", h
    if "00020100fdfd" in h:
        return "RIGHT(3)", h
    if "000200fdfd" in h:
        return "RIGHT(2)", h
    try:
        text = data.decode("ascii")
        return f"TEXT", text
    except:
        pass
    return f"HEX", h


def cps(sc, arg):
    return bytes([sc]) + encode_term(arg) + bytes([FD]) + QD + bytes([FD, FF])


# The strings that were supposedly Right(3)
ORIGINAL_RIGHT3_CLAIMS = [
    b"ilikephp",
    b"/bin/sh",
    b"gizmore",
    b"/bin/solution",
    b"root",
    b"sudo",
    b"dloser",
    b"GZKc.2/VQffio",
    b"gizmore:ilikephp",
]

# Strings that returned Right(6) in our new tests
NEW_RIGHT6 = [
    b"BrownOS",
    b"dloser",
    b"AAA",
    b"abc",
]

print("=" * 70)
print("Re-testing ALL strings claimed to return Right(3)")
print("=" * 70)

for s in ORIGINAL_RIGHT3_CLAIMS:
    time.sleep(0.35)
    payload = cps(0x08, encode_bytes_list(s))
    result = query(payload)
    cls, detail = classify_detailed(result)
    print(f"  sys8({s!r:30s}): {cls}  [{len(result)}b]")

print()
print("=" * 70)
print("Control: strings that returned Right(6) in new tests")
print("=" * 70)

for s in NEW_RIGHT6:
    time.sleep(0.35)
    payload = cps(0x08, encode_bytes_list(s))
    result = query(payload)
    cls, detail = classify_detailed(result)
    print(f"  sys8({s!r:30s}): {cls}  [{len(result)}b]")

print()

# Also test the backdoor pair directly
print("=" * 70)
print("Control: non-string arguments")
print("=" * 70)

time.sleep(0.35)
r = query(cps(0x08, nil))
c, _ = classify_detailed(r)
print(f"  sys8(nil):              {c}")

time.sleep(0.35)
r = query(cps(0x08, encode_byte_term(42)))
c, _ = classify_detailed(r)
print(f"  sys8(int(42)):          {c}")

# Backdoor pair
time.sleep(0.35)
pair = Lam(
    App(
        App(Var(0), Lam(Lam(App(Var(0), Var(0))))),  # A
        Lam(Lam(App(Var(1), Var(0)))),
    )
)  # B
r = query(cps(0x08, pair))
c, _ = classify_detailed(r)
print(f"  sys8(pair(A,B)):        {c}")
