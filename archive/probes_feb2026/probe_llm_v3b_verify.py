#!/usr/bin/env python3
"""
Verify the "sys8 = execve(List<FileID>)" theory.

Prediction: sys8(cons(int(N), nil)) returns:
  - Right(6) if file ID N EXISTS in the filesystem
  - Right(3) if file ID N DOES NOT EXIST

Also tests:
  - Multi-char strings starting with existing vs non-existing first byte
  - Backdoor → sys8(cons(int(N), nil)) elevated chain
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE
FF = 0xFF
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


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        if term.i > 0xFC:
            raise ValueError(f"Var({term.i}) >= 0xFD")
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError


def shift(term: object, n: int, cutoff: int = 0) -> object:
    if isinstance(term, Var):
        return Var(term.i + n) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, n, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, n, cutoff), shift(term.x, n, cutoff))
    return term


def cons(h: object, t: object) -> object:
    return Lam(Lam(App(App(Var(1), shift(h, 2)), shift(t, 2))))


def encode_byte_term(n: int) -> object:
    expr: object = Var(0)
    for idx, weight in (
        (1, 1),
        (2, 2),
        (3, 4),
        (4, 8),
        (5, 16),
        (6, 32),
        (7, 64),
        (8, 128),
    ):
        if n & weight:
            expr = App(Var(idx), expr)
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_bytes_list(bs: bytes) -> object:
    cur: object = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


def query(payload: bytes, timeout_s: float = 5.0) -> bytes:
    delay = 0.2
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
                time.sleep(delay)
                delay *= 2
            else:
                return b""
    return b""


RIGHT6_SIG = "00030200fdfd"
RIGHT3_SIG = "00020100fdfd"
RIGHT2_SIG = "000200fdfd"


def classify(data: bytes) -> str:
    if len(data) == 0:
        return "EMPTY"
    try:
        text = data.decode("ascii")
        if "Invalid term" in text:
            return "INVALID_TERM"
        if "Term too big" in text:
            return "TERM_TOO_BIG"
        return f"TEXT:{text!r}"
    except UnicodeDecodeError:
        pass
    h = data.hex()
    if RIGHT6_SIG in h:
        return "RIGHT(6)"
    if RIGHT3_SIG in h:
        return "RIGHT(3)"
    if RIGHT2_SIG in h:
        return "RIGHT(2)"
    if "00010000fdfd" in h:
        return "RIGHT(1)"
    return f"OTHER:{h}"


def cps(syscall: int, arg: object) -> bytes:
    return bytes([syscall]) + encode_term(arg) + bytes([FD]) + QD + bytes([FD, FF])


def test(name: str, payload: bytes) -> str:
    time.sleep(0.35)
    result = query(payload)
    cls = classify(result)
    print(f"  {name}: {cls}")
    return cls


# Known existing file IDs
EXISTING_IDS = {0, 1, 2, 3, 4, 5, 6, 9, 11, 14, 15, 16, 22, 25, 39, 43, 46, 50, 65, 88}


def main() -> None:
    print("=" * 70)
    print("TEST A: Single-char standard strings — existing vs non-existing IDs")
    print("  Prediction: existing ID → Right(6), non-existing → Right(3)")
    print("=" * 70)

    # Test existing IDs as single-element byte lists
    existing_tests = [
        (0, "/ (root dir)"),
        (1, "/bin"),
        (6, "/var/log/brownos"),
        (11, "/etc/passwd"),
        (14, "/bin/sh"),
        (15, "/bin/sudo"),
        (16, "/bin/false"),
        (22, "/home"),
        (46, "access.log"),
        (65, ".history"),
        (88, "mail/dloser"),
    ]

    results_exist = {}
    for fid, desc in existing_tests:
        name = f"sys8([int({fid:3d})]) EXISTS={desc}"
        cls = test(name, cps(0x08, cons(encode_byte_term(fid), nil)))
        results_exist[fid] = cls

    print()

    # Test NON-existing IDs as single-element byte lists
    nonexist_tests = [7, 8, 10, 12, 13, 17, 20, 30, 47, 100, 105, 200]

    results_noexist = {}
    for fid in nonexist_tests:
        name = f"sys8([int({fid:3d})]) NOT_EXISTS"
        cls = test(name, cps(0x08, cons(encode_byte_term(fid), nil)))
        results_noexist[fid] = cls

    print()
    print("=" * 70)
    print("TEST B: Multi-char strings starting with existing ID byte values")
    print("  If theory holds: first byte = existing ID → Right(6)?")
    print("  Or does multi-char always → Right(3)?")
    print("=" * 70)

    # 2-char string [14, 0] — first byte 14 exists (/bin/sh)
    test("sys8([14, 0])  first=EXISTS", cps(0x08, encode_bytes_list(bytes([14, 0]))))

    # 2-char string [65, 0] — first byte 65 exists (.history)
    test("sys8([65, 0])  first=EXISTS", cps(0x08, encode_bytes_list(bytes([65, 0]))))

    # 2-char string [47, 0] — first byte 47 NOT exists
    test(
        "sys8([47, 0])  first=NOT_EXISTS", cps(0x08, encode_bytes_list(bytes([47, 0])))
    )

    # 2-char string [100, 0] — first byte 100 NOT exists
    test(
        "sys8([100, 0]) first=NOT_EXISTS", cps(0x08, encode_bytes_list(bytes([100, 0])))
    )

    print()
    print("=" * 70)
    print("TEST C: Elevated execve — backdoor then sys8 with valid file ID")
    print("=" * 70)

    # backdoor(nil)(λdummy. sys8(cons(int(14), nil))(QD_shifted))
    # Under 1 lambda: sys8 = g(8) = Var(9), backdoor result bound to Var(0)
    # QD needs +1 shift
    shifted_qd = bytes.fromhex("0600fd000600fd04fdfefd03fdfefdfe")
    for fid, desc in [(14, "/bin/sh"), (15, "/bin/sudo"), (8, "id8 itself")]:
        inner_arg = cons(encode_byte_term(fid), nil)
        inner = (
            bytes([0x09])
            + encode_term(shift(inner_arg, 1))
            + bytes([FD])
            + shifted_qd
            + bytes([FD])
        )
        # λdummy. ((sys8 arg) QD_shifted)
        body = inner + bytes([FE])
        # ((sys201 nil) body)
        payload = bytes([0xC9, 0x00, FE, FE, FD]) + body + bytes([FD, FF])
        test(f"backdoor→sys8([int({fid})]) [{desc}]", payload)

    print()
    print("=" * 70)
    print("TEST D: Elevated execve with plain int (not list)")
    print("=" * 70)

    # backdoor(nil)(λdummy. sys8(int(14))(QD_shifted))
    for fid, desc in [(14, "/bin/sh"), (8, "id8")]:
        inner_arg = encode_byte_term(fid)
        inner = (
            bytes([0x09])
            + encode_term(shift(inner_arg, 1))
            + bytes([FD])
            + shifted_qd
            + bytes([FD])
        )
        body = inner + bytes([FE])
        payload = bytes([0xC9, 0x00, FE, FE, FD]) + body + bytes([FD, FF])
        test(f"backdoor→sys8(int({fid})) [{desc}]", payload)

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    exist_r6 = sum(1 for v in results_exist.values() if v == "RIGHT(6)")
    exist_r3 = sum(1 for v in results_exist.values() if v == "RIGHT(3)")
    noexist_r6 = sum(1 for v in results_noexist.values() if v == "RIGHT(6)")
    noexist_r3 = sum(1 for v in results_noexist.values() if v == "RIGHT(3)")

    print(
        f"  Existing IDs:     Right(6)={exist_r6}  Right(3)={exist_r3}  other={len(results_exist) - exist_r6 - exist_r3}"
    )
    print(
        f"  Non-existing IDs: Right(6)={noexist_r6}  Right(3)={noexist_r3}  other={len(results_noexist) - noexist_r6 - noexist_r3}"
    )

    if exist_r6 == len(results_exist) and noexist_r3 == len(results_noexist):
        print("\n  *** THEORY CONFIRMED: sys8 looks up file IDs from byte list! ***")
    elif exist_r6 > 0 and noexist_r3 > 0:
        print("\n  *** PARTIAL MATCH — pattern exists but not perfect ***")
    else:
        print(
            "\n  Theory DISPROVEN — no correlation between ID existence and error code"
        )


if __name__ == "__main__":
    main()
