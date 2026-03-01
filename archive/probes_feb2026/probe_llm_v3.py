#!/usr/bin/env python3
"""
Test LLM v3 proposals against live BrownOS server.

Probe 1: Introspection — pass raw syscall primitives to other syscalls
Probe 2: 3-Leaf Capability Lists — cons cells with raw globals as elements
Probe 3: Naked-Variable Strings — raw Var indices as character values
Probe 4: Wide metadata integers (61221, 56154) as sys8 args
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


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        if term.i > 0xFC:
            raise ValueError(f"Var({term.i}) cannot be encoded (>= 0xFD)")
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unknown term type: {type(term)}")


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
                return b"CONN_ERR:" + str(e).encode()
    return b""


def shift(term: object, n: int, cutoff: int = 0) -> object:
    """Shift free de Bruijn indices by n."""
    if isinstance(term, Var):
        return Var(term.i + n) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, n, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, n, cutoff), shift(term.x, n, cutoff))
    return term


# Scott nil
nil = Lam(Lam(Var(0)))


def cons(h: object, t: object) -> object:
    """Scott cons: λc.λn. (c h t) — with proper de Bruijn shifting."""
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


def encode_wide_int(n: int) -> object:
    """Additive 9-lambda encoding for values > 255."""
    weights = [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]
    expr: object = Var(0)
    remaining = n
    for idx, w in weights:
        while remaining >= w:
            expr = App(Var(idx), expr)
            remaining -= w
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


RIGHT6_SIG = "00030200fdfd"
RIGHT3_SIG = "000201"  # Right(3) starts with int(3) pattern
RIGHT2_SIG = "000200fdfd"  # Right(2) = Invalid argument


def classify(data: bytes) -> str:
    if isinstance(data, bytes) and data.startswith(b"CONN_ERR:"):
        return f"CONN_ERR: {data.decode()}"
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
        return f"TEXT: {text!r}"
    except UnicodeDecodeError:
        pass
    h = data.hex()
    if RIGHT6_SIG in h:
        return "RIGHT(6) PermDenied"
    if "00020100fdfd" in h:
        return "RIGHT(3) NoSuchFile"
    if RIGHT2_SIG in h:
        return "RIGHT(2) InvalidArg"
    if "00010000fdfd" in h:
        return "RIGHT(1) NotImpl"
    # Check for Left
    if h.endswith("ff") and len(data) > 3:
        return f"*** RESPONSE *** hex={h} [{len(data)}b]"
    return f"HEX: {h} [{len(data)}b]"


def cps_payload(syscall_num: int, arg: object) -> bytes:
    """Build ((syscall arg) QD) + FF"""
    return bytes([syscall_num]) + encode_term(arg) + bytes([FD]) + QD + bytes([FD, FF])


def test(name: str, payload: bytes) -> str:
    time.sleep(0.35)
    result = query(payload)
    cls = classify(result)
    marker = "  *** " if "RESPONSE" in cls or "NOVEL" in cls else "  "
    print(f"{marker}{name}: {cls}")
    if "RESPONSE" in cls or ("HEX" in cls and "RIGHT" not in cls):
        print(f"    raw: {result!r}")
    return cls


def main() -> None:
    print("=" * 70)
    print("PROBE 1: Introspection — raw primitives to other syscalls")
    print("=" * 70)

    # sys1(g(8))(QD) — pass Var(8) to error_string
    test(
        "sys1(Var(8))  [error_string with raw sys8 primitive]",
        cps_payload(0x01, Var(8)),
    )

    # sys1(g(201))(QD) — pass Var(201) to error_string
    test(
        "sys1(Var(201)) [error_string with raw backdoor primitive]",
        cps_payload(0x01, Var(201)),
    )

    # sys1(g(14))(QD) — pass Var(14) to error_string
    test(
        "sys1(Var(14))  [error_string with raw echo primitive]",
        cps_payload(0x01, Var(14)),
    )

    # sys2(g(8))(QD) — force write to serialize a raw primitive
    test(
        "sys2(Var(8))   [write raw sys8 primitive to socket]", cps_payload(0x02, Var(8))
    )

    # sys4(g(8))(QD) — quote a raw primitive (should return bytes [0x08])
    test("sys4(Var(8))   [quote raw sys8 primitive]", cps_payload(0x04, Var(8)))

    print()
    print("=" * 70)
    print("PROBE 2: 3-Leaf Capability Lists — cons with raw globals")
    print("=" * 70)

    # cons(g(201), nil) — "3 leafs" = Var(1), Var(203), Var(0)
    term = cons(Var(201), nil)
    payload_bytes = encode_term(term)
    print(f"  [cons(g201, nil) bytecode: {payload_bytes.hex()}]")
    test("sys8(cons(g201, nil))  [THE 3-leaf candidate]", cps_payload(0x08, term))

    # cons(g(8), nil)
    test("sys8(cons(g8, nil))", cps_payload(0x08, cons(Var(8), nil)))

    # cons(g(14), nil) — echo
    test("sys8(cons(g14, nil))", cps_payload(0x08, cons(Var(14), nil)))

    # cons(g(42), nil) — towel
    test("sys8(cons(g42, nil))", cps_payload(0x08, cons(Var(42), nil)))

    # [g201, g8] two-element list
    test("sys8([g201, g8])", cps_payload(0x08, cons(Var(201), cons(Var(8), nil))))

    # [g8, g201]
    test("sys8([g8, g201])", cps_payload(0x08, cons(Var(8), cons(Var(201), nil))))

    # [g201, g14] — backdoor + echo
    test("sys8([g201, g14])", cps_payload(0x08, cons(Var(201), cons(Var(14), nil))))

    # [g14, g201] — echo + backdoor
    test("sys8([g14, g201])", cps_payload(0x08, cons(Var(14), cons(Var(201), nil))))

    print()
    print("=" * 70)
    print("PROBE 3: Naked-Variable Strings — raw Var(ASCII) as chars")
    print("=" * 70)

    # "sh" = [Var(115), Var(104)]
    test("sys8(rawvar 'sh')", cps_payload(0x08, cons(Var(0x73), cons(Var(0x68), nil))))

    # "ilikephp" using raw Var indices
    ilikephp_raw = nil
    for ch in reversed(b"ilikephp"):
        ilikephp_raw = cons(Var(ch), ilikephp_raw)
    test("sys8(rawvar 'ilikephp')", cps_payload(0x08, ilikephp_raw))

    # Single raw-var chars
    for label, val in [("NUL", 0), ("SOH/1", 1), ("8", 56), ("A", 65), ("a", 97)]:
        test(f"sys8(rawvar '{label}'={val})", cps_payload(0x08, cons(Var(val), nil)))

    # What about single-element standard byte list for comparison?
    test(
        "sys8(std_byte 'A'=65) [control]",
        cps_payload(0x08, cons(encode_byte_term(65), nil)),
    )

    print()
    print("=" * 70)
    print("PROBE 4: Wide metadata integers as sys8 args")
    print("=" * 70)

    # Check payload size first
    for n, label in [(61221, "TCP port"), (56154, "SHA1 iterations")]:
        term = encode_wide_int(n)
        payload = cps_payload(0x08, term)
        print(f"  [int({n}) '{label}' payload size: {len(payload)} bytes]")
        if len(payload) > 1800:
            print(f"    SKIPPED — too close to 2KB limit")
        else:
            test(f"sys8(int({n})) [{label}]", payload)

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("Done. Any '*** RESPONSE ***' above is a potential breakthrough.")


if __name__ == "__main__":
    main()
