#!/usr/bin/env python3
"""
Systematic 3-leaf search for syscall 8.

Key findings so far:
- Echo-extracted values give "Invalid argument" (error 2) - TAGGED
- Direct values give "Permission denied" (error 3) - UNTAGGED
- Syscall 8 can detect runtime provenance!

Strategy: Carefully build and test all 3-leaf patterns with tagged values.
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
PORT = 61221
FD, FE, FF = 0xFD, 0xFE, 0xFF


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


def encode_term(term) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unknown: {type(term)}")


def query(payload: bytes, timeout_s: float = 8.0) -> bytes:
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(timeout_s)
            out = b""
            start = time.time()
            while time.time() - start < timeout_s:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out += chunk
                except socket.timeout:
                    break
            return out
    except Exception as e:
        return f"ERROR: {e}".encode()


nil = Lam(Lam(Var(0)))


def encode_string(s: str):
    def encode_byte(n):
        expr = Var(0)
        for idx, weight in [
            (8, 128),
            (7, 64),
            (6, 32),
            (5, 16),
            (4, 8),
            (3, 4),
            (2, 2),
            (1, 1),
        ]:
            if n & weight:
                expr = App(Var(idx), expr)
        term = expr
        for _ in range(9):
            term = Lam(term)
        return term

    def cons(h, t):
        return Lam(Lam(App(App(Var(1), h), t)))

    cur = nil
    for b in reversed(s.encode()):
        cur = cons(encode_byte(b), cur)
    return cur


def shift(term, delta, cutoff=0):
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    return term


def build_debugger(depth_offset=0):
    """Working debugger continuation that prints error strings."""
    write_idx = 2 + depth_offset
    error_idx = 1 + depth_offset
    left_handler = Lam(App(App(Var(write_idx + 1), encode_string("L")), nil))
    right_handler = Lam(
        App(
            App(Var(error_idx + 1), Var(0)),
            Lam(
                App(
                    App(Var(0), Lam(App(App(Var(write_idx + 3), Var(0)), nil))),
                    Lam(App(App(Var(write_idx + 3), encode_string("?")), nil)),
                )
            ),
        )
    )
    return Lam(App(App(Var(0), left_handler), right_handler))


def test_single_echo_syscall8(echo_arg: int, term_builder, label: str):
    """
    Test pattern: echo(N) -> extract v -> syscall8(term_builder(v)) -> debug

    Depth tracking:
    - After echo continuation: depth 1, echo_result at V0
    - After extraction: depth 2, v at V0
    - syscall8 at V(8+2) = V10
    - After syscall8 cont: depth 3
    """
    debugger = build_debugger(depth_offset=2)
    dbg_s = shift(debugger, 1)

    term = term_builder(Var(0))

    use_v = Lam(App(App(Var(10), term), dbg_s))
    err = Lam(App(App(Var(4), encode_string("E")), nil))
    cont = Lam(App(App(Var(0), use_v), err))

    payload = bytes([0x0E, echo_arg, FD]) + encode_term(cont) + bytes([FD, FF])
    resp = query(payload)
    print(f"{label}: {resp}")
    return resp


def test_double_echo_syscall8(echo_args: tuple, term_builder, label: str):
    """
    Test pattern: echo(a) -> v1 -> echo(b) -> v2 -> syscall8(term_builder(v1, v2))

    Depth tracking:
    - echo1 cont: depth 1, result at V0
    - extract1: depth 2, v1 at V0
    - echo2 cont: depth 3, result at V0, v1 at V1
    - extract2: depth 4, v2 at V0, v1 at V2
    - syscall8 at V(8+4) = V12
    """
    a, b = echo_args

    debugger = build_debugger(depth_offset=4)
    dbg_s = shift(debugger, 1)

    term = term_builder(Var(2), Var(0))

    use_both = Lam(App(App(Var(12), term), dbg_s))
    err4 = Lam(App(App(Var(6), encode_string("E4")), nil))
    extract2 = Lam(App(App(Var(0), use_both), err4))

    err3 = Lam(App(App(Var(5), encode_string("E3")), nil))
    echo2 = Lam(App(App(Var(16), Var(b)), extract2))

    err2 = Lam(App(App(Var(4), encode_string("E2")), nil))
    extract1 = Lam(App(App(Var(0), echo2), err2))

    payload = bytes([0x0E, a, FD]) + encode_term(extract1) + bytes([FD, FF])
    resp = query(payload)
    print(f"{label}: {resp}")
    return resp


def main():
    print("=" * 70)
    print("SYSTEMATIC 3-LEAF SEARCH")
    print("=" * 70)
    print()

    print("=== BASELINE: Single tagged value ===")
    test_single_echo_syscall8(0, lambda v: v, "echo(0) -> v")
    time.sleep(0.2)

    print()
    print("=== SHAPE A: ((v v) v) - 3 copies of same leaf ===")
    test_single_echo_syscall8(0, lambda v: App(App(v, v), v), "echo(0) -> ((v v) v)")
    time.sleep(0.2)

    print()
    print("=== SHAPE B: (v (v v)) - 3 copies of same leaf ===")
    test_single_echo_syscall8(0, lambda v: App(v, App(v, v)), "echo(0) -> (v (v v))")
    time.sleep(0.2)

    print()
    print("=== TWO DIFFERENT TAGGED VALUES ===")
    test_double_echo_syscall8(
        (0, 1), lambda v1, v2: App(v1, v2), "echo(0,1) -> (v1 v2)"
    )
    time.sleep(0.2)

    test_double_echo_syscall8(
        (0, 1), lambda v1, v2: App(v2, v1), "echo(0,1) -> (v2 v1)"
    )
    time.sleep(0.2)

    print()
    print("=== 3-LEAF WITH TWO TAGGED VALUES ===")
    test_double_echo_syscall8(
        (0, 1), lambda v1, v2: App(App(v1, v2), v1), "((v1 v2) v1)"
    )
    time.sleep(0.2)

    test_double_echo_syscall8(
        (0, 1), lambda v1, v2: App(App(v1, v2), v2), "((v1 v2) v2)"
    )
    time.sleep(0.2)

    test_double_echo_syscall8(
        (0, 1), lambda v1, v2: App(v1, App(v2, v1)), "(v1 (v2 v1))"
    )
    time.sleep(0.2)

    test_double_echo_syscall8(
        (0, 1), lambda v1, v2: App(v2, App(v1, v2)), "(v2 (v1 v2))"
    )
    time.sleep(0.2)

    print()
    print("=== SPECIAL INDICES 251, 252 ===")
    test_single_echo_syscall8(251, lambda v: v, "echo(251) -> v")
    time.sleep(0.2)

    test_single_echo_syscall8(252, lambda v: v, "echo(252) -> v")
    time.sleep(0.2)

    test_double_echo_syscall8(
        (251, 252), lambda v1, v2: App(v1, v2), "echo(251,252) -> (v1 v2)"
    )
    time.sleep(0.2)

    test_double_echo_syscall8(
        (251, 252), lambda v1, v2: App(App(v1, v2), nil), "((v251 v252) nil)"
    )
    time.sleep(0.2)

    print()
    print("=" * 70)
    print("SEARCH COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
