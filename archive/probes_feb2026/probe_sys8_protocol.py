#!/usr/bin/env python3
"""
probe_sys8_protocol.py - Protocol-level and exception-context tricks against syscall 8.

Tests 5 axes NOT yet covered by prior probes:
  P1: Out-of-band bytes AFTER 0xFF marker
  P2: Multi-term per connection (no shutdown between)
  P3: Non-singleton parse stacks (multiple items at 0xFF)
  P4: sys8 WITHOUT continuation (1-arg only, not CPS 2-arg)
  P5: g(0) exception-context wrapping sys8
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    encode_byte_term,
    encode_bytes_list,
    encode_term,
)

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

# ---------------------------------------------------------------------------
# Named-term DSL (copied from probe_ultra3.py)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NVar:
    name: str


@dataclass(frozen=True)
class NGlob:
    index: int


@dataclass(frozen=True)
class NLam:
    param: str
    body: object


@dataclass(frozen=True)
class NApp:
    f: object
    x: object


@dataclass(frozen=True)
class NConst:
    term: object


def shift_db(term: object, delta: int, cutoff: int = 0) -> object:
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_db(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_db(term.f, delta, cutoff), shift_db(term.x, delta, cutoff))
    return term


def to_db(term: object, env: tuple[str, ...] = ()) -> object:
    if isinstance(term, NVar):
        return Var(env.index(term.name))
    if isinstance(term, NGlob):
        return Var(term.index + len(env))
    if isinstance(term, NLam):
        return Lam(to_db(term.body, (term.param,) + env))
    if isinstance(term, NApp):
        return App(to_db(term.f, env), to_db(term.x, env))
    if isinstance(term, NConst):
        return shift_db(term.term, len(env))
    raise TypeError(f"Unsupported named-term node: {type(term)}")


def g(i: int) -> NGlob:
    return NGlob(i)


def v(name: str) -> NVar:
    return NVar(name)


def lam(param: str, body: object) -> NLam:
    return NLam(param, body)


def app(f: object, x: object) -> NApp:
    return NApp(f, x)


def apps(*terms: object) -> object:
    out = terms[0]
    for t in terms[1:]:
        out = app(out, t)
    return out


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)


def str_term(s: str) -> NConst:
    return NConst(encode_bytes_list(s.encode("ascii", "replace")))


def write_str(s: str) -> object:
    return apps(g(2), str_term(s), NIL)


# ---------------------------------------------------------------------------
# Observer (write-based, NOT QD)
# ---------------------------------------------------------------------------


def make_observer(left_marker: str = "LEFT\n") -> object:
    right_handler = lam(
        "errcode",
        apps(
            g(1),
            v("errcode"),
            lam(
                "err_str_either",
                apps(
                    v("err_str_either"),
                    lam("errstr", apps(g(2), v("errstr"), NIL)),
                    lam("_e2", write_str("ERR_DECODE_FAIL\n")),
                ),
            ),
        ),
    )
    left_handler = lam("_left_payload", write_str(left_marker))
    return lam("result", apps(v("result"), left_handler, right_handler))


OBS = make_observer()


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------


def recv_all(sock: socket.socket, timeout_s: float = 7.0) -> bytes:
    sock.settimeout(timeout_s)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    return out


def query(payload: bytes, retries: int = 4, timeout_s: float = 7.0) -> bytes:
    delay = 0.35
    last_err: Exception | None = None
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s=timeout_s)
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay = min(delay * 2, 2.0)
    return f"ERROR: {last_err}".encode("ascii", "replace")


def query_raw_no_shutdown(payload: bytes, timeout_s: float = 7.0) -> bytes:
    """Send payload without shutdown — used for raw protocol tests."""
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            return recv_all(sock, timeout_s=timeout_s)
    except Exception as e:
        return f"ERROR: {e}".encode("ascii", "replace")


def query_multi(
    payloads: list[bytes], gap_s: float = 0.3, timeout_s: float = 10.0
) -> bytes:
    """Send multiple payloads on the same connection with gaps between them."""
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            for i, payload in enumerate(payloads):
                sock.sendall(payload)
                if i < len(payloads) - 1:
                    time.sleep(gap_s)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            return recv_all(sock, timeout_s=timeout_s)
    except Exception as e:
        return f"ERROR: {e}".encode("ascii", "replace")


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


def classify(out: bytes) -> str:
    if not out:
        return "EMPTY"
    if out.startswith(b"Invalid term!"):
        return "Invalid term!"
    if out.startswith(b"Encoding failed!"):
        return "Encoding failed!"
    if out.startswith(b"Term too big!"):
        return "Term too big!"
    if out.startswith(b"ERROR:"):
        return out.decode("ascii", "replace")

    try:
        text = out.decode("utf-8", "replace")
        if all((ch == "\n") or (ch == "\r") or (32 <= ord(ch) < 127) for ch in text):
            compact = text.replace("\n", "\\n")
            return f"TEXT:{compact[:120]}"
    except Exception:
        pass

    return f"HEX:{out[:80].hex()}"


def is_breakthrough(classification: str) -> bool:
    """Any result that is NOT Permission denied, EMPTY, or a known error."""
    known_failures = [
        "Permission denied",
        "EMPTY",
        "Invalid term!",
        "Encoding failed!",
        "Term too big!",
        "ERROR:",
        "ERR_DECODE_FAIL",
    ]
    for kf in known_failures:
        if kf in classification:
            return False
    return True


def report(label: str, payload_size: int, classification: str) -> None:
    flag = " *** BREAKTHROUGH ***" if is_breakthrough(classification) else ""
    print(f"{label:62s} payload={payload_size:4d} -> {classification}{flag}")


def section(title: str) -> None:
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


# ---------------------------------------------------------------------------
# Build base sys8(nil)(OBS) payload
# ---------------------------------------------------------------------------


def sys8_nil_obs_payload() -> bytes:
    term = apps(g(8), NIL, OBS)
    db = to_db(term)
    return encode_term(db) + bytes([FF])


def sys8_nil_obs_term_bytes() -> bytes:
    """Just the term bytes for sys8(nil)(OBS), WITHOUT the trailing 0xFF."""
    term = apps(g(8), NIL, OBS)
    db = to_db(term)
    return encode_term(db)


# ---------------------------------------------------------------------------
# GROUP P1: Out-of-band bytes AFTER 0xFF
# ---------------------------------------------------------------------------


def group_p1() -> None:
    section("GROUP P1: Out-of-band bytes AFTER 0xFF")

    base = sys8_nil_obs_term_bytes() + bytes([FF])

    tests = [
        ("P1a sys8(nil)(OBS)+FF+'ilikephp\\n'", base + b"ilikephp\n"),
        ("P1b sys8(nil)(OBS)+FF+nil_bytes", base + bytes([0x00, FE, FE])),
        ("P1c sys8(nil)(OBS)+FF+g8_bytes", base + bytes([0x08, FF])),
    ]

    for label, payload in tests:
        out = query_raw_no_shutdown(payload)
        c = classify(out)
        report(label, len(payload), c)
        time.sleep(0.4)


# ---------------------------------------------------------------------------
# GROUP P2: Multi-term per connection
# ---------------------------------------------------------------------------


def group_p2() -> None:
    section("GROUP P2: Multi-term per connection (no shutdown between)")

    # backdoor(nil)(OBS) payload
    bd_term = apps(g(201), NIL, OBS)
    bd_payload = encode_term(to_db(bd_term)) + bytes([FF])

    sys8_payload = sys8_nil_obs_payload()

    # write("AUTH")(nil) payload
    write_term = apps(g(2), str_term("AUTH"), NIL)
    write_payload = encode_term(to_db(write_term)) + bytes([FF])

    tests = [
        ("P2a backdoor(nil)(OBS) then sys8(nil)(OBS)", [bd_payload, sys8_payload]),
        ("P2b sys8(nil)(OBS) then sys8(nil)(OBS)", [sys8_payload, sys8_payload]),
        ("P2c write('AUTH')(nil) then sys8(nil)(OBS)", [write_payload, sys8_payload]),
    ]

    for label, payloads in tests:
        total_size = sum(len(p) for p in payloads)
        out = query_multi(payloads, gap_s=0.3)
        c = classify(out)
        report(label, total_size, c)
        time.sleep(0.4)


# ---------------------------------------------------------------------------
# GROUP P3: Non-singleton parse stacks
# ---------------------------------------------------------------------------


def group_p3() -> None:
    section("GROUP P3: Non-singleton parse stacks (multiple items at 0xFF)")

    tests = [
        ("P3a g(8)+g(0)+FF (two globals)", bytes([0x08, 0x00, FF])),
        (
            "P3b nil+g(8)+nil+FD+FF (extra nil before)",
            bytes([0x00, FE, FE, 0x08, 0x00, FE, FE, FD, FF]),
        ),
        (
            "P3c g(8)+nil+FD+nil+FF (extra nil after)",
            bytes([0x08, 0x00, FE, FE, FD, 0x00, FE, FE, FF]),
        ),
    ]

    for label, payload in tests:
        out = query(payload)
        c = classify(out)
        report(label, len(payload), c)
        time.sleep(0.4)


# ---------------------------------------------------------------------------
# GROUP P4: sys8 WITHOUT continuation (1-arg only)
# ---------------------------------------------------------------------------


def group_p4() -> None:
    section("GROUP P4: sys8 WITHOUT continuation (1-arg only)")

    # P4a: g(8)(nil) — just one application, no continuation
    # g(8) = Var(8), nil = Lam(Lam(Var(0))), App = FD
    p4a = bytes([0x08, 0x00, FE, FE, FD, FF])

    # P4b: g(8)("ilikephp") — string arg, no continuation
    pw_term = encode_bytes_list(b"ilikephp")
    p4b = bytes([0x08]) + encode_term(pw_term) + bytes([FD, FF])

    # P4c: g(8) alone — just the global
    p4c = bytes([0x08, FF])

    tests = [
        ("P4a g(8)(nil) no continuation", p4a),
        ("P4b g(8)('ilikephp') no continuation", p4b),
        ("P4c g(8) alone", p4c),
    ]

    for label, payload in tests:
        out = query(payload, timeout_s=10.0)
        c = classify(out)
        report(label, len(payload), c)
        time.sleep(0.4)


# ---------------------------------------------------------------------------
# GROUP P5: g(0) exception-context wrapping sys8
# ---------------------------------------------------------------------------


def group_p5() -> None:
    section("GROUP P5: g(0) exception-context wrapping sys8")

    # P5a: g(0)(g(8)(nil)(OBS)) — wrap sys8 call result in g(0)
    p5a = apps(g(0), apps(g(8), NIL, OBS))

    # P5b: g(0)(λex. sys8(ex)(OBS))(nil)
    # g(0) as exception handler; exception value fed to sys8
    p5b = apps(
        g(0),
        lam("ex", apps(g(8), v("ex"), OBS)),
        NIL,
    )

    # P5c: g(0)(λex. write("EX:")(λ_. sys8(nil)(OBS)))
    # Trigger exception, then call sys8 in post-exception context
    p5c = apps(
        g(0),
        lam(
            "ex",
            apps(
                g(2),
                str_term("EX:"),
                lam("_", apps(g(8), NIL, OBS)),
            ),
        ),
    )

    tests = [
        ("P5a g(0)(sys8(nil)(OBS))", p5a),
        ("P5b g(0)(λex.sys8(ex)(OBS))(nil)", p5b),
        ("P5c g(0)(λex.write('EX:')(λ_.sys8(nil)(OBS)))", p5c),
    ]

    for label, term in tests:
        db = to_db(term)
        payload = encode_term(db) + bytes([FF])
        assert len(payload) <= 1900, f"Payload too big: {len(payload)}"
        out = query(payload, timeout_s=10.0)
        c = classify(out)
        report(label, len(payload), c)
        time.sleep(0.4)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 80)
    print("PROBE SYS8 PROTOCOL - Protocol-level & exception-context tricks")
    print(f"Target: {HOST}:{PORT}")
    print(f"Total tests: 18 (across 5 groups)")
    print("=" * 80)

    group_p1()  # 3 tests
    group_p2()  # 3 tests
    group_p3()  # 3 tests
    group_p4()  # 3 tests
    group_p5()  # 3 tests  (subtotal: 15, well under 20)

    print("\n" + "=" * 80)
    print("DONE - 15 tests completed")
    print("=" * 80)


if __name__ == "__main__":
    main()
