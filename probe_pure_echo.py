#!/usr/bin/env python3
"""
probe_pure_echo.py — Pure-Lambda Echo Clone and Special Bytes

The hint: "combining the special bytes... froze my whole system! ... why would an OS even need an echo? I can easily write that myself..."

If echo (0x0E) is just `λx.λk. k(Left(x))`, it wraps its argument in `Left = λl.λr. l(x)`.
Because of the two lambda binders (`λl.λr.`), any `Var(i)` in `x` is shifted by +2.
So `Var(251)` becomes `Var(253)`, which corresponds to the `FD` (App) bytecode marker.
This cannot be typed on the wire natively because `FD` would be parsed as Application.

We will build a pure-lambda echo clone and test what happens when we pass `Var(251)`
and `Var(252)` to it, and then feed the resulting "illegal" terms to `quote`, `sys8`,
and other consumers.
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
# Named-term DSL
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


def shift_db(term, delta, cutoff=0):
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_db(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_db(term.f, delta, cutoff), shift_db(term.x, delta, cutoff))
    return term


def to_db(term, env=()):
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
    raise TypeError(f"Unsupported: {type(term)}")


def g(i):
    return NGlob(i)


def v(name):
    return NVar(name)


def lam(param, body):
    return NLam(param, body)


def app(f, x):
    return NApp(f, x)


def apps(*terms):
    out = terms[0]
    for t in terms[1:]:
        out = app(out, t)
    return out


NIL = NConst(Lam(Lam(Var(0))))


def str_term(s):
    return NConst(encode_bytes_list(s.encode("ascii", "replace")))


def write_str(s):
    return apps(g(2), str_term(s), NIL)


# Left constructor: Left(x) = λl.λr. l(x)
def make_left(x_term):
    return lam("l", lam("r", apps(v("l"), x_term)))


# Pure-lambda Echo: E = λx.λk. k(Left(x))
PURE_ECHO = lam("x", lam("k", apps(v("k"), make_left(v("x")))))


# Standard PSE observer
def make_pse():
    right_h = lam(
        "ec",
        apps(
            g(1),
            v("ec"),
            lam(
                "ei",
                apps(
                    v("ei"),
                    lam("es", apps(g(2), v("es"), NIL)),
                    lam("_e2", write_str("ERR\n")),
                ),
            ),
        ),
    )
    left_h = lam("_lp", write_str("LEFT\n"))
    return lam("r", apps(v("r"), left_h, right_h))


PSE = make_pse()


# Quote-Write observer (QD style)
def make_ps():
    return lam(
        "r",
        apps(
            g(4),
            v("r"),
            lam("qb", apps(g(2), v("qb"), NIL)),
            lam("_qe", write_str("QFAIL\n")),
        ),
    )


PS = make_ps()


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
def recv_all(sock, timeout_s=8.0):
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


def query(payload, timeout_s=8.0):
    delay = 0.3
    for _ in range(3):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                t0 = time.monotonic()
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                resp = recv_all(sock, timeout_s=timeout_s)
                ms = int((time.monotonic() - t0) * 1000)
                return resp, ms
        except Exception as e:
            time.sleep(delay)
            delay = min(delay * 2, 2.0)
    return b"ERROR", -1


def build_payload(term):
    return encode_term(to_db(term)) + bytes([FF])


def classify(out):
    if not out:
        return "EMPTY"
    known = [
        "Invalid term!",
        "Encoding failed!",
        "Term too big!",
        "Permission denied",
        "Not implemented",
        "ERR_DECODE",
        "LEFT\n",
        "LEFT:",
        "QFAIL\n",
        "ERR\n",
    ]
    for t in known:
        if out.startswith(t.encode("ascii")):
            return f"TEXT:{t!r}"
    try:
        text = out.decode("utf-8", "replace")
        if all((ch == "\n") or (ch == "\r") or (32 <= ord(ch) < 127) for ch in text):
            return f"TEXT:{text.strip()!r}"
    except Exception:
        pass
    return f"HEX:{out[:80].hex()}"


def report(label, sz, c, ms=0):
    boring = [
        "Permission denied",
        "EMPTY",
        "Invalid term!",
        "Encoding failed!",
        "Term too big!",
        "ERROR",
        "QFAIL\n",
        "ERR\n",
    ]
    flag = " *** NOVEL ***" if not any(b in c for b in boring) else ""
    print(f"{label:60s} sz={sz:4d} {ms:5d}ms -> {c}{flag}")


def run_tests():
    print("=" * 90)
    print("PROBE PURE ECHO — Testing high-index capabilities")
    print(f"Target: {HOST}:{PORT}")
    print("=" * 90)

    # Group 1: Verification (does it mimic real echo?)
    # echo(0)(quote) vs pure_echo(0)(quote)
    ctrl1 = apps(g(14), g(0), PS)
    p1 = build_payload(ctrl1)
    o1, m1 = query(p1)
    report("  V1: Real echo(0) → quote", len(p1), classify(o1), m1)
    time.sleep(0.3)

    ctrl2 = apps(PURE_ECHO, g(0), PS)
    p2 = build_payload(ctrl2)
    o2, m2 = query(p2)
    report("  V2: Pure echo(0) → quote", len(p2), classify(o2), m2)
    time.sleep(0.3)

    if o1 == o2:
        print("  >>> Pure echo output matches real echo perfectly.")
    else:
        print("  >>> Pure echo output DIFFERS from real echo!")

    print("\n  --- Special Bytes via Pure Echo ---")

    for idx in [250, 251, 252]:
        # PURE_ECHO(Var(idx))(λpayload. sys8(payload)(PSE))
        # Wait, PURE_ECHO passes Left(Var(idx)) to the continuation.
        # So we just provide a continuation that takes the payload and passes to sys8.
        # `λpayload. sys8(payload)(PSE)`
        cont_sys8 = lam("payload", apps(g(8), v("payload"), PSE))
        term = apps(PURE_ECHO, g(idx), cont_sys8)
        p = build_payload(term)
        o, m = query(p)
        report(f"  S{idx}: pure_echo({idx}) → sys8", len(p), classify(o), m)
        time.sleep(0.3)

    print("\n  --- Special Bytes via Quote (Confirming QFAIL) ---")

    for idx in [250, 251, 252]:
        # PURE_ECHO(Var(idx))(PS) -- PS tries to quote Left(Var(idx))
        term = apps(PURE_ECHO, g(idx), PS)
        p = build_payload(term)
        o, m = query(p)
        # We expect QFAIL (which translates to EMPTY from PS if quote silently dies)
        # Actually, quote returning Right means PS prints QFAIL
        # If quote crashes the evaluator, we get EMPTY
        report(f"  Q{idx}: pure_echo({idx}) → quote", len(p), classify(o), m)
        time.sleep(0.3)

    print("\n  --- Can we APPLY a high-index var? ---")
    # What if Var(253) (FD) is applied to something?
    # PURE_ECHO(Var(251))(λpayload. (payload nil) PSE)
    # payload is Left(Var(251)). Left = λl.λr. l(x)
    # Left(Var(251)) applied to nil: (λl.λr. l(x))(nil) = λr. nil(x) = λr. (λab.b)(x) = λr.λb.b
    # That doesn't apply x.
    # We need to unwrap the Left first!

    def make_unwrap_and_apply():
        # λpayload. payload (λx. x(nil)(PSE)) (λerr. write("ERR"))
        # This unwraps Left(x), then calls x(nil)(PSE)
        left_handler = lam("x", apps(v("x"), NIL, PSE))
        right_handler = lam("_", write_str("UNWRAP_ERR\n"))
        return lam("payload", apps(v("payload"), left_handler, right_handler))

    for idx in [250, 251, 252]:
        term = apps(PURE_ECHO, g(idx), make_unwrap_and_apply())
        p = build_payload(term)
        o, m = query(p)
        report(f"  A{idx}: unwrap(pure_echo({idx}))(nil) PSE", len(p), classify(o), m)
        time.sleep(0.3)


if __name__ == "__main__":
    run_tests()
