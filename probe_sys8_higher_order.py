#!/usr/bin/env python3
"""
probe_sys8_higher_order.py - Test if sys8 is a higher-order function that calls its argument

Hypothesis:
  Sys8 does not *consume* a value, but rather *invokes* the term passed to it.
  If sys8 calls its argument with some hidden capability/witness, we can observe
  this by passing functions that either diverge (omega), or print their arguments (QD).

Probes:
  Arity ladder (divergence testing):
  1. sys8(λx. Ω)
  2. sys8(λx. λy. Ω)
  3. sys8(λx. λy. λz. Ω)

  QD as callback:
  4. sys8(QD) K*
  5. sys8(QD) PSE
  6. sys8(λx. QD(x)) K*
  7. sys8(λx. λy. QD(x)) K*
  8. sys8(λx. λy. QD(y)) K*

  Typed callback dumpers:
  9. sys8(λx. quote(x) PS) PSE
  10. sys8(λx. error_string(x) PS) PSE
  11. sys8(λx. name(x) PS) PSE
  12. sys8(λx. readfile(x) PS) PSE
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    parse_term,
    encode_byte_term,
    encode_bytes_list,
    encode_term,
)

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE
FF = 0xFF

QD_bytes = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
# Note: parse_term expects trailing FF, but QD_bytes doesn't have it.
# We will just parse it normally if it works, or build NConst from it.
stack = []
for b in QD_bytes:
    if b == FD:
        x = stack.pop()
        f = stack.pop()
        stack.append(App(f, x))
    elif b == FE:
        body = stack.pop()
        stack.append(Lam(body))
    else:
        stack.append(Var(b))
QD_TERM = stack[0]


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
    raise TypeError(f"Unsupported: {type(term)}")


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


# Constants
NIL = NConst(Lam(Lam(Var(0))))
K_STAR = NIL
QD = NConst(QD_TERM)


def str_term(s: str) -> NConst:
    return NConst(encode_bytes_list(s.encode("ascii", "replace")))


def write_str(s: str) -> object:
    return apps(g(2), str_term(s), NIL)


# Omega = (λx. x x)(λx. x x)
OMEGA = apps(lam("x", apps(v("x"), v("x"))), lam("x", apps(v("x"), v("x"))))


# ---------------------------------------------------------------------------
# Observers
# ---------------------------------------------------------------------------
def make_obs_either() -> object:
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
                    lam("_e2", write_str("ERR_DECODE_FAIL\n")),
                ),
            ),
        ),
    )
    left_h = lam("_lp", write_str("LEFT\n"))
    return lam("r", apps(v("r"), left_h, right_h))


def make_obs_quote_write() -> object:
    return lam(
        "r",
        apps(
            g(4),
            v("r"),
            lam("qb", apps(g(2), v("qb"), NIL)),
            lam("_qe", write_str("QUOTE_FAIL\n")),
        ),
    )


PSE = make_obs_either()
PS = make_obs_quote_write()


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------
def recv_all(sock: socket.socket, timeout_s: float = 6.0) -> bytes:
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


def query(payload: bytes, retries: int = 4, timeout_s: float = 6.0) -> bytes:
    delay = 0.3
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


def build_payload(term: object) -> bytes:
    db = to_db(term)
    enc = encode_term(db)
    return enc + bytes([FF])


def classify(out: bytes) -> str:
    if not out:
        return "EMPTY"
    known_text = [
        "Invalid term!",
        "Encoding failed!",
        "Term too big!",
        "Permission denied",
        "Not implemented",
        "ERR_DECODE_FAIL",
        "LEFT\n",
        "QUOTE_FAIL\n",
        "Not a directory",
        "No such directory or file",
        "Unexpected exception",
        "Invalid argument",
        "Not so fast!",
    ]
    for t in known_text:
        if out.startswith(t.encode("ascii")):
            return f"TEXT:{t!r}"
    try:
        text = out.decode("utf-8", "replace")
        if all((ch == "\n") or (ch == "\r") or (32 <= ord(ch) < 127) for ch in text):
            return f"TEXT:{text.strip()!r}"
    except Exception:
        pass
    return f"HEX:{out[:80].hex()}"


def is_breakthrough(c: str) -> bool:
    blocklist = [
        "Permission denied",
        "EMPTY",
        "Invalid term!",
        "Encoding failed!",
        "Term too big!",
        "ERROR:",
        "ERR_DECODE_FAIL",
        "Not implemented",
        "QUOTE_FAIL",
        "Not a directory",
        "No such directory or file",
        "Invalid argument",
    ]
    return not any(b in c for b in blocklist)


def report(label: str, payload_size: int, c: str) -> None:
    flag = " *** BREAKTHROUGH ***" if is_breakthrough(c) else ""
    print(f"{label:68s} sz={payload_size:4d} -> {c}{flag}")


# ---------------------------------------------------------------------------
# Test runners
# ---------------------------------------------------------------------------
def run_tests() -> None:
    print(
        "================================================================================"
    )
    print("PROBE SYS8 HIGHER ORDER - Testing if sys8 invokes its argument")
    print(f"Target: {HOST}:{PORT}")
    print(
        "================================================================================\n"
    )

    tests = [
        # Arity ladder
        ("P1: sys8(λx. Ω) PSE", apps(g(8), lam("x", OMEGA), PSE)),
        ("P2: sys8(λx. λy. Ω) PSE", apps(g(8), lam("x", lam("y", OMEGA)), PSE)),
        (
            "P3: sys8(λx. λy. λz. Ω) PSE",
            apps(g(8), lam("x", lam("y", lam("z", OMEGA))), PSE),
        ),
        # QD as callback
        ("P4: sys8(QD) K*", apps(g(8), QD, K_STAR)),
        ("P5: sys8(QD) PSE", apps(g(8), QD, PSE)),
        ("P6: sys8(λx. QD(x)) K*", apps(g(8), lam("x", apps(QD, v("x"))), K_STAR)),
        (
            "P7: sys8(λx. λy. QD(x)) K*",
            apps(g(8), lam("x", lam("y", apps(QD, v("x")))), K_STAR),
        ),
        (
            "P8: sys8(λx. λy. QD(y)) K*",
            apps(g(8), lam("x", lam("y", apps(QD, v("y")))), K_STAR),
        ),
        # Typed callback dumpers
        (
            "P9: sys8(λx. quote(x) PS) PSE",
            apps(g(8), lam("x", apps(g(4), v("x"), PS)), PSE),
        ),
        (
            "P10: sys8(λx. error_string(x) PS) PSE",
            apps(g(8), lam("x", apps(g(1), v("x"), PS)), PSE),
        ),
        (
            "P11: sys8(λx. name(x) PS) PSE",
            apps(g(8), lam("x", apps(g(6), v("x"), PS)), PSE),
        ),
        (
            "P12: sys8(λx. readfile(x) PS) PSE",
            apps(g(8), lam("x", apps(g(7), v("x"), PS)), PSE),
        ),
    ]

    for label, term in tests:
        payload = build_payload(term)
        out = query(payload)
        c = classify(out)
        report(label, len(payload), c)
        time.sleep(0.4)


if __name__ == "__main__":
    run_tests()
