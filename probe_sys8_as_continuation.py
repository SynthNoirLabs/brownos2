#!/usr/bin/env python3
"""
probe_sys8_as_continuation.py - Test sys8 as the raw continuation to other syscalls

Hypothesis:
  What if sys8 needs a capability in the form of a "raw minted result term" directly
  from another syscall? If we use adapters (λr. r(8)(K*)) we unwrap the outer Either.
  If we do `(((syscall arg) 8) PSE)`, then `8` receives the EXACT, unmodified term
  produced by `syscall`.

Probes:
  1. (((readdir 0) 8) PSE)
  2. (((readdir 43) 8) PSE)
  3. (((backdoor nil) 8) PSE)
  4. (((name 256) 8) PSE)
  5. (((readfile 11) 8) PSE)
  6. (((readfile 65) 8) PSE)
  7. (((readdir 256) 8) PSE) - raw Right(4)
  8. (((error_string 6) 8) PSE) - raw Right(6)
  9. (((sys8 0) 8) PSE)

  Control (inspection of minted terms without adapters):
  10. (((readdir 0) 4) PS)
  11. (((backdoor nil) 4) PS)
  12. (((name 256) 4) PS)
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


def str_term(s: str) -> NConst:
    return NConst(encode_bytes_list(s.encode("ascii", "replace")))


def write_str(s: str) -> object:
    return apps(g(2), str_term(s), NIL)


def int_term(n: int) -> NConst:
    # Handles encoding for numbers > 255 as well
    if n <= 255:
        return NConst(encode_byte_term(n))
    # Wide int encoding
    expr: object = Var(0)
    weights = ((1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128))
    rem = n
    while rem > 0:
        for idx, weight in reversed(weights):
            if rem >= weight:
                expr = App(Var(idx), expr)
                rem -= weight
                break
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return NConst(term)


# ---------------------------------------------------------------------------
# Observers
# ---------------------------------------------------------------------------
def make_obs_either() -> object:
    """Standard Either observer: print 'LEFT' or error string."""
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
    """Standard QD-style: quote the result, then write."""
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
    print("PROBE SYS8 AS CONTINUATION - Testing raw minted result terms")
    print(f"Target: {HOST}:{PORT}")
    print(
        "================================================================================\n"
    )

    tests = [
        ("P1:  (((readdir N0) 8) PSE)", g(5), int_term(0), g(8), PSE),
        ("P2:  (((readdir N43) 8) PSE)", g(5), int_term(43), g(8), PSE),
        ("P3:  (((backdoor nil) 8) PSE)", g(201), NIL, g(8), PSE),
        ("P4:  (((name N256) 8) PSE)", g(6), int_term(256), g(8), PSE),
        ("P5:  (((readfile N11) 8) PSE)", g(7), int_term(11), g(8), PSE),
        ("P6:  (((readfile N65) 8) PSE)", g(7), int_term(65), g(8), PSE),
        ("P7:  (((readdir N256) 8) PSE)", g(5), int_term(256), g(8), PSE),
        ("P8:  (((error_string N6) 8) PSE)", g(1), int_term(6), g(8), PSE),
        ("P9:  (((sys8 N0) 8) PSE)", g(8), int_term(0), g(8), PSE),
        ("C10: (((readdir N0) 4) PS)", g(5), int_term(0), g(4), PS),
        ("C11: (((backdoor nil) 4) PS)", g(201), NIL, g(4), PS),
        ("C12: (((name N256) 4) PS)", g(6), int_term(256), g(4), PS),
    ]

    for label, syscall, arg, middle_sys, obs in tests:
        term = apps(syscall, arg, middle_sys, obs)
        payload = build_payload(term)
        out = query(payload)
        c = classify(out)
        report(label, len(payload), c)
        time.sleep(0.4)


if __name__ == "__main__":
    run_tests()
