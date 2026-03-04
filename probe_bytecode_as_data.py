#!/usr/bin/env python3
"""
probe_bytecode_as_data.py — Test if sys8 wants BrownOS bytecode as a Scott byte-list

Hypothesis: sys8 is a code verifier/loader. It expects a Scott-encoded byte-list
whose contents are valid BrownOS bytecode. This is fundamentally different from
passing AST values — we're passing the raw hex of programs AS DATA.

Group 1: Direct bytes-as-code (encode_bytes_list of raw bytecodes → sys8)
Group 2: quote(T) → sys8 pipeline (quote produces Left(bytes), feed to sys8)
Group 3: Echo impossible-index diagnostics
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

QD_raw = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


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
KSTAR = NIL


def str_term(s):
    return NConst(encode_bytes_list(s.encode("ascii", "replace")))


def bytes_term(bs: bytes) -> NConst:
    """Encode raw bytes as a Scott byte-list term."""
    return NConst(encode_bytes_list(bs))


def write_str(s):
    return apps(g(2), str_term(s), NIL)


# Standard Either observer
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
                    lam("_e2", write_str("ERR_DECODE_FAIL\n")),
                ),
            ),
        ),
    )
    left_h = lam("_lp", write_str("LEFT\n"))
    return lam("r", apps(v("r"), left_h, right_h))


# PSE that prints the Left payload length indicator
def make_pse_verbose():
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
    left_h = lam(
        "lp",
        apps(
            g(2),
            str_term("LEFT:"),
            lam(
                "_w",
                apps(
                    g(4),
                    v("lp"),
                    lam("qb", apps(g(2), v("qb"), NIL)),
                    lam("_qe", write_str("QUOTE_FAIL\n")),
                ),
            ),
        ),
    )
    return lam("r", apps(v("r"), left_h, right_h))


PSE = make_pse()
PSE_V = make_pse_verbose()


# CPS adapter: unwrap Left, pass to sys8
# C_sys8 = λr. r(sys8)(K*)
def make_c_sys8():
    return lam("r", apps(v("r"), g(8), KSTAR))


C_SYS8 = make_c_sys8()


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
    for _ in range(4):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s=timeout_s)
        except Exception as e:
            time.sleep(delay)
            delay = min(delay * 2, 2.0)
    return b"ERROR"


def build_payload(term):
    db = to_db(term)
    return encode_term(db) + bytes([FF])


def classify(out):
    if not out:
        return "EMPTY"
    known = [
        "Invalid term!",
        "Encoding failed!",
        "Term too big!",
        "Permission denied",
        "Not implemented",
        "ERR_DECODE_FAIL",
        "LEFT\n",
        "LEFT:",
        "QUOTE_FAIL\n",
        "Not a directory",
        "No such directory or file",
        "Unexpected exception",
        "Invalid argument",
        "Not so fast!",
        "Oh, go choke",
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


def is_novel(c):
    boring = [
        "Permission denied",
        "EMPTY",
        "Invalid term!",
        "Encoding failed!",
        "Term too big!",
        "ERROR",
        "ERR_DECODE_FAIL",
        "Not implemented",
        "QUOTE_FAIL",
        "Invalid argument",
    ]
    return not any(b in c for b in boring)


def report(label, sz, c):
    flag = " *** NOVEL ***" if is_novel(c) else ""
    print(f"{label:65s} sz={sz:4d} -> {c}{flag}")


# ---------------------------------------------------------------------------
# GROUP 1: Raw bytecode as Scott byte-list → sys8
# ---------------------------------------------------------------------------
def group1_bytes_as_code():
    print("\n" + "=" * 90)
    print("GROUP 1: sys8(encode_bytes_list(raw_bytecode)) — code-as-data")
    print("=" * 90)

    # The bytecodes we'll encode as Scott byte-lists and pass to sys8
    bytecodes = [
        ("QD without FF", QD_raw),
        ("QD with FF", QD_raw + bytes([FF])),
        ("nil program (00 FE FE)", bytes([0x00, FE, FE])),
        ("nil program + FF", bytes([0x00, FE, FE, FF])),
        ("backdoor(nil) call", bytes([0xC9, 0x00, FE, FE, FD])),
        ("backdoor(nil) call + FF", bytes([0xC9, 0x00, FE, FE, FD, FF])),
        ("((sys8 nil) QD)", bytes([0x08, 0x00, FE, FE, FD]) + QD_raw + bytes([FD])),
        (
            "((sys8 nil) QD) + FF",
            bytes([0x08, 0x00, FE, FE, FD]) + QD_raw + bytes([FD, FF]),
        ),
        ("((readdir 0) QD)", bytes([0x05, 0x00, FD]) + QD_raw + bytes([FD])),
        ("((readdir 0) QD) + FF", bytes([0x05, 0x00, FD]) + QD_raw + bytes([FD, FF])),
        (
            "((bd nil) QD) + FF",
            bytes([0xC9, 0x00, FE, FE, FD]) + QD_raw + bytes([FD, FF]),
        ),
        ("single byte 0x08", bytes([0x08])),
        ("single byte 0xC9", bytes([0xC9])),
        ("empty bytes", bytes([])),
    ]

    for label, bc in bytecodes:
        term = apps(g(8), bytes_term(bc), PSE)
        payload = build_payload(term)
        if len(payload) > 1900:
            print(f"  {label:55s} SKIPPED (payload {len(payload)} bytes > limit)")
            continue
        out = query(payload)
        c = classify(out)
        report(f"  B1: sys8(bytes({label}))", len(payload), c)
        time.sleep(0.35)


# ---------------------------------------------------------------------------
# GROUP 2: quote(T) → C_sys8 → PSE pipeline
# ---------------------------------------------------------------------------
def group2_quote_to_sys8():
    print("\n" + "=" * 90)
    print("GROUP 2: quote(T) → unwrap Left → sys8(quoted_bytes) → PSE")
    print("=" * 90)

    # quote(T) returns Left(bytes). C_sys8 unwraps Left and passes bytes to sys8.
    # Then PSE observes sys8's result.
    targets = [
        ("NIL", NIL),
        ("QD term", NConst(parse_qd())),
        (
            "pair(A,B)",
            NConst(
                Lam(
                    App(
                        App(Var(0), Lam(Lam(App(Var(0), Var(0))))),
                        Lam(Lam(App(Var(1), Var(0)))),
                    )
                )
            ),
        ),
        ("B combinator", NConst(Lam(Lam(App(Var(1), Var(0)))))),
        ("A combinator", NConst(Lam(Lam(App(Var(0), Var(0)))))),
        ("int(0)", NConst(encode_byte_term(0))),
        ("int(8)", NConst(encode_byte_term(8))),
        ("int(201)", NConst(encode_byte_term(201))),
        ("Var(8) raw", NConst(Var(8))),
        ("Var(201) raw", NConst(Var(201))),
    ]

    for label, target_term in targets:
        # ((quote target) C_sys8) PSE
        # But C_sys8 only unwraps Left. We need a full chain:
        # quote(target)(λbytes. sys8(bytes)(PSE))(λerr. write("QFAIL"))
        obs = lam(
            "qr",
            apps(
                v("qr"),
                lam(
                    "qbytes", apps(g(8), v("qbytes"), PSE)
                ),  # Left handler: sys8(bytes)
                lam("_qerr", write_str("QUOTE_ERR\n")),  # Right handler
            ),
        )
        term = apps(g(4), target_term, obs)
        payload = build_payload(term)
        if len(payload) > 1900:
            print(f"  {label:55s} SKIPPED (payload {len(payload)} bytes > limit)")
            continue
        out = query(payload)
        c = classify(out)
        report(f"  Q2: quote({label}) → sys8", len(payload), c)
        time.sleep(0.35)


# ---------------------------------------------------------------------------
# GROUP 3: Echo impossible-index diagnostics
# ---------------------------------------------------------------------------
def group3_echo_impossible():
    print("\n" + "=" * 90)
    print("GROUP 3: Echo impossible-index diagnostics (minted Var(251..252) → sys8)")
    print("=" * 90)

    # echo(Var(251)) → sys8  (via CPS chain, unwrap Left)
    for var_idx in [251, 252]:
        # echo(Var(idx))(λeRes. eRes(λpayload. sys8(payload)(PSE))(λ_. write("ECHO_R")))
        obs = lam(
            "er",
            apps(
                v("er"),
                lam("ep", apps(g(8), v("ep"), PSE)),  # Left: sys8(echoed_payload)
                lam("_ee", write_str("ECHO_RIGHT\n")),  # Right
            ),
        )
        term = apps(g(14), NConst(Var(var_idx)), obs)
        payload = build_payload(term)
        out = query(payload)
        c = classify(out)
        report(f"  E3: echo(V{var_idx}) → sys8(payload)", len(payload), c)
        time.sleep(0.35)

    # Controls: echo(Var(251/252)) → quote(payload) — does quote crash?
    for var_idx in [251, 252]:
        obs = lam(
            "er",
            apps(
                v("er"),
                lam(
                    "ep",
                    apps(
                        g(4),
                        v("ep"),
                        lam("qb", apps(g(2), v("qb"), NIL)),
                        lam("_qe", write_str("ENCODING_FAILED\n")),
                    ),
                ),
                lam("_ee", write_str("ECHO_RIGHT\n")),
            ),
        )
        term = apps(g(14), NConst(Var(var_idx)), obs)
        payload = build_payload(term)
        out = query(payload)
        c = classify(out)
        report(f"  E3c: echo(V{var_idx}) → quote(payload)", len(payload), c)
        time.sleep(0.35)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def parse_qd():
    """Parse QD bytes into AST."""
    stack = []
    for b in QD_raw:
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            stack.append(Lam(stack.pop()))
        else:
            stack.append(Var(b))
    return stack[0]


def main():
    print("=" * 90)
    print("PROBE BYTECODE AS DATA — Testing sys8 as code verifier/loader")
    print(f"Target: {HOST}:{PORT}")
    print("=" * 90)

    group1_bytes_as_code()
    group2_quote_to_sys8()
    group3_echo_impossible()

    print("\n" + "=" * 90)
    print("DONE")
    print("=" * 90)


if __name__ == "__main__":
    main()
