#!/usr/bin/env python3
"""
probe_vfs_unlock.py — Test backdoor as VFS state-unlock + syntactic differential

Genuinely new axes from external LLM:
  H1: backdoor(nil) might flip a VFS permission flag. After calling it,
      readfile(8), readdir(0), or readfile(new_ids) might reveal hidden files.
  H2: Syntactic differential — sys8((λx.x)(nil)) vs sys8(nil) tests whether
      the VM normalizes before sys8 inspects.
  H3: Unwrapped readdir 3-way list → sys8 (with proper Either stripping)
  H4: Unwrapped access.log bytes → sys8 (with proper Either stripping)
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


def int_term(n):
    return NConst(encode_byte_term(n))


def str_term(s):
    return NConst(encode_bytes_list(s.encode("ascii", "replace")))


def write_str(s):
    return apps(g(2), str_term(s), NIL)


# QD as a named-term constant
def parse_qd():
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


QD_TERM = NConst(parse_qd())


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


# PS observer: quote and write
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


PSE = make_pse()
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
        "ERR_DECODE_FAIL",
        "LEFT\n",
        "LEFT:",
        "QFAIL\n",
        "Not a directory",
        "No such directory or file",
        "Unexpected exception",
        "Invalid argument",
        "Not so fast!",
        "Oh, go choke",
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
        "QFAIL",
        "Invalid argument",
        "ERR\n",
    ]
    return not any(b in c for b in boring)


def report(label, sz, c):
    flag = " *** NOVEL ***" if is_novel(c) else ""
    print(f"{label:70s} sz={sz:4d} -> {c}{flag}")


# ---------------------------------------------------------------------------
# GROUP 1: Backdoor VFS state-unlock
# ---------------------------------------------------------------------------
def group1_vfs_unlock():
    print("\n" + "=" * 90)
    print("GROUP 1: Backdoor VFS state-unlock — call backdoor then readfile/readdir")
    print("=" * 90)

    # Control first: readfile(8) WITHOUT backdoor — should fail
    ctrl = apps(g(7), int_term(8), PS)
    payload = build_payload(ctrl)
    out = query(payload)
    report("  CTRL: readfile(8) without backdoor", len(payload), classify(out))
    time.sleep(0.4)

    # P1: backdoor(nil) → ignore result → readfile(8) → PS
    # backdoor(nil)(λ_pair. readfile(8)(PS))(λ_err. write("BD_FAIL"))
    p1 = apps(
        g(201),
        NIL,
        lam("_pair", apps(g(7), int_term(8), PS)),
        lam("_err", write_str("BD_FAIL\n")),
    )
    payload = build_payload(p1)
    out = query(payload)
    report("  P1: backdoor(nil) → readfile(8) → PS", len(payload), classify(out))
    time.sleep(0.4)

    # P2: backdoor(nil) → ignore result → readdir(0) → PS
    p2 = apps(
        g(201),
        NIL,
        lam("_pair", apps(g(5), int_term(0), PS)),
        lam("_err", write_str("BD_FAIL\n")),
    )
    payload = build_payload(p2)
    out = query(payload)
    report("  P2: backdoor(nil) → readdir(0) → PS", len(payload), classify(out))
    time.sleep(0.4)

    # P3: backdoor(nil) → ignore → readfile(7) (readfile itself) → PS
    p3 = apps(
        g(201),
        NIL,
        lam("_pair", apps(g(7), int_term(7), PS)),
        lam("_err", write_str("BD_FAIL\n")),
    )
    payload = build_payload(p3)
    out = query(payload)
    report("  P3: backdoor(nil) → readfile(7) → PS", len(payload), classify(out))
    time.sleep(0.4)

    # P4: backdoor(nil) → ignore → sys8(nil) → PSE
    p4 = apps(
        g(201),
        NIL,
        lam("_pair", apps(g(8), NIL, PSE)),
        lam("_err", write_str("BD_FAIL\n")),
    )
    payload = build_payload(p4)
    out = query(payload)
    report("  P4: backdoor(nil) → sys8(nil) → PSE", len(payload), classify(out))
    time.sleep(0.4)

    # P5: backdoor(nil) → ignore → sys8("ilikephp") → PSE
    p5 = apps(
        g(201),
        NIL,
        lam("_pair", apps(g(8), str_term("ilikephp"), PSE)),
        lam("_err", write_str("BD_FAIL\n")),
    )
    payload = build_payload(p5)
    out = query(payload)
    report("  P5: backdoor(nil) → sys8('ilikephp') → PSE", len(payload), classify(out))
    time.sleep(0.4)

    # P6: backdoor(nil) → USE pair → sys8(pair) → PSE
    p6 = apps(
        g(201),
        NIL,
        lam("pair", apps(g(8), v("pair"), PSE)),
        lam("_err", write_str("BD_FAIL\n")),
    )
    payload = build_payload(p6)
    out = query(payload)
    report("  P6: backdoor(nil) → sys8(pair_result) → PSE", len(payload), classify(out))
    time.sleep(0.4)

    # P7: backdoor(nil) → ignore → readfile(256) → PS (hidden file after unlock?)
    p7 = apps(
        g(201),
        NIL,
        lam("_pair", apps(g(7), int_term(256), PS)),
        lam("_err", write_str("BD_FAIL\n")),
    )
    payload = build_payload(p7)
    out = query(payload)
    report("  P7: backdoor(nil) → readfile(256) → PS", len(payload), classify(out))
    time.sleep(0.4)


# ---------------------------------------------------------------------------
# GROUP 2: Syntactic differential — does VM normalize before sys8?
# ---------------------------------------------------------------------------
def group2_syntactic_diff():
    print("\n" + "=" * 90)
    print(
        "GROUP 2: Syntactic differential — sys8(semantically-same, syntactically-different)"
    )
    print("=" * 90)

    I_COMB = lam("x", v("x"))  # λx.x

    diffs = [
        ("sys8(nil)", NIL),
        ("sys8((I nil))", apps(I_COMB, NIL)),
        ("sys8((K* g201 nil))", apps(lam("_a", lam("_b", v("_b"))), g(201), NIL)),
        ("sys8(Lam(Lam(Var(0))))", NIL),  # same as nil, control
        ("sys8((I (I nil)))", apps(I_COMB, apps(I_COMB, NIL))),
    ]

    for label, arg in diffs:
        term = apps(g(8), arg, PSE)
        payload = build_payload(term)
        out = query(payload)
        report(f"  D2: {label}", len(payload), classify(out))
        time.sleep(0.35)


# ---------------------------------------------------------------------------
# GROUP 3: Unwrapped readdir/readfile → sys8 (proper Either stripping)
# ---------------------------------------------------------------------------
def group3_unwrapped_to_sys8():
    print("\n" + "=" * 90)
    print("GROUP 3: Unwrapped readdir/readfile → sys8 (proper Either strip)")
    print("=" * 90)

    # readdir(0)(λdirlist. sys8(dirlist)(PSE))(λerr. write("RD_ERR"))
    p1 = apps(
        g(5),
        int_term(0),
        lam("dirlist", apps(g(8), v("dirlist"), PSE)),
        lam("_err", write_str("RD_ERR\n")),
    )
    payload = build_payload(p1)
    out = query(payload)
    report("  U3: readdir(0) → unwrap → sys8(3way_list)", len(payload), classify(out))
    time.sleep(0.4)

    # readfile(46)(λlogbytes. sys8(logbytes)(PSE))(λerr. write("RF_ERR"))
    p2 = apps(
        g(7),
        int_term(46),
        lam("logbytes", apps(g(8), v("logbytes"), PSE)),
        lam("_err", write_str("RF_ERR\n")),
    )
    payload = build_payload(p2)
    out = query(payload)
    report(
        "  U3: readfile(46) → unwrap → sys8(access_log)", len(payload), classify(out)
    )
    time.sleep(0.4)

    # readfile(11)(λpasswd. sys8(passwd)(PSE))(λerr. write("RF_ERR"))
    p3 = apps(
        g(7),
        int_term(11),
        lam("passwd", apps(g(8), v("passwd"), PSE)),
        lam("_err", write_str("RF_ERR\n")),
    )
    payload = build_payload(p3)
    out = query(payload)
    report("  U3: readfile(11) → unwrap → sys8(passwd)", len(payload), classify(out))
    time.sleep(0.4)

    # readfile(88)(λmail. sys8(mail)(PSE))(λerr. write("RF_ERR"))
    p4 = apps(
        g(7),
        int_term(88),
        lam("mail", apps(g(8), v("mail"), PSE)),
        lam("_err", write_str("RF_ERR\n")),
    )
    payload = build_payload(p4)
    out = query(payload)
    report("  U3: readfile(88) → unwrap → sys8(mail)", len(payload), classify(out))
    time.sleep(0.4)

    # readfile(65)(λhistory. sys8(history)(PSE))(λerr. ...)
    p5 = apps(
        g(7),
        int_term(65),
        lam("hist", apps(g(8), v("hist"), PSE)),
        lam("_err", write_str("RF_ERR\n")),
    )
    payload = build_payload(p5)
    out = query(payload)
    report("  U3: readfile(65) → unwrap → sys8(history)", len(payload), classify(out))
    time.sleep(0.4)


def main():
    print("=" * 90)
    print("PROBE VFS UNLOCK + SYNTACTIC DIFF + UNWRAPPED ARGS")
    print(f"Target: {HOST}:{PORT}")
    print("=" * 90)

    group1_vfs_unlock()
    group2_syntactic_diff()
    group3_unwrapped_to_sys8()

    print("\n" + "=" * 90)
    print("DONE")
    print("=" * 90)


if __name__ == "__main__":
    main()
