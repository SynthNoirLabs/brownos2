#!/usr/bin/env python3
"""
probe_v34_combined.py — Combined probes from both external LLM responses to v34

Group 1: Poisoned-ADT ladder (fingerprint sys8's internal decoder)
Group 2: Stateful backdoor→sys8 with passwords in same CPS chain
Group 3: Bare 3-leaf programs + post-state diff
Group 4: Hash submissions (bytecode hex strings)
"""

from __future__ import annotations

import hashlib
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


def str_term(s):
    return NConst(encode_bytes_list(s.encode("ascii", "replace")))


def int_term(n):
    return NConst(encode_byte_term(n))


def write_str(s):
    return apps(g(2), str_term(s), NIL)


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


QD = NConst(parse_qd())

# Omega (diverges when evaluated)
OMEGA = apps(lam("x", apps(v("x"), v("x"))), lam("x", apps(v("x"), v("x"))))


# Standard PSE
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


# PSE that writes Left payload via quote
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
                    lam("_e2", write_str("ERR\n")),
                ),
            ),
        ),
    )
    left_h = lam(
        "lp",
        apps(
            g(4),
            v("lp"),
            lam("qb", apps(g(2), v("qb"), NIL)),
            lam("_qe", write_str("QFAIL\n")),
        ),
    )
    return lam("r", apps(v("r"), left_h, right_h))


PSE = make_pse()
PSE_V = make_pse_verbose()


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
def recv_all(sock, timeout_s=10.0):
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


def query(payload, timeout_s=10.0):
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
    return f"HEX:{out[:120].hex()}"


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


def report(label, sz, c, time_ms=0):
    flag = " *** NOVEL ***" if is_novel(c) else ""
    t = f" ({time_ms}ms)" if time_ms else ""
    print(f"{label:70s} sz={sz:4d}{t} -> {c}{flag}")


# ---------------------------------------------------------------------------
# GROUP 1: Poisoned-ADT ladder
# ---------------------------------------------------------------------------
def group1_poisoned_adt():
    print("\n" + "=" * 90)
    print("GROUP 1: Poisoned-ADT ladder — fingerprint sys8's internal decoder")
    print("=" * 90)

    probes = [
        # 9-lambda int shell with omega body
        (
            "sys8(λ^9. Ω) — poisoned int",
            apps(
                g(8),
                lam(
                    "v1",
                    lam(
                        "v2",
                        lam(
                            "v3",
                            lam(
                                "v4",
                                lam(
                                    "v5",
                                    lam("v6", lam("v7", lam("v8", lam("v0", OMEGA)))),
                                ),
                            ),
                        ),
                    ),
                ),
                PSE,
            ),
        ),
        # 2-lambda list shell with omega
        (
            "sys8(λc.λn. Ω) — poisoned 2-way list",
            apps(g(8), lam("c", lam("n", OMEGA)), PSE),
        ),
        # 3-lambda dirlist shell with omega
        (
            "sys8(λd.λf.λn. Ω) — poisoned 3-way dirlist",
            apps(g(8), lam("d", lam("f", lam("n", OMEGA))), PSE),
        ),
        # 2-lambda Either shell with omega
        (
            "sys8(λl.λr. Ω) — poisoned Either",
            apps(g(8), lam("l", lam("r", OMEGA)), PSE),
        ),
        # 9-lambda body that looks like int(1) but tail is omega
        (
            "sys8(λ^9. V1(Ω)) — poisoned int body",
            apps(
                g(8),
                lam(
                    "v1",
                    lam(
                        "v2",
                        lam(
                            "v3",
                            lam(
                                "v4",
                                lam(
                                    "v5",
                                    lam(
                                        "v6",
                                        lam(
                                            "v7",
                                            lam("v8", lam("v0", apps(v("v1"), OMEGA))),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
                PSE,
            ),
        ),
        # 2-way list that looks like cons(byte0, omega)
        (
            "sys8(λc.λn. c(byte0)(Ω)) — poisoned cons",
            apps(g(8), lam("c", lam("n", apps(v("c"), int_term(0), OMEGA))), PSE),
        ),
    ]

    for label, term in probes:
        payload = build_payload(term)
        if len(payload) > 1900:
            print(f"  SKIP: {label} (payload {len(payload)} bytes)")
            continue
        t0 = time.monotonic()
        out = query(payload, timeout_s=12.0)
        ms = int((time.monotonic() - t0) * 1000)
        c = classify(out)
        report(f"  A1: {label}", len(payload), c, ms)
        time.sleep(0.4)

    # Controls: known consumers with same poisoned shapes
    print("\n  --- Controls ---")

    # write(poisoned 2-way list) — should hang if write descends the list
    ctrl1 = apps(g(2), lam("c", lam("n", OMEGA)), NIL)
    payload = build_payload(ctrl1)
    t0 = time.monotonic()
    out = query(payload, timeout_s=12.0)
    ms = int((time.monotonic() - t0) * 1000)
    report(f"  CTRL: write(λc.λn.Ω)", len(payload), classify(out), ms)
    time.sleep(0.4)

    # readfile(poisoned int) — should hang if readfile descends the int
    ctrl2 = apps(
        g(7),
        lam(
            "v1",
            lam(
                "v2",
                lam(
                    "v3",
                    lam(
                        "v4",
                        lam("v5", lam("v6", lam("v7", lam("v8", lam("v0", OMEGA))))),
                    ),
                ),
            ),
        ),
        PSE,
    )
    payload = build_payload(ctrl2)
    t0 = time.monotonic()
    out = query(payload, timeout_s=12.0)
    ms = int((time.monotonic() - t0) * 1000)
    report(f"  CTRL: readfile(λ^9.Ω)", len(payload), classify(out), ms)
    time.sleep(0.4)


# ---------------------------------------------------------------------------
# GROUP 2: Stateful backdoor → sys8 with passwords
# ---------------------------------------------------------------------------
def group2_stateful_chain():
    print("\n" + "=" * 90)
    print("GROUP 2: Stateful backdoor→password→sys8 chain")
    print("=" * 90)

    passwords = [
        ("ilikephp", "ilikephp"),
        ("boss@evil.com", "boss@evil.com"),
        ("gizmore", "gizmore"),
        ("root", "root"),
        ("nil", None),  # will use NIL term
    ]

    for label, pwd in passwords:
        if pwd is None:
            pwd_term = NIL
        else:
            pwd_term = str_term(pwd)

        # backdoor(nil)(λ_pair. sys8(pwd)(PSE))(λ_err. write("BD_FAIL"))
        term = apps(
            g(201),
            NIL,
            lam("_pair", apps(g(8), pwd_term, PSE)),
            lam("_err", write_str("BD_FAIL\n")),
        )
        payload = build_payload(term)
        if len(payload) > 1900:
            print(f"  SKIP: backdoor→sys8('{label}') (payload {len(payload)} bytes)")
            continue
        t0 = time.monotonic()
        out = query(payload, timeout_s=12.0)
        ms = int((time.monotonic() - t0) * 1000)
        c = classify(out)
        report(f"  S2: backdoor→sys8('{label}') PSE", len(payload), c, ms)
        time.sleep(0.4)

    # Also test with verbose PSE (prints Left payload if any)
    print("\n  --- Verbose observer (prints Left payload) ---")
    for label, pwd in [("ilikephp", "ilikephp"), ("nil", None)]:
        if pwd is None:
            pwd_term = NIL
        else:
            pwd_term = str_term(pwd)

        term = apps(
            g(201),
            NIL,
            lam("_pair", apps(g(8), pwd_term, PSE_V)),
            lam("_err", write_str("BD_FAIL\n")),
        )
        payload = build_payload(term)
        if len(payload) > 1900:
            print(f"  SKIP: verbose backdoor→sys8('{label}')")
            continue
        t0 = time.monotonic()
        out = query(payload, timeout_s=12.0)
        ms = int((time.monotonic() - t0) * 1000)
        c = classify(out)
        report(f"  S2v: backdoor→sys8('{label}') PSE_V", len(payload), c, ms)
        time.sleep(0.4)

    # Stateful chain: backdoor→readdir(0)→QD (check if VFS changes)
    print("\n  --- Post-backdoor VFS check with QD ---")
    term = apps(
        g(201),
        NIL,
        lam("_pair", apps(g(5), int_term(0), QD)),
        lam("_err", write_str("BD_FAIL\n")),
    )
    payload = build_payload(term)
    t0 = time.monotonic()
    out = query(payload, timeout_s=12.0)
    ms = int((time.monotonic() - t0) * 1000)
    c = classify(out)
    report(f"  S2d: backdoor→readdir(0)→QD", len(payload), c, ms)
    time.sleep(0.4)

    # Control: readdir(0)→QD WITHOUT backdoor
    ctrl = apps(g(5), int_term(0), QD)
    payload = build_payload(ctrl)
    t0 = time.monotonic()
    out_ctrl = query(payload, timeout_s=12.0)
    ms = int((time.monotonic() - t0) * 1000)
    c_ctrl = classify(out_ctrl)
    report(f"  CTRL: readdir(0)→QD no backdoor", len(payload), c_ctrl, ms)

    if out == out_ctrl:
        print("  >>> readdir output IDENTICAL with/without backdoor")
    else:
        print("  >>> readdir output DIFFERS! *** NOVEL ***")
    time.sleep(0.4)


# ---------------------------------------------------------------------------
# GROUP 3: Bare 3-leaf programs
# ---------------------------------------------------------------------------
def group3_bare_3leaf():
    print("\n" + "=" * 90)
    print("GROUP 3: Bare 3-leaf programs ((backdoor nil) X)")
    print("=" * 90)

    # Test ((201 nil) X) for key syscall values
    targets = [0, 1, 2, 4, 5, 6, 7, 8, 9, 14, 42, 201]
    for x in targets:
        # Build raw: C9 00 FE FE FD <x> FD FF
        nil_bytes = bytes([0x00, FE, FE])
        payload = bytes([0xC9]) + nil_bytes + bytes([FD, x, FD, FF])
        t0 = time.monotonic()
        out = query(payload, timeout_s=10.0)
        ms = int((time.monotonic() - t0) * 1000)
        c = classify(out)
        report(f"  B3: ((201 nil) {x})", len(payload), c, ms)
        time.sleep(0.35)


# ---------------------------------------------------------------------------
# GROUP 4: Hash submissions
# ---------------------------------------------------------------------------
def sha1_iter(s, n):
    h = s.encode("utf-8") if isinstance(s, str) else s
    for _ in range(n):
        h = hashlib.sha1(h).digest()
    return h.hex()


def group4_hash():
    print("\n" + "=" * 90)
    print("GROUP 4: Offline hash candidates (bytecode hex strings)")
    print("=" * 90)
    target = "9252ed65ffac2aa763adb21ef72c0178f1d83286"

    candidates = [
        "c900fefefd08fdff",
        "C900FEFEFD08FDFF",
        "c900fefefd04fdff",
        "c900fefefd02fdff",
        "c900fefefd05fdff",
        "c900fefefd07fdff",
        "c9 00 fe fe fd 08 fd ff",
        "010000fdfefefd0100fdfefefdfefe",
        "boss@evil.com:ilikephp",
        "visit things",
        "3 leafs",
        "3 leaves",
        "three leafs",
        "three leaves",
        "dark magic",
    ]

    for c in candidates:
        h = sha1_iter(c, 56154)
        match = "*** MATCH ***" if h == target else ""
        print(f"  {c:45s} -> {h[:12]}...{h[-12:]} {match}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 90)
    print("PROBE V34 COMBINED — Poisoned ADT + Stateful chains + 3-leaf + Hash")
    print(f"Target: {HOST}:{PORT}")
    print("=" * 90)

    group1_poisoned_adt()
    group2_stateful_chain()
    group3_bare_3leaf()
    group4_hash()

    print("\n" + "=" * 90)
    print("DONE")
    print("=" * 90)


if __name__ == "__main__":
    main()
