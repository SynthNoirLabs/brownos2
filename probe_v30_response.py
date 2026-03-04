#!/usr/bin/env python3
"""
probe_v30_response.py - Test probes suggested by external LLM analysis of v30

Key ideas:
  1. Bare 3-leaf programs (no QD/PSE) — testing for native C++ print side-effect
  2. "boss@evil.com" string — the mail recipient we never tried
  3. "00 FE FE" literal string
  4. sys4(Var(201)) disambiguation — does quote work on high-index globals?
  5. sys8(Left("ilikephp")) — does sys8 reject Either wrappers differently?
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

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


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


# Standard observer
def make_obs_either():
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


PSE = make_obs_either()


# ---------------------------------------------------------------------------
# Network helpers
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


def query_raw(payload, timeout_s=8.0):
    """Send raw bytes, return (response_bytes, close_time_ms)."""
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            t0 = time.monotonic()
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            resp = recv_all(sock, timeout_s=timeout_s)
            t1 = time.monotonic()
            return resp, int((t1 - t0) * 1000)
    except Exception as e:
        return f"ERROR: {e}".encode(), -1


def build_payload(term):
    db = to_db(term)
    enc = encode_term(db)
    return enc + bytes([FF])


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
        "QUOTE_FAIL\n",
        "Not a directory",
        "No such directory or file",
        "Unexpected exception",
        "Invalid argument",
        "Not so fast!",
        "Oh, go choke on a towel!",
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


def report(label, payload_hex, resp_bytes, ms, c):
    flag = (
        " *** BREAKTHROUGH ***"
        if c
        not in (
            "EMPTY",
            "TEXT:'Permission denied'",
            "TEXT:'Not implemented'",
            "TEXT:'Invalid term!'",
            "TEXT:'Encoding failed!'",
            "TEXT:'Term too big!'",
            "TEXT:'Invalid argument'",
            "TEXT:'ERR_DECODE_FAIL'",
        )
        and "ERROR:" not in c
        else ""
    )
    print(f"{label:55s} [{payload_hex:30s}] {ms:5d}ms -> {c}{flag}")


# ---------------------------------------------------------------------------
# PROBES
# ---------------------------------------------------------------------------
def run_probes():
    print("=" * 100)
    print("PROBE V30 RESPONSE — External LLM suggestions")
    print(f"Target: {HOST}:{PORT}")
    print("=" * 100)

    # ---- GROUP 1: Bare 3-leaf programs (no observer, testing for native C++ print) ----
    print("\n--- GROUP 1: Bare 3-leaf programs (hunting native C++ print) ---")

    bare_probes = [
        ("P1: ((quote V201) sys8)", bytes([0x04, 0xC9, FD, 0x08, FD, FF])),
        (
            "P2: ((quote (bd nil)) sys8)",
            bytes([0x04, 0xC9, 0x00, FE, FE, FD, FD, 0x08, FD, FF]),
        ),
        ("P3: ((echo V201) sys8)", bytes([0x0E, 0xC9, FD, 0x08, FD, FF])),
        ("P4: ((sys8 V0) V0)", bytes([0x08, 0x00, FD, 0x00, FD, FF])),
        ("P5: ((sys8 nil) nil)", bytes([0x08, 0x00, FE, FE, FD, 0x00, FE, FE, FD, FF])),
    ]

    for label, payload in bare_probes:
        resp, ms = query_raw(payload)
        c = classify(resp)
        report(label, payload[:-1].hex(), resp, ms, c)
        time.sleep(0.4)

    # ---- GROUP 2: New string arguments via standard CPS ----
    print("\n--- GROUP 2: New string arguments to sys8 ---")

    string_probes = [
        ("P6: sys8('boss@evil.com') PSE", "boss@evil.com"),
        ("P7: sys8('00 FE FE') PSE", "00 FE FE"),
        ("P8: sys8('mailer') PSE", "mailer"),
        ("P9: sys8('brownos') PSE", "brownos"),
        ("P10: sys8('boss') PSE", "boss"),
    ]

    for label, s in string_probes:
        term = apps(g(8), str_term(s), PSE)
        payload = build_payload(term)
        resp, ms = query_raw(payload)
        c = classify(resp)
        report(label, f"sz={len(payload)}", resp, ms, c)
        time.sleep(0.4)

    # ---- GROUP 3: Disambiguation probes ----
    print("\n--- GROUP 3: Disambiguation ---")

    # Does quote work on Var(201)?
    # ((quote Var(201)) QD) — quote the backdoor global itself
    p_q201 = bytes([0x04, 0xC9, FD]) + QD + bytes([FD, FF])
    resp, ms = query_raw(p_q201)
    c = classify(resp)
    report("P11: ((quote V201) QD)", p_q201[:-1].hex(), resp, ms, c)
    time.sleep(0.4)

    # Does quote work on Var(8)?
    p_q8 = bytes([0x04, 0x08, FD]) + QD + bytes([FD, FF])
    resp, ms = query_raw(p_q8)
    c = classify(resp)
    report("P12: ((quote V8) QD)", p_q8[:-1].hex(), resp, ms, c)
    time.sleep(0.4)

    # sys8 with Left-wrapped string — does it give Right(3) instead of Right(6)?
    left_ilikephp = NConst(Lam(Lam(App(Var(1), encode_bytes_list(b"ilikephp")))))
    term = apps(g(8), left_ilikephp, PSE)
    payload = build_payload(term)
    resp, ms = query_raw(payload)
    c = classify(resp)
    report("P13: sys8(Left('ilikephp')) PSE", f"sz={len(payload)}", resp, ms, c)
    time.sleep(0.4)

    # sys8 with Right-wrapped code — does error type change?
    right_6 = NConst(Lam(Lam(App(Var(0), encode_byte_term(6)))))
    term = apps(g(8), right_6, PSE)
    payload = build_payload(term)
    resp, ms = query_raw(payload)
    c = classify(resp)
    report("P14: sys8(Right(6)) PSE", f"sz={len(payload)}", resp, ms, c)
    time.sleep(0.4)

    # ---- GROUP 4: Bare 3-leaf with sys8 receiving quoted backdoor pair ----
    print("\n--- GROUP 4: More bare 3-leaf variants ---")

    # ((quote nil) sys8)
    p = bytes([0x04, 0x00, FE, FE, FD, 0x08, FD, FF])
    resp, ms = query_raw(p)
    c = classify(resp)
    report("P15: ((quote nil) sys8)", p[:-1].hex(), resp, ms, c)
    time.sleep(0.4)

    # ((readfile int11) sys8) — passwd content → sys8
    # We need int(11) encoded. 11 = 8+2+1, but as a simple Var at top level, Var(11) IS global 11.
    # Actually in bare 3-leaf: Var(7) = readfile, Var(11) is just global 11 (a stub).
    # For proper CPS: 07 <int(11)> FD 08 FD FF
    int11 = encode_byte_term(11)
    payload_rf = bytes([0x07]) + encode_term(int11) + bytes([FD, 0x08, FD, FF])
    resp, ms = query_raw(payload_rf)
    c = classify(resp)
    report("P16: ((readfile int11) sys8)", f"sz={len(payload_rf)}", resp, ms, c)
    time.sleep(0.4)


# ---------------------------------------------------------------------------
# HASH CANDIDATES (offline)
# ---------------------------------------------------------------------------
def sha1_iter(s, n):
    h = s.encode("utf-8")
    for _ in range(n):
        h = hashlib.sha1(h).digest()
    return h.hex()


def test_hash_candidates():
    print("\n" + "=" * 100)
    print("OFFLINE HASH CANDIDATES — sha1^56154(candidate) vs target")
    print("=" * 100)
    target = "9252ed65ffac2aa763adb21ef72c0178f1d83286"

    candidates = [
        "boss@evil.com",
        "00 FE FE",
        "De Bruijn",
        "debruijn",
        "de Bruijn",
        "De Bruijn OS",
        "BrownOS",
        "brownos",
        "Nicolaas Govert de Bruijn",
        "Term too big!",
        "04C9FD08FDFF",
        "lambda",
        "Lambda",
        "backdoor",
        "Backdoor",
        "permission denied",
        "Permission denied",
        "wtf",
        "Uhm... yeah... no...",
        "Not so fast!",
        "mailer@brownos",
        "evil",
        "sudo deluser dloser",
        "crypt",
        "nil",
        "false",
        "true",
        "K*",
        "Scott",
        "scott",
        "Church",
        "church",
        "CPS",
        "cps",
    ]

    for c in candidates:
        h = sha1_iter(c, 56154)
        match = "*** MATCH ***" if h == target else ""
        # Only print first/last few chars of hash to save space
        print(f"  {c:40s} -> {h[:12]}...{h[-12:]} {match}")


if __name__ == "__main__":
    run_probes()
    test_hash_candidates()
