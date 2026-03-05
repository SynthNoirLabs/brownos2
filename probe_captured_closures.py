#!/usr/bin/env python3
"""
probe_captured_closures.py — Testing the environment-carrying closure theory

Hypothesis: sys8 accepts a runtime closure whose environment captures the backdoor pair.
This is distinct from passing the raw pair as a closed term.
A shallow gate can inspect the closure object's environment without applying it or
descending into its body.

Key tests:
1. `sys8(λx. pair(A,B))` (literal closed term)
2. `backdoor(nil)(λp. sys8(λx. p))` (captured closure)
3. Different captured values: `A`, `B`, `string`, `nil`
4. Arity shell variants: `λx. p`, `λx.λy. p`, `λx.λy. y(p)`
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
A = NConst(Lam(Lam(App(Var(0), Var(0)))))
B = NConst(Lam(Lam(App(Var(1), Var(0)))))
PAIR_AB = NConst(Lam(App(App(Var(0), A.term), B.term)))


def str_term(s):
    return NConst(encode_bytes_list(s.encode("ascii", "replace")))


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
                    lam("_e2", write_str("ERR\n")),
                ),
            ),
        ),
    )
    left_h = lam("_lp", write_str("LEFT\n"))
    return lam("r", apps(v("r"), left_h, right_h))


PSE = make_pse()


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
                t0 = time.monotonic()
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                resp = recv_all(sock, timeout_s=timeout_s)
                return resp, int((time.monotonic() - t0) * 1000)
        except Exception:
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
        "LEFT\n",
        "No such directory or file",
        "Not a directory",
        "Not a file",
        "Unexpected exception",
        "Invalid argument",
        "Not so fast!",
        "ERR\n",
    ]
    for t in known:
        if out.startswith(t.encode("ascii")):
            return f"TEXT:{t!r}"
    try:
        text = out.decode("utf-8", "replace")
        if all((ch == "\n") or (32 <= ord(ch) < 127) for ch in text):
            return f"TEXT:{text.strip()!r}"
    except:
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
        "Not implemented",
        "Invalid argument",
        "Not a directory",
        "No such directory or file",
        "Not a file",
        "ERR\n",
    ]
    flag = " *** NOVEL ***" if not any(b in c for b in boring) else ""
    print(f"{label:65s} sz={sz:4d} {ms:5d}ms -> {c}{flag}")


# ---------------------------------------------------------------------------
# GROUP A: Closure-capability core
# ---------------------------------------------------------------------------
def group_a_closure_core():
    print("\n" + "=" * 90)
    print("GROUP A: Closure-capability core — literal vs captured")
    print("=" * 90)

    # 1. Literal closed term: sys8(λx. pair(A,B))
    term1 = apps(g(8), lam("x", PAIR_AB), PSE)
    p1 = build_payload(term1)
    o1, m1 = query(p1)
    report("  A1: sys8(λx. literal_pair)", len(p1), classify(o1), m1)
    time.sleep(0.3)

    # 2. Captured closure: backdoor(nil)(λp. sys8(λx. p)(PSE))
    term2 = apps(
        g(201),
        NIL,
        lam("p", apps(g(8), lam("x", v("p")), PSE)),
        lam("_e", write_str("BD_FAIL\n")),
    )
    p2 = build_payload(term2)
    o2, m2 = query(p2)
    report(
        "  A2: backdoor(nil)(λp. sys8(λx. p)) — captured pair",
        len(p2),
        classify(o2),
        m2,
    )
    time.sleep(0.3)

    # 3. Trivial lambda control: sys8(λx. x)
    term3 = apps(g(8), lam("x", v("x")), PSE)
    p3 = build_payload(term3)
    o3, m3 = query(p3)
    report("  A3: sys8(λx. x)", len(p3), classify(o3), m3)
    time.sleep(0.3)


# ---------------------------------------------------------------------------
# GROUP B: Same body, different environment
# ---------------------------------------------------------------------------
def group_b_captured_values():
    print("\n" + "=" * 90)
    print("GROUP B: Same λ-body, different captured values")
    print("=" * 90)

    # Build: (λval. sys8(λx. val)(PSE))(target_value)
    def test_captured(val_term, label):
        term = apps(lam("val", apps(g(8), lam("x", v("val")), PSE)), val_term)
        p = build_payload(term)
        o, m = query(p)
        report(f"  B: capture({label})", len(p), classify(o), m)
        time.sleep(0.3)

    test_captured(PAIR_AB, "literal_pair")
    test_captured(A, "combinator_A")
    test_captured(B, "combinator_B")
    test_captured(str_term("ilikephp"), "string")
    test_captured(NIL, "nil")


# ---------------------------------------------------------------------------
# GROUP C: Arity shell variants of the same captured env
# ---------------------------------------------------------------------------
def group_c_arity_variants():
    print("\n" + "=" * 90)
    print("GROUP C: Arity shell variants capturing the backdoor pair")
    print("=" * 90)

    # λx. p
    term1 = apps(
        g(201),
        NIL,
        lam("p", apps(g(8), lam("x", v("p")), PSE)),
        lam("_e", write_str("BD_FAIL\n")),
    )

    # λx. λy. p
    term2 = apps(
        g(201),
        NIL,
        lam("p", apps(g(8), lam("x", lam("y", v("p"))), PSE)),
        lam("_e", write_str("BD_FAIL\n")),
    )

    # λx. λy. y p
    term3 = apps(
        g(201),
        NIL,
        lam("p", apps(g(8), lam("x", lam("y", apps(v("y"), v("p")))), PSE)),
        lam("_e", write_str("BD_FAIL\n")),
    )

    for idx, term in enumerate([term1, term2, term3], 1):
        p = build_payload(term)
        o, m = query(p)
        lbl = ["λx. p", "λx. λy. p", "λx. λy. y p"][idx - 1]
        report(f"  C{idx}: backdoor(nil) → sys8({lbl})", len(p), classify(o), m)
        time.sleep(0.3)


def main():
    print("=" * 90)
    print("PROBE CAPTURED CLOSURES — Testing runtime-only capability objects")
    print(f"Target: {HOST}:{PORT}")
    print("=" * 90)

    group_a_closure_core()
    group_b_captured_values()
    group_c_arity_variants()

    print("\n" + "=" * 90 + "\nDONE\n" + "=" * 90)


if __name__ == "__main__":
    main()
