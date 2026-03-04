#!/usr/bin/env python3
"""
probe_v35_whnf.py — WHNF shell census + path-valid poisons + pair-applied + full 3-leaf sweep

Key insight from external LLM: our poisoned-ADT controls were flawed.
EMPTY from controls doesn't distinguish "didn't inspect" from "inspected and rejected silently."
We need path-valid poisons and better controls.

Group 1: WHNF shell census — sys8 with varying lambda depths and minimal bodies
Group 2: Path-valid poisons — terms that look correct to a shallow decoder but diverge deeper
Group 3: Pair(A,B) applied to syscalls — backdoor(nil)(λp. p(X))
Group 4: Full ((201 nil) X) sweep for X=0..252 (checking timing + output)
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
# Named-term DSL (same as prior probes)
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


# PSE that also handles specific error codes
def make_pse_detail():
    """Observer that prints error CODE number, not just string."""
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
                    lam("_e2", write_str("ERR_DECODE\n")),
                ),
            ),
            lam("_e1", write_str("ERRSTR_FAIL\n")),
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
                    lam("_qe", write_str("QFAIL\n")),
                ),
            ),
        ),
    )
    return lam("r", apps(v("r"), left_h, right_h))


PSE_D = make_pse_detail()


# Simple PSE
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
        "LEFT:",
        "LEFT\n",
        "QFAIL\n",
        "Not a directory",
        "No such directory or file",
        "Unexpected exception",
        "Invalid argument",
        "Not so fast!",
        "Oh, go choke",
        "ERR\n",
        "ERRSTR_FAIL",
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
        "ERR_DECODE",
        "Not implemented",
        "QFAIL",
        "Invalid argument",
        "ERR\n",
        "ERRSTR_FAIL",
    ]
    flag = " *** NOVEL ***" if not any(b in c for b in boring) else ""
    print(f"{label:65s} sz={sz:4d} {ms:5d}ms -> {c}{flag}")


# ---------------------------------------------------------------------------
# GROUP 1: WHNF Shell Census
# ---------------------------------------------------------------------------
def group1_whnf_census():
    print("\n" + "=" * 90)
    print("GROUP 1: WHNF Shell Census — sys8 with varying lambda depths")
    print("=" * 90)

    # Build λ^k.body for different k and body patterns
    def make_lam_k(k, body_named):
        """Wrap body in k lambdas with names _0.._k-1"""
        term = body_named
        for i in range(k - 1, -1, -1):
            term = lam(f"_{i}", term)
        return term

    shells = []

    # k=0: no lambdas, raw body
    shells.append(("k=0 V0", g(0)))  # Var(0) = stuck global
    shells.append(("k=0 nil", NIL))

    # k=1..3,9: λ^k.V0 (innermost bound var)
    for k in [1, 2, 3, 9]:
        shells.append((f"k={k} V0", make_lam_k(k, v("_0"))))

    # k=2: different body patterns
    shells.append(("k=2 (V1 V0)", make_lam_k(2, apps(v("_1"), v("_0")))))
    shells.append(("k=2 (V0 V0)", make_lam_k(2, apps(v("_0"), v("_0")))))
    shells.append(("k=2 ((V1 V0) V0)", make_lam_k(2, apps(v("_1"), v("_0"), v("_0")))))

    # k=9: different bodies (int-like)
    shells.append(("k=9 (V1 V0)", make_lam_k(9, apps(v("_1"), v("_0")))))  # = int(1)
    shells.append(("k=9 (V8 V0)", make_lam_k(9, apps(v("_8"), v("_0")))))  # = int(128)
    shells.append(
        ("k=9 (V8(V8 V0))", make_lam_k(9, apps(v("_8"), apps(v("_8"), v("_0")))))
    )  # = int(256)

    # Same extensional value, different bodies
    shells.append(("nil_plain = λcλn.n", lam("c", lam("n", v("n")))))
    shells.append(
        ("nil_I = λcλn.(I n)", lam("c", lam("n", apps(lam("x", v("x")), v("n")))))
    )
    shells.append(
        (
            "nil_K = λcλn.((K n) c)",
            lam("c", lam("n", apps(lam("a", lam("b", v("a"))), v("n"), v("c")))),
        )
    )

    shells.append(("zero_plain = λ^9.V0", make_lam_k(9, v("_0"))))
    shells.append(
        ("zero_I = λ^9.(I V0)", make_lam_k(9, apps(lam("x", v("x")), v("_0"))))
    )

    for label, shell_term in shells:
        term = apps(g(8), shell_term, PSE)
        payload = build_payload(term)
        if len(payload) > 1900:
            print(f"  SKIP: {label}")
            continue
        out, ms = query(payload)
        c = classify(out)
        report(f"  W1: sys8({label})", len(payload), c, ms)
        time.sleep(0.3)


# ---------------------------------------------------------------------------
# GROUP 2: Path-valid poisons with proper controls
# ---------------------------------------------------------------------------
def group2_path_valid_poisons():
    print("\n" + "=" * 90)
    print("GROUP 2: Path-valid poisons (terms that look correct but diverge deeper)")
    print("=" * 90)

    OMEGA = apps(lam("x", apps(v("x"), v("x"))), lam("x", apps(v("x"), v("x"))))

    # int(256) variants: good and poisoned
    def make_int256_good():
        return NConst(encode_byte_term(256 if False else 0))  # placeholder

    # Actually build int(256) = λ^9. V8(V8(V0))
    def mk9(body):
        return lam(
            "w1",
            lam(
                "w2",
                lam(
                    "w3",
                    lam(
                        "w4",
                        lam("w5", lam("w6", lam("w7", lam("w8", lam("w0", body))))),
                    ),
                ),
            ),
        )

    good256 = mk9(apps(v("w8"), apps(v("w8"), v("w0"))))
    poison256a = mk9(apps(v("w8"), apps(v("w8"), OMEGA)))  # omega at V0 position
    poison256b = mk9(apps(v("w8"), OMEGA))  # omega at inner app
    poison256c = mk9(
        apps(lam("x", v("x")), apps(v("w8"), apps(v("w8"), v("w0"))))
    )  # I wrapped

    int_variants = [
        ("good256", good256),
        ("poison256a (Ω at base)", poison256a),
        ("poison256b (Ω at mid)", poison256b),
        ("poison256c (I-wrapped)", poison256c),
    ]

    # Test against name() — which we KNOW decodes int(256) → "wtf"
    print("\n  --- name() control (should give 'wtf' for good256) ---")
    for label, t in int_variants:
        term = apps(g(6), t, PSE)
        payload = build_payload(term)
        out, ms = query(payload)
        c = classify(out)
        report(f"  P2c: name({label})", len(payload), c, ms)
        time.sleep(0.3)

    # Test against sys8
    print("\n  --- sys8 with same variants ---")
    for label, t in int_variants:
        term = apps(g(8), t, PSE)
        payload = build_payload(term)
        out, ms = query(payload)
        c = classify(out)
        report(f"  P2s: sys8({label})", len(payload), c, ms)
        time.sleep(0.3)

    # Bytes-list poisons: cons('A', omega) vs cons('A', nil)
    print("\n  --- write() control (path-valid list poisons) ---")
    consA_nil = lam("c", lam("n", apps(v("c"), int_term(65), NIL)))
    consA_omega = lam("c", lam("n", apps(v("c"), int_term(65), OMEGA)))

    for label, t in [("cons('A', nil)", consA_nil), ("cons('A', Ω)", consA_omega)]:
        term = apps(g(2), t, NIL)
        payload = build_payload(term)
        out, ms = query(payload)
        c = classify(out)
        report(f"  P2w: write({label})", len(payload), c, ms)
        time.sleep(0.3)

    # Same to sys8
    print("\n  --- sys8 with list poisons ---")
    for label, t in [("cons('A', nil)", consA_nil), ("cons('A', Ω)", consA_omega)]:
        term = apps(g(8), t, PSE)
        payload = build_payload(term)
        out, ms = query(payload)
        c = classify(out)
        report(f"  P2s: sys8({label})", len(payload), c, ms)
        time.sleep(0.3)


# ---------------------------------------------------------------------------
# GROUP 3: Pair(A,B) applied to syscalls
# ---------------------------------------------------------------------------
def group3_pair_applied():
    print("\n" + "=" * 90)
    print("GROUP 3: backdoor(nil)(λp. p(X))(λ_. nil) — pair applied to syscalls")
    print("=" * 90)

    # backdoor(nil)(λpair. pair(X))(λ_err. nil)
    # pair(X) = X(A)(B) where A=λab.bb, B=λab.ab
    # So if X=sys8, we get sys8(A)(B)
    targets = [
        ("write=2", 2),
        ("quote=4", 4),
        ("readdir=5", 5),
        ("name=6", 6),
        ("readfile=7", 7),
        ("sys8=8", 8),
        ("echo=14", 14),
        ("towel=42", 42),
        ("backdoor=201", 201),
    ]

    for label, x in targets:
        term = apps(
            g(201),
            NIL,
            lam("pair", apps(v("pair"), g(x))),
            lam("_err", write_str("BD_FAIL\n")),
        )
        payload = build_payload(term)
        out, ms = query(payload)
        c = classify(out)
        report(f"  PA3: pair({label})", len(payload), c, ms)
        time.sleep(0.35)

    # Also: pair applied to sys8 WITH an observer after
    # backdoor(nil)(λpair. (pair(sys8))(PSE))(λ_err. nil)
    # = sys8(A)(B) then PSE... but B is the continuation, so sys8(A)(B) = B(result) if sys8 returns
    print("\n  --- pair(sys8) with trailing PSE ---")
    term = apps(
        g(201),
        NIL,
        lam("pair", apps(apps(v("pair"), g(8)), PSE)),
        lam("_err", write_str("BD_FAIL\n")),
    )
    payload = build_payload(term)
    out, ms = query(payload)
    c = classify(out)
    report(f"  PA3: (pair(sys8))(PSE)", len(payload), c, ms)
    time.sleep(0.35)


# ---------------------------------------------------------------------------
# GROUP 4: Full bare 3-leaf sweep ((201 nil) X) for X=0..252
# ---------------------------------------------------------------------------
def group4_full_sweep():
    print("\n" + "=" * 90)
    print("GROUP 4: Full ((201 nil) X) sweep X=0..252 — timing + output")
    print("=" * 90)

    nil_bytes = bytes([0x00, FE, FE])
    results = {}
    anomalies = []

    for x in range(253):
        payload = bytes([0xC9]) + nil_bytes + bytes([FD, x, FD, FF])
        out, ms = query(payload, timeout_s=8.0)
        c = classify(out)
        results[x] = (c, ms)

        # Only print anomalies or every 50th
        if c != "EMPTY" or ms > 1000 or x % 50 == 0:
            flag = " *** ANOMALY ***" if c != "EMPTY" or ms > 1000 else ""
            print(f"  B4: ((201 nil) {x:3d})  {ms:5d}ms -> {c}{flag}")
            if c != "EMPTY" or ms > 1000:
                anomalies.append(x)

        time.sleep(0.15)  # lighter delay for sweep

    # Summary
    print(f"\n  --- Summary: {len(anomalies)} anomalies out of 253 ---")
    for x in anomalies:
        c, ms = results[x]
        print(f"  X={x:3d}: {ms:5d}ms -> {c}")

    # Timing histogram
    times = [results[x][1] for x in range(253)]
    avg = sum(times) / len(times)
    mx = max(times)
    mn = min(times)
    print(f"  Timing: avg={avg:.0f}ms min={mn}ms max={mx}ms")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 90)
    print(
        "PROBE V35 WHNF — Shell census + path-valid poisons + pair-applied + full sweep"
    )
    print(f"Target: {HOST}:{PORT}")
    print("=" * 90)

    group1_whnf_census()
    group2_path_valid_poisons()
    group3_pair_applied()
    group4_full_sweep()

    print("\n" + "=" * 90)
    print("DONE")
    print("=" * 90)


if __name__ == "__main__":
    main()
