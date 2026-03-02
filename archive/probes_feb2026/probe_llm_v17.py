#!/usr/bin/env python3
"""
probe_llm_v17.py — Test LLM v17 "Forged Token" theory.

Theory: sys8 expects Left(Var(201)) as a "capability token".
Key claim: manually forging Left(sys201) = Lam(Lam(App(Var(1), Var(203)))) bypasses permission.

NOTE: echo(g(201))→sys8 was ALREADY tested in 5+ probes (all Right(6)/EMPTY).
But we test the MANUALLY FORGED version (source-level, not echo-constructed)
for absolute certainty, plus a sweep of Left(Var(N)) for all active syscall IDs.
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
    encode_term,
    parse_term,
    decode_either,
    decode_byte_term,
    decode_bytes_list,
)

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
QD_TERM = parse_term(QD_BYTES)

NIL = Lam(Lam(Var(0)))


def shift_term(term, delta, cutoff=0):
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_term(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_term(term.f, delta, cutoff), shift_term(term.x, delta, cutoff))
    raise TypeError(f"Unknown: {type(term)}")


def query_raw(payload: bytes, timeout_s: float = 5.0) -> bytes:
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            sock.settimeout(timeout_s)
            out = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out += chunk
                    if FF in chunk:
                        break
                except socket.timeout:
                    break
            return out
    except Exception as e:
        return b"ERR:" + str(e).encode()


def classify(resp: bytes) -> str:
    if not resp:
        return "EMPTY"
    if resp.startswith(b"ERR:"):
        return resp.decode()
    hx = resp.hex()
    if hx == "00030200fdfdfefefefefefefefefefdfefeff":
        return "Right(6)=PermDenied"
    if "000200fdfefefefefefefefefefdfefeff" in hx:
        return "Right(2)=InvalidArg"
    if "000100fdfefefefefefefefefefdfefeff" in hx:
        return "Right(1)=NotImpl"
    if "000300fdfdfefefefefefefefefefdfefeff" in hx:
        return "Right(3)=NoSuchFile"  # Note: Right(3) has different encoding
    if b"Encoding failed" in resp:
        return "EncodingFailed"
    if b"Invalid term" in resp:
        return "InvalidTerm"
    if FF in resp:
        try:
            term = parse_term(resp[: resp.index(FF) + 1])
            tag, payload_inner = decode_either(term)
            if tag == "Left":
                try:
                    bs = decode_bytes_list(payload_inner)
                    text = bs.decode("utf-8", "replace")
                    return f"Left(string={text!r})"
                except Exception:
                    return f"Left(<non-string>)"
            elif tag == "Right":
                try:
                    code = decode_byte_term(payload_inner)
                    return f"Right({code})"
                except Exception:
                    return f"Right(<non-int>)"
        except Exception:
            pass
    return f"HEX={hx[:80]}({len(resp)}b)"


def run(label: str, term: object, delay: float = 0.4) -> str:
    payload = encode_term(term) + bytes([FF])
    if len(payload) > 2000:
        print(f"  [{label}] SKIP: too large ({len(payload)}b)")
        return "TOO_LARGE"
    time.sleep(delay)
    resp = query_raw(payload)
    result = classify(resp)
    print(f"  [{label}] → {result}")
    return result


def make_left(inner: object) -> object:
    """Manually forge Left(inner) = λl.λr. l(inner_shifted)."""
    # Left(X) = Lam(Lam(App(Var(1), X_shifted_by_2)))
    inner_shifted = shift_term(inner, 2)
    return Lam(Lam(App(Var(1), inner_shifted)))


def make_right(inner: object) -> object:
    """Manually forge Right(inner) = λl.λr. r(inner_shifted)."""
    inner_shifted = shift_term(inner, 2)
    return Lam(Lam(App(Var(0), inner_shifted)))


def main() -> None:
    print("=" * 60)
    print("LLM v17 PROBE — Forged Token Theory")
    print("=" * 60)

    # ================================================================
    # SECTION 1: The exact LLM claims — manually forged Left(Var(201))
    # Left(Var(201)) = Lam(Lam(App(Var(1), Var(203))))
    # ================================================================
    print("\n[1] MANUALLY FORGED Left(Var(N)) → sys8 — THE CORE CLAIMS")

    # Probe 1: sys8(Left(Var(201)))(QD) — "The 2014 Forged Token"
    forged_201 = make_left(Var(201))
    t1 = App(App(Var(8), forged_201), QD_TERM)
    run("P1: sys8(Left(Var(201)))(QD) — forged backdoor token", t1)

    # Probe 2: sys8(Left(Var(8)))(QD) — "Left(sys8) token"
    forged_8 = make_left(Var(8))
    t2 = App(App(Var(8), forged_8), QD_TERM)
    run("P2: sys8(Left(Var(8)))(QD) — forged sys8 token", t2)

    # Probe 3: sys8(Left(Var(14)))(QD) — "Left(echo) token"
    forged_14 = make_left(Var(14))
    t3 = App(App(Var(8), forged_14), QD_TERM)
    run("P3: sys8(Left(Var(14)))(QD) — forged echo token", t3)

    # ================================================================
    # SECTION 2: Sweep Left(Var(N)) for ALL active syscall IDs
    # ================================================================
    print("\n[2] Left(Var(N)) SWEEP — All active syscall IDs + specials")

    key_ids = [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]
    specials = [3, 100, 200, 202, 250, 251, 252]

    for n in key_ids + specials:
        forged = make_left(Var(n))
        t = App(App(Var(8), forged), QD_TERM)
        run(f"sys8(Left(Var({n})))(QD)", t)

    # ================================================================
    # SECTION 3: Right(Var(N)) — maybe sys8 wants Right, not Left?
    # ================================================================
    print("\n[3] Right(Var(N)) — alternative token polarity")

    for n in [201, 8, 14, 0, 1]:
        forged = make_right(Var(n))
        t = App(App(Var(8), forged), QD_TERM)
        run(f"sys8(Right(Var({n})))(QD)", t)

    # ================================================================
    # SECTION 4: Left(NIL), Left(Left(Var(201))), etc.
    # ================================================================
    print("\n[4] Nested/wrapped tokens")

    # Left(nil)
    t4a = App(App(Var(8), make_left(NIL)), QD_TERM)
    run("sys8(Left(nil))(QD)", t4a)

    # Left(Left(Var(201)))
    t4b = App(App(Var(8), make_left(make_left(Var(201)))), QD_TERM)
    run("sys8(Left(Left(Var(201))))(QD)", t4b)

    # Left(pair) — where pair = λs.s(A)(B), A=λa.λb.bb, B=λa.λb.ab
    A = Lam(Lam(App(Var(0), Var(0))))
    B = Lam(Lam(App(Var(1), Var(0))))
    pair = Lam(App(App(Var(0), A), B))
    t4c = App(App(Var(8), make_left(pair)), QD_TERM)
    run("sys8(Left(pair))(QD)", t4c)

    # ================================================================
    # SECTION 5: Echo-mediated Var(201) → sys8 (CPS, for comparison)
    # This SHOULD match Section 1 Probe 1. If it differs, there's a
    # provenance distinction in the C++ implementation.
    # ================================================================
    print("\n[5] ECHO-MEDIATED Left(Var(201)) → sys8 (CPS comparison)")

    qd_s1 = shift_term(QD_TERM, 1)
    # echo(Var(201))(λleft. sys8(left)(QD_s1))
    echo_201_sys8 = App(App(Var(14), Var(201)), Lam(App(App(Var(9), Var(0)), qd_s1)))
    run("echo(g(201))(λl. sys8(l)(QD)) — CPS echo-mediated", echo_201_sys8)

    # echo(Var(8))(λleft. sys8(left)(QD_s1))
    echo_8_sys8 = App(App(Var(14), Var(8)), Lam(App(App(Var(9), Var(0)), qd_s1)))
    run("echo(g(8))(λl. sys8(l)(QD)) — CPS echo-mediated", echo_8_sys8)

    # ================================================================
    # SECTION 6: The 3-leaf bare programs
    # App(App(Var(A), Var(B)), Var(C)) — no QD, just 3 leaves
    # These have EXACTLY 3 Var nodes.
    # ================================================================
    print("\n[6] TRUE 3-LEAF bare programs (no QD)")

    combos = [
        (14, 201, 8, "echo(g201)(sys8)"),
        (14, 201, 2, "echo(g201)(write)"),
        (14, 8, 201, "echo(sys8)(backdoor)"),
        (8, 14, 201, "sys8(echo)(backdoor)"),
        (201, 14, 8, "backdoor(echo)(sys8)"),
        (14, 201, 4, "echo(g201)(quote)"),
        (4, 201, 2, "quote(g201)(write)"),
        (4, 8, 2, "quote(sys8)(write)"),
        (14, 8, 2, "echo(sys8)(write)"),
    ]

    for a, b, c, label in combos:
        t = App(App(Var(a), Var(b)), Var(c))
        run(f"3L: {label} = ({a} {b}) {c}", t)

    # ================================================================
    # SUMMARY
    # ================================================================
    print("\n" + "=" * 60)
    print("DONE — All v17 forged token tests complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
