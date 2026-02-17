#!/usr/bin/env python3
"""
probe_sys8_tracks.py - Four new experimental axes against BrownOS syscall 8.

Track 2: Echo-mediated (echo X -> unwrap Left -> sys8)
Track 3: Combinator algebra from backdoor pair components
Track 4: Credential strings as sys8 argument
Track 5: Quote -> sys8 (quote T -> unwrap Left -> sys8)
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
FF = 0xFF


# ---------------------------------------------------------------------------
# Named-term DSL (copied from probe_ultra3.py)
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
    raise TypeError(f"Unsupported named-term node: {type(term)}")


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


# ---------------------------------------------------------------------------
# Network helpers (copied from probe_ultra3.py)
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
        if FF in chunk:
            continue
    return out


def query(payload: bytes, retries: int = 4, timeout_s: float = 7.0) -> bytes:
    delay = 0.2
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


def classify(out: bytes) -> str:
    if not out:
        return "EMPTY"
    if out.startswith(b"Invalid term!"):
        return "Invalid term!"
    if out.startswith(b"Encoding failed!"):
        return "Encoding failed!"
    if out.startswith(b"ERROR:"):
        return out.decode("ascii", "replace")

    try:
        text = out.decode("utf-8", "replace")
        if all((ch == "\n") or (ch == "\r") or (32 <= ord(ch) < 127) for ch in text):
            compact = text.replace("\n", "\\n")
            return f"TEXT:{compact[:120]}"
    except Exception:
        pass

    return f"HEX:{out[:80].hex()}"


# ---------------------------------------------------------------------------
# Term constructors
# ---------------------------------------------------------------------------

NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)


def int_term(n: int) -> NConst:
    return NConst(encode_byte_term(n))


def bytes_term(bs: bytes) -> NConst:
    return NConst(encode_bytes_list(bs))


def str_term(s: str) -> NConst:
    return bytes_term(s.encode("ascii", "replace"))


def write_str(s: str) -> object:
    return apps(g(2), str_term(s), NIL)


# ---------------------------------------------------------------------------
# Observer: Either unwrap that writes error text or LEFT marker
# ---------------------------------------------------------------------------


def make_observer(left_marker: str = "LEFT\n") -> object:
    right_handler = lam(
        "errcode",
        apps(
            g(1),
            v("errcode"),
            lam(
                "err_str_either",
                apps(
                    v("err_str_either"),
                    lam("errstr", apps(g(2), v("errstr"), NIL)),
                    lam("_e2", write_str("ERR_DECODE_FAIL\n")),
                ),
            ),
        ),
    )
    left_handler = lam("_left_payload", write_str(left_marker))
    return lam("result", apps(v("result"), left_handler, right_handler))


OBS = make_observer()


# ---------------------------------------------------------------------------
# Execution helpers
# ---------------------------------------------------------------------------

FLAGGED: list[str] = []


def run_case(
    label: str, term: object, sleep_s: float = 0.40, timeout_s: float = 7.0
) -> None:
    db_term = to_db(term)
    payload = encode_term(db_term) + bytes([FF])
    if len(payload) > 1900:
        print(f"{label:62s} payload={len(payload):4d} -> SKIPPED (>1900)")
        return
    out = query(payload, timeout_s=timeout_s)
    result = classify(out)
    flag = ""
    if "Permission denied" not in result and result not in (
        "EMPTY",
        "Invalid term!",
        "Encoding failed!",
    ):
        # Check for known "Permission denied" in TEXT form
        if "Permission denied" not in result:
            flag = " *** FLAGGED ***"
            FLAGGED.append(f"{label} -> {result}")
    print(f"{label:62s} payload={len(payload):4d} -> {result}{flag}")
    time.sleep(sleep_s)


def section(title: str) -> None:
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


# ---------------------------------------------------------------------------
# GROUP A: Echo-mediated (Track 2)
# echo(X) -> Left(echoed) -> unwrap -> sys8(echoed)(OBS)
# ---------------------------------------------------------------------------


def group_a_echo_mediated() -> None:
    section("GROUP A: ECHO-MEDIATED sys8 (Track 2)")

    def echo_to_sys8(x: object) -> object:
        return apps(
            g(14),
            x,
            lam(
                "echo_res",
                apps(
                    v("echo_res"),
                    lam("echoed", apps(g(8), v("echoed"), OBS)),
                    lam("_echoerr", write_str("ECHOERR\n")),
                ),
            ),
        )

    tests = [
        ("nil", NIL),
        ("int(8)", int_term(8)),
        ("g(8)", g(8)),
        ("str('ilikephp')", str_term("ilikephp")),
    ]

    for name, x in tests:
        run_case(f"A echo({name})->sys8(echoed)", echo_to_sys8(x))


# ---------------------------------------------------------------------------
# GROUP B: Combinator algebra from backdoor (Track 3)
# g(201)(nil) -> Left(pair) -> pair(λa.λb. sys8(COMBO(a,b))(OBS))
# ---------------------------------------------------------------------------


def group_b_combinator_algebra() -> None:
    section("GROUP B: COMBINATOR ALGEBRA FROM BACKDOOR (Track 3)")

    combinators = [
        ("a(a)", lambda: apps(v("a"), v("a"))),
        ("b(b)", lambda: apps(v("b"), v("b"))),
        ("a(b)", lambda: apps(v("a"), v("b"))),
        ("b(a)", lambda: apps(v("b"), v("a"))),
        ("b(a(b))", lambda: apps(v("b"), apps(v("a"), v("b")))),
    ]

    for combo_name, combo_fn in combinators:
        combo = combo_fn()
        term = apps(
            g(201),
            NIL,
            lam(
                "bd_res",
                apps(
                    v("bd_res"),
                    lam(
                        "pair",
                        apps(
                            v("pair"),
                            lam("a", lam("b", apps(g(8), combo, OBS))),
                        ),
                    ),
                    lam("_bderr", write_str("BDERR\n")),
                ),
            ),
        )
        run_case(f"B backdoor->sys8({combo_name})", term, timeout_s=5.0)


# ---------------------------------------------------------------------------
# GROUP C: Credential strings (Track 4)
# sys8(str_term(S))(OBS)
# ---------------------------------------------------------------------------


def group_c_credential_strings() -> None:
    section("GROUP C: CREDENTIAL STRINGS (Track 4)")

    strings = [
        "gizmore:ilikephp",
        "gizmore:GZKc.2/VQffio:1000:1000:Gizmore:/home/gizmore:/bin/sh",
        "sudo",
        "root",
        "gizmore",
        "dloser",
    ]

    for s in strings:
        run_case(f"C sys8('{s[:40]}')", apps(g(8), str_term(s), OBS))


# ---------------------------------------------------------------------------
# GROUP D: Quote -> sys8 (Track 5)
# quote(T) -> Left(bytes) -> sys8(bytes)(OBS)
# ---------------------------------------------------------------------------


def group_d_quote_to_sys8() -> None:
    section("GROUP D: QUOTE->sys8 (Track 5)")

    def quote_to_sys8(t: object) -> object:
        return apps(
            g(4),
            t,
            lam(
                "qr",
                apps(
                    v("qr"),
                    lam("qbytes", apps(g(8), v("qbytes"), OBS)),
                    lam("_qerr", write_str("QERR\n")),
                ),
            ),
        )

    targets = [
        ("g(8)", g(8)),
        ("g(201)", g(201)),
        ("g(14)", g(14)),
        ("nil", NIL),
        ("g(0)", g(0)),
    ]

    for name, t in targets:
        run_case(f"D quote({name})->sys8(quoted)", quote_to_sys8(t))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 80)
    print("PROBE SYS8 TRACKS - 4 New Experimental Axes")
    print("=" * 80)

    group_a_echo_mediated()
    group_b_combinator_algebra()
    group_c_credential_strings()
    group_d_quote_to_sys8()

    print("\n" + "=" * 80)
    if FLAGGED:
        print(f"FLAGGED RESULTS ({len(FLAGGED)}):")
        for f in FLAGGED:
            print(f"  {f}")
    else:
        print("No non-Permission-denied results flagged.")
    print("=" * 80)
    print("DONE")


if __name__ == "__main__":
    main()
