#!/usr/bin/env python3
"""
Probe syscall 8 with runtime-created high-index globals and wrapper forms.

Focus:
- K-combinator generated terms that can produce Var(253+)/FD/FE/FF values at runtime
- Echo-wrapped raw Either values fed directly into syscall 8
- Backdoor-pair component extraction (A/B) routed into syscall 8
- Syscall-position wrappers where the syscall head reduces to g(8)
- Raw "term term FD obs FD FF" payload shape with lambda terms in ?? slots
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Any

from solve_brownos_answer import App, Lam, Var, FF, encode_bytes_list, encode_term

HOST = "wc3.wechall.net"
PORT = 61221

ResultRow = dict[str, Any]


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
        try:
            return Var(env.index(term.name))
        except ValueError as exc:
            raise ValueError(f"Unbound name: {term.name}") from exc
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


def v(n: str) -> NVar:
    return NVar(n)


def lam(p: str, b: object) -> NLam:
    return NLam(p, b)


def app(f: object, x: object) -> NApp:
    return NApp(f, x)


def apps(*t: object) -> object:
    out = t[0]
    for x in t[1:]:
        out = app(out, x)
    return out


NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)


def recv_all(sock: socket.socket, timeout_s: float = 10.0) -> bytes:
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


def query_named(term: object, timeout_s: float = 10.0, retries: int = 2) -> bytes:
    payload = encode_term(to_db(term)) + bytes([FF])
    delay = 0.2
    for attempt in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s=timeout_s)
        except Exception:
            if attempt == retries - 1:
                return b""
            time.sleep(delay)
            delay = min(delay * 2, 2.0)
    return b""


def query_raw(payload_bytes: bytes, timeout_s: float = 10.0, retries: int = 2) -> bytes:
    delay = 0.2
    for attempt in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload_bytes)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s=timeout_s)
        except Exception:
            if attempt == retries - 1:
                return b""
            time.sleep(delay)
            delay = min(delay * 2, 2.0)
    return b""


def write_str(s: str) -> object:
    return apps(g(2), NConst(encode_bytes_list(s.encode("latin-1"))), NIL)


def obs() -> object:
    right_handler = lam(
        "err_code",
        apps(
            g(1),
            v("err_code"),
            lam(
                "err_res",
                apps(
                    v("err_res"),
                    lam("errstr", apps(g(2), v("errstr"), NIL)),
                    lam("_e2", write_str("?")),
                ),
            ),
        ),
    )
    left_handler = lam("_payload", write_str("LEFT!"))
    return lam("res", apps(v("res"), left_handler, right_handler))


OBS = obs()


def classify_output(raw: bytes) -> str:
    if not raw:
        return "EMPTY"
    text = raw.decode("latin-1", errors="replace")
    if "Permission denied" in text:
        return "PERMISSION_DENIED"
    if "LEFT!" in text:
        return "LEFT_SUCCESS_MARKER"
    return "NON_PERMISSION_DENIED"


def render_output(raw: bytes) -> str:
    if not raw:
        return "<empty>"
    text = raw.decode("latin-1", errors="replace")
    return f"raw={raw!r} text={text!r}"


def run_named_test(
    label: str, term: object, results: list[ResultRow], timeout_s: float = 12.0
) -> None:
    out = query_named(term, timeout_s=timeout_s)
    verdict = classify_output(out)
    print(f"{label}\n  {render_output(out)}\n  verdict={verdict}")
    results.append({"label": label, "raw": out, "verdict": verdict})
    time.sleep(0.3)


def run_raw_test(
    label: str, payload: bytes, results: list[ResultRow], timeout_s: float = 12.0
) -> None:
    out = query_raw(payload, timeout_s=timeout_s)
    verdict = classify_output(out)
    print(f"{label}\n  {render_output(out)}\n  verdict={verdict}")
    results.append({"label": label, "raw": out, "verdict": verdict})
    time.sleep(0.3)


def main() -> None:
    results: list[ResultRow] = []

    # Combinators
    k_comb = lam("a", lam("b", v("a")))
    k_second = lam("a", lam("b", v("b")))

    # Backdoor pair components documented in previous probes.
    a_term = lam("a", lam("b", app(v("b"), v("b"))))
    b_term = lam("a", lam("b", app(v("a"), v("b"))))

    # K-generated test terms.
    k_g252 = app(k_comb, g(252))
    k_g251 = app(k_comb, g(251))
    kk_g252 = app(k_comb, k_g252)
    kk_g251 = app(k_comb, k_g251)
    kkk_g252 = app(k_comb, kk_g252)

    print("=" * 72)
    print("PHASE 1: K(g(252))/K(g(251)) directly to syscall 8")
    print("=" * 72)
    run_named_test("P1-A sys8(K(g(252)), OBS)", apps(g(8), k_g252, OBS), results)
    run_named_test("P1-B sys8(K(g(251)), OBS)", apps(g(8), k_g251, OBS), results)

    print()
    print("=" * 72)
    print("PHASE 2: echo(K(...)) then feed raw Either to syscall 8")
    print("=" * 72)
    run_named_test(
        "P2-A echo(K(g(252)), lambda e. sys8(e, OBS))",
        apps(g(14), k_g252, lam("e", apps(g(8), v("e"), OBS))),
        results,
    )
    run_named_test(
        "P2-B echo(K(g(251)), lambda e. sys8(e, OBS))",
        apps(g(14), k_g251, lam("e", apps(g(8), v("e"), OBS))),
        results,
    )

    print()
    print("=" * 72)
    print("PHASE 3: Nested K applications for higher-shifted globals")
    print("=" * 72)
    run_named_test("P3-A sys8(K(K(g(252))), OBS)", apps(g(8), kk_g252, OBS), results)
    run_named_test("P3-B sys8(K(K(g(251))), OBS)", apps(g(8), kk_g251, OBS), results)
    run_named_test(
        "P3-C echo(K(K(g(252))), lambda e. sys8(e, OBS))",
        apps(g(14), kk_g252, lam("e", apps(g(8), v("e"), OBS))),
        results,
    )
    run_named_test(
        "P3-D sys8(K(K(K(g(252)))), OBS)", apps(g(8), kkk_g252, OBS), results
    )

    print()
    print("=" * 72)
    print("PHASE 4: Backdoor A/B shapes and extracted components")
    print("=" * 72)
    run_named_test(
        "P4-A echo(A, lambda e. sys8(e, OBS))",
        apps(g(14), a_term, lam("e", apps(g(8), v("e"), OBS))),
        results,
    )
    run_named_test(
        "P4-B echo(B, lambda e. sys8(e, OBS))",
        apps(g(14), b_term, lam("e", apps(g(8), v("e"), OBS))),
        results,
    )

    extracted_a = apps(
        g(201),
        NIL,
        lam(
            "bd_res",
            apps(
                v("bd_res"),
                lam("pair", apps(g(8), apps(v("pair"), k_comb, NIL), OBS)),
                lam("_bd_err", write_str("BD_RIGHT")),
            ),
        ),
    )
    run_named_test("P4-C sys8(A_extracted_from_backdoor, OBS)", extracted_a, results)

    extracted_b = apps(
        g(201),
        NIL,
        lam(
            "bd_res",
            apps(
                v("bd_res"),
                lam("pair", apps(g(8), apps(v("pair"), k_second, NIL), OBS)),
                lam("_bd_err", write_str("BD_RIGHT")),
            ),
        ),
    )
    run_named_test("P4-D sys8(B_extracted_from_backdoor, OBS)", extracted_b, results)

    print()
    print("=" * 72)
    print("PHASE 5: Syscall-position terms that reduce to g(8)")
    print("=" * 72)
    run_named_test(
        "P5-A ((lambda x. g(8)) nil) nil OBS",
        apps(app(lam("x", g(8)), NIL), NIL, OBS),
        results,
    )
    run_named_test(
        "P5-B (((lambda x. lambda y. y) nil) g(8)) nil OBS",
        apps(app(app(lam("x", lam("y", v("y"))), NIL), g(8)), NIL, OBS),
        results,
    )

    print()
    print("=" * 72)
    print("PHASE 6: Creative two-slot chaining without quote/QD observer")
    print("=" * 72)
    run_named_test(
        "P6-A (lambda x. sys8(x, OBS)) K(g(252))",
        apps(lam("x", apps(g(8), v("x"), OBS)), k_g252),
        results,
    )

    term1 = lam("x", apps(g(8), v("x")))
    term2 = kk_g252
    payload = (
        encode_term(to_db(term1))
        + encode_term(to_db(term2))
        + bytes([0xFD])
        + encode_term(to_db(OBS))
        + bytes([0xFD, FF])
    )
    run_raw_test(
        "P6-B RAW: <lambda_sys8_partial> <K(K(g252))> FD <OBS> FD FF",
        payload,
        results,
    )

    print()
    print("=" * 72)
    print("RESULT SUMMARY")
    print("=" * 72)

    perm = [r for r in results if r["verdict"] == "PERMISSION_DENIED"]
    left = [r for r in results if r["verdict"] == "LEFT_SUCCESS_MARKER"]
    non_perm = [r for r in results if r["verdict"] == "NON_PERMISSION_DENIED"]
    empty = [r for r in results if r["verdict"] == "EMPTY"]

    print(f"total_tests={len(results)}")
    print(f"permission_denied={len(perm)}")
    print(f"left_marker={len(left)}")
    print(f"non_permission_nonempty={len(non_perm)}")
    print(f"empty={len(empty)}")

    print()
    print("Non-'Permission denied' responses (includes empty/non-empty):")
    for row in left + non_perm + empty:
        rendered = render_output(row["raw"])
        print(f"- {row['label']}: {row['verdict']} | {rendered}")


if __name__ == "__main__":
    main()
