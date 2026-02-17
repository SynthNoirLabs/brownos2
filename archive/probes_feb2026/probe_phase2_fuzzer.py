#!/usr/bin/env python3
"""
probe_phase2_fuzzer.py — Phase 2 fuzzer: sys8 with novel lambda terms + sys2 exploration.

Axes:
  F1: sys8 with Church numerals 0..5
  F2: sys8 with combinators (I, K, S, omega, Y)
  F3: sys8 with self-referential / recursive terms
  F4: sys8 double-invocation (sys8 result fed back to sys8)
  F5: sys2 class-sensitivity deep probe (varied structural args)
  F6: sys8 with login-syscall-like sequences (sys8 after manipulating g(0)/g(3))
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
DELAY = 0.4

FD = 0xFD
FF = 0xFF

# ---------------------------------------------------------------------------
# Named-term DSL (from probe_sys8_tracks.py)
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


# Church numerals (λf.λx. f^n x)
def church(n: int) -> NConst:
    """Church numeral n = λf.λx. f(f(...(x)...))"""
    body: object = Var(0)  # x
    for _ in range(n):
        body = App(Var(1), body)  # f(...)
    return NConst(Lam(Lam(body)))


# Identity: λx.x
I = NConst(Lam(Var(0)))

# K combinator (Church true): λa.λb. a
K = NConst(Lam(Lam(Var(1))))

# S combinator: λf.λg.λx. f(x)(g(x))
S = NConst(Lam(Lam(Lam(App(App(Var(2), Var(0)), App(Var(1), Var(0)))))))

# Omega (self-application): (λx.xx)(λx.xx) — DANGEROUS: diverges!
# We won't send this raw but may use sub-parts
OMEGA_HALF = NConst(Lam(App(Var(0), Var(0))))  # λx.x x

# Y combinator: λf. (λx. f(x x))(λx. f(x x))
Y_INNER = Lam(App(Var(1), App(Var(0), Var(0))))  # λx. f(x x)
Y = NConst(Lam(App(Y_INNER, Y_INNER)))  # WARNING: may diverge

# Backdoor components
A_DB = Lam(Lam(App(Var(0), Var(0))))  # λa.λb. b b
B_DB = Lam(Lam(App(Var(1), Var(0))))  # λa.λb. a b
A = NConst(A_DB)
B = NConst(B_DB)


# Scott pair: λf. f(X)(Y)
def scott_pair(x: object, y: object) -> object:
    return lam("f", apps(v("f"), x, y))


# Int term (9-lambda encoded byte)
def int_term(n: int) -> NConst:
    return NConst(encode_byte_term(n))


# String term
def str_term(s: str) -> NConst:
    return NConst(encode_bytes_list(s.encode("ascii", "replace")))


# ---------------------------------------------------------------------------
# Observer: Either unwrap that writes error text or LEFT marker
# ---------------------------------------------------------------------------


def write_str(s: str) -> object:
    return apps(g(2), str_term(s), NIL)


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
# Raw observer: writes the Left payload itself (not a marker)
# ---------------------------------------------------------------------------


def make_raw_observer() -> object:
    """Observer that writes the Left payload as bytes (for sys2 probing)."""
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
    # For Left: write the payload directly (assuming it's bytes)
    left_handler = lam("payload", apps(g(2), v("payload"), NIL))
    return lam("result", apps(v("result"), left_handler, right_handler))


RAW_OBS = make_raw_observer()


# QD observer: uses quote to serialize the Left payload
def make_qd_observer() -> object:
    """Observer that quotes the Left payload for raw inspection."""
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
                    lam("_e2", write_str("ERR\n")),
                ),
            ),
        ),
    )
    # For Left: quote the payload and write the result
    left_handler = lam(
        "payload",
        apps(
            g(4),
            v("payload"),
            lam(
                "qr",
                apps(
                    v("qr"),
                    lam("qbytes", apps(g(2), v("qbytes"), NIL)),
                    lam("_qerr", write_str("QFAIL\n")),
                ),
            ),
        ),
    )
    return lam("result", apps(v("result"), left_handler, right_handler))


QD_OBS = make_qd_observer()


# ---------------------------------------------------------------------------
# Execution helpers
# ---------------------------------------------------------------------------

RESULTS: list[tuple[str, str]] = []
FLAGGED: list[str] = []
_request_count = 0
MAX_REQUESTS = 45


def run_case(
    label: str, term: object, sleep_s: float = DELAY, timeout_s: float = 7.0
) -> str | None:
    global _request_count
    if _request_count >= MAX_REQUESTS:
        print(f"  [{label}] SKIPPED — rate limit ({MAX_REQUESTS} reached)")
        return None
    db_term = to_db(term)
    payload = encode_term(db_term) + bytes([FF])
    if len(payload) > 1500:
        result = f"SKIPPED (payload={len(payload)} > 1500)"
        print(f"  {label:58s} -> {result}")
        RESULTS.append((label, result))
        return result
    _request_count += 1
    out = query(payload, timeout_s=timeout_s)
    result = classify(out)
    flag = ""
    if (
        "Permission denied" not in result
        and result
        not in (
            "EMPTY",
            "Invalid term!",
            "Encoding failed!",
        )
        and not result.startswith("ERROR:")
    ):
        flag = " *** FLAGGED ***"
        FLAGGED.append(f"{label} -> {result}")
    print(f"  {label:58s} -> {result}{flag}")
    RESULTS.append((label, result))
    time.sleep(sleep_s)
    return result


def section(title: str) -> None:
    print(f"\n{'=' * 78}")
    print(f"  {title}")
    print(f"{'=' * 78}")


# ---------------------------------------------------------------------------
# F1: sys8 with Church numerals
# ---------------------------------------------------------------------------


def group_f1_church_numerals() -> None:
    section("F1: sys8(Church numeral n) — n=0..5")
    for n in range(6):
        run_case(f"F1 sys8(church({n}))", apps(g(8), church(n), OBS))


# ---------------------------------------------------------------------------
# F2: sys8 with classic combinators
# ---------------------------------------------------------------------------


def group_f2_combinators() -> None:
    section("F2: sys8(combinator)")
    cases = [
        ("I (identity)", I),
        ("K (true)", K),
        ("S", S),
        ("omega_half (λx.xx)", OMEGA_HALF),
        ("A (backdoor)", A),
        ("B (backdoor)", B),
    ]
    for name, comb in cases:
        run_case(f"F2 sys8({name})", apps(g(8), comb, OBS))


# ---------------------------------------------------------------------------
# F3: sys8 with self-referential / structural terms
# ---------------------------------------------------------------------------


def group_f3_structural() -> None:
    section("F3: sys8(structural terms)")

    # Scott pair of two Church numerals
    run_case("F3 sys8(pair(0,1))", apps(g(8), scott_pair(church(0), church(1)), OBS))

    # Nested Scott pair: pair(pair(0,1), 2)
    run_case(
        "F3 sys8(pair(pair(0,1),2))",
        apps(g(8), scott_pair(scott_pair(church(0), church(1)), church(2)), OBS),
    )

    # Scott triple: λf. f(0)(1)(2)
    triple = lam("f", apps(v("f"), church(0), church(1), church(2)))
    run_case("F3 sys8(triple(0,1,2))", apps(g(8), triple, OBS))

    # List [0]
    cons_0_nil = NConst(
        Lam(Lam(App(App(Var(1), encode_byte_term(0)), Lam(Lam(Var(0))))))
    )
    run_case("F3 sys8([0])", apps(g(8), cons_0_nil, OBS))

    # sys8 applied to g(8) itself
    run_case("F3 sys8(g(8))", apps(g(8), g(8), OBS))

    # sys8 applied to g(2) (write syscall)
    run_case("F3 sys8(g(2))", apps(g(8), g(2), OBS))


# ---------------------------------------------------------------------------
# F4: sys8 double-invocation / chained
# ---------------------------------------------------------------------------


def group_f4_double_sys8() -> None:
    section("F4: sys8 result fed back into sys8")

    # sys8(nil) -> take result -> sys8(result)(OBS)
    run_case(
        "F4 sys8(nil)->sys8(result)",
        apps(g(8), NIL, lam("r1", apps(g(8), v("r1"), OBS))),
    )

    # sys8(I) -> take result -> sys8(result)(OBS)
    run_case(
        "F4 sys8(I)->sys8(result)", apps(g(8), I, lam("r1", apps(g(8), v("r1"), OBS)))
    )

    # sys8(K) -> feed to sys8 -> feed to sys8
    run_case(
        "F4 sys8(K)->sys8->sys8",
        apps(
            g(8), K, lam("r1", apps(g(8), v("r1"), lam("r2", apps(g(8), v("r2"), OBS))))
        ),
    )


# ---------------------------------------------------------------------------
# F5: sys2 deep exploration
# ---------------------------------------------------------------------------


def group_f5_sys2() -> None:
    section("F5: sys2 (write) class-sensitivity exploration")

    # sys2(nil)(OBS) — known: EMPTY
    run_case("F5 sys2(nil)", apps(g(2), NIL, OBS))

    # sys2(I)(OBS) — identity as arg
    run_case("F5 sys2(I)", apps(g(2), I, OBS))

    # sys2(K)(OBS) — K combinator
    run_case("F5 sys2(K)", apps(g(2), K, OBS))

    # sys2(church(1))(OBS) — Church 1
    run_case("F5 sys2(church(1))", apps(g(2), church(1), OBS))

    # sys2(int_term(65))(OBS) — byte term for 'A'
    run_case("F5 sys2(int_term(65))", apps(g(2), int_term(65), OBS))

    # sys2(pair(int(72), nil))(OBS) — known: Right(InvalidArg)
    run_case("F5 sys2(pair(int72,nil))", apps(g(2), scott_pair(int_term(72), NIL), OBS))

    # sys2 with string "Hi" — should just write "Hi"
    run_case("F5 sys2('Hi')", apps(g(2), str_term("Hi"), OBS))

    # sys2 with A (backdoor component)
    run_case("F5 sys2(A)", apps(g(2), A, OBS))

    # sys2 with g(8) (syscall ref)
    run_case("F5 sys2(g(8))", apps(g(2), g(8), OBS))

    # sys2 with raw observer to see what sys2 returns
    run_case("F5 sys2('test')(raw_obs)", apps(g(2), str_term("test"), RAW_OBS))


# ---------------------------------------------------------------------------
# F6: sys8 with context-setting preambles
# ---------------------------------------------------------------------------


def group_f6_preamble_sys8() -> None:
    section("F6: sys8 with preamble syscalls")

    # Read passwd -> then sys8(result)
    run_case(
        "F6 read(11)->sys8(content)",
        apps(
            g(7),
            int_term(11),
            lam(
                "pw_either",
                apps(
                    v("pw_either"),
                    lam("content", apps(g(8), v("content"), OBS)),
                    lam("_err", write_str("READERR\n")),
                ),
            ),
        ),
    )

    # Read .history -> sys8(content)
    run_case(
        "F6 read(65)->sys8(content)",
        apps(
            g(7),
            int_term(65),
            lam(
                "hist_either",
                apps(
                    v("hist_either"),
                    lam("content", apps(g(8), v("content"), OBS)),
                    lam("_err", write_str("READERR\n")),
                ),
            ),
        ),
    )

    # Read backdoor -> sys8(pair)
    run_case(
        "F6 backdoor->sys8(pair)",
        apps(
            g(201),
            NIL,
            lam(
                "bd_either",
                apps(
                    v("bd_either"),
                    lam("pair", apps(g(8), v("pair"), OBS)),
                    lam("_err", write_str("BDERR\n")),
                ),
            ),
        ),
    )

    # sys8 with the error code 6 itself (meta: Permission denied code)
    run_case("F6 sys8(int(6))", apps(g(8), int_term(6), OBS))

    # sys8 with int(0) — maybe special
    run_case("F6 sys8(int(0))", apps(g(8), int_term(0), OBS))

    # sys8 with QD observer (inspect actual returned term)
    run_case("F6 sys8(nil)(QD_OBS)", apps(g(8), NIL, QD_OBS))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 78)
    print("  PROBE PHASE 2 FUZZER — sys8 novel terms + sys2 exploration")
    print(f"  Target: {HOST}:{PORT}")
    print(f"  Max requests: {MAX_REQUESTS}, delay: {DELAY}s")
    print("=" * 78)

    start = time.time()

    group_f1_church_numerals()
    group_f2_combinators()
    group_f3_structural()
    group_f4_double_sys8()
    group_f5_sys2()
    group_f6_preamble_sys8()

    elapsed = time.time() - start

    print(f"\n{'=' * 78}")
    print(f"  SUMMARY — {_request_count} requests in {elapsed:.1f}s")
    print(f"{'=' * 78}")

    if FLAGGED:
        print(f"\n  FLAGGED ({len(FLAGGED)}):")
        for f in FLAGGED:
            print(f"    {f}")
    else:
        print("\n  No non-Permission-denied results flagged (all denied/empty/error).")

    # Categorize results
    cats: dict[str, int] = {}
    for _, r in RESULTS:
        key = r.split(":")[0] if ":" in r else r[:30]
        cats[key] = cats.get(key, 0) + 1
    print(f"\n  Result categories:")
    for k, cnt in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"    {k:40s} x{cnt}")

    print(f"\n{'=' * 78}")
    print("  DONE")
    print(f"{'=' * 78}")


if __name__ == "__main__":
    main()
