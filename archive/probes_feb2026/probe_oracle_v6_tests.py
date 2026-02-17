#!/usr/bin/env python3
"""
probe_oracle_v6_tests.py - Test Oracle #6 recommendations:

1. echo(251) -> Left(Var(253)) -> unwrap -> call Var(253) as hidden primitive
2. echo(252) -> Left(Var(254)) -> unwrap -> call Var(254) as hidden primitive
3. echo(250) -> Left(Var(252)) -> unwrap -> call Var(252) = highest normal global
4. Broader ?? ?? FD QD FD interpretations (non-syscall terms)
5. echo(g(8)) - echo syscall 8 itself
6. sys8 with omega combinator
7. Backdoor pair components applied to each other
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Any

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FF,
    FD,
    FE,
    QD,
    encode_bytes_list,
    encode_term,
    parse_term,
    decode_either,
    decode_byte_term,
    decode_bytes_list,
)

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
IDENTITY = NConst(Lam(Var(0)))


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
    delay = 0.3
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
    delay = 0.3
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
    """Observer continuation: prints LEFT! for Left, resolves error string for Right."""
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


def obs_detailed() -> object:
    """Observer that quotes the Left payload for inspection."""
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
                    lam("_e2", write_str("ERR?")),
                ),
            ),
        ),
    )
    # For Left: quote the payload then write it
    left_handler = lam(
        "payload",
        apps(
            g(4),  # quote
            v("payload"),
            lam(
                "quote_either",
                apps(
                    v("quote_either"),
                    lam("qbytes", apps(g(2), v("qbytes"), NIL)),  # write the bytes
                    lam("_qerr", write_str("QUOTE_FAIL")),
                ),
            ),
        ),
    )
    return lam("res", apps(v("res"), left_handler, right_handler))


OBS = obs()
OBS_DETAILED = obs_detailed()


def classify_output(raw: bytes) -> str:
    if not raw:
        return "EMPTY"
    text = raw.decode("latin-1", errors="replace")
    if "Invalid term!" in text:
        return "INVALID_TERM"
    if "Term too big!" in text:
        return "TERM_TOO_BIG"
    if "Encoding failed!" in text:
        return "ENCODING_FAILED"
    if "Permission denied" in text:
        return "PERMISSION_DENIED"
    if "LEFT!" in text:
        return "LEFT_SUCCESS"
    if "QUOTE_FAIL" in text:
        return "QUOTE_FAIL"
    if "?" == text.strip():
        return "UNKNOWN_ERROR"
    if "Not implemented" in text:
        return "NOT_IMPL"
    if "No such" in text:
        return "NO_SUCH"
    return f"OTHER({text[:100]!r})"


def run_test(
    label: str, term: object, results: list[ResultRow], timeout_s: float = 12.0
) -> None:
    out = query_named(term, timeout_s=timeout_s)
    verdict = classify_output(out)
    text = out.decode("latin-1", errors="replace")[:200]
    print(f"  {label}")
    print(f"    raw_hex={out[:80].hex()}")
    print(f"    text={text!r}")
    print(f"    verdict={verdict}")
    results.append({"label": label, "raw": out, "verdict": verdict})
    time.sleep(0.35)


def run_raw_test(
    label: str, payload: bytes, results: list[ResultRow], timeout_s: float = 12.0
) -> None:
    out = query_raw(payload, timeout_s=timeout_s)
    verdict = classify_output(out)
    text = out.decode("latin-1", errors="replace")[:200]
    print(f"  {label}")
    print(f"    payload_hex={payload.hex()}")
    print(f"    raw_hex={out[:80].hex()}")
    print(f"    text={text!r}")
    print(f"    verdict={verdict}")
    results.append({"label": label, "raw": out, "verdict": verdict})
    time.sleep(0.35)


def phase_1_echo_hidden_globals(results: list[ResultRow]) -> None:
    """
    Core Oracle #6 idea: echo(N) returns Left(Var(N+2)) under the 2 lambdas of the Either.
    For N=251: Left(Var(253)). Var(253) at depth 0 = g(253). If g(253) is a hidden
    primitive (since byte 0xFD can't be directly encoded as a Var in wire format),
    calling it might do something special.

    Approach: Use echo to get Left(Var(253)), then unwrap the Left and call the result.
    """
    print("\n" + "=" * 72)
    print("PHASE 1: echo(N) -> unwrap Left -> call hidden global")
    print("=" * 72)

    for echo_arg, target_global in [(251, 253), (252, 254), (250, 252)]:
        # Test 1a: echo(N) then observe the raw result via QD-like observer
        # echo(N, lambda either. either (lambda payload. quote(payload, ...)) ...)
        run_test(
            f"P1.{echo_arg}a echo({echo_arg}) -> observe via detailed obs",
            apps(g(14), g(echo_arg), OBS_DETAILED),
            results,
        )

        # Test 1b: echo(N) -> unwrap Left -> CALL the unwrapped value with nil -> observe
        # echo(N, lambda either. either (lambda val. val nil OBS) (lambda err. ...))
        run_test(
            f"P1.{echo_arg}b echo({echo_arg}) -> unwrap Left -> call(nil, OBS)",
            apps(
                g(14),
                g(echo_arg),
                lam(
                    "either",
                    apps(
                        v("either"),
                        lam(
                            "val", apps(v("val"), NIL, OBS)
                        ),  # unwrap Left, call val(nil, OBS)
                        lam("_err", write_str(f"ECHO{echo_arg}_RIGHT")),
                    ),
                ),
            ),
            results,
        )

        # Test 1c: echo(N) -> unwrap Left -> call with nil -> detailed obs
        run_test(
            f"P1.{echo_arg}c echo({echo_arg}) -> unwrap Left -> call(nil, OBS_DETAILED)",
            apps(
                g(14),
                g(echo_arg),
                lam(
                    "either",
                    apps(
                        v("either"),
                        lam("val", apps(v("val"), NIL, OBS_DETAILED)),
                        lam("_err", write_str(f"ECHO{echo_arg}_RIGHT")),
                    ),
                ),
            ),
            results,
        )

        # Test 1d: echo(N) -> unwrap Left -> use it as SYSCALL ARGUMENT to sys8
        run_test(
            f"P1.{echo_arg}d echo({echo_arg}) -> unwrap Left -> sys8(val, OBS)",
            apps(
                g(14),
                g(echo_arg),
                lam(
                    "either",
                    apps(
                        v("either"),
                        lam(
                            "val", apps(g(8), v("val"), OBS)
                        ),  # use echoed val as sys8 arg
                        lam("_err", write_str(f"ECHO{echo_arg}_RIGHT")),
                    ),
                ),
            ),
            results,
        )


def phase_2_broad_question_marks(results: list[ResultRow]) -> None:
    """
    Test the '?? ?? FD QD FD' pattern with non-syscall terms in the ?? positions.
    The cheat sheet says: 'just like with QD, don't be too literal with the ??s'
    """
    print("\n" + "=" * 72)
    print("PHASE 2: Broader ?? ?? FD QD FD - non-syscall ?? terms")
    print("=" * 72)

    # The QD hex for the standard observer
    qd_hex = "0500fd000500fd03fdfefd02fdfefdfe"
    qd_bytes = bytes.fromhex(qd_hex)

    # Backdoor pair components (known structure)
    a_term = lam("a", lam("b", app(v("b"), v("b"))))  # λa.λb.(b b)
    b_term = lam("a", lam("b", app(v("a"), v("b"))))  # λa.λb.(a b)
    omega = lam("x", app(v("x"), v("x")))  # λx.(x x)

    # 2a: (A B) QD - backdoor pair components applied to each other
    run_test("P2a (A B) QD", apps(app(a_term, b_term), OBS_DETAILED), results)

    # 2b: (B A) QD - reversed
    run_test("P2b (B A) QD", apps(app(b_term, a_term), OBS_DETAILED), results)

    # 2c: (omega nil) QD - omega applied to nil
    run_test(
        "P2c (omega nil) QD",
        apps(app(omega, NIL), OBS_DETAILED),
        results,
        timeout_s=8.0,
    )

    # 2d: (identity identity) QD - trivial
    run_test("P2d (id id) QD", apps(app(IDENTITY, IDENTITY), OBS_DETAILED), results)

    # 2e: Directly use raw bytes for ?? ?? FD QD FD with unusual terms
    # Try: g(201) g(14) FD QD FD FF - backdoor and echo in ?? slots
    payload_2e = bytes([201, 14, FD]) + qd_bytes + bytes([FD, FF])
    run_raw_test("P2e RAW: g(201) g(14) FD QD FD FF", payload_2e, results)

    # 2f: g(14) g(201) FD QD FD FF - echo and backdoor swapped
    payload_2f = bytes([14, 201, FD]) + qd_bytes + bytes([FD, FF])
    run_raw_test("P2f RAW: g(14) g(201) FD QD FD FF", payload_2f, results)

    # 2g: g(8) g(201) FD QD FD FF - sys8 and backdoor
    payload_2g = bytes([8, 201, FD]) + qd_bytes + bytes([FD, FF])
    run_raw_test("P2g RAW: g(8) g(201) FD QD FD FF", payload_2g, results)

    # 2h: g(201) g(8) FD QD FD FF - backdoor and sys8
    payload_2h = bytes([201, 8, FD]) + qd_bytes + bytes([FD, FF])
    run_raw_test("P2h RAW: g(201) g(8) FD QD FD FF", payload_2h, results)

    # 2i: g(42) g(8) FD QD FD FF - towel and sys8
    payload_2i = bytes([42, 8, FD]) + qd_bytes + bytes([FD, FF])
    run_raw_test("P2i RAW: g(42) g(8) FD QD FD FF", payload_2i, results)

    # 2j: g(14) g(8) FD QD FD FF - echo and sys8
    payload_2j = bytes([14, 8, FD]) + qd_bytes + bytes([FD, FF])
    run_raw_test("P2j RAW: g(14) g(8) FD QD FD FF", payload_2j, results)

    # 2k: nil g(8) FD QD FD FF - nil and sys8
    nil_enc = encode_term(NIL_DB)
    payload_2k = nil_enc + bytes([8, FD]) + qd_bytes + bytes([FD, FF])
    run_raw_test("P2k RAW: nil g(8) FD QD FD FF", payload_2k, results)

    # 2l: omega g(8) FD QD FD FF - omega and sys8
    omega_enc = encode_term(to_db(omega))
    payload_2l = omega_enc + bytes([8, FD]) + qd_bytes + bytes([FD, FF])
    run_raw_test("P2l RAW: omega g(8) FD QD FD FF", payload_2l, results, timeout_s=8.0)


def phase_3_echo_sys8_itself(results: list[ResultRow]) -> None:
    """
    Test echoing g(8) itself - does echo have special behavior for syscall 8?
    """
    print("\n" + "=" * 72)
    print("PHASE 3: echo(g(8)) - echo syscall 8 itself")
    print("=" * 72)

    # 3a: echo(g(8), OBS) - echo syscall 8 as a value, observe
    run_test("P3a echo(g(8), OBS)", apps(g(14), g(8), OBS), results)

    # 3b: echo(g(8), OBS_DETAILED) - with quote
    run_test("P3b echo(g(8), OBS_DETAILED)", apps(g(14), g(8), OBS_DETAILED), results)

    # 3c: echo(g(8)) -> unwrap Left -> call with nil, OBS
    run_test(
        "P3c echo(g(8)) -> unwrap -> call(nil, OBS)",
        apps(
            g(14),
            g(8),
            lam(
                "either",
                apps(
                    v("either"),
                    lam("val", apps(v("val"), NIL, OBS)),
                    lam("_err", write_str("ECHO8_RIGHT")),
                ),
            ),
        ),
        results,
    )

    # 3d: echo(g(8)) -> unwrap Left -> use as sys8 arg
    run_test(
        "P3d echo(g(8)) -> unwrap -> sys8(val, OBS)",
        apps(
            g(14),
            g(8),
            lam(
                "either",
                apps(
                    v("either"),
                    lam("val", apps(g(8), v("val"), OBS)),
                    lam("_err", write_str("ECHO8_RIGHT")),
                ),
            ),
        ),
        results,
    )


def phase_4_sys8_omega(results: list[ResultRow]) -> None:
    """
    Test sys8 with omega combinator as argument.
    """
    print("\n" + "=" * 72)
    print("PHASE 4: sys8 with omega combinator")
    print("=" * 72)

    omega = lam("x", app(v("x"), v("x")))

    # 4a: sys8(omega, OBS)
    run_test("P4a sys8(omega, OBS)", apps(g(8), omega, OBS), results)

    # 4b: sys8(omega omega, OBS) - divergent argument
    # This might hang, so short timeout
    run_test(
        "P4b sys8(omega(omega), OBS)",
        apps(g(8), app(omega, omega), OBS),
        results,
        timeout_s=6.0,
    )


def phase_5_backdoor_chain(results: list[ResultRow]) -> None:
    """
    Multi-step: backdoor -> extract pair -> use pair components creatively with sys8.
    """
    print("\n" + "=" * 72)
    print("PHASE 5: Backdoor chain -> pair -> creative sys8 uses")
    print("=" * 72)

    k_comb = lam("a", lam("b", v("a")))
    k_second = lam("a", lam("b", v("b")))

    # 5a: backdoor(nil) -> unwrap Left(pair) -> pair(pair)(nil) -> sys8(result, OBS)
    # Apply the pair to itself - pair is λx.λy.((x A) B)
    # pair(pair) = (pair A) B... then result goes to sys8
    run_test(
        "P5a backdoor -> pair(pair)(nil) -> sys8",
        apps(
            g(201),
            NIL,
            lam(
                "bd",
                apps(
                    v("bd"),
                    lam(
                        "pair",
                        apps(
                            g(8),
                            apps(v("pair"), v("pair"), NIL),
                            OBS,
                        ),
                    ),
                    lam("_err", write_str("BD_ERR")),
                ),
            ),
        ),
        results,
    )

    # 5b: backdoor(nil) -> unwrap -> (A B) where A=λa.λb.(bb), B=λa.λb.(ab)
    # (A B) = ω = λx.(xx). Then sys8(ω, OBS)
    run_test(
        "P5b backdoor -> extract A,B -> A(B)=omega -> sys8(omega, OBS)",
        apps(
            g(201),
            NIL,
            lam(
                "bd",
                apps(
                    v("bd"),
                    lam(
                        "pair",
                        apps(
                            # pair is λx.λy.((x A) B). To extract A: pair(K)(nil)
                            # To extract B: pair(K')(nil) where K'=λa.λb.b
                            # Then A(B) = omega
                            g(8),
                            apps(
                                apps(v("pair"), k_comb, NIL),  # extract A
                                apps(
                                    v("pair"), k_second, NIL
                                ),  # extract B, apply A to B
                            ),
                            OBS,
                        ),
                    ),
                    lam("_err", write_str("BD_ERR")),
                ),
            ),
        ),
        results,
    )

    # 5c: backdoor(nil) -> extract omega via A(B) -> call omega with g(8) -> observe
    run_test(
        "P5c backdoor -> A(B)=omega -> omega(g(8)) -> observe",
        apps(
            g(201),
            NIL,
            lam(
                "bd",
                apps(
                    v("bd"),
                    lam(
                        "pair",
                        apps(
                            # omega(g(8)) = g(8)(g(8)) which is sys8(sys8)...
                            apps(
                                apps(v("pair"), k_comb, NIL),  # A
                                apps(v("pair"), k_second, NIL),  # B -> A(B) = omega
                            ),
                            g(8),  # omega(g(8)) = g(8)(g(8))
                            OBS,
                        ),
                    ),
                    lam("_err", write_str("BD_ERR")),
                ),
            ),
        ),
        results,
        timeout_s=8.0,
    )


def phase_6_echo_chain_into_sys8(results: list[ResultRow]) -> None:
    """
    Echo chain: echo(X) -> get Left(X') -> echo(X') -> get Left(X'') -> sys8(X'', OBS)
    Double-echo to see if chained echo produces something different.
    """
    print("\n" + "=" * 72)
    print("PHASE 6: Echo chains into sys8")
    print("=" * 72)

    # 6a: echo(251) -> unwrap -> echo(val) -> unwrap -> call val2(nil, OBS)
    run_test(
        "P6a echo(251) -> unwrap -> echo(val) -> unwrap -> val2(nil, OBS)",
        apps(
            g(14),
            g(251),
            lam(
                "e1",
                apps(
                    v("e1"),
                    lam(
                        "v1",
                        apps(
                            g(14),
                            v("v1"),
                            lam(
                                "e2",
                                apps(
                                    v("e2"),
                                    lam("v2", apps(v("v2"), NIL, OBS)),
                                    lam("_err2", write_str("E2_RIGHT")),
                                ),
                            ),
                        ),
                    ),
                    lam("_err1", write_str("E1_RIGHT")),
                ),
            ),
        ),
        results,
    )

    # 6b: echo(251) -> unwrap -> echo(val) -> unwrap -> sys8(val2, OBS)
    run_test(
        "P6b echo(251) -> unwrap -> echo(val) -> unwrap -> sys8(val2, OBS)",
        apps(
            g(14),
            g(251),
            lam(
                "e1",
                apps(
                    v("e1"),
                    lam(
                        "v1",
                        apps(
                            g(14),
                            v("v1"),
                            lam(
                                "e2",
                                apps(
                                    v("e2"),
                                    lam("v2", apps(g(8), v("v2"), OBS)),
                                    lam("_err2", write_str("E2_RIGHT")),
                                ),
                            ),
                        ),
                    ),
                    lam("_err1", write_str("E1_RIGHT")),
                ),
            ),
        ),
        results,
    )


def phase_7_raw_var253_callable(results: list[ResultRow]) -> None:
    """
    Direct approach: Can we construct a raw payload that places 0xFD in a Var position
    and see what happens? Normally 0xFD is App, but what if the parser has a special mode?

    Also: test what echo(251) actually returns by quoting it through QD.
    """
    print("\n" + "=" * 72)
    print("PHASE 7: Raw payload experiments + QD observation of echo results")
    print("=" * 72)

    qd_bytes = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

    # 7a: echo(251, QD) - standard QD observation of echo(251)
    # This is: g(14) g(251) FD QD FD FF -> echo(g(251), QD)
    payload_7a = bytes([14, 251, FD]) + qd_bytes + bytes([FD, FF])
    run_raw_test("P7a echo(g(251), QD)", payload_7a, results)

    # 7b: echo(252, QD)
    payload_7b = bytes([14, 252, FD]) + qd_bytes + bytes([FD, FF])
    run_raw_test("P7b echo(g(252), QD)", payload_7b, results)

    # 7c: echo(250, QD)
    payload_7c = bytes([14, 250, FD]) + qd_bytes + bytes([FD, FF])
    run_raw_test("P7c echo(g(250), QD)", payload_7c, results)

    # 7d: echo(0, QD) - baseline
    payload_7d = bytes([14, 0, FD]) + qd_bytes + bytes([FD, FF])
    run_raw_test("P7d echo(g(0), QD) [baseline]", payload_7d, results)

    # 7e: echo(8, QD)
    payload_7e = bytes([14, 8, FD]) + qd_bytes + bytes([FD, FF])
    run_raw_test("P7e echo(g(8), QD)", payload_7e, results)

    # 7f: echo(42, QD) - towel baseline
    payload_7f = bytes([14, 42, FD]) + qd_bytes + bytes([FD, FF])
    run_raw_test("P7f echo(g(42), QD) [baseline]", payload_7f, results)

    # 7g: sys8(nil, QD) - baseline for comparison
    payload_7g = (
        bytes([8]) + encode_term(NIL_DB) + bytes([FD]) + qd_bytes + bytes([FD, FF])
    )
    run_raw_test("P7g sys8(nil, QD) [baseline]", payload_7g, results)


def main() -> None:
    print("=" * 72)
    print("probe_oracle_v6_tests.py")
    print(f"target: {HOST}:{PORT}")
    print("=" * 72)

    results: list[ResultRow] = []

    # Run QD-based observations first to understand echo behavior
    phase_7_raw_var253_callable(results)

    # Core Oracle #6 tests
    phase_1_echo_hidden_globals(results)

    # Broader ?? ?? FD QD FD
    phase_2_broad_question_marks(results)

    # Echo sys8 itself
    phase_3_echo_sys8_itself(results)

    # Omega combinator
    phase_4_sys8_omega(results)

    # Backdoor chain
    phase_5_backdoor_chain(results)

    # Echo chains
    phase_6_echo_chain_into_sys8(results)

    # Summary
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)

    verdicts: dict[str, list[str]] = {}
    for r in results:
        v_class = r["verdict"]
        if v_class not in verdicts:
            verdicts[v_class] = []
        verdicts[v_class].append(r["label"])

    for v_class, labels in sorted(verdicts.items()):
        print(f"\n{v_class} ({len(labels)}):")
        for lb in labels:
            print(f"  - {lb}")

    # Highlight anything non-standard
    interesting = [
        r
        for r in results
        if r["verdict"]
        not in (
            "PERMISSION_DENIED",
            "EMPTY",
            "NOT_IMPL",
            "UNKNOWN_ERROR",
        )
    ]
    if interesting:
        print("\n*** INTERESTING RESULTS ***")
        for r in interesting:
            print(f"  {r['label']}: {r['verdict']}")
            text = r["raw"].decode("latin-1", errors="replace")[:300]
            print(f"    -> {text!r}")


if __name__ == "__main__":
    main()
