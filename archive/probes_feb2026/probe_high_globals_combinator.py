#!/usr/bin/env python3
"""
probe_high_globals_combinator.py - Characterize g(248)-g(252) as potential combinators.

Previous tests used them as syscalls: g(N)(arg, cont).
This tests them as combinators with 1, 2, 3 args of various types including
Either values, pairs, and other structured data.

Also tests:
- g(N)(Right(6)) — does it transform the error?
- g(N)(Left(nil)) — does it transform the success?
- g(N)(g(8)) — does it dispatch through sys8?
- g(N) g(8) FD obs FD — the cheat sheet trampoline pattern
- Interactive IO: sys8 with socket kept open for second-stage
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
    encode_byte_term,
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


def query_interactive(
    payload1: bytes, payload2: bytes, wait_between: float = 1.0, timeout_s: float = 10.0
) -> tuple[bytes, bytes]:
    """Send payload1, wait, read any response, send payload2, read response.
    Does NOT shutdown write between sends."""
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload1)
            time.sleep(wait_between)
            # Try to read any immediate response
            sock.settimeout(1.0)
            resp1 = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp1 += chunk
            except socket.timeout:
                pass
            # Send second payload
            try:
                sock.sendall(payload2)
            except Exception:
                return resp1, b"ERR:send2_failed"
            # Read second response
            sock.settimeout(timeout_s)
            resp2 = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp2 += chunk
            except socket.timeout:
                pass
            return resp1, resp2
    except Exception as e:
        return b"", f"ERR:connect:{e}".encode()


def write_str(s: str) -> object:
    return apps(g(2), NConst(encode_bytes_list(s.encode("latin-1"))), NIL)


def obs() -> object:
    """Write-only observer: prints LEFT! for Left, error string for Right."""
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


# Scott-encoded Either values
def scott_left(payload: object) -> object:
    """Left x = λl.λr. l x"""
    return lam("l", lam("r", app(v("l"), payload)))


def scott_right(code: object) -> object:
    """Right y = λl.λr. r y"""
    return lam("l", lam("r", app(v("r"), code)))


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
        return "PERM_DENIED"
    if "LEFT!" in text:
        return "LEFT!"
    if "Not implemented" in text:
        return "NOT_IMPL"
    if "Invalid argument" in text:
        return "INVALID_ARG"
    if "No such" in text:
        return "NO_SUCH"
    if "Rate limit" in text:
        return "RATE_LIMIT"
    if "Exception" in text:
        return "EXCEPTION"
    if text.strip() == "?":
        return "UNKNOWN_ERR"
    return f"OTHER({text[:80]!r})"


def run_test(
    label: str, term: object, results: list[ResultRow], timeout_s: float = 8.0
) -> None:
    out = query_named(term, timeout_s=timeout_s)
    verdict = classify_output(out)
    print(f"  {label} -> {verdict}")
    if verdict.startswith("OTHER"):
        print(f"    hex={out[:60].hex()}")
    results.append({"label": label, "raw": out, "verdict": verdict})
    time.sleep(0.35)


def run_raw_test(
    label: str, payload: bytes, results: list[ResultRow], timeout_s: float = 8.0
) -> None:
    out = query_raw(payload, timeout_s=timeout_s)
    verdict = classify_output(out)
    print(f"  {label} -> {verdict}")
    if verdict.startswith("OTHER"):
        print(f"    hex={out[:60].hex()}")
    results.append({"label": label, "raw": out, "verdict": verdict})
    time.sleep(0.35)


def phase_1_combinator_characterization(results: list[ResultRow]) -> None:
    """
    Test g(248)-g(252) with 1 argument of various types.
    If they're combinators, they might DO something with the argument
    rather than treating it as a syscall call.
    """
    print("\n" + "=" * 72)
    print("PHASE 1: g(248-252) with 1 argument (combinator test)")
    print("=" * 72)

    # Construct some standard inputs
    right_6 = scott_right(NConst(encode_byte_term(6)))  # Right(6) = Permission denied
    right_1 = scott_right(NConst(encode_byte_term(1)))  # Right(1) = Not implemented
    left_nil = scott_left(NIL)  # Left(nil)
    left_hello = scott_left(NConst(encode_bytes_list(b"hello")))  # Left("hello")

    inputs = [
        ("Right(6)", right_6),
        ("Right(1)", right_1),
        ("Left(nil)", left_nil),
        ("Left('hello')", left_hello),
        ("nil", NIL),
        ("g(8)", g(8)),
        ("g(14)", g(14)),
        ("g(201)", g(201)),
        ("identity", IDENTITY),
    ]

    for n in range(248, 253):
        print(f"\n  --- g({n}) ---")
        for inp_name, inp_val in inputs:
            # g(N)(input) — only 1 arg, write the result to output
            # We need to observe the result. Since g(N)(X) might return something,
            # we wrap: g(N)(X)(obs_left)(obs_right) to see if it's an Either
            # But we don't know if it returns an Either! So try multiple framings:

            # Frame A: Treat result as Either -> apply left_handler and right_handler
            run_test(
                f"g({n})({inp_name}) as Either -> OBS",
                apps(
                    app(g(n), inp_val),
                    lam("_L", write_str(f"g{n}({inp_name})=LEFT")),
                    lam("_R", write_str(f"g{n}({inp_name})=RIGHT")),
                ),
                results,
            )


def phase_2_trampoline_pattern(results: list[ResultRow]) -> None:
    """
    Test the cheat sheet '?? ?? FD QD FD' pattern with g(248-252) as first ??.
    Uses write-only observer instead of QD to avoid encoding issues.
    """
    print("\n" + "=" * 72)
    print("PHASE 2: g(N) g(8) FD obs FD - trampoline pattern")
    print("=" * 72)

    for n in range(248, 253):
        # Pattern: g(N) g(8) FD OBS FD FF = (g(N)(g(8)))(OBS)
        # This is: apply g(N) to g(8), then apply result to OBS
        run_test(
            f"(g({n})(g(8)))(OBS) - trampoline",
            apps(app(g(n), g(8)), OBS),
            results,
        )

    # Also try g(N) as SECOND ??:
    for n in range(248, 253):
        # g(8) g(N) FD OBS FD FF = (g(8)(g(N)))(OBS) = sys8(g(N), OBS)
        run_test(
            f"sys8(g({n}), OBS)",
            apps(g(8), g(n), OBS),
            results,
        )

    # Try g(N)(g(8))(nil)(OBS) — 3-arg calling convention where g(N) dispatches
    for n in range(248, 253):
        run_test(
            f"g({n})(g(8))(nil)(OBS) - dispatch",
            apps(g(n), g(8), NIL, OBS),
            results,
        )


def phase_3_two_arg_combinator(results: list[ResultRow]) -> None:
    """
    Test g(248-252) with 2 arguments to see if they act as binary combinators.
    """
    print("\n" + "=" * 72)
    print("PHASE 3: g(248-252) with 2 arguments (binary combinator)")
    print("=" * 72)

    for n in range(248, 253):
        # g(N)(nil, nil) — then observe output
        run_test(
            f"g({n})(nil, nil) -> write result",
            apps(g(n), NIL, NIL),
            results,
            timeout_s=5.0,
        )

        # g(N)(g(8), nil) — g(8) as first arg, nil as second
        run_test(
            f"g({n})(g(8), nil) -> write result",
            apps(g(n), g(8), NIL),
            results,
            timeout_s=5.0,
        )

        # g(N)(nil, g(8)) — nil as first, g(8) as second
        run_test(
            f"g({n})(nil, g(8)) -> write result",
            apps(g(n), NIL, g(8)),
            results,
            timeout_s=5.0,
        )


def phase_4_either_transform(results: list[ResultRow]) -> None:
    """
    Can g(248-252) transform an Either? Specifically, does g(N)(Right(6))
    become Left(something)?

    Also: use sys8's own result as input to g(N).
    """
    print("\n" + "=" * 72)
    print("PHASE 4: g(N) transforms sys8's Right(6) result?")
    print("=" * 72)

    for n in range(248, 253):
        # sys8(nil, λresult. g(N)(result)(left_handler)(right_handler))
        run_test(
            f"sys8(nil) -> g({n})(result) -> observe Either",
            apps(
                g(8),
                NIL,
                lam(
                    "res",
                    apps(
                        app(g(n), v("res")),
                        lam("_L", write_str(f"TRANSFORMED_LEFT_{n}")),
                        lam("_R", write_str(f"STILL_RIGHT_{n}")),
                    ),
                ),
            ),
            results,
        )

    # Also: backdoor result -> g(N) -> sys8
    for n in range(248, 253):
        run_test(
            f"backdoor -> g({n})(pair) -> sys8(result, OBS)",
            apps(
                g(201),
                NIL,
                lam(
                    "bd",
                    apps(
                        v("bd"),
                        lam("pair", apps(g(8), app(g(n), v("pair")), OBS)),
                        lam("_err", write_str("BD_ERR")),
                    ),
                ),
            ),
            results,
        )


def phase_5_interactive_io(results: list[ResultRow]) -> None:
    """
    Test interactive IO: send sys8 call, keep socket open, send more data.
    Maybe sys8 expects a second-stage input from the socket.
    """
    print("\n" + "=" * 72)
    print("PHASE 5: Interactive IO - sys8 then second-stage input")
    print("=" * 72)

    # Build sys8(nil, OBS) payload WITHOUT FF terminator first
    sys8_payload_no_ff = (
        bytes([8])
        + encode_term(NIL_DB)
        + bytes([FD])
        + encode_term(to_db(OBS))
        + bytes([FD])
    )

    # Stage 1: sys8(nil, OBS) FF
    stage1 = sys8_payload_no_ff + bytes([FF])
    # Stage 2: some follow-up data
    stage2_variants = [
        ("nil FF", encode_term(NIL_DB) + bytes([FF])),
        (
            "g(201) nil FD QD FD FF",
            bytes([201]) + encode_term(NIL_DB) + bytes([FD]) + QD + bytes([FD, FF]),
        ),
        (
            "password 'ilikephp' FF",
            encode_term(to_db(NConst(encode_bytes_list(b"ilikephp")))) + bytes([FF]),
        ),
        ("raw 0x00 FF", bytes([0x00, FF])),
        ("raw 0x08 FF", bytes([0x08, FF])),
    ]

    for label2, stage2 in stage2_variants:
        print(f"\n  Interactive: sys8(nil,OBS) FF -> wait -> {label2}")
        resp1, resp2 = query_interactive(stage1, stage2, wait_between=1.0)
        v1 = classify_output(resp1)
        v2 = classify_output(resp2)
        print(f"    resp1: {v1} ({resp1[:40].hex() if resp1 else 'empty'})")
        print(f"    resp2: {v2} ({resp2[:40].hex() if resp2 else 'empty'})")
        results.append(
            {
                "label": f"interactive: sys8 -> {label2}",
                "raw": resp1 + resp2,
                "verdict": f"r1={v1},r2={v2}",
            }
        )
        time.sleep(0.5)

    # Also try: send sys8 WITHOUT FF, wait, then send FF
    print(f"\n  Interactive: sys8(nil,OBS) [no FF] -> wait -> FF")
    resp1, resp2 = query_interactive(sys8_payload_no_ff, bytes([FF]), wait_between=1.0)
    v1 = classify_output(resp1)
    v2 = classify_output(resp2)
    print(f"    resp1: {v1} ({resp1[:40].hex() if resp1 else 'empty'})")
    print(f"    resp2: {v2} ({resp2[:40].hex() if resp2 else 'empty'})")
    results.append(
        {
            "label": "interactive: sys8 [no FF] -> FF",
            "raw": resp1 + resp2,
            "verdict": f"r1={v1},r2={v2}",
        }
    )


def phase_6_raw_trampoline_qd(results: list[ResultRow]) -> None:
    """
    Raw byte patterns: g(N) g(8) FD QD FD FF for N in 248-252.
    Even though QD might fail for some results, let's see what happens.
    """
    print("\n" + "=" * 72)
    print("PHASE 6: Raw g(N) g(8) FD QD FD FF patterns")
    print("=" * 72)

    qd_bytes = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

    for n in range(248, 253):
        # g(N) g(8) FD QD FD FF
        payload = bytes([n, 8, FD]) + qd_bytes + bytes([FD, FF])
        run_raw_test(f"RAW: g({n}) g(8) FD QD FD FF", payload, results)

    # Also try reversed: g(8) g(N) FD QD FD FF
    for n in range(248, 253):
        payload = bytes([8, n, FD]) + qd_bytes + bytes([FD, FF])
        run_raw_test(f"RAW: g(8) g({n}) FD QD FD FF", payload, results)


def main() -> None:
    print("=" * 72)
    print("probe_high_globals_combinator.py")
    print(f"target: {HOST}:{PORT}")
    print("=" * 72)

    results: list[ResultRow] = []

    phase_1_combinator_characterization(results)
    phase_2_trampoline_pattern(results)
    phase_3_two_arg_combinator(results)
    phase_4_either_transform(results)
    phase_5_interactive_io(results)
    phase_6_raw_trampoline_qd(results)

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

    # Highlight non-standard results
    standard = {"PERM_DENIED", "EMPTY", "NOT_IMPL", "UNKNOWN_ERR", "INVALID_ARG"}
    interesting = [
        r for r in results if not any(r["verdict"].startswith(s) for s in standard)
    ]
    if interesting:
        print("\n*** INTERESTING RESULTS ***")
        for r in interesting:
            print(f"  {r['label']}: {r['verdict']}")
            text = r["raw"].decode("latin-1", errors="replace")[:200]
            print(f"    -> {text!r}")


if __name__ == "__main__":
    main()
