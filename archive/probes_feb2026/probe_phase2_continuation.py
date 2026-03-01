#!/usr/bin/env python3
"""
probe_phase2_continuation.py — Phase 2: sys8 continuation-shape experiments.

HYPOTHESIS: sys8 might check its CONTINUATION (second CPS argument), not its
first argument. All previous tests varied the first argument but used standard
continuations (OBS, QD, identity, write_k, etc.).

Categories:
  C1: Backdoor-derived continuations (A, B, combos)
  C2: Syscall-as-continuation (g(N) in continuation position)
  C3: Complex CPS chains as continuation
  C4: QD continuation variants
  C5: Raw bytecode experiments
  C6: Continuation that builds/processes the answer
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
    parse_term,
    decode_either,
    decode_byte_term,
)

HOST = "wc3.wechall.net"
PORT = 61221
DELAY = 0.45

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


# ---------------------------------------------------------------------------
# Named-term DSL (from probe_phase2_fuzzer.py)
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


def query_bytes(payload: bytes, retries: int = 4, timeout_s: float = 7.0) -> bytes:
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
    if out.startswith(b"Term too big!"):
        return "Term too big!"
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


def classify_qd(out: bytes) -> str:
    """Classify output from QD-observed syscalls: try to decode Either."""
    if not out:
        return "EMPTY"
    if out.startswith(b"Invalid term!"):
        return "Invalid term!"
    if out.startswith(b"Encoding failed!"):
        return "Encoding failed!"
    if out.startswith(b"Term too big!"):
        return "Term too big!"
    if out.startswith(b"ERROR:"):
        return out.decode("ascii", "replace")
    try:
        term = parse_term(out)
        tag, payload = decode_either(term)
        if tag == "Right":
            code = decode_byte_term(payload)
            return f"Right({code})"
        return f"Left({term})"
    except Exception:
        pass
    return classify(out)


# ---------------------------------------------------------------------------
# Constant terms
# ---------------------------------------------------------------------------

NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)

A_DB = Lam(Lam(App(Var(0), Var(0))))  # A = lambda a.lambda b. b b
B_DB = Lam(Lam(App(Var(1), Var(0))))  # B = lambda a.lambda b. a b
A = NConst(A_DB)
B = NConst(B_DB)

I = NConst(Lam(Var(0)))  # identity


def int_term(n: int) -> NConst:
    return NConst(encode_byte_term(n))


def str_term(s: str) -> NConst:
    return NConst(encode_bytes_list(s.encode("ascii", "replace")))


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

RESULTS: list[tuple[str, str]] = []
FLAGGED: list[str] = []
_request_count = 0
MAX_REQUESTS = 35


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
    out = query_bytes(payload, timeout_s=timeout_s)
    result = classify(out)
    flag = ""
    if is_breakthrough(label, result):
        flag = " *** BREAKTHROUGH ***"
        FLAGGED.append(f"{label} -> {result}")
    print(f"  {label:58s} -> {result}{flag}")
    RESULTS.append((label, result))
    time.sleep(sleep_s)
    return result


def run_raw(
    label: str, raw_payload: bytes, sleep_s: float = DELAY, timeout_s: float = 7.0
) -> str | None:
    """Send raw bytes directly (no named-term compilation)."""
    global _request_count
    if _request_count >= MAX_REQUESTS:
        print(f"  [{label}] SKIPPED — rate limit ({MAX_REQUESTS} reached)")
        return None
    if len(raw_payload) > 1500:
        result = f"SKIPPED (payload={len(raw_payload)} > 1500)"
        print(f"  {label:58s} -> {result}")
        RESULTS.append((label, result))
        return result
    _request_count += 1
    out = query_bytes(raw_payload, timeout_s=timeout_s)
    result = classify(out)
    flag = ""
    if is_breakthrough(label, result):
        flag = " *** BREAKTHROUGH ***"
        FLAGGED.append(f"{label} -> {result}")
    print(f"  {label:58s} -> {result}{flag}")
    RESULTS.append((label, result))
    time.sleep(sleep_s)
    return result


def run_qd(
    label: str, syscall_num: int, arg: object, sleep_s: float = DELAY
) -> str | None:
    """Run ((g(N) arg) QD) and classify via Either decoding."""
    global _request_count
    if _request_count >= MAX_REQUESTS:
        print(f"  [{label}] SKIPPED — rate limit ({MAX_REQUESTS} reached)")
        return None
    db_arg = to_db(arg)
    payload = (
        bytes([syscall_num]) + encode_term(db_arg) + bytes([FD]) + QD + bytes([FD, FF])
    )
    if len(payload) > 1500:
        result = f"SKIPPED (payload={len(payload)} > 1500)"
        print(f"  {label:58s} -> {result}")
        RESULTS.append((label, result))
        return result
    _request_count += 1
    out = query_bytes(payload)
    result = classify_qd(out)
    flag = ""
    # Anything other than Right(6) from sys8 is a breakthrough
    if syscall_num == 0x08 and result != "Right(6)" and is_breakthrough(label, result):
        flag = " *** BREAKTHROUGH ***"
        FLAGGED.append(f"{label} -> {result}")
    print(f"  {label:58s} -> {result}{flag}")
    RESULTS.append((label, result))
    time.sleep(sleep_s)
    return result


def is_breakthrough(label: str, result: str) -> bool:
    if "sys8" not in label.lower():
        return False

    if result.startswith("Left(") or result.startswith("TEXT:LEFT"):
        return True

    if result.startswith("Right("):
        return result != "Right(6)"

    return False


def section(title: str) -> None:
    print(f"\n{'=' * 78}")
    print(f"  {title}")
    print(f"{'=' * 78}")


# ---------------------------------------------------------------------------
# C1: Backdoor-derived continuations
# ---------------------------------------------------------------------------


def group_c1_backdoor_continuations() -> None:
    section("C1: Backdoor A/B as continuation of sys8")

    # sys8(nil)(A) — A as continuation: A(result) = lambda b. b b
    run_case("C1 sys8(nil)(A)", apps(g(8), NIL, A))

    # sys8(nil)(B) — B as continuation: B(result) = lambda b. result(b)
    run_case("C1 sys8(nil)(B)", apps(g(8), NIL, B))

    # sys8(nil)(lambda r. A(r)(B))
    run_case("C1 sys8(nil)(lr.A(r)(B))", apps(g(8), NIL, lam("r", apps(A, v("r"), B))))

    # sys8(nil)(lambda r. B(r)(A))
    run_case("C1 sys8(nil)(lr.B(r)(A))", apps(g(8), NIL, lam("r", apps(B, v("r"), A))))

    # sys8(nil)(lambda r. B(A)(r))
    run_case("C1 sys8(nil)(lr.B(A)(r))", apps(g(8), NIL, lam("r", apps(B, A, v("r")))))

    # sys8(nil)(lambda r. A(B)(r)) = result(result) (since A(B)(r) = r(r))
    run_case("C1 sys8(nil)(lr.A(B)(r))", apps(g(8), NIL, lam("r", apps(A, B, v("r")))))

    # sys8(nil)(lambda r. r(A)(B)) — result applied to A then B
    run_case("C1 sys8(nil)(lr.r(A)(B))", apps(g(8), NIL, lam("r", apps(v("r"), A, B))))


# ---------------------------------------------------------------------------
# C2: Syscall-as-continuation
# ---------------------------------------------------------------------------


def group_c2_syscall_as_continuation() -> None:
    section("C2: Syscall as continuation of sys8")

    # sys8(nil)(g(2)) — write as continuation
    run_case("C2 sys8(nil)(g(2))", apps(g(8), NIL, g(2)))

    # sys8(nil)(g(4)) — quote as continuation
    run_case("C2 sys8(nil)(g(4))", apps(g(8), NIL, g(4)))

    # sys8(nil)(g(5)) — readdir as continuation
    run_case("C2 sys8(nil)(g(5))", apps(g(8), NIL, g(5)))

    # sys8(nil)(g(7)) — readfile as continuation
    run_case("C2 sys8(nil)(g(7))", apps(g(8), NIL, g(7)))

    # sys8(nil)(g(8)) — sys8 ITSELF as continuation!
    run_case("C2 sys8(nil)(g(8))", apps(g(8), NIL, g(8)))

    # sys8(nil)(g(14)) — echo as continuation
    run_case("C2 sys8(nil)(g(14))", apps(g(8), NIL, g(14)))

    # sys8(nil)(g(42)) — towel as continuation
    run_case("C2 sys8(nil)(g(42))", apps(g(8), NIL, g(42)))

    # sys8(nil)(g(201)) — backdoor as continuation
    run_case("C2 sys8(nil)(g(201))", apps(g(8), NIL, g(201)))


# ---------------------------------------------------------------------------
# C3: Complex CPS chains as continuation
# ---------------------------------------------------------------------------


def group_c3_cps_chains() -> None:
    section("C3: Complex CPS chains as continuation of sys8")

    # sys8(nil)(lambda r. g(2)(r)(lambda _.nil))
    run_case(
        "C3 sys8(nil)(lr.write(r))",
        apps(g(8), NIL, lam("r", apps(g(2), v("r"), lam("_", NIL)))),
    )

    # sys8(nil)(lambda r. g(4)(r)(lambda q. g(2)(q)(lambda _.nil)))
    run_case(
        "C3 sys8(nil)(lr.quote(r)->write)",
        apps(
            g(8),
            NIL,
            lam(
                "r",
                apps(
                    g(4),
                    v("r"),
                    lam(
                        "q",
                        apps(
                            v("q"),
                            lam("qbytes", apps(g(2), v("qbytes"), lam("_", NIL))),
                            lam("_qerr", NIL),
                        ),
                    ),
                ),
            ),
        ),
    )

    # sys8(nil)(lambda r. g(201)(r)(lambda p. g(2)(p)(lambda _.nil)))
    # backdoor(result) then write
    run_case(
        "C3 sys8(nil)(lr.backdoor(r)->write)",
        apps(
            g(8),
            NIL,
            lam(
                "r",
                apps(
                    g(201),
                    v("r"),
                    lam(
                        "p",
                        apps(
                            v("p"),
                            lam("payload", apps(g(2), v("payload"), lam("_", NIL))),
                            lam("_err", write_str("BD_ERR\n")),
                        ),
                    ),
                ),
            ),
        ),
    )

    # sys8(nil)(lambda r. g(8)(r)(lambda s. OBS(s)))
    # double sys8: sys8(result) then observe
    run_case(
        "C3 sys8(nil)(lr.sys8(r)->OBS)",
        apps(g(8), NIL, lam("r", apps(g(8), v("r"), OBS))),
    )


# ---------------------------------------------------------------------------
# C4: QD continuation variants
# ---------------------------------------------------------------------------


def group_c4_qd_variants() -> None:
    section("C4: QD continuation variants")

    # sys8(QD)(OBS) — QD as the ARGUMENT (not continuation)
    # QD is a raw bytes sequence; we need to parse it as a term
    qd_term = NConst(parse_term(QD + bytes([FF])))
    run_case("C4 sys8(QD_term)(OBS)", apps(g(8), qd_term, OBS))

    # sys8(nil)(QD_term) — QD term as continuation
    run_case("C4 sys8(nil)(QD_term)", apps(g(8), NIL, qd_term))

    # QD applied to sys8: QD(g(8)) — evaluate QD with sys8 as input
    run_case("C4 QD(g(8))", apps(qd_term, g(8)))

    # sys8(nil) with standard QD (baseline check)
    run_qd("C4 sys8(nil)(QD) [baseline]", 0x08, NIL)


# ---------------------------------------------------------------------------
# C5: Raw bytecode experiments
# ---------------------------------------------------------------------------


def group_c5_raw_bytecode() -> None:
    section("C5: Raw bytecode experiments")

    # The ENTIRE QD cheat sheet example as a standalone program:
    # 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE FF
    run_raw("C5 QD standalone", QD + bytes([FF]))

    # sys8(nil)(QD) using raw bytes:
    # 08 = g(8), 00 FE FE = nil, FD = app, QD bytes, FD = app, FF
    nil_bytes = bytes([0x00, FE, FE])
    raw_sys8_nil_qd = bytes([0x08]) + nil_bytes + bytes([FD]) + QD + bytes([FD, FF])
    run_raw("C5 raw sys8(nil)(QD)", raw_sys8_nil_qd)

    # sys8 with continuation being QD bytes preceded by 0x08:
    # ((g(8) nil) ((g(8) nil) QD))
    # Inner: g(8)(nil) as continuation of outer g(8)(nil), then QD observes inner result
    inner = bytes([0x08]) + nil_bytes + bytes([FD]) + QD + bytes([FD])
    outer = bytes([0x08]) + nil_bytes + bytes([FD]) + inner + bytes([FD, FF])
    if len(outer) <= 1500:
        run_raw("C5 g8(nil)(g8(nil)(QD))", outer)

    # What if we send the QD example from cheatsheet: "QD ?? FD"
    # meaning QD(nil) — apply QD to nil
    qd_nil = QD + nil_bytes + bytes([FD, FF])
    run_raw("C5 QD(nil)", qd_nil)

    # "?? ?? FD QD FD" — (arg arg FD) QD FD = ((arg arg) QD)
    # Use: ((nil nil) QD) — nonsensical but tests the second cheatsheet pattern
    double_nil_qd = nil_bytes + nil_bytes + bytes([FD]) + QD + bytes([FD, FF])
    run_raw("C5 ((nil nil) QD)", double_nil_qd)


# ---------------------------------------------------------------------------
# C6: Continuation that builds/processes the answer
# ---------------------------------------------------------------------------


def group_c6_answer_builder() -> None:
    section("C6: Continuation that processes/extracts sys8 result")

    # sys8(nil)(identity) — lambda r. r
    run_case("C6 sys8(nil)(identity)", apps(g(8), NIL, I))

    # sys8(nil)(lambda r. r(nil))
    run_case("C6 sys8(nil)(lr.r(nil))", apps(g(8), NIL, lam("r", apps(v("r"), NIL))))

    # sys8(nil)(lambda r. r(A)(B)) — if result is a selector
    run_case(
        "C6 sys8(nil)(lr.r(A)(B))",
        apps(g(8), NIL, lam("r", apps(v("r"), A, B))),
    )

    # sys8(nil)(lambda r. write(quote(r))) — observe what sys8 actually returns
    run_case(
        "C6 sys8(nil)(lr.write(quote(r)))",
        apps(
            g(8),
            NIL,
            lam(
                "r",
                apps(
                    g(4),
                    v("r"),
                    lam(
                        "q_either",
                        apps(
                            v("q_either"),
                            lam("qbytes", apps(g(2), v("qbytes"), lam("_", NIL))),
                            lam("_err", write_str("QFAIL\n")),
                        ),
                    ),
                ),
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 78)
    print("  PROBE PHASE 2 CONTINUATION — sys8 continuation-shape experiments")
    print(f"  Target: {HOST}:{PORT}")
    print(f"  Max requests: {MAX_REQUESTS}, delay: {DELAY}s")
    print("=" * 78)

    start = time.time()

    group_c1_backdoor_continuations()
    group_c2_syscall_as_continuation()
    group_c3_cps_chains()
    group_c4_qd_variants()
    group_c5_raw_bytecode()
    group_c6_answer_builder()

    elapsed = time.time() - start

    print(f"\n{'=' * 78}")
    print(f"  SUMMARY — {_request_count} requests in {elapsed:.1f}s")
    print(f"{'=' * 78}")

    if FLAGGED:
        print(f"\n  *** BREAKTHROUGHS ({len(FLAGGED)}) ***")
        for f in FLAGGED:
            print(f"    {f}")
    else:
        print(
            "\n  No breakthroughs. All continuation shapes returned Right(6)/EMPTY/error."
        )

    # Categorize results
    cats: dict[str, int] = {}
    for _, r in RESULTS:
        key = r if len(r) < 40 else r[:40]
        cats[key] = cats.get(key, 0) + 1
    print(f"\n  Result categories:")
    for k, cnt in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"    {k:50s} x{cnt}")

    print(f"\n  Total: {len(RESULTS)} tests, {_request_count} network requests")
    print(f"{'=' * 78}")
    print("  DONE")
    print(f"{'=' * 78}")


if __name__ == "__main__":
    main()
