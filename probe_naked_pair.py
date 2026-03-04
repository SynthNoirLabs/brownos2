#!/usr/bin/env python3
"""
probe_naked_pair.py - Test sys8 with naked backdoor pair and raw-write continuation.

New insights from forum re-read (March 2026):
  - dloser 2016: "substructures [from syscall outputs] might be helpful elsewhere"
  - l3st3r (solver): used "bad QD" that skips quote → writes result directly as bytes
  - Forum exchange: EMPTY = success "if you didn't want it to return anything"
  - Oracle: QD fails silently when result contains Var(253..255); computed head is
    a "crucial property"; runtime-only terms constructed via echo/backdoor

Key untested axis:
  P1-P4: backdoor(nil) unwrapped Left → naked pair(A,B) → sys8(pair)
          [previously we passed Left(pair), NEVER the naked pair itself]
  P5-P6: sys8 with a "raw writer" continuation that bypasses Either decode
          [tests if sys8 returns something non-Either that OBS misses]
  P7-P8: sys8 with echo-mediated Var(251/252) — high-index runtime terms
          [only constructible at runtime, unquotable by standard QD]
  P9:    sys8 with naked A combinator from backdoor
  P10:   sys8 with naked B combinator from backdoor
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

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

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
    raise TypeError(f"Unsupported: {type(term)}")


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
# Constants
# ---------------------------------------------------------------------------

NIL_DB = Lam(Lam(Var(0)))  # K* = nil = λa.λb.b
NIL = NConst(NIL_DB)

# A = λa.λb. b b
A_DB = Lam(Lam(App(Var(0), Var(0))))
A = NConst(A_DB)

# B = λa.λb. a b
B_DB = Lam(Lam(App(Var(1), Var(0))))
B = NConst(B_DB)

# pair(A,B) = λs. s A B (Scott pair)
PAIR_AB_DB = Lam(App(App(Var(0), A_DB), B_DB))
PAIR_AB = NConst(PAIR_AB_DB)


def str_term(s: str) -> NConst:
    return NConst(encode_bytes_list(s.encode("ascii", "replace")))


def write_str(s: str) -> object:
    return apps(g(2), str_term(s), NIL)


# ---------------------------------------------------------------------------
# Observers
# ---------------------------------------------------------------------------


def make_obs_either() -> object:
    """Standard Either observer: print 'LEFT' or error string."""
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


def make_obs_raw_write() -> object:
    """
    'Bad QD' style raw-write continuation.
    Attempts to write the result directly as if it were a bytes list,
    bypassing Either decode. Will print something if sys8 returns a
    bytes list directly (not wrapped in Either).
    """
    return lam("r", apps(g(2), v("r"), NIL))


def make_obs_quote_write() -> object:
    """
    Standard QD-style: quote the result, then write if Left.
    Same as real QD but as named term.
    """
    return lam(
        "r",
        apps(
            g(4),
            v("r"),  # quote(r) → Either Left(bytes) | Right(err)
            lam(
                "qb",  # qb = quoted bytes
                apps(g(2), v("qb"), NIL),
            ),  # write(qb)
            lam("_qe", write_str("QUOTE_FAIL\n")),
        ),
    )


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
    return out


def query(payload: bytes, retries: int = 4, timeout_s: float = 7.0) -> bytes:
    delay = 0.3
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


def build_payload(term: object) -> bytes:
    db = to_db(term)
    enc = encode_term(db)
    return enc + bytes([FF])


def classify(out: bytes) -> str:
    if not out:
        return "EMPTY"
    known_text = [
        "Invalid term!",
        "Encoding failed!",
        "Term too big!",
        "Permission denied",
        "Not implemented",
        "ERR_DECODE_FAIL",
        "LEFT\n",
        "QUOTE_FAIL\n",
    ]
    for t in known_text:
        if out.startswith(t.encode("ascii")):
            return f"TEXT:{t!r}"
    try:
        text = out.decode("utf-8", "replace")
        if all((ch == "\n") or (ch == "\r") or (32 <= ord(ch) < 127) for ch in text):
            return f"TEXT:{text.strip()!r}"
    except Exception:
        pass
    return f"HEX:{out[:80].hex()}"


def is_breakthrough(c: str) -> bool:
    blocklist = [
        "Permission denied",
        "EMPTY",
        "Invalid term!",
        "Encoding failed!",
        "Term too big!",
        "ERROR:",
        "ERR_DECODE_FAIL",
        "Not implemented",
        "QUOTE_FAIL",
    ]
    return not any(b in c for b in blocklist)


def report(label: str, payload_size: int, c: str) -> None:
    flag = " *** BREAKTHROUGH ***" if is_breakthrough(c) else ""
    print(f"{label:68s} sz={payload_size:4d} -> {c}{flag}")


def section(title: str) -> None:
    print(f"\n{'=' * 80}")
    print(title)
    print("='*80")


# ---------------------------------------------------------------------------
# Group P1-P4: Naked pair and components from backdoor
# ---------------------------------------------------------------------------


def group_p1_naked_pair() -> None:
    section("GROUP P1-P4: Naked backdoor pair (unwrapped Left) → sys8")

    OBS = make_obs_either()

    # P1: backdoor(nil) → unwrap Left → sys8(pair)(OBS)
    # backdoor returns Left(pair), so:
    # backdoor(nil)(λpair. sys8(pair)(OBS))(λ_. write("BD_FAIL"))
    p1_term = apps(
        g(201),
        NIL,  # backdoor(nil)
        lam(
            "pair",  # Left handler: got the pair
            apps(g(8), v("pair"), NConst(to_db(OBS))),  # sys8(pair)(OBS)
        ),
        lam(
            "_err",  # Right handler
            write_str("BD_RIGHT\n"),
        ),
    )

    p1 = build_payload(p1_term)
    if len(p1) <= 1900:
        out = query(p1)
        c = classify(out)
        report("P1 backdoor(nil)→unwrap→sys8(naked_pair)(OBS)", len(p1), c)
    else:
        print(f"P1 skipped: payload too big ({len(p1)} bytes)")
    time.sleep(0.4)

    # P2: sys8(A)(OBS) — naked A combinator
    p2_term = apps(g(8), A, NConst(to_db(OBS)))
    p2 = build_payload(p2_term)
    out = query(p2)
    c = classify(out)
    report("P2 sys8(naked_A)(OBS)", len(p2), c)
    time.sleep(0.4)

    # P3: sys8(B)(OBS) — naked B combinator
    p3_term = apps(g(8), B, NConst(to_db(OBS)))
    p3 = build_payload(p3_term)
    out = query(p3)
    c = classify(out)
    report("P3 sys8(naked_B)(OBS)", len(p3), c)
    time.sleep(0.4)

    # P4: sys8(pair(A,B))(OBS) — explicit pair term (not from backdoor)
    p4_term = apps(g(8), PAIR_AB, NConst(to_db(OBS)))
    p4 = build_payload(p4_term)
    out = query(p4)
    c = classify(out)
    report("P4 sys8(pair_A_B_direct)(OBS)", len(p4), c)
    time.sleep(0.4)


# ---------------------------------------------------------------------------
# Group P5-P6: Raw-write continuation (bypasses Either decode)
# ---------------------------------------------------------------------------


def group_p5_raw_write() -> None:
    section("GROUP P5-P6: sys8 with raw-write continuation (bad QD style)")

    RAW = make_obs_raw_write()
    RAW_db = to_db(RAW)

    # P5: sys8(nil)(raw_write) — skip Either, just try to write raw result
    p5_term = apps(g(8), NIL, NConst(RAW_db))
    p5 = build_payload(p5_term)
    out = query(p5, timeout_s=10.0)
    c = classify(out)
    report("P5 sys8(nil)(raw_write_cont)", len(p5), c)
    time.sleep(0.4)

    # P6: sys8(nil)(λr. r(raw_write)(raw_write)) — apply result to two raw writers
    # Tests if result is a function that wants two args (like Either-style)
    # but with raw writers instead of proper handlers
    RAW2 = lam(
        "r",
        apps(
            v("r"),
            lam("_a", write_str("BRANCH_A\n")),
            lam("_b", write_str("BRANCH_B\n")),
        ),
    )
    RAW2_db = to_db(RAW2)
    p6_term = apps(g(8), NIL, NConst(RAW2_db))
    p6 = build_payload(p6_term)
    out = query(p6, timeout_s=10.0)
    c = classify(out)
    report("P6 sys8(nil)(branch_A_or_B_cont)", len(p6), c)
    time.sleep(0.4)


# ---------------------------------------------------------------------------
# Group P7-P8: Echo-mediated high-index runtime terms → sys8
# ---------------------------------------------------------------------------


def group_p7_echo_highidx() -> None:
    section("GROUP P7-P8: Echo high-index Var (runtime-only) → sys8")

    OBS = make_obs_either()
    OBS_db = to_db(OBS)

    # P7: echo(Var(251)) → Left contains runtime Var(253) → unwrap → sys8
    # echo(Var(251))(λleft_payload. sys8(left_payload)(OBS))(λ_. write("ECHO_RIGHT"))
    # Var(251) at top level = global[251] — a stub that returns Right(1)
    # But the ECHOED Left(V251) is a runtime term with high index
    p7_term = apps(
        g(14),
        NConst(Var(251)),  # echo(Var(251))
        lam(
            "ep",  # Left handler: ep = echoed payload = Left(Var(251))
            apps(g(8), v("ep"), NConst(OBS_db)),  # sys8(ep)(OBS)
        ),
        lam("_er", write_str("ECHO_RIGHT\n")),
    )
    p7 = build_payload(p7_term)
    out = query(p7, timeout_s=10.0)
    c = classify(out)
    report("P7 echo(V251)→unwrap→sys8(V253_runtime)(OBS)", len(p7), c)
    time.sleep(0.4)

    # P8: echo(Var(252)) → Left contains runtime Var(254)
    p8_term = apps(
        g(14),
        NConst(Var(252)),  # echo(Var(252))
        lam("ep", apps(g(8), v("ep"), NConst(OBS_db))),
        lam("_er", write_str("ECHO_RIGHT\n")),
    )
    p8 = build_payload(p8_term)
    out = query(p8, timeout_s=10.0)
    c = classify(out)
    report("P8 echo(V252)→unwrap→sys8(V254_runtime)(OBS)", len(p8), c)
    time.sleep(0.4)


# ---------------------------------------------------------------------------
# Group P9-P11: sys8 with quote-style continuation (non-standard)
# ---------------------------------------------------------------------------


def group_p9_alt_cont() -> None:
    section("GROUP P9-P11: sys8 with alternative observers")

    # P9: sys8(nil) with QD-style (quote+write) named-term observer
    QW = make_obs_quote_write()
    QW_db = to_db(QW)
    p9_term = apps(g(8), NIL, NConst(QW_db))
    p9 = build_payload(p9_term)
    out = query(p9, timeout_s=10.0)
    c = classify(out)
    report("P9 sys8(nil)(quote_write_obs)", len(p9), c)
    time.sleep(0.4)

    # P10: sys8(pair(A,B)) with quote-write observer
    p10_term = apps(g(8), PAIR_AB, NConst(QW_db))
    p10 = build_payload(p10_term)
    out = query(p10, timeout_s=10.0)
    c = classify(out)
    report("P10 sys8(pair_A_B)(quote_write_obs)", len(p10), c)
    time.sleep(0.4)

    # P11: Verify OBS sanity — sys7(int(11)) should give "Permission denied" as RIGHT
    # Wait: sys7 should return Left(passwd), not Right. Use sys8 as baseline.
    # Actually just baseline: sys8(int(0)) should still be Right(6).
    OBS = make_obs_either()
    OBS_db = to_db(OBS)
    baseline_term = apps(g(8), NConst(encode_byte_term(0)), NConst(OBS_db))
    b_payload = build_payload(baseline_term)
    out = query(b_payload)
    c = classify(out)
    report("P11 BASELINE sys8(int(0))(OBS)", len(b_payload), c)
    time.sleep(0.4)


# ---------------------------------------------------------------------------
# Group P12: Backdoor pair unwrapped, then apply pair to itself → sys8
# ---------------------------------------------------------------------------


def group_p12_pair_self() -> None:
    section("GROUP P12: Pair applied to itself and A/B variants → sys8")

    OBS = make_obs_either()
    OBS_db = to_db(OBS)

    # P12a: sys8(A(A))(OBS) — A applied to A (terminates to λb. b A)
    AA = NConst(Lam(App(A_DB, A_DB)))  # λb. b (λa.λb.b b) = result of A(A)
    p12a_term = apps(g(8), AA, NConst(OBS_db))
    p12a = build_payload(p12a_term)
    out = query(p12a)
    c = classify(out)
    report("P12a sys8(A_applied_A)(OBS)", len(p12a), c)
    time.sleep(0.4)

    # P12b: sys8(B(A))(OBS) — B applied to A
    BA = NConst(Lam(App(A_DB, Var(0))))  # λb. A(b) = result of B(A)
    p12b_term = apps(g(8), BA, NConst(OBS_db))
    p12b = build_payload(p12b_term)
    out = query(p12b)
    c = classify(out)
    report("P12b sys8(B_applied_A)(OBS)", len(p12b), c)
    time.sleep(0.4)

    # P12c: sys8(A(B))(OBS) — A applied to B
    AB_result = NConst(Lam(App(Var(0), B_DB)))  # λb. b B = result of A(B)
    p12c_term = apps(g(8), AB_result, NConst(OBS_db))
    p12c = build_payload(p12c_term)
    out = query(p12c)
    c = classify(out)
    report("P12c sys8(A_applied_B)(OBS)", len(p12c), c)
    time.sleep(0.4)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 80)
    print(
        "PROBE NAKED PAIR - Naked backdoor pair + raw-write continuation + high-index"
    )
    print(f"Target: {HOST}:{PORT}")
    print("=" * 80)

    group_p1_naked_pair()  # P1-P4: naked pair/A/B from backdoor
    group_p5_raw_write()  # P5-P6: raw-write bypass observer
    group_p7_echo_highidx()  # P7-P8: echo high-index runtime terms
    group_p9_alt_cont()  # P9-P11: alt observers
    group_p12_pair_self()  # P12a-c: pair combinator variants

    print("\n" + "=" * 80)
    print("DONE")
    print("=" * 80)


if __name__ == "__main__":
    main()
