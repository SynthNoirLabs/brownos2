#!/usr/bin/env python3
"""
probe_phase2_echo_raw.py — Echo raw / special-byte probe (Phase 2).

KEY INSIGHT (dloser Jan 2026 hint): The echo syscall (0x0E) returns Left(term)
at the TERM level. If we feed the echo result directly to sys8 WITHOUT
unwrapping via CPS destructuring, sys8 receives a closure that internally
contains variables with special-byte indices (253/254/255). These variables
CANNOT be serialized by quote but CAN exist as runtime values.

This probe differs from probe_phase2_echo_special.py by:
  - Sending raw bytecode sequences (bypassing encode_term for Var 253+ tests)
  - Passing echo results to sys8 WITHOUT Any unwrapping
  - Systematic 3-leaf enumeration with high-index globals
  - Testing direct raw bytecodes as sys8 arguments (FB FC FD FA FD patterns)
  - Exploring whether the VM treats Left-wrapped special-byte terms differently

Categories:
  R1: Raw 3-leaf bytecode — hand-crafted byte sequences with 3 variable bytes
  R2: Echo→sys8 NO unwrap — echo(g(N))→sys8(raw_Left) for various N
  R3: Nested echo stacking WITHOUT unwrap at any level
  R4: Backdoor→echo→sys8 raw chain (no destructuring)
  R5: 3-leaf systematic with high indices near special boundary
  R6: Echo with constructed terms → raw to sys8
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
    encode_byte_term,
    encode_bytes_list,
    encode_term,
)

HOST = "wc3.wechall.net"
PORT = 61221
DELAY = 0.45
MAX_REQUESTS = 35

FD = 0xFD
FE = 0xFE
FF = 0xFF

TARGET_HASH = "9252ed65ffac2aa763adb21ef72c0178f1d83286"


# ---------------------------------------------------------------------------
# Named-term DSL (matches existing probes)
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


def check_answer_hash(candidate: str) -> bool:
    """Check if sha1^56154(candidate) == TARGET_HASH."""
    h = candidate.encode("utf-8")
    for _ in range(56154):
        h = hashlib.sha1(h).digest()
    return hashlib.sha1(h).hexdigest() == TARGET_HASH


# ---------------------------------------------------------------------------
# Term constants
# ---------------------------------------------------------------------------

NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)

A_DB = Lam(Lam(App(Var(0), Var(0))))  # λa.λb. b b
B_DB = Lam(Lam(App(Var(1), Var(0))))  # λa.λb. a b
A = NConst(A_DB)
B = NConst(B_DB)

I = NConst(Lam(Var(0)))


def int_term(n: int) -> NConst:
    return NConst(encode_byte_term(n))


def str_term(s: str) -> NConst:
    return NConst(encode_bytes_list(s.encode("ascii", "replace")))


# ---------------------------------------------------------------------------
# Observers
# ---------------------------------------------------------------------------

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def write_str(s: str) -> object:
    return apps(g(2), str_term(s), NIL)


def make_observer() -> object:
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
    left_handler = lam("_left_payload", write_str("LEFT\n"))
    return lam("result", apps(v("result"), left_handler, right_handler))


OBS = make_observer()


def make_breakthrough_observer() -> object:
    """Observer that writes 'BT:' + quote(payload) if Left, else error string."""
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
    left_handler = lam(
        "payload",
        apps(
            g(2),
            str_term("BT:"),
            lam(
                "_w1",
                apps(
                    g(4),
                    v("payload"),
                    lam(
                        "q_either",
                        apps(
                            v("q_either"),
                            lam("qbytes", apps(g(2), v("qbytes"), NIL)),
                            lam("_qerr", write_str("QUOTE_FAIL\n")),
                        ),
                    ),
                ),
            ),
        ),
    )
    return lam("result", apps(v("result"), left_handler, right_handler))


BT_OBS = make_breakthrough_observer()


# ---------------------------------------------------------------------------
# Execution helpers
# ---------------------------------------------------------------------------

RESULTS: list[tuple[str, str]] = []
FLAGGED: list[str] = []
_request_count = 0


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
    is_breakthrough = (
        "Permission denied" not in result
        and result
        not in (
            "EMPTY",
            "Invalid term!",
            "Encoding failed!",
            "Term too big!",
        )
        and not result.startswith("ERROR:")
    )
    if is_breakthrough:
        flag = " *** BREAKTHROUGH ***"
        FLAGGED.append(f"{label} -> {result}")
        if result.startswith("TEXT:"):
            candidate = result[5:].replace("\\n", "\n").strip()
            if candidate and len(candidate) < 100:
                print(f"    *** TESTING ANSWER HASH: '{candidate}' ***")
                if check_answer_hash(candidate):
                    print(f"    *** HASH MATCH! ANSWER = '{candidate}' ***")
    print(f"  {label:58s} -> {result}{flag}")
    RESULTS.append((label, result))
    time.sleep(sleep_s)
    return result


def run_raw(
    label: str, payload_bytes: bytes, sleep_s: float = DELAY, timeout_s: float = 7.0
) -> str | None:
    """Send raw bytecode directly (no encode_term)."""
    global _request_count
    if _request_count >= MAX_REQUESTS:
        print(f"  [{label}] SKIPPED — rate limit ({MAX_REQUESTS} reached)")
        return None
    if len(payload_bytes) > 1500:
        result = f"SKIPPED (payload={len(payload_bytes)} > 1500)"
        print(f"  {label:58s} -> {result}")
        RESULTS.append((label, result))
        return result
    _request_count += 1
    out = query(payload_bytes, timeout_s=timeout_s)
    result = classify(out)
    flag = ""
    is_breakthrough = (
        "Permission denied" not in result
        and result
        not in (
            "EMPTY",
            "Invalid term!",
            "Encoding failed!",
            "Term too big!",
        )
        and not result.startswith("ERROR:")
    )
    if is_breakthrough:
        flag = " *** BREAKTHROUGH ***"
        FLAGGED.append(f"{label} -> {result}")
        if result.startswith("TEXT:"):
            candidate = result[5:].replace("\\n", "\n").strip()
            if candidate and len(candidate) < 100:
                print(f"    *** TESTING ANSWER HASH: '{candidate}' ***")
                if check_answer_hash(candidate):
                    print(f"    *** HASH MATCH! ANSWER = '{candidate}' ***")
    print(f"  {label:58s} -> {result}{flag}")
    RESULTS.append((label, result))
    time.sleep(sleep_s)
    return result


def section(title: str) -> None:
    print(f"\n{'=' * 78}")
    print(f"  {title}")
    print(f"{'=' * 78}")


# ---------------------------------------------------------------------------
# R1: Raw 3-leaf bytecode — hand-crafted byte sequences
# The idea: FD in bytecode means App, but what if the parser/VM treats
# certain sequences differently? We send raw bytes that form 3-leaf terms
# with variables near the special boundary, then observe sys8's response.
# ---------------------------------------------------------------------------


def group_r1_raw_bytecodes() -> None:
    section("R1: Raw 3-leaf bytecode → sys8")

    # sys8(g(251)(g(252)))(OBS)
    # = App(App(g(8), App(g(251), g(252))), OBS)
    # Bytecodes: 08 FB FC FD FD <OBS> FD FF
    # But we need OBS encoded too. Let's use QD instead for simplicity.
    # sys8(g(251)(g(252)))(QD)
    # = App(App(g(8), App(g(251), g(252))), QD)
    # = 08 FB FC FD FD QD FD FF
    run_raw(
        "R1a sys8(g251(g252))(QD) raw",
        bytes([0x08, 0xFB, 0xFC, FD, FD]) + QD + bytes([FD, FF]),
    )

    # sys8(App(App(g(251), g(252)), g(250)))(QD)
    # = App(App(g(8), App(App(g(251), g(252)), g(250))), QD)
    # = 08 FB FC FD FA FD FD QD FD FF
    run_raw(
        "R1b sys8(g251(g252)(g250))(QD) raw",
        bytes([0x08, 0xFB, 0xFC, FD, 0xFA, FD, FD]) + QD + bytes([FD, FF]),
    )

    # sys8(App(g(251), App(g(252), g(250))))(QD)
    # = 08 FB FC FA FD FD FD QD FD FF
    run_raw(
        "R1c sys8(g251(g252(g250)))(QD) raw",
        bytes([0x08, 0xFB, 0xFC, 0xFA, FD, FD, FD]) + QD + bytes([FD, FF]),
    )

    # 3-leaf with g(0), g(8), g(201): sys8(g(0)(g(201)))(QD)
    # = App(App(g(8), App(g(0), g(201))), QD)
    # = 08 00 C9 FD FD QD FD FF
    run_raw(
        "R1d sys8(g0(g201))(QD) raw",
        bytes([0x08, 0x00, 0xC9, FD, FD]) + QD + bytes([FD, FF]),
    )

    # sys8(nil)(QD) as raw baseline — nil = 00 FE FE
    # = App(App(g(8), nil), QD) = 08 00 FE FE FD QD FD FF
    run_raw(
        "R1e sys8(nil)(QD) raw baseline",
        bytes([0x08, 0x00, FE, FE, FD]) + QD + bytes([FD, FF]),
    )


# ---------------------------------------------------------------------------
# R2: Echo→sys8 NO unwrap
# Key difference from E2: we pass the ENTIRE echo result directly to sys8
# as a lambda-calculus value. No CPS destructuring of the Either.
# echo(X)(λresult. sys8(result)(OBS))
# The echo result is Left(X) = a closure. sys8 receives the closure directly.
# ---------------------------------------------------------------------------


def group_r2_echo_raw_to_sys8() -> None:
    section("R2: Echo→sys8 raw (no unwrap)")

    for idx in [251, 252, 250, 249, 248]:
        run_case(
            f"R2 echo(g({idx}))->sys8(raw_left)",
            apps(
                g(0x0E),
                g(idx),
                lam("result", apps(g(8), v("result"), OBS)),
            ),
        )

    # Also echo(nil) — known to work, baseline
    run_case(
        "R2 echo(nil)->sys8(raw_left)",
        apps(
            g(0x0E),
            NIL,
            lam("result", apps(g(8), v("result"), OBS)),
        ),
    )

    # echo(g(8)) — echo the sys8 syscall itself, pass Left(g(8)) to sys8
    run_case(
        "R2 echo(g(8))->sys8(raw_left)",
        apps(
            g(0x0E),
            g(8),
            lam("result", apps(g(8), v("result"), OBS)),
        ),
    )


# ---------------------------------------------------------------------------
# R3: Nested echo stacking WITHOUT unwrap
# echo(X) → Left(X). echo(Left(X)) → Left(Left(X)). Pass to sys8 as-is.
# Each echo wrapping adds 2 more lambdas. The inner term gets shifted.
# After N wrappings, the original Var(K) is at de Bruijn index K + 2N
# in the innermost scope.
# ---------------------------------------------------------------------------


def group_r3_nested_echo() -> None:
    section("R3: Nested echo (no unwrap) → sys8")

    # Triple echo: echo(echo(echo(g(247)))) — after 3 wraps, inner is +6=253=FD!
    run_case(
        "R3a echo^3(g(247))->sys8  [+6=253]",
        apps(
            g(0x0E),
            g(247),
            lam(
                "e1",
                apps(
                    g(0x0E),
                    v("e1"),
                    lam(
                        "e2",
                        apps(
                            g(0x0E),
                            v("e2"),
                            lam("e3", apps(g(8), v("e3"), OBS)),
                        ),
                    ),
                ),
            ),
        ),
    )

    # Triple echo: g(248) → +6 = 254 = FE
    run_case(
        "R3b echo^3(g(248))->sys8  [+6=254]",
        apps(
            g(0x0E),
            g(248),
            lam(
                "e1",
                apps(
                    g(0x0E),
                    v("e1"),
                    lam(
                        "e2",
                        apps(
                            g(0x0E),
                            v("e2"),
                            lam("e3", apps(g(8), v("e3"), OBS)),
                        ),
                    ),
                ),
            ),
        ),
    )

    # Triple echo: g(249) → +6 = 255 = FF!
    run_case(
        "R3c echo^3(g(249))->sys8  [+6=255]",
        apps(
            g(0x0E),
            g(249),
            lam(
                "e1",
                apps(
                    g(0x0E),
                    v("e1"),
                    lam(
                        "e2",
                        apps(
                            g(0x0E),
                            v("e2"),
                            lam("e3", apps(g(8), v("e3"), OBS)),
                        ),
                    ),
                ),
            ),
        ),
    )

    # Double echo with BT_OBS to see if Left success produces different output
    run_case(
        "R3d echo^2(g(251))->sys8(BT_OBS) [+4=255]",
        apps(
            g(0x0E),
            g(251),
            lam(
                "e1",
                apps(
                    g(0x0E),
                    v("e1"),
                    lam("e2", apps(g(8), v("e2"), BT_OBS)),
                ),
            ),
        ),
    )


# ---------------------------------------------------------------------------
# R4: Backdoor→echo→sys8 raw chain
# Get the backdoor pair, DON'T extract A/B, echo the ENTIRE pair,
# then pass the Left(pair) to sys8 directly.
# ---------------------------------------------------------------------------


def group_r4_backdoor_echo_raw() -> None:
    section("R4: Backdoor→echo→sys8 raw chain")

    # backdoor(nil)(λbd_result. echo(bd_result)(λecho_r. sys8(echo_r)(OBS)))
    # Don't destructure the Either from backdoor — pass raw Either to echo
    run_case(
        "R4a bd(nil)->echo(bd_either)->sys8(raw)",
        apps(
            g(201),
            NIL,
            lam(
                "bd_result",
                apps(
                    g(0x0E),
                    v("bd_result"),
                    lam("echo_r", apps(g(8), v("echo_r"), OBS)),
                ),
            ),
        ),
    )

    # Backdoor → destructure to get pair → echo(pair) → sys8(Left(pair)) raw
    run_case(
        "R4b bd->pair->echo(pair)->sys8(raw)",
        apps(
            g(201),
            NIL,
            lam(
                "bd_either",
                apps(
                    v("bd_either"),
                    lam(
                        "pair",
                        apps(
                            g(0x0E),
                            v("pair"),
                            lam("echo_r", apps(g(8), v("echo_r"), OBS)),
                        ),
                    ),
                    lam("_err", write_str("BD_ERR\n")),
                ),
            ),
        ),
    )

    # Backdoor → extract A → echo(A) → sys8(Left(A)) — NO unwrap of Left
    run_case(
        "R4c bd->A->echo(A)->sys8(Left(A))",
        apps(
            g(201),
            NIL,
            lam(
                "bd_either",
                apps(
                    v("bd_either"),
                    lam(
                        "pair",
                        apps(
                            v("pair"),
                            lam(
                                "a_val",
                                lam(
                                    "_b",
                                    apps(
                                        g(0x0E),
                                        v("a_val"),
                                        lam("echo_r", apps(g(8), v("echo_r"), OBS)),
                                    ),
                                ),
                            ),
                        ),
                    ),
                    lam("_err", write_str("BD_ERR\n")),
                ),
            ),
        ),
    )


# ---------------------------------------------------------------------------
# R5: Systematic 3-leaf terms with high indices
# "3 leafs" = 3 Var nodes. We try many combinations near the boundary.
# These are sent as raw args to sys8.
# Structure: App(App(Var(a), Var(b)), Var(c)) = "left-associated 3-leaf"
# ---------------------------------------------------------------------------


def group_r5_systematic_3leaf() -> None:
    section("R5: Systematic 3-leaf high-index → sys8")

    # Pairs of (a, b, c) for App(App(g(a), g(b)), g(c))
    triples = [
        (252, 252, 252),  # highest encodable var, all same
        (251, 252, 0),  # two high + 0
        (0, 251, 252),  # 0 + two high
        (8, 251, 252),  # sys8-index + two high
        (201, 251, 252),  # backdoor-index + two high
        (14, 251, 252),  # echo-index + two high
        (252, 251, 14),  # two high + echo
        (252, 0, 252),  # high-0-high
    ]
    for a, b, c in triples:
        run_case(
            f"R5 sys8(g{a}(g{b})(g{c}))",
            apps(g(8), apps(g(a), g(b), g(c)), OBS),
        )


# ---------------------------------------------------------------------------
# R6: Echo with constructed terms → raw to sys8
# Construct terms inside CPS chains that CONTAIN high-index variables,
# then echo them and pass the Left wrapper to sys8.
# ---------------------------------------------------------------------------


def group_r6_echo_constructed() -> None:
    section("R6: Echo with constructed terms → sys8 raw")

    # echo(App(g(252), g(252))) — 2-leaf, echo wraps to Left with Var(254) inside
    run_case(
        "R6a echo(g252(g252))->sys8",
        apps(
            g(0x0E),
            app(g(252), g(252)),
            lam("echo_r", apps(g(8), v("echo_r"), OBS)),
        ),
    )

    # echo(pair(g(251), g(252))) — Scott pair containing high vars
    # pair(x,y) = λf. f(x)(y)
    pair_high = lam("f", apps(v("f"), g(251), g(252)))
    run_case(
        "R6b echo(pair(g251,g252))->sys8",
        apps(
            g(0x0E),
            pair_high,
            lam("echo_r", apps(g(8), v("echo_r"), OBS)),
        ),
    )

    # echo at the PROGRAM level: don't use echo syscall, manually construct
    # Left(g(252)) = λl.λr. l(g(252))
    # As bytecode: build Lam(Lam(App(Var(1), Var(254))))
    # But Var(254) = 0xFE = Lam marker! Can't encode directly.
    # Instead: use echo syscall to produce this term at runtime, then feed to sys8.
    # That's what R2 already does. But let's try a different approach:
    # Construct the Left manually in bytecode where the inner var is g(252),
    # which under 2 lambdas becomes Var(254) in de Bruijn. But 254=0xFE=Lam!
    # The parser would interpret it as Lam, not Var. So this CAN'T be encoded.
    # This confirms: echo is the ONLY way to create terms with Var(253+) inside.

    # Novel: echo(g(252)) → Left(g(252)). This Left has Var(254) inside.
    # Now apply the Left as if it were a function: Left(x)(f)(g) = f(x)
    # So Left(g(252))(sys8)(OBS) = sys8(g(252))
    # This is equivalent to sys8(g(252))(OBS) — which we've tested.
    # But the MECHANISM is different: we're using Left as a dispatcher.
    # What if sys8 checks HOW it was called?
    run_case(
        "R6c echo(g252)->Left(sys8)(OBS) [Left dispatches]",
        apps(
            g(0x0E),
            g(252),
            lam("left_result", apps(v("left_result"), g(8), g(8))),
            # left_result = Left(g(252)) = λl.λr.l(g(252))
            # left_result(g(8))(g(8)) = g(8)(g(252)) = sys8(g(252))
            # Then sys8(g(252)) gets applied to... second g(8)? No, CPS.
            # Actually: left_result(g(8))(g(8))
            #   = (λl.λr.l(g252))(g8)(g8)
            #   = (λr.g8(g252))(g8)
            #   = g8(g252)
            # This is sys8 applied to g(252) but without continuation!
            # Let me fix: use OBS as 3rd arg would need different structure.
        ),
    )

    # Fixed: echo(g(252)) → use Left destructuring to call sys8 with OBS
    # echo(g(252))(λleft. left(λpayload. sys8(payload)(OBS))(λ_. write("RIGHT")))
    # This unwraps the Left, extracts g(252), passes to sys8.
    # Already tested in E2. Let's try the OPPOSITE: use Left as-is as sys8's arg.
    # Actually, we DID this in R2. So let's do something novel:

    # Novel: use echo to construct a 3-leaf term at runtime, then sys8 it
    # echo(g(252)) → Left(g(252))
    # echo(Left(g(252))) → Left(Left(g(252)))
    # Now Left(Left(g(252))) has 3 leaves inside:
    #   Left(Left(g252)) = λl.λr.l(Left(g252))
    #   Left(g252) = λl'.λr'.l'(g252)
    # Var nodes: l (=Var(1)), l' (=Var(1 under 2 more = Var(3)), g252 (=Var(252+4=256))
    # Wait, this is tricky. Let's just try it.
    run_case(
        "R6d echo^2(g252)->sys8 [3 vars inside]",
        apps(
            g(0x0E),
            g(252),
            lam(
                "e1",
                apps(
                    g(0x0E),
                    v("e1"),
                    lam("e2", apps(g(8), v("e2"), OBS)),
                ),
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 78)
    print("  PROBE PHASE 2: Echo Raw / Special-Byte → sys8 (No Unwrap)")
    print(f"  Target: {HOST}:{PORT}")
    print(f"  Max requests: {MAX_REQUESTS}, delay: {DELAY}s")
    print("=" * 78)

    start = time.time()

    group_r1_raw_bytecodes()
    group_r2_echo_raw_to_sys8()
    group_r3_nested_echo()
    group_r4_backdoor_echo_raw()
    group_r5_systematic_3leaf()
    group_r6_echo_constructed()

    elapsed = time.time() - start

    print(f"\n{'=' * 78}")
    print(f"  SUMMARY — {_request_count} requests in {elapsed:.1f}s")
    print(f"{'=' * 78}")

    if FLAGGED:
        print(f"\n  *** BREAKTHROUGHS ({len(FLAGGED)}) ***:")
        for f in FLAGGED:
            print(f"    {f}")
    else:
        print("\n  No breakthroughs (all denied/empty/error).")

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
