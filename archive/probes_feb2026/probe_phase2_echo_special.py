#!/usr/bin/env python3
"""
probe_phase2_echo_special.py — Echo + special bytes probe.

Key insight from dloser hints:
  - "3 leafs" = the solution term has exactly 3 Var references
  - Echo (0x0E) returns Left(input). Left = λl.λr. l(payload) => payload is under 2 lambdas (+2 shift).
  - If we echo g(251), the Left payload has Var(253) inside — that's byte 0xFD!
  - Var(252) → 0xFE (lambda marker), Var(250) → 0xFC (still valid but borderline)
  - QD/quote fails with "Encoding failed!" on these terms — can't serialize them.
  - BUT: we can pass the echo-produced term DIRECTLY to sys8 without serialization.

Categories:
  E1: Echo baseline — echo(nil), echo(g(0)), echo(g(251)), echo(g(252))
  E2: Echo→sys8 pipeline — echo(g(N)) → unwrap Left → feed payload to sys8
  E3: 3-leaf terms with special-byte-adjacent globals → sys8
  E4: Backdoor + echo combinations → sys8
  E5: Echo→echo stacking (double-echo shifts by +4)
  E6: 3-leaf terms from echo payloads fed to sys8
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
MAX_REQUESTS = 40

FD = 0xFD
FE = 0xFE
FF = 0xFF

TARGET_HASH = "9252ed65ffac2aa763adb21ef72c0178f1d83286"


# ---------------------------------------------------------------------------
# Named-term DSL (matches project convention)
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


def scott_pair(x: object, y: object) -> object:
    return lam("f", apps(v("f"), x, y))


# ---------------------------------------------------------------------------
# Observers
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


def make_breakthrough_observer() -> object:
    """Observer that writes 'BT:' + payload bytes if Left, else error string."""
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
    # For Left: write marker + try to write payload as bytes
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


def make_raw_write_observer() -> object:
    """Observer that writes the Left payload directly as byte list."""
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
    left_handler = lam("payload", apps(g(2), v("payload"), NIL))
    return lam("result", apps(v("result"), left_handler, right_handler))


RAW_OBS = make_raw_write_observer()


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
    # Flag anything that's NOT Permission denied / EMPTY / Invalid / Encoding failed / ERROR
    is_breakthrough = (
        "Permission denied" not in result
        and result
        not in (
            "EMPTY",
            "Invalid term!",
            "Encoding failed!",
        )
        and not result.startswith("ERROR:")
    )
    if is_breakthrough:
        flag = " *** BREAKTHROUGH ***"
        FLAGGED.append(f"{label} -> {result}")
        # Check if output looks like an answer
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
# E1: Echo baseline — verify echo behavior and special-byte edge cases
# ---------------------------------------------------------------------------


def group_e1_echo_baseline() -> None:
    section("E1: Echo baseline")

    # echo(nil)(QD) — should return Left(nil), QD prints it
    run_case("E1 echo(nil)(OBS)", apps(g(0x0E), NIL, OBS))

    # echo(g(0))(OBS) — echo a free variable
    run_case("E1 echo(g(0))(OBS)", apps(g(0x0E), g(0), OBS))

    # echo(g(251))(OBS) — this should produce Left with Var(253) inside
    # Var(253) = 0xFD = App marker! QD/quote should fail!
    run_case("E1 echo(g(251))(OBS)", apps(g(0x0E), g(251), OBS))

    # echo(g(252))(OBS) — produces Left with Var(254) = 0xFE = Lambda marker
    run_case("E1 echo(g(252))(OBS)", apps(g(0x0E), g(252), OBS))

    # echo(g(250))(OBS) — produces Left with Var(252) = 0xFC (still valid byte)
    run_case("E1 echo(g(250))(OBS)", apps(g(0x0E), g(250), OBS))


# ---------------------------------------------------------------------------
# E2: Echo → sys8 pipeline — echo-produced terms directly to sys8
# Key: echo(g(N)) → Left(g(N)). Unwrap Left → get g(N).
# The payload g(N) under Left's 2 lambdas has de Bruijn index N+2.
# When we unwrap via CPS, the variable reverts to g(N).
# BUT: what if we DON'T unwrap the Either, and instead pass the WHOLE
# Left(g(N)) to sys8? The Left wrapper CONTAINS the special-byte variable.
# ---------------------------------------------------------------------------


def group_e2_echo_to_sys8() -> None:
    section("E2: Echo-produced terms → sys8")

    # Strategy A: echo(g(N)) → unwrap Left → pass payload to sys8
    # echo(g(251))(λresult. result(λpayload. sys8(payload)(OBS))(λerr. write(err)))
    for idx, label_suffix in [(251, "251→253"), (252, "252→254"), (250, "250→252")]:
        run_case(
            f"E2a echo(g({idx}))->unwrap->sys8 [{label_suffix}]",
            apps(
                g(0x0E),
                g(idx),
                lam(
                    "echo_result",
                    apps(
                        v("echo_result"),
                        lam("payload", apps(g(8), v("payload"), OBS)),
                        lam("_err", write_str("ECHO_ERR\n")),
                    ),
                ),
            ),
        )

    # Strategy B: pass the WHOLE echo result (Left term) to sys8
    # The Left term itself is λl.λr.l(g(N+2)) — it CONTAINS the special byte variable
    for idx in [251, 252]:
        run_case(
            f"E2b echo(g({idx}))->sys8(whole_left)",
            apps(
                g(0x0E),
                g(idx),
                lam("echo_result", apps(g(8), v("echo_result"), OBS)),
            ),
        )

    # Strategy C: echo(nil) → sys8(Left(nil))
    run_case(
        "E2c echo(nil)->sys8(whole_left)",
        apps(
            g(0x0E),
            NIL,
            lam("echo_result", apps(g(8), v("echo_result"), OBS)),
        ),
    )


# ---------------------------------------------------------------------------
# E3: 3-leaf terms with special-byte-adjacent globals → sys8
# "My record is 3 leafs" — the solution term has exactly 3 Var references.
# We try App(App(Var(a), Var(b)), Var(c)) and App(Var(a), App(Var(b), Var(c)))
# with special globals (251, 252, 253 range).
# ---------------------------------------------------------------------------


def group_e3_three_leaf_terms() -> None:
    section("E3: 3-leaf terms (special byte globals) → sys8")

    # App(App(g(251), g(252)), g(250)) — three special-adjacent globals
    run_case(
        "E3 sys8(g251(g252)(g250))",
        apps(g(8), apps(g(251), g(252), g(250)), OBS),
    )

    # App(g(251), App(g(252), g(250)))
    run_case(
        "E3 sys8(g251(g252 g250))",
        apps(g(8), app(g(251), app(g(252), g(250))), OBS),
    )

    # Three leaves using backdoor components mixed with specials
    # A = λa.λb.bb, B = λa.λb.ab. These have 2 leaves each.
    # A(g(251)) has: inside A's body, b=g(251), so bb = g(251)(g(251)) under lambda
    # That's App(Var(251), Var(251)) ... but wait, A = λa.λb.bb so A(X) = λb.bb
    # A(X)(Y) = Y(Y). So A(g(251))(g(252)) = g(252)(g(252)) — 2 leaves.
    # B(g(251))(g(252)) = g(251)(g(252)) — 2 leaves.
    # We need 3 leaves. B(A)(g(251)) = A(g(251)) = λb.bb... then applied to nothing = 2 leaves.
    # What about: App(B(A), g(251)) = (λa.λb.ab)(λa.λb.bb)(g(251))
    #   = (λb.(λa.λb.bb)(b))(g(251)) = (λa.λb.bb)(g(251)) = λb.g(251)(b)... wait no
    # Let me think differently. A literal 3-leaf term:
    # Lam(App(App(Var(0), Var(0)), Var(0))) — λx.((x x) x) — 3 leaves, all same var
    three_leaf_self = NConst(Lam(App(App(Var(0), Var(0)), Var(0))))
    run_case("E3 sys8(λx.((x x) x))", apps(g(8), three_leaf_self, OBS))

    # 3-leaf with different vars: App(App(g(8), g(201)), g(14))
    run_case(
        "E3 sys8(g8(g201)(g14))",
        apps(g(8), apps(g(8), g(201), g(14)), OBS),
    )


# ---------------------------------------------------------------------------
# E4: Backdoor + echo combinations → sys8
# Get A, B from backdoor. Echo them. Feed the echo results to sys8.
# ---------------------------------------------------------------------------


def group_e4_backdoor_echo() -> None:
    section("E4: Backdoor + echo → sys8")

    # backdoor(nil) → unwrap Left → get pair → extract A →
    # echo(A) → pass whole echo result to sys8
    run_case(
        "E4 bd->A->echo(A)->sys8(left)",
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
                                    "_b_val",
                                    apps(
                                        g(0x0E),
                                        v("a_val"),
                                        lam("echo_r", apps(g(8), v("echo_r"), OBS)),
                                    ),
                                ),
                            ),
                        ),
                    ),
                    lam("_err", write_str("BDERR\n")),
                ),
            ),
        ),
    )

    # backdoor(nil) → extract B → echo(B) → sys8(echo result)
    run_case(
        "E4 bd->B->echo(B)->sys8(left)",
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
                                "_a_val",
                                lam(
                                    "b_val",
                                    apps(
                                        g(0x0E),
                                        v("b_val"),
                                        lam("echo_r", apps(g(8), v("echo_r"), OBS)),
                                    ),
                                ),
                            ),
                        ),
                    ),
                    lam("_err", write_str("BDERR\n")),
                ),
            ),
        ),
    )

    # backdoor(nil) → extract pair → echo(pair) → sys8(echo result)
    run_case(
        "E4 bd->echo(pair)->sys8(left)",
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
                    lam("_err", write_str("BDERR\n")),
                ),
            ),
        ),
    )

    # Direct: echo the backdoor syscall itself (g(201))
    run_case(
        "E4 echo(g(201))->sys8",
        apps(
            g(0x0E),
            g(201),
            lam("echo_r", apps(g(8), v("echo_r"), OBS)),
        ),
    )


# ---------------------------------------------------------------------------
# E5: Double-echo stacking — echo(echo(X)) shifts variables by +4
# After double-echo: g(249) → Var(253)=0xFD, g(250) → Var(254)=0xFE
# Pass double-echoed terms to sys8.
# ---------------------------------------------------------------------------


def group_e5_double_echo() -> None:
    section("E5: Double-echo stacking → sys8")

    # echo(echo(g(249))) → double-wrapped Left. Inner payload has Var(253)=0xFD!
    # But we pass the whole double-Left structure to sys8
    run_case(
        "E5 echo(echo(g(249)))->sys8",
        apps(
            g(0x0E),
            g(249),
            lam(
                "inner_left",
                apps(
                    g(0x0E),
                    v("inner_left"),
                    lam("outer_left", apps(g(8), v("outer_left"), OBS)),
                ),
            ),
        ),
    )

    # echo(echo(g(250))) — inner has Var(254)=0xFE
    run_case(
        "E5 echo(echo(g(250)))->sys8",
        apps(
            g(0x0E),
            g(250),
            lam(
                "inner_left",
                apps(
                    g(0x0E),
                    v("inner_left"),
                    lam("outer_left", apps(g(8), v("outer_left"), OBS)),
                ),
            ),
        ),
    )


# ---------------------------------------------------------------------------
# E6: Echo-produced 3-leaf terms fed to sys8
# Construct terms with exactly 3 Var nodes using echo's +2 shift property,
# then feed them directly to sys8 without unwrapping.
# ---------------------------------------------------------------------------


def group_e6_echo_3leaf_sys8() -> None:
    section("E6: Echo-produced 3-leaf terms → sys8")

    # echo(App(g(251), App(g(252), g(250)))) — 3-leaf term with special-adjacent globals
    # The echo produces Left(3-leaf-term) where inside the term, vars are shifted +2
    three_leaf_1 = app(g(251), app(g(252), g(250)))
    run_case(
        "E6 echo(g251(g252(g250)))->sys8",
        apps(
            g(0x0E),
            three_leaf_1,
            lam("echo_r", apps(g(8), v("echo_r"), OBS)),
        ),
    )

    # echo(App(App(g(251), g(252)), g(250)))
    three_leaf_2 = apps(g(251), g(252), g(250))
    run_case(
        "E6 echo(g251(g252)(g250))->sys8",
        apps(
            g(0x0E),
            three_leaf_2,
            lam("echo_r", apps(g(8), v("echo_r"), OBS)),
        ),
    )

    # echo(App(g(251), App(g(251), g(251)))) — 3 copies of 251
    three_same = app(g(251), app(g(251), g(251)))
    run_case(
        "E6 echo(g251(g251(g251)))->sys8",
        apps(
            g(0x0E),
            three_same,
            lam("echo_r", apps(g(8), v("echo_r"), OBS)),
        ),
    )

    # Now try the UNWRAPPED version: echo(3-leaf) → unwrap Left → sys8(payload)
    # The payload will have the original 3-leaf term (echo is identity on terms)
    run_case(
        "E6 echo(3leaf)->unwrap->sys8",
        apps(
            g(0x0E),
            three_leaf_1,
            lam(
                "echo_r",
                apps(
                    v("echo_r"),
                    lam("payload", apps(g(8), v("payload"), OBS)),
                    lam("_err", write_str("ECHO_ERR\n")),
                ),
            ),
        ),
    )

    # Use BT_OBS for one test to see what sys8 returns if it ever succeeds
    run_case(
        "E6 echo(3leaf)->sys8(BT_OBS)",
        apps(
            g(0x0E),
            three_leaf_1,
            lam("echo_r", apps(g(8), v("echo_r"), BT_OBS)),
        ),
    )

    # A key combo: backdoor A has 2 leaves (Var(0), Var(0) = bb).
    # If we apply A to one arg: A(g(251)) = (λa.λb.bb)(g(251)) = λb.bb
    # That's 2 leaves. Apply to another: A(g(251))(g(252)) = g(252)(g(252)) = 2 leaves.
    # B(g(251))(g(252)) = g(251)(g(252)) = 2 leaves.
    # For 3 leaves: λx.x(x)(x) applied? Or App(B(A), App(g(251), g(252)))...
    # Let me try: B applied to result of A(g(251)): B(A(g(251)))(g(252))
    # = B(λb.bb)(g(252)) = (λa.λb.ab)(λb.bb)(g(252)) = (λb.(λb.bb)(b))(g(252))
    # = (λb.bb)(g(252)) = g(252)(g(252)) — still 2 leaves. Hmm.
    # How about we just echo a raw 3-leaf term with a lambda:
    # λx. x(g(251))(g(252)) — that's 3 leaves: x, g(251), g(252)
    three_leaf_lam = lam("x", apps(v("x"), g(251), g(252)))
    run_case(
        "E6 echo(λx.x(g251)(g252))->sys8",
        apps(
            g(0x0E),
            three_leaf_lam,
            lam("echo_r", apps(g(8), v("echo_r"), OBS)),
        ),
    )

    # 3-leaf: the backdoor pair itself echoed through, then sys8
    # pair(A,B) = λf.f(A)(B) — this has 3 leaves: f, A(2 leaves), B(2 leaves) — actually more
    # Simpler 3-leaf: g(8)(g(201))(g(14))
    run_case(
        "E6 echo(g8(g201)(g14))->sys8",
        apps(
            g(0x0E),
            apps(g(8), g(201), g(14)),
            lam("echo_r", apps(g(8), v("echo_r"), OBS)),
        ),
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 78)
    print("  PROBE PHASE 2: Echo + Special Bytes → sys8")
    print(f"  Target: {HOST}:{PORT}")
    print(f"  Max requests: {MAX_REQUESTS}, delay: {DELAY}s")
    print("=" * 78)

    start = time.time()

    group_e1_echo_baseline()
    group_e2_echo_to_sys8()
    group_e3_three_leaf_terms()
    group_e4_backdoor_echo()
    group_e5_double_echo()
    group_e6_echo_3leaf_sys8()

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
