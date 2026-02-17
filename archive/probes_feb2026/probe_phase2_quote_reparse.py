#!/usr/bin/env python3
"""
probe_phase2_quote_reparse.py — Quote-reparse attack probe.

HYPOTHESIS: Use quote (sys4) to serialize terms to bytecode, then feed
those bytes back to the system (especially sys8) as Scott byte lists.

The insight: quote adds a trailing FF and uses FD/FE as structural markers.
The quoted bytes of a term ARE valid bytecode. Feeding them back as a byte
list (NOT as raw bytecode, but as a Scott-encoded list of byte values)
might be what sys8 expects.

Categories:
  Q1: Quote baseline — observe raw quoted bytes of key terms
  Q2: Quote backdoor result — quote(pair(A,B)) → byte list → sys8
  Q3: "3 leafs" bytecodes — small programs with 3 variable bytes → sys8
  Q4: Backdoor-derived bytecode to sys8 as Scott byte list
  Q5: Special byte values as Scott byte lists → sys8
  Q6: "00 FE FE" variants as byte lists → sys8
  Q7: Systematic small bytecodes as Scott byte lists → sys8
  Q8: Echo + quote combination → sys8
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
# Named-term DSL (matches project convention from existing probes)
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


def bytes_list_term(bs: bytes) -> NConst:
    return NConst(encode_bytes_list(bs))


def scott_pair(x: object, y: object) -> object:
    return lam("f", apps(v("f"), x, y))


# ---------------------------------------------------------------------------
# Observers
# ---------------------------------------------------------------------------


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


def make_quote_write_observer() -> object:
    """Observer: Left → quote the payload → write bytes. Right → write error string."""
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
            g(4),  # quote
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
    )
    return lam("result", apps(v("result"), left_handler, right_handler))


QW_OBS = make_quote_write_observer()


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
        print(f"  [{label}] SKIPPED -- rate limit ({MAX_REQUESTS} reached)")
        return None
    db_term = to_db(term)
    payload = encode_term(db_term) + bytes([FF])
    if len(payload) > 1900:
        result = f"SKIPPED (payload={len(payload)} > 1900)"
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
# Q1: Quote baseline — observe raw quoted bytes of key terms
# Use quote (sys4) to serialize terms, then write the raw bytes.
# This lets us SEE the bytecode representation.
# ---------------------------------------------------------------------------


def group_q1_quote_baseline() -> None:
    section("Q1: Quote baseline — observe bytecodes of key terms")

    # quote(nil) → should produce bytes for λ.λ.0 = 00 FE FE FF
    run_case(
        "Q1 quote(nil)->write",
        apps(
            g(4),  # quote
            NIL,
            lam(
                "q_either",
                apps(
                    v("q_either"),
                    lam("qbytes", apps(g(2), v("qbytes"), NIL)),
                    lam("_qerr", write_str("Q_FAIL\n")),
                ),
            ),
        ),
    )

    # quote(A) → A = λa.λb.bb = 00 00 FD FE FE FF
    run_case(
        "Q1 quote(A)->write",
        apps(
            g(4),
            A,
            lam(
                "q_either",
                apps(
                    v("q_either"),
                    lam("qbytes", apps(g(2), v("qbytes"), NIL)),
                    lam("_qerr", write_str("Q_FAIL\n")),
                ),
            ),
        ),
    )

    # quote(B) → B = λa.λb.ab = 01 00 FD FE FE FF
    run_case(
        "Q1 quote(B)->write",
        apps(
            g(4),
            B,
            lam(
                "q_either",
                apps(
                    v("q_either"),
                    lam("qbytes", apps(g(2), v("qbytes"), NIL)),
                    lam("_qerr", write_str("Q_FAIL\n")),
                ),
            ),
        ),
    )

    # quote(g(8)) → should produce 08 FF
    run_case(
        "Q1 quote(g(8))->write",
        apps(
            g(4),
            g(8),
            lam(
                "q_either",
                apps(
                    v("q_either"),
                    lam("qbytes", apps(g(2), v("qbytes"), NIL)),
                    lam("_qerr", write_str("Q_FAIL\n")),
                ),
            ),
        ),
    )


# ---------------------------------------------------------------------------
# Q2: Quote backdoor result → bytelist → sys8
# backdoor(nil) → Left(pair(A,B)) → quote(pair(A,B)) → bytes → sys8(bytes)
# ---------------------------------------------------------------------------


def group_q2_quote_backdoor_to_sys8() -> None:
    section("Q2: Quote backdoor result → byte list → sys8")

    # Step 1: backdoor(nil) → unwrap Left → get pair → quote(pair) → write bytes
    # This is observational: see what the quoted backdoor pair looks like.
    run_case(
        "Q2a bd->pair->quote(pair)->write",
        apps(
            g(201),  # backdoor
            NIL,
            lam(
                "bd_either",
                apps(
                    v("bd_either"),
                    lam(
                        "pair",
                        apps(
                            g(4),  # quote(pair)
                            v("pair"),
                            lam(
                                "q_either",
                                apps(
                                    v("q_either"),
                                    lam("qbytes", apps(g(2), v("qbytes"), NIL)),
                                    lam("_qerr", write_str("Q_FAIL\n")),
                                ),
                            ),
                        ),
                    ),
                    lam("_err", write_str("BD_ERR\n")),
                ),
            ),
        ),
    )

    # Step 2: backdoor(nil) → unwrap → pair → quote(pair) → unwrap → bytelist → sys8(bytelist)
    # The quoted bytes become a Scott byte list which we pass to sys8.
    run_case(
        "Q2b bd->pair->quote->bytelist->sys8",
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
                            g(4),  # quote(pair) → Left(bytelist)
                            v("pair"),
                            lam(
                                "q_either",
                                apps(
                                    v("q_either"),
                                    lam("qbytes", apps(g(8), v("qbytes"), OBS)),
                                    lam("_qerr", write_str("Q_FAIL\n")),
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
# Q3: "3 leafs" bytecode programs as Scott byte lists → sys8
# Small bytecodes with exactly 3 variable-bytes (0x00-0xFC).
# The rest are FD (App) and FE (Lam) structural markers.
# ---------------------------------------------------------------------------


def group_q3_three_leaf_bytecodes() -> None:
    section("Q3: 3-leaf bytecodes as Scott byte lists -> sys8")

    # a b FD c FD FF = App(App(Var(a), Var(b)), Var(c))
    # Try with a=0, b=0, c=0: App(App(Var(0), Var(0)), Var(0))
    run_case(
        "Q3a bytes[00 00 FD 00 FD FF]->sys8",
        apps(g(8), bytes_list_term(bytes([0x00, 0x00, FD, 0x00, FD, FF])), OBS),
    )

    # a b c FD FD FF = App(Var(a), App(Var(b), Var(c)))
    run_case(
        "Q3b bytes[00 00 00 FD FD FF]->sys8",
        apps(g(8), bytes_list_term(bytes([0x00, 0x00, 0x00, FD, FD, FF])), OBS),
    )

    # 00 FE FE bytecodes (from the "start with 00 FE FE" hint)
    # 00 FE FE FF = nil itself
    run_case(
        "Q3c bytes[00 FE FE FF]->sys8",
        apps(g(8), bytes_list_term(bytes([0x00, FE, FE, FF])), OBS),
    )

    # 00 FE FE with extra structure: 00 FE 00 FE FF = Lam(Var(0)) ... wait
    # Actually: 00 FE = Lam(Var(0)), 00 FE = Lam(Var(0)), but that's 2 items on stack
    # Let me parse carefully:
    # 00 FE FE 08 FD FF:
    #   push Var(0), Lam -> Lam(Var(0)), Lam -> Lam(Lam(Var(0)))=nil, push Var(8), App -> App(nil, Var(8))
    # That's nil applied to g(8) - interesting!
    run_case(
        "Q3d bytes[00 FE FE 08 FD FF]->sys8",
        apps(g(8), bytes_list_term(bytes([0x00, FE, FE, 0x08, FD, FF])), OBS),
    )


# ---------------------------------------------------------------------------
# Q4: Backdoor-derived bytecode to sys8 as Scott byte list
# Pre-computed bytecodes of known terms, sent as Scott byte lists.
# ---------------------------------------------------------------------------


def group_q4_precomputed_bytecodes() -> None:
    section("Q4: Pre-computed bytecodes as byte lists → sys8")

    # Bytecode of g(8): just 08 FF
    run_case(
        "Q4a bytes[08 FF]->sys8",
        apps(g(8), bytes_list_term(bytes([0x08, FF])), OBS),
    )

    # Bytecode of nil: 00 FE FE FF
    run_case(
        "Q4b bytes[00 FE FE FF]=nil->sys8",
        apps(g(8), bytes_list_term(bytes([0x00, FE, FE, FF])), OBS),
    )

    # Bytecode of A (λa.λb.bb): 00 00 FD FE FE FF
    run_case(
        "Q4c bytes[A]->sys8",
        apps(g(8), bytes_list_term(bytes([0x00, 0x00, FD, FE, FE, FF])), OBS),
    )

    # Bytecode of B (λa.λb.ab): 01 00 FD FE FE FF
    run_case(
        "Q4d bytes[B]->sys8",
        apps(g(8), bytes_list_term(bytes([0x01, 0x00, FD, FE, FE, FF])), OBS),
    )

    # Bytecode of pair(A,B) = λf.f(A)(B):
    # pair(A,B) = Lam(App(App(Var(0), A_shifted), B_shifted))
    # A under 1 lambda: A = Lam(Lam(App(Var(0),Var(0)))) → shifts: Var indices +1
    # Actually A is closed (only Var(0),Var(1) bound by its own lambdas), so no shift.
    # pair(A,B) bytecode:
    #   Var(0) A FD B FD FE FF
    #   = 00  [00 00 FD FE FE]  FD  [01 00 FD FE FE]  FD  FE  FF
    pair_bytes = bytes(
        [
            0x00,
            0x00,
            0x00,
            FD,
            FE,
            FE,
            FD,
            0x01,
            0x00,
            FD,
            FE,
            FE,
            FD,
            FE,
            FF,
        ]
    )
    run_case(
        "Q4e bytes[pair(A,B)]->sys8",
        apps(g(8), bytes_list_term(pair_bytes), OBS),
    )


# ---------------------------------------------------------------------------
# Q5: Special byte values as Scott byte lists → sys8
# Literal FD, FE, FF values encoded as Scott byte list elements.
# ---------------------------------------------------------------------------


def group_q5_special_byte_lists() -> None:
    section("Q5: Special byte values as Scott byte lists → sys8")

    # Just FD
    run_case(
        "Q5a bytes[FD]->sys8",
        apps(g(8), bytes_list_term(bytes([FD])), OBS),
    )

    # Just FE
    run_case(
        "Q5b bytes[FE]->sys8",
        apps(g(8), bytes_list_term(bytes([FE])), OBS),
    )

    # Just FF
    run_case(
        "Q5c bytes[FF]->sys8",
        apps(g(8), bytes_list_term(bytes([FF])), OBS),
    )

    # FD + FE
    run_case(
        "Q5d bytes[FD FE]->sys8",
        apps(g(8), bytes_list_term(bytes([FD, FE])), OBS),
    )

    # FD + FE + FF — all three special bytes combined
    run_case(
        "Q5e bytes[FD FE FF]->sys8",
        apps(g(8), bytes_list_term(bytes([FD, FE, FF])), OBS),
    )

    # 00 FE FE — the "start with 00 FE FE" hint as a byte list!
    run_case(
        "Q5f bytes[00 FE FE]->sys8",
        apps(g(8), bytes_list_term(bytes([0x00, FE, FE])), OBS),
    )


# ---------------------------------------------------------------------------
# Q6: "00 FE FE" variants — exploring the mail hint more deeply
# The mail says "start with 00 FE FE". This might mean:
# - The byte list argument to sys8 should start with [0x00, 0xFE, 0xFE]
# - And then have more bytes after
# ---------------------------------------------------------------------------


def group_q6_00fefe_variants() -> None:
    section("Q6: '00 FE FE' prefix variants as byte lists → sys8")

    # 00 FE FE + 00 (= nil bytecode without FF + another byte)
    run_case(
        "Q6a bytes[00 FE FE 00]->sys8",
        apps(g(8), bytes_list_term(bytes([0x00, FE, FE, 0x00])), OBS),
    )

    # 00 FE FE + FF (= nil bytecode = complete program)
    # Already done in Q3c, but let's do one with different observer
    # Actually Q3c used OBS. Skip exact dupe. Try with 08 appended.
    # 00 FE FE 08 = nil bytecode without FF, then g(8) index
    run_case(
        "Q6b bytes[00 FE FE 08]->sys8",
        apps(g(8), bytes_list_term(bytes([0x00, FE, FE, 0x08])), OBS),
    )

    # 00 FE FE + FD (App marker after nil) — this is nil applied to... nothing?
    # Actually parse: push 0, Lam, Lam, App — but App needs 2 stack items, only 1 (nil)!
    # As a raw byte list to sys8 though, we're just sending data.
    run_case(
        "Q6c bytes[00 FE FE FD]->sys8",
        apps(g(8), bytes_list_term(bytes([0x00, FE, FE, FD])), OBS),
    )

    # 00 FE FE + C9 (201 = backdoor index)
    run_case(
        "Q6d bytes[00 FE FE C9]->sys8",
        apps(g(8), bytes_list_term(bytes([0x00, FE, FE, 0xC9])), OBS),
    )

    # 00 FE FE + 00 FE FE (doubled nil prefix)
    run_case(
        "Q6e bytes[00 FE FE 00 FE FE]->sys8",
        apps(g(8), bytes_list_term(bytes([0x00, FE, FE, 0x00, FE, FE])), OBS),
    )


# ---------------------------------------------------------------------------
# Q7: Systematic small bytecodes as Scott byte lists → sys8
# Complete valid bytecode programs sent as byte lists.
# ---------------------------------------------------------------------------


def group_q7_systematic_bytecodes() -> None:
    section("Q7: Systematic valid bytecodes as byte lists → sys8")

    # g(8) bytecode: 08 FF
    # Already in Q4a. Try backdoor call bytecode:
    # g(201)(nil) = 00 FE FE C9 FD FF → App(Lam(Lam(Var(0))), Var(201))
    # Wait: bytecode is stack-based. C9 = Var(201), 00 FE FE = nil, FD = App
    # So: push Var(201), push nil, App(Var(201), nil) = g(201)(nil)
    # Nope: stack order: first C9 pushes Var(201), then 00 FE FE pushes nil, then FD pops nil and Var(201)
    # App(f, x) pops x then f. So FD pops x=nil, f=Var(201) → App(Var(201), nil)?
    # Actually in the parser: FD pops x then f (x=top, f=below): x=nil, f=Var(201)
    # So App(Var(201), nil) = g(201)(nil). Bytecode: C9 00 FE FE FD FF
    run_case(
        "Q7a bytes[C9 00 FE FE FD FF]=g201(nil)->sys8",
        apps(g(8), bytes_list_term(bytes([0xC9, 0x00, FE, FE, FD, FF])), OBS),
    )

    # Identity: 00 FE FF
    run_case(
        "Q7b bytes[00 FE FF]=identity->sys8",
        apps(g(8), bytes_list_term(bytes([0x00, FE, FF])), OBS),
    )

    # sys8(nil) bytecode: 08 00 FE FE FD FF
    run_case(
        "Q7c bytes[08 00 FE FE FD FF]=g8(nil)->sys8",
        apps(g(8), bytes_list_term(bytes([0x08, 0x00, FE, FE, FD, FF])), OBS),
    )

    # The "00 FE FE" WITHOUT trailing FF — incomplete bytecode, but as a byte list
    run_case(
        "Q7d bytes[00 FE FE]=nil_no_ff->sys8",
        apps(g(8), bytes_list_term(bytes([0x00, FE, FE])), OBS),
    )


# ---------------------------------------------------------------------------
# Q8: Echo + quote combination → byte list → sys8
# echo(term) → Left(term) → quote(Left(term)) → bytes with FE markers → sys8
# ---------------------------------------------------------------------------


def group_q8_echo_quote_sys8() -> None:
    section("Q8: Echo + quote → byte list → sys8")

    # echo(nil) → Left(nil) → quote(Left(nil)) → bytes → sys8(bytes)
    # Left(nil) = λl.λr.l(nil) = Lam(Lam(App(Var(1), nil_shifted)))
    # The quoted bytes will contain the Left constructor's FE markers.
    run_case(
        "Q8a echo(nil)->quote(Left)->bytes->sys8",
        apps(
            g(0x0E),  # echo
            NIL,
            lam(
                "echo_result",
                apps(
                    g(4),  # quote(echo_result = Left(nil))
                    v("echo_result"),
                    lam(
                        "q_either",
                        apps(
                            v("q_either"),
                            lam("qbytes", apps(g(8), v("qbytes"), OBS)),
                            lam("_qerr", write_str("Q_FAIL\n")),
                        ),
                    ),
                ),
            ),
        ),
    )

    # echo(g(8)) → Left(g(8)) → quote → bytes → sys8(bytes)
    run_case(
        "Q8b echo(g8)->quote(Left)->bytes->sys8",
        apps(
            g(0x0E),
            g(8),
            lam(
                "echo_result",
                apps(
                    g(4),
                    v("echo_result"),
                    lam(
                        "q_either",
                        apps(
                            v("q_either"),
                            lam("qbytes", apps(g(8), v("qbytes"), OBS)),
                            lam("_qerr", write_str("Q_FAIL\n")),
                        ),
                    ),
                ),
            ),
        ),
    )

    # echo(A) → Left(A) → quote → bytes → sys8(bytes)
    run_case(
        "Q8c echo(A)->quote(Left)->bytes->sys8",
        apps(
            g(0x0E),
            A,
            lam(
                "echo_result",
                apps(
                    g(4),
                    v("echo_result"),
                    lam(
                        "q_either",
                        apps(
                            v("q_either"),
                            lam("qbytes", apps(g(8), v("qbytes"), OBS)),
                            lam("_qerr", write_str("Q_FAIL\n")),
                        ),
                    ),
                ),
            ),
        ),
    )

    # Also: observe what echo(nil) quote looks like (just write it)
    run_case(
        "Q8d echo(nil)->quote(Left)->write_bytes",
        apps(
            g(0x0E),
            NIL,
            lam(
                "echo_result",
                apps(
                    g(4),
                    v("echo_result"),
                    lam(
                        "q_either",
                        apps(
                            v("q_either"),
                            lam("qbytes", apps(g(2), v("qbytes"), NIL)),
                            lam("_qerr", write_str("Q_FAIL\n")),
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
    print("  PROBE PHASE 2: Quote-Reparse Attack")
    print(f"  Target: {HOST}:{PORT}")
    print(f"  Max requests: {MAX_REQUESTS}, delay: {DELAY}s")
    print("=" * 78)

    start = time.time()

    group_q1_quote_baseline()
    group_q2_quote_backdoor_to_sys8()
    group_q3_three_leaf_bytecodes()
    group_q4_precomputed_bytecodes()
    group_q5_special_byte_lists()
    group_q6_00fefe_variants()
    group_q7_systematic_bytecodes()
    group_q8_echo_quote_sys8()

    elapsed = time.time() - start

    print(f"\n{'=' * 78}")
    print(f"  SUMMARY -- {_request_count} requests in {elapsed:.1f}s")
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
