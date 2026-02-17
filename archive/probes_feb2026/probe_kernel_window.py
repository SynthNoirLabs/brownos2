#!/usr/bin/env python3
"""
probe_kernel_window.py - Test sys8 called from within other syscalls' continuations.

HYPOTHESIS: sys8's "Permission denied" check depends on execution context.
If sys8 is called from within another syscall's continuation (while the "kernel"
is still active), it might succeed.

We also test:
1. sys8 called from backdoor's continuation (highest privilege?)
2. sys8 called from echo's continuation
3. sys8 called from towel's continuation
4. sys8 called from readfile's continuation
5. sys8 called from write's continuation
6. Chained syscalls: backdoor → use pair → sys8
7. The continuation writes EXACTLY what sys8 returns (to see full result)

NEW: Also test whether sys8's CONTINUATION receives something interesting
when we DON'T use OBS/QD but instead inspect the raw Either structure.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FF,
    FD,
    FE,
    QD,
    encode_term,
    encode_byte_term,
    encode_bytes_list,
)

HOST = "wc3.wechall.net"
PORT = 61221


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


def shift_db(term, delta, cutoff=0):
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_db(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_db(term.f, delta, cutoff), shift_db(term.x, delta, cutoff))
    return term


def to_db(term, env=()):
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


def g(i):
    return NGlob(i)


def v(n):
    return NVar(n)


def lam(p, b):
    return NLam(p, b)


def app(f, x):
    return NApp(f, x)


def apps(*t):
    out = t[0]
    for x in t[1:]:
        out = app(out, x)
    return out


NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)


def recv_all(sock, timeout_s=5.0):
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


def query_named_timed(term, timeout_s=5.0):
    payload = encode_term(to_db(term)) + bytes([FF])
    try:
        start = time.monotonic()
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            result = recv_all(sock, timeout_s=timeout_s)
        elapsed = time.monotonic() - start
        return result, elapsed
    except Exception as e:
        elapsed = time.monotonic() - start
        return f"ERR:{e}".encode(), elapsed


def query_raw_timed(payload, timeout_s=5.0):
    try:
        start = time.monotonic()
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            result = recv_all(sock, timeout_s=timeout_s)
        elapsed = time.monotonic() - start
        return result, elapsed
    except Exception as e:
        elapsed = time.monotonic() - start
        return f"ERR:{e}".encode(), elapsed


def write_str(s):
    return apps(g(2), NConst(encode_bytes_list(s.encode("latin-1"))), NIL)


def classify(raw, elapsed):
    if not raw:
        if elapsed >= 4.5:
            return "TIMEOUT(diverged?)"
        return f"EMPTY({elapsed:.2f}s)"
    text = raw.decode("latin-1", errors="replace")
    if "Permission denied" in text:
        return f"PERM_DENIED({elapsed:.2f}s)"
    if "Not implemented" in text:
        return f"NOT_IMPL({elapsed:.2f}s)"
    if "Invalid" in text:
        return f"INVALID({elapsed:.2f}s)"
    if "Encoding failed" in text:
        return f"ENCODING_FAILED({elapsed:.2f}s)"
    return f"OTHER({text[:80]!r},{elapsed:.2f}s)"


# ===================================================================
# OBS: observer that writes the error/success string
# ===================================================================
def obs_no_quote():
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


OBS = obs_no_quote()


# ===================================================================
# Verbose observer: writes different markers for different results
# ===================================================================
def obs_verbose():
    """Writes 'L:' then quotes the Left payload, or 'R:N' for Right(N)."""
    # For Right: write "R:" then the error string
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
                    lam("_e2", write_str("R:?")),
                ),
            ),
        ),
    )
    # For Left: write "L:" then quote the payload
    left_handler = lam(
        "payload",
        apps(
            g(4),
            v("payload"),  # quote the payload
            lam(
                "quote_either",
                apps(
                    v("quote_either"),
                    lam("bytes", apps(g(2), v("bytes"), NIL)),  # write the quoted bytes
                    lam("_", write_str("L:quote_err")),
                ),
            ),
        ),
    )
    return lam("res", apps(v("res"), left_handler, right_handler))


OBS_V = obs_verbose()


def phase_1_kernel_window():
    """
    Call sys8 from within other syscalls' continuations.
    Pattern: syscall(arg, λresult. sys8(nil, OBS))
    If the kernel is "active" during the continuation, sys8 might succeed.
    """
    print("=" * 72)
    print("PHASE 1: sys8 inside other syscalls' continuations")
    print("=" * 72)

    # Baseline
    out, elapsed = query_named_timed(apps(g(8), NIL, OBS), timeout_s=5.0)
    print(f"  baseline: sys8(nil, OBS) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # sys8 inside backdoor's continuation
    # backdoor(nil, λpair. sys8(nil, OBS))
    term = apps(g(201), NIL, lam("pair", apps(g(8), NIL, OBS)))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor(nil, λ_. sys8(nil, OBS)) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # sys8 inside echo's continuation
    # echo(nil, λechoResult. sys8(nil, OBS))
    term = apps(g(14), NIL, lam("_echo", apps(g(8), NIL, OBS)))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  echo(nil, λ_. sys8(nil, OBS)) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # sys8 inside towel's continuation
    term = apps(g(42), NIL, lam("_towel", apps(g(8), NIL, OBS)))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  towel(nil, λ_. sys8(nil, OBS)) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # sys8 inside readdir's continuation
    term = apps(g(5), NConst(encode_byte_term(0)), lam("_rd", apps(g(8), NIL, OBS)))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  readdir(0, λ_. sys8(nil, OBS)) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # sys8 inside readfile's continuation
    term = apps(g(7), NConst(encode_byte_term(1)), lam("_rf", apps(g(8), NIL, OBS)))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  readfile(1, λ_. sys8(nil, OBS)) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # sys8 inside write's continuation
    term = apps(g(2), NConst(encode_bytes_list(b"X")), lam("_w", apps(g(8), NIL, OBS)))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  write('X', λ_. sys8(nil, OBS)) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # sys8 inside quote's continuation
    term = apps(g(4), NIL, lam("_q", apps(g(8), NIL, OBS)))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  quote(nil, λ_. sys8(nil, OBS)) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # sys8 inside name's continuation
    term = apps(g(6), NConst(encode_byte_term(0)), lam("_n", apps(g(8), NIL, OBS)))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  name(0, λ_. sys8(nil, OBS)) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # sys8 inside error_string's continuation
    term = apps(g(1), NConst(encode_byte_term(0)), lam("_e", apps(g(8), NIL, OBS)))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  error_string(0, λ_. sys8(nil, OBS)) -> {classify(out, elapsed)}")
    time.sleep(0.3)


def phase_2_backdoor_pair_as_arg():
    """
    Get the backdoor pair, then pass IT to sys8.
    The pair is the only "special" value we can get.
    backdoor(nil, λpair. sys8(pair, OBS))
    """
    print("\n" + "=" * 72)
    print("PHASE 2: Use backdoor result as sys8 argument")
    print("=" * 72)

    # backdoor(nil, λpair. sys8(pair, OBS))
    term = apps(g(201), NIL, lam("pair", apps(g(8), v("pair"), OBS)))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor → sys8(pair, OBS) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # backdoor(nil, λpair. sys8(pair, OBS_V))
    term = apps(g(201), NIL, lam("pair", apps(g(8), v("pair"), OBS_V)))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor → sys8(pair, OBS_V) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # Extract pair components and use them
    # backdoor(nil, λresult. result(λpayload. payload(λA.λB. sys8(A, OBS))))
    # pair = λx.λy.((x A) B), so pair(f)(g) = ((f A) B)
    # We want to extract A: pair(λa.λb.a)(dummy) = A
    # Then sys8(A, OBS)
    term = apps(
        g(201),
        NIL,
        lam(
            "result",
            apps(
                v("result"),
                lam(
                    "pair",
                    apps(  # Left handler: got the pair
                        apps(v("pair"), lam("a", lam("b", v("a"))), NIL),  # extract A
                        lam(
                            "_dummy",
                            apps(
                                g(
                                    8
                                ),  # _dummy is B since pair(K) returns A and K gets called with A, B...
                                # Actually pair(K, nil) = ((K A) B)(nil)... no.
                                # pair = λx.λy.((x A) B). pair(K) = λy.((K A) B). pair(K)(nil) = (K A) B.
                                # K = λa.λb.a. So K(A) = λb.A. (λb.A)(B) = A.
                                # So pair(K)(nil) = A. Good.
                                NIL,  # this is the dummy for pair's second arg
                                OBS,
                            ),
                        ),
                    ),
                ),
                lam("_err", write_str("BD_ERR")),  # Right handler
            ),
        ),
    )
    # Hmm, this is getting complex. Let me simplify.

    # Actually: backdoor returns Either. Left(pair).
    # pair(λa.λb.a)(nil) = A
    # pair(λa.λb.b)(nil) = B

    # Let's build it step by step:
    # unwrap_left = λresult. result (λpayload. ...) (λerr. write("ERR"))
    # In the Left branch, payload = pair
    # pair (λA.λB. sys8(A, OBS)) (nil) = ((λA.λB.sys8(A,OBS)) A) B) (nil)
    # Hmm, pair takes 2 args: pair(f)(g) = f(A)(B)
    # So: pair(λA.λB. sys8(A, OBS)) = λg. (λA.λB. sys8(A, OBS))(A)(B) = λg. sys8(A, OBS)
    # Then (pair(...))(nil) = sys8(A, OBS)

    # Build: backdoor(nil) → Left(pair) → pair(λA.λB. sys8(A, OBS))(nil)
    extract_and_call = lam(
        "result",
        apps(
            v("result"),
            lam(
                "pair",  # Left handler
                apps(
                    apps(v("pair"), lam("A", lam("B", apps(g(8), v("A"), OBS)))),
                    NIL,  # dummy second arg to pair
                ),
            ),
            lam("_err", write_str("BD_ERR")),  # Right handler
        ),
    )
    term = apps(g(201), NIL, extract_and_call)
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor → extract A → sys8(A, OBS) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # Same but with B
    extract_B = lam(
        "result",
        apps(
            v("result"),
            lam(
                "pair",
                apps(apps(v("pair"), lam("A", lam("B", apps(g(8), v("B"), OBS)))), NIL),
            ),
            lam("_err", write_str("BD_ERR")),
        ),
    )
    term = apps(g(201), NIL, extract_B)
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor → extract B → sys8(B, OBS) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # Use omega (= A(B)) as sys8 arg
    extract_omega = lam(
        "result",
        apps(
            v("result"),
            lam(
                "pair",
                apps(
                    apps(
                        v("pair"),
                        lam("A", lam("B", apps(g(8), app(v("A"), v("B")), OBS))),
                    ),
                    NIL,
                ),
            ),
            lam("_err", write_str("BD_ERR")),
        ),
    )
    term = apps(g(201), NIL, extract_omega)
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor → omega=(A B) → sys8(ω, OBS) -> {classify(out, elapsed)}")
    time.sleep(0.3)


def phase_3_nested_kernel():
    """
    DEEP nesting: backdoor → within continuation → echo → within continuation → sys8
    Multiple levels of "kernel" context.
    """
    print("\n" + "=" * 72)
    print("PHASE 3: Deeply nested kernel contexts")
    print("=" * 72)

    # backdoor(nil, λ_. echo(nil, λ_. sys8(nil, OBS)))
    term = apps(
        g(201), NIL, lam("_bd", apps(g(14), NIL, lam("_echo", apps(g(8), NIL, OBS))))
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor → echo → sys8(nil, OBS) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # echo(nil, λ_. backdoor(nil, λ_. sys8(nil, OBS)))
    term = apps(
        g(14), NIL, lam("_echo", apps(g(201), NIL, lam("_bd", apps(g(8), NIL, OBS))))
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  echo → backdoor → sys8(nil, OBS) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # backdoor pair passed as CONTINUATION to sys8 (not as argument)
    # sys8(nil, λresult. backdoor(nil, λbd_result. bd_result(λpair. pair(λA.λB. write("GOT:" OBS))(nil))))
    # Simpler: use backdoor result AS the continuation
    # backdoor(nil, λbd_either. bd_either(λpair. sys8(nil, pair)) (...))
    # So sys8(nil, pair) where pair = λf.λg.f(A)(B)
    # sys8 calls pair(Right(6)) = λg.Right(6)(A)(B) which tries to apply Right(6) as Either
    # Right(6) = λl.λr.r(6). So Right(6)(A)(B) = B(6). B = λa.λb.a(b). B(6) = λb.6(b). Hmm.

    # Let's just try: use the raw pair as sys8's continuation
    term = apps(
        g(201),
        NIL,
        lam(
            "bd_result",
            apps(
                v("bd_result"),
                lam(
                    "pair", apps(g(8), NIL, v("pair"))
                ),  # Left: use pair as continuation
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor → sys8(nil, pair_as_cont) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # What if we use backdoor's LEFT directly (without unwrapping) as sys8 arg?
    # backdoor returns Either. What if we pass the ENTIRE Either to sys8?
    term = apps(g(201), NIL, lam("bd_either", apps(g(8), v("bd_either"), OBS)))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor → sys8(bd_either_raw, OBS) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # Triple nesting with ALL known syscalls
    # write → readfile → backdoor → sys8
    term = apps(
        g(2),
        NConst(encode_bytes_list(b"X")),
        lam(
            "_w",
            apps(
                g(7),
                NConst(encode_byte_term(1)),
                lam("_rf", apps(g(201), NIL, lam("_bd", apps(g(8), NIL, OBS)))),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  write → readfile → backdoor → sys8(nil, OBS) -> {classify(out, elapsed)}")
    time.sleep(0.3)


def phase_4_sys8_raw_result():
    """
    Instead of using OBS which formats the Either, let's capture the RAW result.
    sys8(nil, λresult. quote(result, λq_either. q_either(λbytes. write(bytes, nil))(λ_. write("QF", nil))))

    This quotes the raw result of sys8 and writes the bytes.
    """
    print("\n" + "=" * 72)
    print("PHASE 4: Quote sys8's raw result (not the Either)")
    print("=" * 72)

    # sys8(nil, λresult. quote(result, λeither. either(λbytes. write(bytes, nil))(λ_. write("QF"))))
    term = apps(
        g(8),
        NIL,
        lam(
            "result",
            apps(
                g(4),
                v("result"),
                lam(
                    "q_either",
                    apps(
                        v("q_either"),
                        lam("bytes", apps(g(2), v("bytes"), NIL)),
                        lam("_qf", write_str("QUOTE_FAIL")),
                    ),
                ),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  sys8(nil) → quote(result) → write -> {classify(out, elapsed)}")
    if out:
        print(f"    raw hex: {out.hex()}")
    time.sleep(0.3)

    # Also: just write a marker BEFORE sys8's continuation processes the result
    # to confirm sys8 returns something to the continuation
    term = apps(
        g(8),
        NIL,
        lam(
            "result",
            apps(
                g(2),
                NConst(encode_bytes_list(b"RESULT:")),
                lam(
                    "_w",
                    apps(
                        g(4),
                        v("result"),
                        lam(
                            "q_either",
                            apps(
                                v("q_either"),
                                lam("bytes", apps(g(2), v("bytes"), NIL)),
                                lam("_qf", write_str("QF")),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  sys8(nil) → write('RESULT:') → quote(result) -> {classify(out, elapsed)}")
    if out:
        print(f"    raw hex: {out.hex()}")
    time.sleep(0.3)


def phase_5_raw_wire_patterns():
    """
    Test raw wire patterns inspired by cheat sheet.
    "?? ?? FD QD FD" — where ?? can be ANY term, not just single bytes.

    Try: the ENTIRE backdoor-extract-pair as the first ??.
    Try: nested applications as ??.
    """
    print("\n" + "=" * 72)
    print("PHASE 5: Raw wire patterns with compound terms")
    print("=" * 72)

    qd_bytes = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
    nil_enc = encode_term(NIL_DB)

    # Standard: 08 <nil> FD QD FD FF = sys8(nil, QD)
    p = bytes([0x08]) + nil_enc + bytes([FD]) + qd_bytes + bytes([FD, FF])
    out, elapsed = query_raw_timed(p)
    print(f"  08 nil FD QD FD FF -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # What if syscall 8 has a DIFFERENT calling convention?
    # Try: 08 FD QD FD FF (no argument — sys8 applied to QD directly)
    p = bytes([0x08, FD]) + qd_bytes + bytes([FD, FF])
    out, elapsed = query_raw_timed(p)
    print(f"  08 FD QD FD FF -> {classify(out, elapsed)}")
    if out:
        print(f"    raw: {out.hex()}")
    time.sleep(0.3)

    # Try: QD 08 FD FF (QD applied to sys8)
    p = qd_bytes + bytes([0x08, FD, FF])
    out, elapsed = query_raw_timed(p)
    print(f"  QD 08 FD FF -> {classify(out, elapsed)}")
    if out:
        print(f"    raw: {out.hex()}")
    time.sleep(0.3)

    # Backdoor(nil) as first ?? : C9 <nil> FD <something> FD QD FD FF
    # This is: backdoor(nil, λ_. something) then QD observes
    # But we need to put sys8 INSIDE.
    # backdoor nil FD (sys8 nil FD QD FD) FD FF  -- this doesn't quite work as wire

    # Actually in wire: A B FD = App(A, B)
    # So: C9 nil FD = App(g(201), nil) = partial backdoor
    # Then: (C9 nil FD) CONT FD = App(backdoor(nil), CONT) = backdoor(nil, CONT)
    # CONT = sys8(nil, QD) = 08 nil FD QD FD
    # Full: C9 nil FD 08 nil FD QD FD FD FF
    # = App(App(g(201), nil), App(App(g(8), nil), QD))
    # = backdoor(nil, sys8(nil, QD))
    # But sys8(nil, QD) is evaluated FIRST (since it's an argument to backdoor's cont)
    # No wait — this is postfix. Let me trace:
    # C9 → push g(201)
    # nil → push nil
    # FD → pop nil, pop g(201), push App(g(201), nil)
    # 08 → push g(8)
    # nil → push nil
    # FD → pop nil, pop g(8), push App(g(8), nil)
    # QD → push QD_term
    # FD → pop QD_term, pop App(g(8),nil), push App(App(g(8),nil), QD_term) = sys8(nil, QD)
    # FD → pop sys8(nil,QD), pop App(g(201),nil), push App(App(g(201),nil), sys8(nil,QD))
    # = backdoor(nil, sys8(nil, QD))
    # FF → evaluate
    # So this evaluates: backdoor(nil) → Left(pair) passed to continuation sys8(nil, QD)
    # But sys8(nil, QD) is a TERM (already fully applied), not a lambda waiting for an arg.
    # Since the continuation should be λresult.BODY, but we gave it sys8(nil,QD) which is a
    # fully applied syscall expression... it would just be ignored.
    # Actually: backdoor(nil, K) calls K(Left(pair)). K = sys8(nil, QD).
    # So: sys8(nil, QD)(Left(pair)). sys8 is a 2-arg syscall, already got nil and QD.
    # So sys8(nil, QD) is evaluated first → returns Right(6) to QD → QD outputs bytes.
    # Then the result of QD (which is a write action) gets applied to Left(pair).
    # This is wrong. We want the continuation to be a LAMBDA.

    # Let's try the right pattern:
    # backdoor(nil, λbd_res. sys8(nil, QD))
    # Wire: C9 nil FD (λbd_res. 08 nil FD QD FD) FD FF
    # λbd_res means: body FE. In body, bd_res = Var(0), and all globals shift by 1.
    # So g(8) inside lambda = Var(9), g(2) = Var(3), etc.
    # QD inside lambda shifts too... this is why we use named terms normally.

    # Let's just use the named-term builder for these.

    # Backdoor cont → sys8
    term = apps(
        g(201),
        NIL,
        lam(
            "_bd",
            apps(
                g(8),
                NIL,
                lam(
                    "res",
                    apps(
                        v("res"),
                        lam("payload", write_str("LEFT!!!")),
                        lam(
                            "errcode",
                            apps(
                                g(1),
                                v("errcode"),
                                lam(
                                    "estr",
                                    apps(
                                        v("estr"),
                                        lam("s", apps(g(2), v("s"), NIL)),
                                        lam("_", write_str("??")),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor(nil, λ_. sys8(nil, verbose_obs)) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # Now: backdoor(nil, λpair. sys8(pair, verbose_obs))
    # Use the backdoor's RESULT as sys8's argument
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
                        g(8),
                        v("pair"),
                        lam(
                            "res",
                            apps(
                                v("res"),
                                lam("payload", write_str("LEFT!!!")),
                                lam(
                                    "errcode",
                                    apps(
                                        g(1),
                                        v("errcode"),
                                        lam(
                                            "estr",
                                            apps(
                                                v("estr"),
                                                lam("s", apps(g(2), v("s"), NIL)),
                                                lam("_", write_str("??")),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor → unwrap → sys8(pair, verbose_obs) -> {classify(out, elapsed)}")
    time.sleep(0.3)


def phase_6_continuation_is_sys8():
    """
    What if sys8 IS the continuation for another syscall?
    i.e., echo(something, g(8)) or backdoor(nil, g(8))

    The other syscall would call g(8)(result). But g(8) needs 2 args: g(8)(arg)(cont).
    So g(8)(result) = partially applied. Then what?

    Actually: if we pass g(8) as continuation, and the syscall calls g(8)(result),
    that's a partial application. Nothing happens unless something else provides the second arg.

    But what if we use: λresult. sys8(result, OBS) AS the continuation?
    Then: echo(something, λresult. sys8(result, OBS))
    Echo returns Left(something+2). Then sys8(Left(something+2), OBS).
    """
    print("\n" + "=" * 72)
    print("PHASE 6: sys8 as receiver of other syscall results")
    print("=" * 72)

    # echo(g(8), λresult. result(λpayload. sys8(payload, OBS))(λerr. write_err))
    # echo(g(8)) = Left(Var(10)) inside Either.
    # Unwrap: payload = g(8) (shifted back after unwrap)
    # Then sys8(g(8), OBS) — we've done this. But in a different context!

    for syscall_name, syscall_idx in [("echo", 14), ("towel", 42), ("backdoor", 201)]:
        if syscall_idx == 201:
            arg = NIL
        elif syscall_idx == 14:
            arg = NConst(encode_byte_term(8))  # echo(8)
        else:
            arg = NIL

        # syscall(arg, λresult. sys8(result, OBS))
        # Note: we pass the RAW Either result to sys8
        term = apps(g(syscall_idx), arg, lam("result", apps(g(8), v("result"), OBS)))
        out, elapsed = query_named_timed(term, timeout_s=5.0)
        print(
            f"  {syscall_name}(arg, λres. sys8(res, OBS)) -> {classify(out, elapsed)}"
        )
        time.sleep(0.3)

        # syscall(arg, λresult. result(λpayload. sys8(payload, OBS))(λerr. write_err))
        # Unwrap the Either, then pass the payload to sys8
        term = apps(
            g(syscall_idx),
            arg,
            lam(
                "result",
                apps(
                    v("result"),
                    lam("payload", apps(g(8), v("payload"), OBS)),  # Left
                    lam("errcode", write_str("SYS_ERR")),
                ),
            ),
        )  # Right
        out, elapsed = query_named_timed(term, timeout_s=5.0)
        print(
            f"  {syscall_name}(arg, λres. unwrap → sys8(payload, OBS)) -> {classify(out, elapsed)}"
        )
        time.sleep(0.3)


def phase_7_backdoor_pair_as_continuation():
    """
    Use the backdoor pair components A, B as CONTINUATIONS for sys8.
    A = λa.λb.(b b) — applies second arg to itself
    B = λa.λb.(a b) — applies first arg to second

    sys8(nil, A) → A(Right(6)) = λb.(b b) — then needs another arg
    sys8(nil, B) → B(Right(6)) = λb.(Right(6) b) = λb.b(6)... hmm

    What if we use pair itself: sys8(nil, pair)?
    pair = λx.λy.((x A) B)
    pair(Right(6)) = λy.((Right(6) A) B) = λy.(A(6)(B)) ... this is getting weird.
    Actually Right(6) = λl.λr.r(6). Right(6)(A) = λr.r(6) applied to A...
    A is the first arg of Right. Right = λl.λr.r(arg). So Right(6)(A)(B) = B(6).
    B(6) = λb.(6 b). Then this is applied to... nothing more.

    Hmm, this might be interesting. Let's trace:
    sys8(nil, pair): sys8 returns Right(6) to pair.
    pair(Right(6)) = λy.((Right(6) A) B)
    = λy.(B(6))
    = λy.(λb.(6 b))
    This is stuck (6 isn't a function). But the VM might handle it differently.

    Let's just test and see.
    """
    print("\n" + "=" * 72)
    print("PHASE 7: Backdoor pair/A/B as sys8 continuation")
    print("=" * 72)

    # Get pair from backdoor, use as sys8 continuation
    # backdoor(nil, λbd_either. bd_either(λpair. sys8(nil, pair))(λerr. write_err))
    term = apps(
        g(201),
        NIL,
        lam(
            "bd_either",
            apps(
                v("bd_either"),
                lam("pair", apps(g(8), NIL, v("pair"))),
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor → sys8(nil, pair) -> {classify(out, elapsed)}")
    if out:
        print(f"    raw: {out.hex()}")
    time.sleep(0.3)

    # Extract A, use as sys8 continuation
    # pair(λA.λB.A)(nil) = A
    term = apps(
        g(201),
        NIL,
        lam(
            "bd_either",
            apps(
                v("bd_either"),
                lam(
                    "pair",
                    apps(
                        g(8),
                        NIL,
                        apps(apps(v("pair"), lam("A", lam("B", v("A")))), NIL),
                    ),
                ),
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor → extract A → sys8(nil, A) -> {classify(out, elapsed)}")
    if out:
        print(f"    raw: {out.hex()}")
    time.sleep(0.3)

    # Extract B, use as sys8 continuation
    term = apps(
        g(201),
        NIL,
        lam(
            "bd_either",
            apps(
                v("bd_either"),
                lam(
                    "pair",
                    apps(
                        g(8),
                        NIL,
                        apps(apps(v("pair"), lam("A", lam("B", v("B")))), NIL),
                    ),
                ),
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor → extract B → sys8(nil, B) -> {classify(out, elapsed)}")
    if out:
        print(f"    raw: {out.hex()}")
    time.sleep(0.3)

    # Use omega as continuation
    term = apps(
        g(201),
        NIL,
        lam(
            "bd_either",
            apps(
                v("bd_either"),
                lam(
                    "pair",
                    apps(
                        g(8),
                        NIL,
                        apps(
                            apps(v("pair"), lam("A", lam("B", app(v("A"), v("B"))))),
                            NIL,
                        ),
                    ),
                ),
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor → omega → sys8(nil, ω) -> {classify(out, elapsed)}")
    if out:
        print(f"    raw: {out.hex()}")
    time.sleep(0.3)


def phase_8_pass_sys8_to_backdoor():
    """
    What if we pass g(8) (or a partial application of sys8) as an argument to other syscalls?
    Or what if sys8 is supposed to be used as a FUNCTION, not as a syscall?

    sys8 = g(8). In the VM, g(8) is a 2-arg function (arg, cont).
    If we don't call it as a syscall but pass it around, interesting things might happen.
    """
    print("\n" + "=" * 72)
    print("PHASE 8: Pass sys8 as a value / function")
    print("=" * 72)

    # echo(g(8), OBS_V) — we know this returns Left(Var(10))
    term = apps(g(14), g(8), OBS_V)
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  echo(g(8), OBS_V) -> {classify(out, elapsed)}")
    if out:
        print(f"    raw: {out.hex()}")
    time.sleep(0.3)

    # quote(g(8), OBS) — what does quote return for a global?
    term = apps(
        g(4),
        g(8),
        lam(
            "q_result",
            apps(
                v("q_result"),
                lam("bytes", apps(g(2), v("bytes"), NIL)),
                lam("_qerr", write_str("Q_ERR")),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  quote(g(8)) → write bytes -> {classify(out, elapsed)}")
    if out:
        print(f"    raw: {out.hex()}")
    time.sleep(0.3)

    # Apply g(8) to itself: g(8)(g(8))(OBS)
    term = apps(g(8), g(8), OBS)
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  sys8(sys8, OBS) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # Apply backdoor pair to g(8) as a function
    # pair(g(8))(nil) = g(8)(A)(B)... = sys8(A, B)
    # where A = λa.λb.(bb), B = λa.λb.(ab)
    # sys8(A, B) → B(Right(6)) = λb.(Right(6) b) = ???
    term = apps(
        g(201),
        NIL,
        lam(
            "bd_either",
            apps(
                v("bd_either"),
                lam("pair", apps(apps(v("pair"), g(8)), OBS)),
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  backdoor → pair(g(8))(OBS) -> {classify(out, elapsed)}")
    if out and len(out) > 0:
        print(f"    raw: {out.hex()}")
    time.sleep(0.3)


def main():
    print("=" * 72)
    print("probe_kernel_window.py - Testing sys8 in various execution contexts")
    print(f"target: {HOST}:{PORT}")
    print("=" * 72)

    phase_1_kernel_window()
    phase_2_backdoor_pair_as_arg()
    phase_3_nested_kernel()
    phase_4_sys8_raw_result()
    phase_5_raw_wire_patterns()
    phase_6_continuation_is_sys8()
    phase_7_backdoor_pair_as_continuation()
    phase_8_pass_sys8_to_backdoor()

    print("\nAll phases complete.")


if __name__ == "__main__":
    main()
