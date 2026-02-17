#!/usr/bin/env python3
"""
probe_oracle10_theories.py - Test Oracle #10's three theories.

Theory 1: Pass echo's raw Either result (containing unquotable Var(253+))
          directly to sys8 WITHOUT unwrapping and WITHOUT quoting.
Theory 2: Test integer encodings beyond 8 bits (Var(9), Var(10), etc. as weights).
Theory 3: Over-apply sys8's Right(6) result — treat it as a callable.
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


def write_str(s):
    return apps(g(2), NConst(encode_bytes_list(s.encode("latin-1"))), NIL)


def classify(raw, elapsed):
    if not raw:
        if elapsed >= 4.5:
            return "TIMEOUT"
        return f"EMPTY({elapsed:.2f}s)"
    text = raw.decode("latin-1", errors="replace")
    if "Permission denied" in text:
        return f"PERM_DENIED({elapsed:.2f}s)"
    if "Not implemented" in text:
        return f"NOT_IMPL({elapsed:.2f}s)"
    if "Invalid" in text:
        return f"INVALID({elapsed:.2f}s)"
    if "Encoding failed" in text:
        return f"ENC_FAIL({elapsed:.2f}s)"
    if text.strip() == "LEFT!":
        return f"LEFT!({elapsed:.2f}s)"
    return f"OTHER({raw[:40].hex()},{elapsed:.2f}s)"


# No-quote observer: just writes "L" for Left or the error string for Right
def obs_noquote():
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


OBS = obs_noquote()


def theory_1_raw_echo_results():
    """
    Theory 1: Pass echo's raw Either result (with unquotable Var(253+) inside)
    directly to sys8 WITHOUT unwrapping.

    echo(g(251)) = Left(Var(253)) — this Left wrapping contains Var(253) = 0xFD internally.
    We pass the ENTIRE Left(Var(253)) to sys8 as the argument.

    Previously we unwrapped and got back g(251). Here we DON'T unwrap.
    """
    print("=" * 72)
    print("THEORY 1: Raw echo results as sys8 argument (no unwrap)")
    print("=" * 72)

    for echo_arg in [250, 251, 252]:
        # echo(g(N), λecho_result. sys8(echo_result, OBS))
        # echo returns Left(Var(N+2)). The raw Either is passed to sys8.
        term = apps(g(14), g(echo_arg), lam("echo_raw", apps(g(8), v("echo_raw"), OBS)))
        out, elapsed = query_named_timed(term, timeout_s=6.0)
        print(
            f"  echo(g({echo_arg})) → raw → sys8(Left(Var({echo_arg + 2})), OBS) -> {classify(out, elapsed)}"
        )
        time.sleep(0.35)

    for echo_arg in [250, 251, 252]:
        # Same but as CONTINUATION: sys8(nil, echo_raw_result)
        term = apps(g(14), g(echo_arg), lam("echo_raw", apps(g(8), NIL, v("echo_raw"))))
        out, elapsed = query_named_timed(term, timeout_s=6.0)
        print(
            f"  echo(g({echo_arg})) → raw → sys8(nil, Left(Var({echo_arg + 2}))) -> {classify(out, elapsed)}"
        )
        if out:
            print(f"    raw hex: {out[:40].hex()}")
        time.sleep(0.35)

    # Also: echo(g(251)) gives Left(Var(253)). What if we call this as a FUNCTION?
    # Left(Var(253)) = λl.λr.l(Var(253)). Calling it as f(x)(y) would give x(Var(253)).
    # If x is sys8: sys8(Var(253)) = sys8(g(251)) after de Bruijn resolution.
    # But Var(253) inside the Left wrapper IS g(251) under 2 lambdas.
    # So calling Left(Var(253))(sys8)(dummy) = sys8(g(251))(dummy). Still PermDenied.

    # BUT: what if we DON'T apply it as Either but use the raw term?
    # echo(g(251)) → Left(Var(253)). This is λl.λr.l(Var(255)) (shifted under 2 lambdas).
    # Wait no: echo(g(251)) returns Left(Var(253)).
    # Left(x) = λl.λr.l(x). So Left(Var(253)) = λl.λr.l(Var(253)).
    # But Var(253) under 2 lambdas means: the actual term is λ.λ.(1 Var(253)).
    # Var(253) at depth 2 = global Var(251). When we apply this to f and g:
    # Left(Var(253))(f)(g) = f(Var(253-2)) = f(g(251)). Same as unwrapping.

    # Let me try a DIFFERENT approach: pass the echo result to ITSELF
    # echo(g(251)) → raw → echo(raw, OBS)
    # This should give Left(Left(Var(255))) inside, and then OBS would fail to quote.
    print("\n  --- Double echo (chained) ---")

    # echo(g(251), λres1. echo(res1, λres2. sys8(res2, OBS)))
    # res1 = Left(Var(253)). echo(Left(Var(253))) = Left(Left(Var(255)))
    # res2 = Left(Left(Var(255))). sys8(Left(Left(Var(255))), OBS)
    term = apps(
        g(14),
        g(251),
        lam("res1", apps(g(14), v("res1"), lam("res2", apps(g(8), v("res2"), OBS)))),
    )
    out, elapsed = query_named_timed(term, timeout_s=6.0)
    print(f"  echo(251) → echo(res1) → sys8(res2, OBS) -> {classify(out, elapsed)}")
    time.sleep(0.35)

    # Triple echo
    term = apps(
        g(14),
        g(251),
        lam(
            "r1",
            apps(
                g(14),
                v("r1"),
                lam("r2", apps(g(14), v("r2"), lam("r3", apps(g(8), v("r3"), OBS)))),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=6.0)
    print(f"  echo^3(251) → sys8(res3, OBS) -> {classify(out, elapsed)}")
    time.sleep(0.35)

    # What about echo(g(250))? That gives Left(Var(252)) which IS quotable.
    # Then echo(Left(Var(252))) gives Left(Left(Var(254))). Var(254) = FE = Lam marker!
    term = apps(
        g(14),
        g(250),
        lam("r1", apps(g(14), v("r1"), lam("r2", apps(g(8), v("r2"), OBS)))),
    )
    out, elapsed = query_named_timed(term, timeout_s=6.0)
    print(f"  echo(250) → echo(res1) → sys8(res2, OBS) -> {classify(out, elapsed)}")
    time.sleep(0.35)

    # Key insight from Oracle: try echo(Lam(Var(251))) to get different internal structures
    # Lam(Var(251)) at top level: the Var(251) inside the Lam is a free var → global g(250).
    # echo(Lam(g(250))) → Left(Lam(Var(252))). Under the Either's 2 lambdas, Var(252) = g(250).
    # So echoing a Lam preserves the structure inside.

    # Let's try: echo various lambda-wrapped terms
    print("\n  --- Echo of lambda-wrapped terms ---")

    # echo(λ.g(251)) → Left(λ.Var(254)) — Var(254) = FE inside! (under 3 lambdas)
    # The λ in "λ.g(251)" at top level: inside the lambda, g(251) = Var(252).
    # So Lam(Var(252)). echo(Lam(Var(252))) → Left(Lam(Var(254))).
    # Under Either's 2 lambdas, that's λ.λ.l(Lam(Var(254))).
    # When we unwrap: Lam(Var(254-2)) = Lam(Var(252)) = Lam(g(251)). Same thing.
    # Under the hood though, the VM has Var(254) in memory.

    # Let me try something different: echo applied to echo's own result
    # and then using the result as a CONTINUATION, not argument
    print("\n  --- Echo results as sys8 CONTINUATION (not arg) ---")

    for echo_arg in [248, 249, 250, 251, 252]:
        term = apps(g(14), g(echo_arg), lam("echo_raw", apps(g(8), NIL, v("echo_raw"))))
        out, elapsed = query_named_timed(term, timeout_s=6.0)
        result = classify(out, elapsed)
        hex_str = out[:40].hex() if out else ""
        print(f"  echo(g({echo_arg})) → sys8(nil, echo_raw) -> {result}")
        if out and "OTHER" in result:
            print(f"    raw: {hex_str}")
        time.sleep(0.35)

    # Now the interesting one: use echo result as BOTH arg and continuation
    print("\n  --- Echo result as BOTH arg and cont ---")
    term = apps(
        g(14), g(251), lam("echo_raw", apps(g(8), v("echo_raw"), v("echo_raw")))
    )
    out, elapsed = query_named_timed(term, timeout_s=6.0)
    print(f"  echo(251) → sys8(raw, raw) -> {classify(out, elapsed)}")
    if out:
        print(f"    raw: {out[:40].hex()}")
    time.sleep(0.35)


def theory_2_extended_integers():
    """
    Theory 2: Test if the integer encoding supports values beyond 255.

    The standard encoding uses 9 lambdas and Var(0)-Var(8) as weights (0,1,2,4,...,128).
    What if Var(9) = weight 256? Then we could encode IDs up to 511.

    Test: Create a term with Var(9) inside 9 lambdas and see if name() recognizes it.
    """
    print("\n" + "=" * 72)
    print("THEORY 2: Extended integer encoding (Var(9)+ as weights)")
    print("=" * 72)

    # Standard encoding of 0: λ^9.Var(0) = Lam^9(Var(0))
    # Standard encoding of 1: λ^9.App(Var(1), Var(0)) = Lam^9(App(Var(1), Var(0)))
    # Standard encoding of 255: λ^9.App(Var(8), App(Var(7), ...all weights...))

    # Test: encoding of 256 = λ^9.Var(9) (if Var(9) maps to weight 256)
    # Inside 9 lambdas, Var(9) is a free variable → global g(0).
    # Hmm, that's a problem. Var(9) inside 9 lambdas = g(0) = exception handler.
    # So when the VM evaluates this, it's calling g(0) which diverges.

    # Actually wait — the integer encoding is NOT evaluated by the VM.
    # It's a STRUCTURAL encoding: λ^9.body where body is built from App/Var.
    # The "integer" is decoded by pattern-matching the term structure, not by evaluating it.
    # So Var(9) inside 9 lambdas is just a structural reference to the 10th lambda parameter
    # (which doesn't exist, since there are only 9 lambdas: params 0-8).

    # But the DECODER might interpret Var(9) as weight 256 if it supports it.
    # Let's build the term and test name() with it.

    # 256 = just Var(9) under 9 lambdas
    def make_extended_int(val):
        """Build an integer term with potential extended weights."""
        # weights: 0→0, 1→1, 2→2, 3→4, 4→8, 5→16, 6→32, 7→64, 8→128, 9→256, 10→512
        weights = {
            0: 0,
            1: 1,
            2: 2,
            3: 4,
            4: 8,
            5: 16,
            6: 32,
            7: 64,
            8: 128,
            9: 256,
            10: 512,
        }
        expr = Var(0)
        remaining = val
        for idx in sorted(weights.keys(), key=lambda k: weights[k], reverse=True):
            w = weights[idx]
            if w == 0:
                continue
            if remaining >= w:
                expr = App(Var(idx), expr)
                remaining -= w
        if remaining != 0:
            return None  # Can't encode
        term = expr
        for _ in range(9):
            term = Lam(term)
        return term

    # Test: name(256)
    int_256 = make_extended_int(256)
    if int_256:
        term = apps(g(6), NConst(int_256), OBS)
        out, elapsed = query_named_timed(term, timeout_s=5.0)
        print(f"  name(256_extended) -> {classify(out, elapsed)}")
        if out:
            text = out.decode("latin-1", errors="replace")
            print(f"    text: {text!r}")
        time.sleep(0.35)

    # Test: readfile(256) with extended encoding
    if int_256:
        term = apps(g(7), NConst(int_256), OBS)
        out, elapsed = query_named_timed(term, timeout_s=5.0)
        print(f"  readfile(256_extended) -> {classify(out, elapsed)}")
        if out:
            text = out.decode("latin-1", errors="replace")
            print(f"    text: {text[:80]!r}")
        time.sleep(0.35)

    # Test: sys8 with 256 as arg
    if int_256:
        term = apps(g(8), NConst(int_256), OBS)
        out, elapsed = query_named_timed(term, timeout_s=5.0)
        print(f"  sys8(256_extended, OBS) -> {classify(out, elapsed)}")
        time.sleep(0.35)

    # Test other extended values: 257, 300, 511, 512
    for val in [257, 300, 511, 512]:
        int_term = make_extended_int(val)
        if int_term:
            term = apps(g(6), NConst(int_term), OBS)
            out, elapsed = query_named_timed(term, timeout_s=5.0)
            print(f"  name({val}_extended) -> {classify(out, elapsed)}")
            if out:
                text = out.decode("latin-1", errors="replace")
                if "Not implemented" not in text and "?" not in text[:5]:
                    print(f"    text: {text[:80]!r}")
            time.sleep(0.35)

    # What about using 10+ lambdas? Maybe the encoding supports more than 9 lambdas.
    print("\n  --- 10-lambda integer encoding ---")
    # 256 with 10 lambdas: λ^10.App(Var(9), Var(0))
    # Var(9) at depth 10 = 10th param. With 10 lambdas, params are 0-9.
    # So Var(9) IS a valid param reference.
    int_256_10lam = App(Var(9), Var(0))
    for _ in range(10):
        int_256_10lam = Lam(int_256_10lam)
    term = apps(g(6), NConst(int_256_10lam), OBS)
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  name(256_10lam) -> {classify(out, elapsed)}")
    if out:
        text = out.decode("latin-1", errors="replace")
        print(f"    text: {text[:80]!r}")
    time.sleep(0.35)

    # Same for readfile
    term = apps(g(7), NConst(int_256_10lam), OBS)
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  readfile(256_10lam) -> {classify(out, elapsed)}")
    if out:
        text = out.decode("latin-1", errors="replace")
        print(f"    text: {text[:80]!r}")
    time.sleep(0.35)


def theory_3_overapply_result():
    """
    Theory 3: Over-apply sys8's Right(6) result.

    Right(6) = λl.λr.r(6). It's a 2-arg function.
    What if we apply it to MORE than 2 args?
    Right(6)(a)(b) = b(6). Then (b(6))(extra_args)...

    Or: treat the result as something other than an Either.
    """
    print("\n" + "=" * 72)
    print("THEORY 3: Over-apply sys8's result / treat as non-Either")
    print("=" * 72)

    # sys8(nil, λresult. result(λx. write_str("L:") x)(λy. write_str("R:") y)(λz. write_str("E1:") z))
    # Apply result to 3 handlers instead of 2
    term = apps(
        g(8),
        NIL,
        lam(
            "result",
            apps(
                v("result"),
                lam("x", write_str("L")),
                lam("y", write_str("R")),
                lam("z", write_str("EXTRA1")),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  sys8 result applied to 3 handlers -> {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')!r}")
    time.sleep(0.35)

    # Apply to 4 handlers
    term = apps(
        g(8),
        NIL,
        lam(
            "result",
            apps(
                v("result"),
                lam("x", write_str("L")),
                lam("y", write_str("R")),
                lam("z", write_str("E1")),
                lam("w", write_str("E2")),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  sys8 result applied to 4 handlers -> {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')!r}")
    time.sleep(0.35)

    # What if the result ISN'T an Either at all?
    # Apply result to nil (1 arg only)
    term = apps(g(8), NIL, lam("result", apps(v("result"), NIL)))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  sys8 result applied to 1 arg (nil) -> {classify(out, elapsed)}")
    time.sleep(0.35)

    # Apply result to a single observer function
    term = apps(
        g(8),
        NIL,
        lam(
            "result",
            apps(
                v("result"),
                lam(
                    "inner",
                    apps(
                        g(4),
                        v("inner"),  # quote the inner value
                        lam(
                            "q",
                            apps(
                                v("q"),
                                lam("bytes", apps(g(2), v("bytes"), NIL)),
                                lam("_", write_str("QF")),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  sys8 result(λx. quote(x) → write) -> {classify(out, elapsed)}")
    if out:
        print(f"    raw: {out[:40].hex()}")
    time.sleep(0.35)

    # Apply result to ITSELF
    term = apps(g(8), NIL, lam("result", apps(v("result"), v("result"))))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  sys8 result applied to itself -> {classify(out, elapsed)}")
    time.sleep(0.35)

    # What if we use result as an integer (apply to 9 args)?
    # If Right(6) happens to be an integer representation...
    # Right(6) = λl.λr.r(6). Not a 9-lambda term. Different shape.
    # But what if we decode the error code differently?

    # Let's try: extract the Right's payload and use IT
    # sys8(nil, λresult. result(λ_l. write("L"))(λcode. code(args...)))
    # Right(6)(l_handler)(r_handler) = r_handler(6)
    # If 6 is encode_byte_term(6) it's a 9-lambda term. Then code(arg1)(arg2)...
    # Actually the VM's "6" is just a term. What term IS 6?
    # error_string(6) → "Permission denied". So the error code is passed as an integer term.

    # Let's quote the error code itself
    term = apps(
        g(8),
        NIL,
        lam(
            "result",
            apps(
                v("result"),
                lam("_l", write_str("L")),
                lam(
                    "code",
                    apps(
                        g(4),
                        v("code"),
                        lam(
                            "q",
                            apps(
                                v("q"),
                                lam("bytes", apps(g(2), v("bytes"), NIL)),
                                lam("_", write_str("QF")),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  sys8 → Right(code) → quote(code) → write -> {classify(out, elapsed)}")
    if out:
        print(f"    raw: {out[:60].hex()}")
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # CRITICAL: What if the error code ISN'T an integer but something more complex?
    # Let's apply the error code as a function
    term = apps(
        g(8),
        NIL,
        lam(
            "result",
            apps(
                v("result"),
                lam("_l", write_str("L")),
                lam("code", apps(v("code"), lam("x", write_str("CODE_AS_FUNC")))),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  sys8 → Right(code) → code as function -> {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')!r}")
    time.sleep(0.35)


def theory_4_backdoor_as_interrupt():
    """
    BONUS: "interrupt and transfer parameters to the kernel"
    What if backdoor is literally an interrupt — and the pair IS the kernel interface?

    pair = λx.λy.((x A) B)
    A = λa.λb.(b b)
    B = λa.λb.(a b)

    pair(sys8)(nil) = ((sys8 A) B)(nil) = sys8(A)(B)(nil)
    But sys8 takes 2 args, so sys8(A, B) then applied to nil.
    sys8(A, B) → B(Right(6)) = (λb.(Right(6) b))
    Then applied to nil: Right(6)(nil) = λr.r(6) → needs another arg... stuck.

    What if: pair(sys8)(OBS)?
    sys8(A, B)(OBS) = B(Right(6))(OBS) = (λb.(Right(6) b))(OBS) = Right(6)(OBS)
    = λr.r(6) applied to OBS = OBS(6). OBS expects an Either... gets 6 directly.

    Hmm, let me just test various combinations.
    """
    print("\n" + "=" * 72)
    print("THEORY 4 (BONUS): Backdoor pair as kernel interrupt")
    print("=" * 72)

    # pair(sys8)(OBS)
    term = apps(
        g(201),
        NIL,
        lam(
            "bd_res",
            apps(
                v("bd_res"),
                lam("pair", apps(apps(v("pair"), g(8)), OBS)),
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  pair(sys8)(OBS) -> {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # pair(OBS)(sys8)
    term = apps(
        g(201),
        NIL,
        lam(
            "bd_res",
            apps(
                v("bd_res"),
                lam("pair", apps(apps(v("pair"), OBS), g(8))),
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  pair(OBS)(sys8) -> {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # pair(g(8))(OBS) — sys8 in first position
    # pair(g(8)) = λy.((g(8) A) B) = λy.sys8(A, B)
    # sys8(A, B) → B(Right(6)) = (λb.(Right(6) b)). This is a function.
    # Applied to OBS: (λb.(Right(6) b))(OBS) = Right(6)(OBS) = OBS(6)
    # But OBS expects an Either. 6 is not an Either. OBS would try 6(left_handler)(right_handler)...
    # Actually: OBS = λres. res(left_handler)(right_handler)
    # So OBS(6) = 6(left_handler)(right_handler)
    # 6 is an integer term (9 lambdas). Applied to left_handler → strips one lambda.
    # We'd get some weird partial application.

    # Let me try: pair(nil)(sys8)
    # pair(nil) = λy.((nil A) B) = λy.(A)(B)... wait
    # nil = λa.λb.b. nil(A) = λb.b. nil(A)(B) = B.
    # pair(nil) = λy.B. Then pair(nil)(sys8) = B.
    # B = λa.λb.(a b).
    # So we'd just get B, which is a function, not a syscall result.

    # What about: (A B) = omega. omega(sys8)?
    # omega = λx.(x x). omega(sys8) = sys8(sys8).
    # sys8(sys8) → partial application (needs second arg).
    # Then we need to apply to OBS: omega(sys8)(OBS) = sys8(sys8)(OBS) = sys8(sys8, OBS)
    term = apps(
        g(201),
        NIL,
        lam(
            "bd_res",
            apps(
                v("bd_res"),
                lam(
                    "pair",  # Left: got pair
                    apps(
                        apps(
                            v("pair"),
                            lam("A", lam("B", apps(app(v("A"), v("B")), g(8), OBS))),
                        ),  # omega(sys8, OBS) = sys8(sys8)(OBS)
                        NIL,
                    ),
                ),
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=6.0)
    print(f"  omega(sys8)(OBS) via pair extraction -> {classify(out, elapsed)}")
    time.sleep(0.35)

    # The most literal reading of gizmore's hint:
    # "cmd to interrupt and transfer my parameters to the kernel"
    # What if the "cmd" is the backdoor, "interrupt" is calling it,
    # and "transfer parameters" means passing something TO the backdoor?
    # But backdoor only accepts nil!
    # Unless... what if the "parameters" are the pair (A, B) themselves?
    # And "kernel" is sys8?

    # So: get pair, then sys8(A, B)?
    # We tested sys8(A, OBS), sys8(B, OBS), sys8(pair, OBS). All PermDenied.
    # What about sys8(A, B) without our OBS? Just raw?
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
                        apps(v("pair"), lam("A", lam("B", apps(g(8), v("A"), v("B"))))),
                        NIL,
                    ),
                ),
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=6.0)
    print(f"  sys8(A, B) raw (no OBS) -> {classify(out, elapsed)}")
    if out:
        print(f"    raw: {out[:40].hex()}")
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # And: sys8(B, A)?
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
                        apps(v("pair"), lam("A", lam("B", apps(g(8), v("B"), v("A"))))),
                        NIL,
                    ),
                ),
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named_timed(term, timeout_s=6.0)
    print(f"  sys8(B, A) raw -> {classify(out, elapsed)}")
    if out:
        print(f"    raw: {out[:40].hex()}")
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)


def main():
    print("=" * 72)
    print("probe_oracle10_theories.py - Testing Oracle #10's three theories")
    print(f"target: {HOST}:{PORT}")
    print("=" * 72)

    theory_1_raw_echo_results()
    theory_2_extended_integers()
    theory_3_overapply_result()
    theory_4_backdoor_as_interrupt()

    print("\nAll theories tested.")


if __name__ == "__main__":
    main()
