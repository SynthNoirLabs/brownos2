#!/usr/bin/env python3
"""
Probe: beta-reduction-manufactured Var(253..255) + sys8 inside backdoor context.

Three hypotheses:
  H1: Beta-reduction can create Var(253/254/255) at runtime. Feed these to sys8.
  H2: sys8 only works inside backdoor continuation context.
  H3: QD (which uses quote) destroys evidence — use quote-free observer only.

Key idea:  (λ.λ.Var(1)) applied to Var(252)  →  λ.Var(253)  at runtime
           because substitution shifts Var(252) by +1 under one binder.

           Similarly Var(252) → Var(254) under two binders, etc.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import App, Lam, Var, encode_term, encode_bytes_list

HOST = "wc3.wechall.net"
PORT = 61221
FF = 0xFF


# -- Named-term builder (from probe_mail_focus.py) --


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


def int_term(n):
    expr = Var(0)
    for idx, weight in (
        (1, 1),
        (2, 2),
        (3, 4),
        (4, 8),
        (5, 16),
        (6, 32),
        (7, 64),
        (8, 128),
    ):
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def recv_all(sock, timeout_s=7.0):
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


def query_named(term, timeout_s=10.0, retries=3):
    payload = encode_term(to_db(term)) + bytes([FF])
    delay = 0.2
    for attempt in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s=timeout_s)
        except Exception as e:
            if attempt == retries - 1:
                return b""
            time.sleep(delay)
            delay = min(delay * 2, 2.0)
    return b""


def classify(out):
    if not out:
        return "silent"
    if out.startswith(b"Invalid term!"):
        return "invalid"
    if out.startswith(b"Encoding failed!"):
        return "encfail"
    try:
        text = out.decode("latin-1")
    except Exception:
        text = out.hex()
    return f"text:{text}" if len(out) < 60 else f"hex:{out[:40].hex()}..."


def write_str(s):
    """Named term: write(string_literal, nil)"""
    return apps(g(2), NConst(encode_bytes_list(s.encode())), NIL)


def write_marker(ch):
    """Write a single-char marker then continue with nil"""
    return apps(g(2), NConst(encode_bytes_list(ch.encode())), NIL)


# ========== QUOTE-FREE OBSERVER (OBS) ==========
# Discriminates Either:
#   Left(x)  → write("L:")  (no quote!)
#   Right(n) → error_string(n) → write(the_string)
def obs_full():
    """
    λres. res
        (λ_payload. write("L:", nil))
        (λerr_code. g(1)(err_code, λerr_res. err_res
            (λstr. write(str, nil))
            (λ_. write("?", nil))
        ))
    """
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
                    lam("_e2", write_marker("?")),
                ),
            ),
        ),
    )

    left_handler = lam("_payload", write_str("L:"))

    return lam("res", apps(v("res"), left_handler, right_handler))


def obs_left_detail():
    """
    Like obs_full but on Left(x), tries to quote x and write the result.
    This is for comparison — it DOES use quote so may fail on unquotable terms.
    """
    left_handler = lam(
        "payload",
        apps(
            g(4),
            v("payload"),
            lam(
                "qres",
                apps(
                    v("qres"),
                    lam("qbytes", apps(g(2), v("qbytes"), NIL)),
                    lam("_qe", write_str("Q!")),
                ),
            ),
        ),
    )

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
                    lam("_e2", write_marker("?")),
                ),
            ),
        ),
    )

    return lam("res", apps(v("res"), left_handler, right_handler))


# ========== PHASE 1: Beta-shift verification ==========
# (λ.λ.Var(1)) Var(252) should reduce to λ.Var(253)
# We verify by trying to quote it — should get "Encoding failed!"


def test_beta_shift_verify():
    print("\n" + "=" * 60)
    print("PHASE 1: Verify beta-reduction creates Var(253)")
    print("=" * 60)

    # K combinator = λx.λy.x = in de Bruijn: Lam(Lam(Var(1)))
    # K(Var(252)) should reduce to Lam(Var(253))
    # But Var(253) = 0xFD = App marker! So quote should fail.

    # Build: quote(K(g(252)), obs)
    # K = λ.λ.Var(1)  (closed, no free vars)
    K_comb = NConst(Lam(Lam(Var(1))))

    # K applied to g(252) — at top level, g(252) is Var(252)
    # After reduction: K(g(252)) → λy.g(252) → but inside λy, g(252) shifts to Var(253)
    # Actually wait: g(252) at top level (0 binders) = Var(252)
    # K = λx.λy.x — applying to Var(252):
    #   (λx.λy.x)(Var(252)) → λy.[Var(252)/x] = λy.Var(253)
    #   (because Var(252) is a free var, and going under λy shifts it by +1)
    # Actually no — in de Bruijn, K = Lam(Lam(Var(1)))
    # Apply K to Var(252): substitute Var(252) for Var(0) in Lam(Var(1))
    # But Var(1) in Lam(Var(1)) refers to x (bound by outer lambda)
    # After substitution: Lam(shift(Var(252), +1, cutoff=0)) = Lam(Var(253))
    # YES! So (K g(252)) → Lam(Var(253))

    # Now try to quote this term
    test_term = apps(K_comb, g(252))
    prog = apps(g(4), test_term, obs_left_detail())

    out = query_named(prog)
    print(f"  quote(K(g(252))): {classify(out)}")
    print(f"    raw: {out[:80]}")

    # Also test: just pass K(g(252)) directly to QD-like observer
    # Actually, let's verify with echo first
    prog2 = apps(g(14), apps(K_comb, g(252)), obs_full())
    out2 = query_named(prog2)
    print(f"  echo(K(g(252))): {classify(out2)}")
    print(f"    raw: {out2[:80]}")

    # Same but with 251: K(g(251)) → Lam(Var(252)) — still quotable!
    prog3 = apps(g(4), apps(K_comb, g(251)), obs_left_detail())
    out3 = query_named(prog3)
    print(f"  quote(K(g(251))): {classify(out3)} [should succeed, 252 is quotable]")
    print(f"    raw: {out3[:80]}")

    # K(g(252))(anything) → g(252) = Var(252) — back to normal
    # So the Var(253) only exists INSIDE the lambda
    # To use Var(253) as an actual argument, we need to eliminate the outer lambda

    # NEW: Use I combinator inside: (λf. f Var(252)) (λx. x) — but that's just Var(252)

    # What about: construct something that EVALUATES to a term containing Var(253) at top level?
    # (λf. f) Var(253) — but we can't encode Var(253) on wire!
    # We need beta-reduction to produce a top-level Var(253).

    # Approach: use S combinator or apply the result in a way that exposes Var(253)
    # (λ.Var(1)) in environment where Var(0) is bound = parent's Var(0)
    # Hmm, this is tricky in de Bruijn...

    # Actually the simplest: pass K(g(252)) to echo.
    # echo(K(g(252))) → Left(K(g(252))) — but the argument is evaluated first!
    # The VM evaluates K(g(252)) → Lam(Var(253))
    # Then echo(Lam(Var(253))) → Left(Lam(Var(253)))
    # Now if we extract Left payload, we get Lam(Var(253)) — a term containing Var(253)

    # Can we feed this to sys8?
    print()
    return True


# ========== PHASE 2: sys8 with beta-shift terms ==========


def test_sys8_with_beta_shifted():
    print("\n" + "=" * 60)
    print("PHASE 2: sys8 with beta-reduction-created unquotable terms")
    print("=" * 60)

    OBS = obs_full()
    K_comb = NConst(Lam(Lam(Var(1))))

    # Test 1: sys8(K(g(252))) — the VM reduces K(g(252)) to Lam(Var(253))
    # BEFORE passing it to sys8. So sys8 gets an argument containing Var(253).
    prog1 = apps(g(8), apps(K_comb, g(252)), OBS)
    out1 = query_named(prog1)
    print(f"  sys8(K(g(252))): {classify(out1)} [arg contains Var(253)]")
    print(f"    raw: {out1[:80]}")
    time.sleep(0.3)

    # Test 2: sys8(K(K(g(251))))
    # K(g(251)) → Lam(Var(252))
    # K(Lam(Var(252))) → Lam(Lam(Var(252))) — wait that's different
    # Actually: K applied to Lam(Var(252)) →  Lam(shift(Lam(Var(252)),+1,0))
    #  = Lam(Lam(Var(253))) — two lambdas deep
    # Hmm, let's also try direct approaches.

    # Test 2: Actually create Var(253) at TOP level via self-application trick
    # (λx. x x)(λx. g(252)) — this is (λx.xx)(λx.252)
    # → (λx.g(252))(λx.g(252)) → g(252) — still just 252
    # That doesn't work.

    # What about using the 3-arg pattern from cheat sheet?
    # ?? ?? FD QD FD  means  ((term1 term2) QD)
    # What if term1 = sys8, term2 = K(g(252)), and observer = OBS?
    # That's: sys8(K(g(252)), OBS) — same as test 1

    # Test 2: sys8 with Lam(Var(253)) wrapped differently
    # What if we apply it to something first?
    # K(g(252)) = λ_.Var(253) — if we apply this to nil, we get Var(253)
    # But Var(253) at top level = g(253-0) = g(253)... which doesn't exist as a global (max is 252)
    # Wait — there are 253 globals, numbered 0-252. So g(253) would be... out of bounds?
    # OR: the VM might treat Var(253) specially since 253=0xFD=App in the encoding!

    # Test 2: Apply K(g(252)) to nil → should evaluate to g(252+1)=Var(253) at top level
    # Actually K(g(252))(nil) → Var(253) at the same level as the globals
    # But there IS no g(253)... unless it's a special/hidden thing

    # Let's try it via a two-step: first reduce K(g(252))(nil) and pass to sys8
    # sys8 would get Var(253) directly — a free variable with index 253 at top level
    prog2a = apps(g(8), apps(K_comb, g(252), NIL), OBS)
    out2a = query_named(prog2a)
    print(f"  sys8(K(g(252))(nil)): {classify(out2a)} [Var(253) at top level]")
    print(f"    raw: {out2a[:80]}")
    time.sleep(0.3)

    # Test 3: Use Var(254) — K applied twice with shifts
    # K(g(252))(nil) → Var(253)   (= 0xFD = App token)
    # Now try: something that gives us Var(254) = 0xFE = Lam token
    # (λ.λ.Var(2))(g(252)) → λ.Var(254)?
    # Actually (λ.λ.Var(2)) in de Bruijn: Var(2) refers to the variable 2 levels up = free
    # If we apply (λ.λ.Var(2)) to g(252), we substitute g(252) for the outermost lambda's var
    # But Var(2) inside λ.λ. refers to the free variable 2 = g(252) from outside!
    # After substitution of g(252) for the outer lambda: inner λ.Var(2-1+shift)...
    # This is getting complex. Let me use the named builder.

    # Alternative: direct encode — Var(252) applied to nil
    # At top level, Var(252) = g(252). g(252) is a known global.
    # To get Var(253), we need index 253 at top level = beyond all globals.
    # The named-term builder won't produce Var(253) because NGlob(253) = Var(253+0) = Var(253)
    # which is 0xFD in encoding — can't encode!

    # So we MUST create it via beta-reduction.
    # K(g(252))(nil) reduces inside the VM:
    # Step 1: K(g(252)) = (Lam(Lam(Var(1))))(Var(252)) → Lam(shift(Var(252),+1,0)) = Lam(Var(253))
    # Step 2: Lam(Var(253))(nil_term) = [nil/Var(0)]Var(253) — but Var(253) has index 253
    # Wait: nil = Lam(Lam(Var(0))). Substituting nil for Var(0) in Var(253):
    #   253 > 0 (the bound variable), so Var(253) → Var(253-1) = Var(252)
    # So K(g(252))(nil) → Var(252) — we're back to g(252)! The lambda application undoes the shift!

    # This is the fundamental issue with de Bruijn — applying the outer lambda cancels the shift.
    # To get Var(253) at top level, we need it OUTSIDE any lambda.

    # The ONLY way to get Var(253) free at top level is to have it as a free variable
    # in our top-level term. But we can't encode it!

    # UNLESS... we use a different trick. What about:
    # echo(g(252)) → Left(Var(252+2)) = Left(Var(254)) — because Left wraps under 2 lambdas
    # Then extract Left payload: the payload is Var(254) which, when freed from Left's lambdas,
    # becomes Var(254-2) = Var(252) again. The shift cancels on extraction!

    # So the key insight might be: DON'T extract from Left. Use the WHOLE Left-wrapped term.
    # echo(g(252)) produces a TERM whose normal form, when inspected raw, has Var(254) inside.
    # If we pass this Left-wrapped thing directly to sys8 without unpacking...

    prog3 = apps(g(8), apps(g(14), g(252), lam("echo_res", v("echo_res"))), OBS)
    out3 = query_named(prog3)
    print(f"  sys8(echo(g(252)) raw Left): {classify(out3)}")
    print(f"    raw: {out3[:80]}")
    time.sleep(0.3)

    # Test 4: What about making sys8 itself the argument or continuation in weird ways?
    # sys8 applied to itself?
    prog4 = apps(g(8), g(8), OBS)
    out4 = query_named(prog4)
    print(f"  sys8(sys8): {classify(out4)}")
    print(f"    raw: {out4[:80]}")
    time.sleep(0.3)

    # Test 5: What about: sys8 where the ARGUMENT is the backdoor pair itself?
    # backdoor(nil) → Left(pair), extract pair, pass pair to sys8
    disc_backdoor = lam(
        "bd_res",
        apps(
            v("bd_res"),
            lam("pair", apps(g(8), v("pair"), OBS)),
            lam("bd_err", write_str("BE")),
        ),
    )
    prog5 = apps(g(201), NIL, disc_backdoor)
    out5 = query_named(prog5)
    print(f"  backdoor→pair→sys8(pair): {classify(out5)}")
    print(f"    raw: {out5[:80]}")
    time.sleep(0.3)

    # Test 6: sys8 where argument is pair applied to pair: pair(pair)
    # The backdoor pair = (A, B) where A=λa.λb.bb, B=λa.λb.ab
    # pair is: λsel. sel A B
    # pair(pair) = (λsel. sel A B)(λsel. sel A B) = (λsel. sel A B) A B
    # → A(B) which is the omega combinator
    disc_bd2 = lam(
        "bd_res",
        apps(
            v("bd_res"),
            lam("pair", apps(g(8), apps(v("pair"), v("pair")), OBS)),
            lam("bd_err", write_str("BE")),
        ),
    )
    prog6 = apps(g(201), NIL, disc_bd2)
    out6 = query_named(prog6)
    print(f"  backdoor→pair→sys8(pair(pair)): {classify(out6)}")
    print(f"    raw: {out6[:80]}")
    time.sleep(0.3)

    print()


# ========== PHASE 3: sys8 INSIDE backdoor continuation ==========


def test_sys8_inside_backdoor():
    print("\n" + "=" * 60)
    print("PHASE 3: sys8 inside backdoor continuation, observe outside")
    print("=" * 60)

    OBS = obs_full()

    # Pattern: whole_program = backdoor(nil, λpair. sys8(arg, λres. res))
    # Then apply whole_program to OBS at the top
    # i.e., (λ_outer. backdoor(nil, ...inner returns Either...)) QD-like
    # Actually: the inner continuation returns the Either result,
    # and the outer level observes it.

    # Approach A: backdoor → ignore pair → sys8(nil) → return result to outer
    # The result of sys8 is Right(6). We want to see if being inside backdoor changes this.

    # Structure: backdoor(nil, λpair. sys8(nil, λsys8_result. sys8_result))
    # The whole thing evaluates to sys8_result = Right(6)
    # Then we apply OBS to it at the outer level

    # But wait — CPS doesn't work that way. Syscalls consume the continuation.
    # backdoor(nil, K_cont) → K_cont(Left(pair))
    # Inside K_cont: sys8(nil, K_cont2) → K_cont2(Right(6))
    # K_cont2 could be identity: λr.r → returns Right(6)
    # But then who observes it? There's no outer continuation...

    # Actually the CPS chain is:
    # ((g(201) nil) (λpair. ((g(8) nil) (λresult. <observe result here>))))
    # We need the observation INSIDE the chain, not outside.

    # Test A: sys8(nil) inside backdoor continuation, with OBS
    prog_a = apps(g(201), NIL, lam("pair", apps(g(8), NIL, OBS)))
    out_a = query_named(prog_a)
    print(f"  A: backdoor→sys8(nil) [OBS inside]: {classify(out_a)}")
    print(f"    raw: {out_a[:80]}")
    time.sleep(0.3)

    # Test B: sys8 with pair as argument
    prog_b = apps(g(201), NIL, lam("pair", apps(g(8), v("pair"), OBS)))
    out_b = query_named(prog_b)
    print(f"  B: backdoor→sys8(pair) [OBS inside]: {classify(out_b)}")
    print(f"    raw: {out_b[:80]}")
    time.sleep(0.3)

    # Test C: sys8 with pair's first component (A = λa.λb.bb)
    prog_c = apps(
        g(201),
        NIL,
        lam(
            "pair",
            apps(
                g(8),
                apps(v("pair"), lam("a", lam("b", v("a")))),  # pair(K) = fst = A
                OBS,
            ),
        ),
    )
    out_c = query_named(prog_c)
    print(f"  C: backdoor→sys8(fst(pair)) [A component]: {classify(out_c)}")
    print(f"    raw: {out_c[:80]}")
    time.sleep(0.3)

    # Test D: sys8 with pair's second component (B = λa.λb.ab)
    prog_d = apps(
        g(201),
        NIL,
        lam(
            "pair",
            apps(
                g(8),
                apps(v("pair"), lam("a", lam("b", v("b")))),  # pair(KI) = snd = B
                OBS,
            ),
        ),
    )
    out_d = query_named(prog_d)
    print(f"  D: backdoor→sys8(snd(pair)) [B component]: {classify(out_d)}")
    print(f"    raw: {out_d[:80]}")
    time.sleep(0.3)

    # Test E: sys8 with A(B) = omega combinator — but this diverges!
    # Skip this one, it would timeout.

    # Test F: sys8 with backdoor result (the Left-wrapped pair without unwrapping)
    # i.e., pass the raw Either to sys8
    prog_f = apps(
        g(201), NIL, lam("either_result", apps(g(8), v("either_result"), OBS))
    )
    out_f = query_named(prog_f)
    print(f"  F: backdoor→sys8(raw Either result): {classify(out_f)}")
    print(f"    raw: {out_f[:80]}")
    time.sleep(0.3)

    # Test G: DOUBLE BACKDOOR — call backdoor twice, use both results
    # backdoor(nil) → Left(pair1) → backdoor(pair1) → ???
    prog_g = apps(
        g(201),
        NIL,
        lam(
            "res1",
            apps(
                v("res1"),
                lam(
                    "pair1",
                    apps(
                        g(201),
                        v("pair1"),
                        lam(
                            "res2",
                            apps(
                                v("res2"),
                                lam("pair2", apps(g(8), v("pair2"), OBS)),
                                lam("err2", write_str("E2")),
                            ),
                        ),
                    ),
                ),
                lam("err1", write_str("E1")),
            ),
        ),
    )
    out_g = query_named(prog_g)
    print(f"  G: backdoor(nil)→pair→backdoor(pair)→sys8: {classify(out_g)}")
    print(f"    raw: {out_g[:80]}")
    time.sleep(0.3)

    print()


# ========== PHASE 4: The "second example" deep dive ==========
# ?? ?? FD QD FD  = ((term1 term2) QD)
# "don't be too literal with the ??s"
# What if ?? can be COMPOSITE multi-byte terms?


def test_second_example_creative():
    print("\n" + "=" * 60)
    print("PHASE 4: Creative interpretations of '?? ?? FD QD FD'")
    print("=" * 60)

    OBS = obs_full()

    # The second example shows: apply two things together, then observe with QD
    # What if the purpose is to COMBINE two syscall results?

    # Test A: (echo(sys8))(nil) observed with OBS
    # echo(sys8) → Left(sys8_term) = a Left-wrapped thing
    # Applying Left(sys8) to nil: (λl.λr. l sys8)(nil) = λr. nil(sys8)
    # → nil(sys8) = (λc.λn.n)(sys8) = λn.n
    # Hmm, this just gives identity...

    # Test B: sys8 applied directly to echo (as if echo IS the argument)
    prog_b = apps(g(8), g(14), OBS)
    out_b = query_named(prog_b)
    print(f"  B: sys8(echo): {classify(out_b)}")
    print(f"    raw: {out_b[:80]}")
    time.sleep(0.3)

    # Test C: echo applied to sys8, result passed to sys8
    # echo(sys8) → Left(sys8) → extract → pass to sys8
    prog_c = apps(
        g(14),
        g(8),
        lam(
            "echo_res",
            apps(
                v("echo_res"),
                lam("inner_sys8", apps(g(8), v("inner_sys8"), OBS)),
                lam("echo_err", write_str("EE")),
            ),
        ),
    )
    out_c = query_named(prog_c)
    print(f"  C: echo(sys8)→extract→sys8(echoed_sys8): {classify(out_c)}")
    print(f"    raw: {out_c[:80]}")
    time.sleep(0.3)

    # Test D: readfile(8) → get contents of /bin/solution → pass to sys8
    # File 8 is /bin/solution — what if its contents need to be "executed"?
    prog_d = apps(
        g(7),
        NConst(int_term(8)),
        lam(
            "rf_res",
            apps(
                v("rf_res"),
                lam("file_bytes", apps(g(8), v("file_bytes"), OBS)),
                lam("rf_err", write_str("RF")),
            ),
        ),
    )
    out_d = query_named(prog_d)
    print(f"  D: readfile(8)→sys8(contents): {classify(out_d)}")
    print(f"    raw: {out_d[:80]}")
    time.sleep(0.3)

    # Test E: What if we need to apply the backdoor PAIR to sys8?
    # pair = λsel. sel A B
    # pair(sys8) = sys8 A B = sys8(A, B_as_continuation)
    # So: pair(sys8) = ((sys8 A) B) where A=λa.λb.bb, B=λa.λb.ab
    # This calls sys8 with argument A and continuation B!
    # If sys8 succeeds: B(result) = (λa.λb.ab)(result) = λb.result(b)
    # If sys8 fails: B(Right(6)) = λb.Right(6)(b)
    prog_e = apps(
        g(201),
        NIL,
        lam(
            "bd_res",
            apps(
                v("bd_res"),
                lam(
                    "pair",
                    # pair(sys8) = sys8(A)(B) where A and B are the pair components
                    # We observe the final result with write
                    apps(
                        apps(v("pair"), g(8)),  # pair(sys8) = sys8(A)(B)
                        lam(
                            "final_obs",  # This is what B returns
                            apps(
                                v("final_obs"),
                                lam("_l", write_str("LEFT!")),
                                lam("_r", write_str("RIGHT")),
                            ),
                        ),
                    ),
                ),
                lam("bd_err", write_str("BE")),
            ),
        ),
    )
    out_e = query_named(prog_e, timeout_s=15.0)
    print(f"  E: pair(sys8) [pair selects A as arg, B as cont]: {classify(out_e)}")
    print(f"    raw: {out_e[:80]}")
    time.sleep(0.3)

    # Test F: What about using pair components as continuation for sys8?
    # sys8(nil, A) where A = λa.λb.bb
    # If sys8(nil) → Right(6), then A(Right(6)) = (λa.λb.bb)(Right(6)) = λb.bb
    # Which is... just A again. Not useful.
    # But what if A is a "magic continuation" that the kernel recognizes?
    prog_f = apps(
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
                        NIL,
                        lam(
                            "sys8_res",
                            apps(
                                v("sys8_res"),
                                lam("success", write_str("WIN!")),
                                lam(
                                    "err",
                                    # On error, try with A as arg
                                    apps(
                                        g(8),
                                        apps(v("pair"), lam("a", lam("b", v("a")))),
                                        OBS,
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
                lam("bd_err", write_str("BE")),
            ),
        ),
    )
    out_f = query_named(prog_f, timeout_s=15.0)
    print(f"  F: sys8(nil) err → sys8(pair_fst): {classify(out_f)}")
    print(f"    raw: {out_f[:80]}")
    time.sleep(0.3)

    print()


# ========== PHASE 5: sys8 with access.log content ==========


def test_sys8_with_access_log():
    print("\n" + "=" * 60)
    print("PHASE 5: sys8 with dynamic file content (access.log id=46)")
    print("=" * 60)

    OBS = obs_full()

    # readfile(46) → Left(log_bytes) → sys8(log_bytes)
    prog = apps(
        g(7),
        NConst(int_term(46)),
        lam(
            "rf_res",
            apps(
                v("rf_res"),
                lam("log_bytes", apps(g(8), v("log_bytes"), OBS)),
                lam("rf_err", write_str("RF")),
            ),
        ),
    )
    out = query_named(prog, timeout_s=15.0)
    print(f"  sys8(access_log_content): {classify(out)}")
    print(f"    raw: {out[:120]}")
    time.sleep(0.3)

    # Also try: sys8 with the READFILE RESULT (the Either, not unwrapped)
    prog2 = apps(
        g(7), NConst(int_term(46)), lam("rf_res", apps(g(8), v("rf_res"), OBS))
    )
    out2 = query_named(prog2, timeout_s=15.0)
    print(f"  sys8(readfile_either_raw): {classify(out2)}")
    print(f"    raw: {out2[:120]}")
    time.sleep(0.3)

    print()


# ========== PHASE 6: "Kernel interrupt" — use echo to create unevaluated thunks ==========


def test_echo_kernel_interrupt():
    print("\n" + "=" * 60)
    print("PHASE 6: Echo as 'kernel interrupt' - passing unevaluated code")
    print("=" * 60)

    OBS = obs_full()

    # gizmore said: "the cmd to interrupt and transfer my parameters to the kernel"
    # dloser said: "SPOILER ALERT"
    # What if echo can transfer a term to the evaluator in a special way?

    # echo(program) → Left(program) — but the program is already evaluated
    # What if we echo a PARTIALLY APPLIED syscall?
    # echo(g(8) nil) — this evaluates g(8)(nil) first, then echo gets Right(6)
    # But what if we echo JUST g(8) without applying it?
    # echo(g(8)) → Left(g(8)) — sys8 as a value!

    # Then extract and apply it?
    # extract(Left(g(8))) → g(8) → apply to arg → same thing...

    # What if we echo a LAMBDA that contains sys8?
    # echo(λx. sys8(x)) → Left(λx. sys8(x))
    # Then extract and apply to an argument

    # The interesting thing: echo preserves the term. What if there's a DIFFERENT
    # echo-like syscall or if echo has a side effect we haven't noticed?

    # Test: echo with MULTIPLE arguments (echo is CPS: echo(arg, cont))
    # What if echo(arg, cont) has a side effect that changes sys8's behavior?
    # We test: echo(something) → then immediately sys8(something_else)

    # Chain: echo(backdoor_pair) → then sys8(nil)
    prog_a = apps(
        g(201),
        NIL,
        lam(
            "bd_res",
            apps(
                v("bd_res"),
                lam(
                    "pair",
                    apps(g(14), v("pair"), lam("echo_res", apps(g(8), NIL, OBS))),
                ),
                lam("bd_err", write_str("BE")),
            ),
        ),
    )
    out_a = query_named(prog_a, timeout_s=15.0)
    print(f"  A: backdoor→echo(pair)→sys8(nil): {classify(out_a)}")
    print(f"    raw: {out_a[:80]}")
    time.sleep(0.3)

    # Test B: echo(sys8) → then sys8(echo_result)
    prog_b = apps(g(14), g(8), lam("echo_res", apps(g(8), v("echo_res"), OBS)))
    out_b = query_named(prog_b)
    print(f"  B: echo(sys8)→sys8(echo_result): {classify(out_b)}")
    print(f"    raw: {out_b[:80]}")
    time.sleep(0.3)

    # Test C: DEEP chain — echo(echo(echo(sys8))) → sys8
    prog_c = apps(
        g(14),
        g(8),
        lam(
            "e1",
            apps(
                g(14),
                v("e1"),
                lam("e2", apps(g(14), v("e2"), lam("e3", apps(g(8), v("e3"), OBS)))),
            ),
        ),
    )
    out_c = query_named(prog_c, timeout_s=15.0)
    print(f"  C: echo^3(sys8)→sys8(result): {classify(out_c)}")
    print(f"    raw: {out_c[:80]}")
    time.sleep(0.3)

    print()


# ========== MAIN ==========

if __name__ == "__main__":
    print("BrownOS Probe: Beta-Shift + Kernel Context")
    print("Using QUOTE-FREE observer (OBS) throughout")

    test_beta_shift_verify()
    test_sys8_with_beta_shifted()
    test_sys8_inside_backdoor()
    test_second_example_creative()
    test_sys8_with_access_log()
    test_echo_kernel_interrupt()

    print("\n" + "=" * 60)
    print("ALL PHASES COMPLETE")
    print("=" * 60)
