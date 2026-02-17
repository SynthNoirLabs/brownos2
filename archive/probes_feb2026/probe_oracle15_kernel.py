#!/usr/bin/env python3
"""
probe_oracle15_kernel.py — "Kernel" hypothesis testing.

Key hypotheses to test:
1. Omega combinator (from backdoor) as sys8 argument
2. Self-application patterns triggering evaluator behavior
3. Environment shadowing — can we rebind g(8)?
4. Different argument structures to sys8
5. Partial application / quote of sys8 results
6. The "cmd to interrupt and transfer parameters to the kernel"
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
    parse_term,
    decode_either,
    decode_bytes_list,
)

HOST = "wc3.wechall.net"
PORT = 61221


# ── Named-term helpers ───────────────────────────────────────────────


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
I_DB = Lam(Var(0))
I = NConst(I_DB)

# Omega combinator components (from backdoor)
# A = λa.λb.(b b)
A_DB = Lam(Lam(App(Var(0), Var(0))))
A = NConst(A_DB)
# B = λa.λb.(a b)
B_DB = Lam(Lam(App(Var(1), Var(0))))
B = NConst(B_DB)
# omega = A(B) = λx.(x x)
OMEGA_DB = Lam(App(Var(0), Var(0)))
OMEGA = NConst(OMEGA_DB)
# OMEGA_OMEGA = (λx.xx)(λx.xx) — diverges
# Don't send this directly or it'll timeout/loop

QD_TERM = NConst(parse_term(QD + bytes([FF])))


def int_term(n):
    return NConst(encode_byte_term(n))


def write_str(s):
    return apps(g(2), NConst(encode_bytes_list(s.encode("latin-1"))), NIL)


# ── Network ──────────────────────────────────────────────────────────


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


def query_named(term, timeout_s=5.0):
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
        return b"", 0.0


def query_raw(payload, timeout_s=5.0):
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
        return b"", 0.0


def classify(raw, elapsed):
    if not raw:
        if elapsed >= 4.5:
            return "TIMEOUT"
        return f"EMPTY({elapsed:.1f}s)"
    text = raw.decode("latin-1", errors="replace")
    if text.startswith("Encoding failed"):
        return "ENC_FAIL"
    if "Permission denied" in text:
        return "PERM_DENIED"
    if "Not implemented" in text:
        return "NOT_IMPL"
    if "Invalid argument" in text:
        return "INVALID_ARG"
    if "No such" in text:
        return "NO_SUCH"
    if "Not so fast" in text:
        return "RATE_LIM"
    if "Term too big" in text:
        return "TOO_BIG"
    if FF in raw:
        return f"QD:{raw[:30].hex()}"
    return f"DATA:{text[:60]!r}"


def full_cps_syscall(syscall_g, argument, label=""):
    """Standard CPS syscall: syscall(arg, cont) where cont decodes Either."""
    term = apps(
        syscall_g,
        argument,
        lam(
            "result",
            apps(
                v("result"),
                lam(
                    "data",  # Left handler
                    apps(g(2), v("data"), NIL),
                ),
                lam(
                    "errcode",  # Right handler
                    apps(
                        g(1),
                        v("errcode"),
                        lam(
                            "es",
                            apps(
                                v("es"),
                                lam("str", apps(g(2), v("str"), NIL)),
                                lam("_", write_str("?")),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    result = classify(out, elapsed)
    if label:
        print(f"  {label}: {result}")
    if out:
        text = out.decode("latin-1", errors="replace")
        if label:
            print(f"    text: {text[:80]!r}")
    return out, elapsed, result


# ── Phase 1: Omega Combinator as sys8 Argument ──────────────────────


def phase_1_omega_args():
    print("=" * 72)
    print("PHASE 1: Omega combinator components as sys8 argument")
    print("  A=λab.bb, B=λab.ab, ω=λx.xx from backdoor")
    print("=" * 72)

    # sys8(A) — the first backdoor component
    full_cps_syscall(g(8), A, "sys8(A)")
    time.sleep(0.3)

    # sys8(B) — the second backdoor component
    full_cps_syscall(g(8), B, "sys8(B)")
    time.sleep(0.3)

    # sys8(ω) — omega = λx.xx
    full_cps_syscall(g(8), OMEGA, "sys8(ω = λx.xx)")
    time.sleep(0.3)

    # sys8(pair(A,B)) — reconstruct the backdoor's output pair
    # pair = λx.λy.((x A) B) where A and B are the backdoor components
    # Actually the backdoor returns Left(pair), where pair = λsel. sel A B
    # So: pair = λsel. ((sel A) B)
    PAIR = lam("sel", apps(v("sel"), A, B))
    full_cps_syscall(g(8), PAIR, "sys8(pair(A,B))")
    time.sleep(0.3)

    # sys8 with the backdoor result directly chained
    # backdoor(nil, λresult. result(λpair. sys8(pair, cont), λerr. ...))
    print("\n  --- sys8 with backdoor output piped directly ---")
    term = apps(
        g(201),
        NIL,
        lam(
            "bd_result",
            apps(
                v("bd_result"),
                lam(
                    "pair",  # Left: got the pair from backdoor
                    apps(
                        g(8),
                        v("pair"),
                        lam(
                            "s8_result",
                            apps(
                                v("s8_result"),
                                lam("data", apps(g(2), v("data"), NIL)),
                                lam(
                                    "errcode",
                                    apps(
                                        g(1),
                                        v("errcode"),
                                        lam(
                                            "es",
                                            apps(
                                                v("es"),
                                                lam("str", apps(g(2), v("str"), NIL)),
                                                lam("_", write_str("?")),
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
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  backdoor→sys8(pair): {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.3)


# ── Phase 2: Environment Shadowing ───────────────────────────────────


def phase_2_env_shadowing():
    print("\n" + "=" * 72)
    print("PHASE 2: Environment shadowing — can we rebind g(8)?")
    print("  Wrap syscall in lambdas to shift indices")
    print("=" * 72)

    # Idea: In de Bruijn indexing, g(8) = Var(8 + depth).
    # If we wrap our code in 8 lambdas, then at depth 8, Var(8) would be
    # the outermost lambda parameter, NOT g(0).
    # But the VM binds globals BEFORE our code runs, so Var(n) for n >= depth
    # should still resolve to globals.

    # Let's verify: wrap code in N lambdas, then try to call "g(8)" which
    # is now Var(8+N). Does it still resolve to the real sys8?

    # Actually wait — if we DON'T supply arguments to those lambdas,
    # the lambdas never fire. We need to apply them.

    # Test: (λx. sys8(x)(cont))(nil) — x=nil, should be same as sys8(nil)
    # This is trivial. More interesting:

    # Test: what if we create a term that, after beta-reduction, has
    # Var(8) pointing to something WE control?
    # (λ.λ.λ.λ.λ.λ.λ.λ.λ. <body using Var(8)>) v0 v1 v2 v3 v4 v5 v6 v7 v8
    # where v8 is OUR function that returns Left(answer)

    # In body (depth 9): Var(8) = param at position 0 (outermost lambda)
    # But sys8 would be Var(8+9) = Var(17). So this doesn't help — the
    # VM resolves Var(17) as g(8).

    # UNLESS: the VM is buggy and resolves syscalls by a different mechanism!

    # Let's test: manually construct a term where byte 0x08 appears in
    # a context where it should resolve to a LOCAL binding, not g(8).
    # If the VM treats 0x08 as always meaning "syscall 8" regardless of
    # de Bruijn depth, that's a bug we could exploit.

    # Construct: (λ.λ.λ.λ.λ.λ.λ.λ.λ. (08 ?? FD QD FD)) arg0..arg8
    # At depth 9, byte 0x08 = Var(8) = the 8th lambda param (0-indexed from innermost)
    # If VM correctly handles de Bruijn: Var(8) = outermost param = what we provide
    # If VM treats byte 0x08 as g(8) always: PermDenied

    # We provide as the outermost arg: g(14) (echo), which always succeeds
    # If Var(8) resolves to g(14), we should see echo behavior.
    # If Var(8) resolves to g(8), we should see PermDenied.

    print("\n  --- Test: Does de Bruijn indexing work correctly for byte 0x08? ---")
    print("  (9 lambdas deep, Var(8) should be outermost param)")

    # Build manually: 9 lambdas wrapping (Var(8) nil QD)
    # At depth 9: Var(8) = outermost lambda param
    # QD as continuation
    qd = parse_term(QD + bytes([FF]))
    nil = Lam(Lam(Var(0)))

    inner = App(App(Var(8), nil), qd)  # Var(8)(nil)(QD)
    body = inner
    for _ in range(9):
        body = Lam(body)

    # Apply to 9 args: first 8 are nil, last (outermost param) is g(14)
    # Wait — args are applied left to right, outermost lambda gets FIRST arg
    # body = λ0.λ1.λ2.λ3.λ4.λ5.λ6.λ7.λ8. ...
    # (body arg0 arg1 ... arg8) → arg0 binds outermost (Var(8) in body)
    # Actually in de Bruijn: outermost lambda binds highest index
    # λ.λ.λ.λ.λ.λ.λ.λ.λ.body where body at depth 9:
    #   Var(0) = innermost lambda param (9th lambda, last applied arg)
    #   Var(8) = outermost lambda param (1st lambda, first applied arg)

    # So: first arg goes to Var(8), second to Var(7), etc.
    # We want Var(8) = echo = g(14).
    # So first arg = g(14), remaining 8 args = nil.

    term = body
    # Apply first arg: g(14) — goes to Var(8) (outermost lambda)
    term = App(term, Var(14))  # g(14) at depth 0
    # Apply 8 more nil args for remaining lambdas
    for _ in range(8):
        term = App(term, nil)

    payload = encode_term(term) + bytes([FF])
    out, elapsed = query_raw(payload, timeout_s=8.0)
    result = classify(out, elapsed)
    print(f"  9-lambda wrap, Var(8)=g(14) test: {result}")
    if out:
        text = out.decode("latin-1", errors="replace")
        print(f"    text: {text[:80]!r}")
        if FF in out:
            try:
                parsed = parse_term(out)
                tag, payload_data = decode_either(parsed)
                print(f"    decoded: {tag}(...)")
            except Exception as e:
                print(f"    parse: {e}")
    time.sleep(0.3)

    # Now the REVERSE test: same structure but Var(8) should be the real g(8)
    # Just call g(8) at depth 0 with nil and QD — this is our baseline
    baseline_term = App(App(Var(8), nil), qd)
    payload = encode_term(baseline_term) + bytes([FF])
    out, elapsed = query_raw(payload, timeout_s=8.0)
    result = classify(out, elapsed)
    print(f"  Baseline g(8)(nil)(QD) at depth 0: {result}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.3)


# ── Phase 3: Raw Byte Encoding Experiments ───────────────────────────


def phase_3_raw_encoding():
    print("\n" + "=" * 72)
    print("PHASE 3: Raw byte encoding experiments")
    print("  Testing alternative encodings that might trigger different behavior")
    print("=" * 72)

    qd = QD

    # What if the syscall dispatch doesn't use the de Bruijn index directly?
    # What if it uses the RAW BYTE from the encoding?

    # Test: send a term where sys8 is not Var(8) but constructed through
    # application/reduction to produce the same behavior.

    # E.g., (λx.x(nil)(QD))(Var(8)) — should reduce to Var(8)(nil)(QD)
    # Same result, but the byte 0x08 appears as an argument, not function position.

    print("\n  --- 3a: Indirect sys8 invocation via beta-reduction ---")

    nil = Lam(Lam(Var(0)))
    qd_term = parse_term(QD + bytes([FF]))

    # (λf. f nil QD) g(8)
    # body = App(App(Var(0), nil_shifted), qd_shifted)
    # At depth 1: Var(0) = param, nil needs shift, qd needs shift
    nil_s = shift_db(nil, 1)
    qd_s = shift_db(qd_term, 1)
    body = App(App(Var(0), nil_s), qd_s)
    indirect = App(Lam(body), Var(8))

    payload = encode_term(indirect) + bytes([FF])
    out, elapsed = query_raw(payload, timeout_s=8.0)
    result = classify(out, elapsed)
    print(f"  (λf.f(nil)(QD))(g(8)): {result}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.3)

    # Test: What about encoding Var(8) via Church numeral?
    # church_8 = λf.λx. f(f(f(f(f(f(f(f(x))))))))
    # Then: church_8 succ zero → 8
    # If we could convert this to a syscall call...
    # This probably won't work since syscall dispatch is by the evaluator, not terms.

    # More interesting: what if we use a DIFFERENT global that reduces to the
    # same behavior as sys8 but isn't permission-checked?

    # Test: Apply the backdoor omega to sys8
    print("\n  --- 3b: ω(g(8)) — omega applied to sys8 ---")
    # ω = λx.xx. So ω(g(8)) = g(8)(g(8)). sys8 applied to itself.
    # sys8(g(8)) with CPS pattern — g(8) as argument to sys8
    # This is: g(8)(g(8))(QD)
    term = App(App(Var(8), Var(8)), qd_term)
    payload = encode_term(term) + bytes([FF])
    out, elapsed = query_raw(payload, timeout_s=8.0)
    result = classify(out, elapsed)
    print(f"  g(8)(g(8))(QD) = ω(g(8))(QD): {result}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.3)

    # Test: g(8)(ω)(QD) — omega as argument to sys8
    omega = Lam(App(Var(0), Var(0)))
    term = App(App(Var(8), omega), qd_term)
    payload = encode_term(term) + bytes([FF])
    out, elapsed = query_raw(payload, timeout_s=8.0)
    result = classify(out, elapsed)
    print(f"  g(8)(ω)(QD): {result}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.3)

    # Test: g(8)(QD)(QD) — use QD as argument AND continuation
    print("\n  --- 3c: g(8)(QD)(QD) — QD as both arg and cont ---")
    term = App(App(Var(8), qd_term), qd_term)
    payload = encode_term(term) + bytes([FF])
    out, elapsed = query_raw(payload, timeout_s=8.0)
    result = classify(out, elapsed)
    print(f"  g(8)(QD)(QD): {result}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.3)


# ── Phase 4: Construct Call/CC-like Terms ────────────────────────────


def phase_4_callcc():
    print("\n" + "=" * 72)
    print("PHASE 4: Call/CC and continuation capture")
    print("  Can we capture the evaluator's internal continuation?")
    print("=" * 72)

    # In CPS lambda calculus, call/cc can be encoded as:
    # callcc = λf.λk. f (λx.λ_. k x) k
    # This gives f a "continuation" that, when called, aborts to k.

    # But our VM uses syscalls with CPS. What if we use the continuation
    # that sys8 passes to its internal handler?

    # Key idea: What if sys8's "permission denied" is checked in the
    # continuation, not in sys8 itself? If we supply a "fake" continuation
    # that bypasses the check...

    # Test: sys8(nil)(λx.x) — use identity as continuation
    # If PermDenied is in the continuation, identity might not trigger it
    print("\n  --- 4a: sys8 with identity continuation ---")
    full_cps_syscall(g(8), NIL, "sys8(nil) with full CPS")
    time.sleep(0.3)

    # Test: sys8(nil) without any continuation at all
    # Just send: g(8) nil FD FF → sys8(nil) = partial application
    # The result IS the partial application. If we QD that...
    print("\n  --- 4b: QD(sys8(nil)) — observe partial application ---")
    # QD(g(8)(nil))
    term = apps(g(8), NIL)  # partial application
    qd_observe = apps(term, QD_TERM)  # pass QD as the second arg (continuation)
    # Actually this is just sys8(nil)(QD) which is the standard pattern...

    # Let's try: quote(sys8(nil)(QD)) — quote the RESULT
    # Actually no: sys8(nil)(QD) would evaluate sys8 first, get PermDenied,
    # then QD would get Right(6).

    # Different approach: what if we DON'T apply the continuation immediately?
    # What if we wrap sys8 in a way that captures its partial application?

    # (λk. quote(k, ...)) (sys8(nil))
    # This should: evaluate sys8(nil) to a partial function, then quote it.
    # But sys8(nil) in CPS... does it return a value or does it invoke the cont?

    # Actually: g(8) IS a function of 2 args: g(8)(arg)(cont).
    # g(8)(nil) should be a partial application — a closure waiting for cont.
    # If the VM actually evaluates this lazily, g(8)(nil) is a value (closure).
    # We can then pass this value to quote.

    print("\n  --- 4c: quote(g(8)(nil)) — quote the partial application ---")
    term = apps(
        g(4),  # quote
        apps(g(8), NIL),  # sys8(nil) = partial application
        lam(
            "result",
            apps(
                v("result"),
                lam("bytes", apps(g(2), v("bytes"), NIL)),
                lam(
                    "errcode",
                    apps(
                        g(1),
                        v("errcode"),
                        lam(
                            "es",
                            apps(
                                v("es"),
                                lam("str", apps(g(2), v("str"), NIL)),
                                lam("_", write_str("QF")),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    result = classify(out, elapsed)
    print(f"  quote(sys8(nil)): {result}")
    if out:
        text = out.decode("latin-1", errors="replace")
        print(f"    text: {text[:80]!r}")
        if FF in out:
            print(f"    hex: {out[: out.index(FF) + 1].hex()}")
    time.sleep(0.3)

    # Test: quote(g(8)) — we know this returns 0x08. But what about:
    # echo(g(8)(nil)) — echo the partial application
    print("\n  --- 4d: echo(g(8)(nil)) — echo the partial application ---")
    term = apps(
        g(14),  # echo
        apps(g(8), NIL),  # sys8(nil) = partial
        lam(
            "result",
            apps(
                v("result"),
                lam(
                    "data",  # Left
                    apps(
                        g(4),
                        v("data"),  # quote the echo payload
                        lam(
                            "qr",
                            apps(
                                v("qr"),
                                lam("bytes", apps(g(2), v("bytes"), NIL)),
                                lam("_", write_str("QF")),
                            ),
                        ),
                    ),
                ),
                lam(
                    "errcode",  # Right
                    apps(
                        g(1),
                        v("errcode"),
                        lam(
                            "es",
                            apps(
                                v("es"),
                                lam("str", apps(g(2), v("str"), NIL)),
                                lam("_", write_str("?")),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    result = classify(out, elapsed)
    print(f"  echo(sys8(nil)): {result}")
    if out:
        text = out.decode("latin-1", errors="replace")
        print(f"    text: {text[:80]!r}")
        if FF in out:
            print(f"    hex: {out[: out.index(FF) + 1].hex()}")
    time.sleep(0.3)

    # CRUCIAL TEST: What if sys8's permission check happens at APPLICATION
    # time (when it receives its 2nd arg = continuation)?
    # What if sys8(nil) is just a closure, not yet checked?
    # Then: we need to AVOID giving it a standard continuation.

    # What if we apply sys8(nil) to ITSELF?
    # sys8(nil)(sys8(nil)) — recursive, might crash or reveal something
    print("\n  --- 4e: sys8(nil)(sys8(nil)) — self-feeding ---")
    s8nil = apps(g(8), NIL)
    term = apps(s8nil, s8nil)
    out, elapsed = query_named(term, timeout_s=8.0)
    result = classify(out, elapsed)
    print(f"  sys8(nil)(sys8(nil)): {result}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.3)


# ── Phase 5: Chaining Syscalls in Unusual Ways ──────────────────────


def phase_5_chaining():
    print("\n" + "=" * 72)
    print("PHASE 5: Unusual syscall chaining")
    print("  What if the 'kernel' is accessed by chaining syscalls?")
    print("=" * 72)

    # What if we need to use the backdoor result AS the continuation for sys8?
    # backdoor(nil, λres. res(λpair. sys8(nil, pair), ...))
    # Here pair is used as the continuation. pair = λsel. sel A B
    # sys8(nil)(pair) → pair(Right(6)) = Right(6)(A)(B) = A(6) = λb.bb (?)
    # Actually: Right(6) = λl.λr. r(6). Applied to pair's A and B...
    # pair(Right(6)) = (λsel. sel A B)(Right(6)) = Right(6) A B
    # = (λl.λr. r(6)) A B = B(6) = (λa.λb. a b)(6) = λb. 6 b
    # Hmm, 6 is an error code, not a function... but in lambda calculus
    # everything is a function.

    print("\n  --- 5a: Use backdoor pair components as sys8 continuation ---")

    # sys8(nil)(A)
    term_a = apps(g(8), NIL, A)
    out, elapsed = query_named(term_a, timeout_s=8.0)
    print(f"  sys8(nil)(A): {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.3)

    # sys8(nil)(B)
    term_b = apps(g(8), NIL, B)
    out, elapsed = query_named(term_b, timeout_s=8.0)
    print(f"  sys8(nil)(B): {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.3)

    # sys8(nil)(ω) — omega as continuation
    term_w = apps(g(8), NIL, OMEGA)
    out, elapsed = query_named(term_w, timeout_s=8.0)
    print(f"  sys8(nil)(ω): {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.3)

    # What if we chain: readfile → use content as sys8 arg?
    # readfile(65) returns gizmore's .history which has "ilikephp"
    # sys8("ilikephp") as string
    print("\n  --- 5b: sys8 with gizmore password as byte-list arg ---")
    pw_bytes = NConst(encode_bytes_list(b"ilikephp"))
    full_cps_syscall(g(8), pw_bytes, "sys8('ilikephp')")
    time.sleep(0.3)

    # sys8 with the integer 8
    full_cps_syscall(g(8), int_term(8), "sys8(int(8))")
    time.sleep(0.3)

    # sys8 with the integer 201 (backdoor syscall number)
    full_cps_syscall(g(8), int_term(201), "sys8(int(201))")
    time.sleep(0.3)


# ── Phase 6: What if "the kernel" is g(0) (exception handler)? ──────


def phase_6_exception_kernel():
    print("\n" + "=" * 72)
    print("PHASE 6: Exception handler as 'kernel'?")
    print("  g(0) swallows everything. What if it's the kernel entry point?")
    print("=" * 72)

    # g(0) is the exception handler — it takes anything and produces no output.
    # What if passing specific args to g(0) triggers kernel behavior?

    # Test: g(0)(g(8)) — exception handler called with sys8
    print("\n  --- 6a: g(0) applied to various things ---")

    tests = [
        (apps(g(0), g(8)), "g(0)(g(8))"),
        (apps(g(0), g(8), NIL), "g(0)(g(8))(nil)"),
        (apps(g(0), g(8), NIL, QD_TERM), "g(0)(g(8))(nil)(QD)"),
        (apps(g(0), OMEGA), "g(0)(ω)"),
        (apps(g(0), g(201)), "g(0)(backdoor)"),
    ]

    for term, name in tests:
        out, elapsed = query_named(term, timeout_s=6.0)
        result = classify(out, elapsed)
        if "EMPTY" not in result and "TIMEOUT" not in result:
            print(f"  {name}: {result}")
            if out:
                print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
        time.sleep(0.25)

    # What if we use exception handler AS the argument to sys8?
    print("\n  --- 6b: sys8(g(0))(QD) ---")
    term = apps(g(8), g(0), QD_TERM)
    out, elapsed = query_named(term, timeout_s=6.0)
    print(f"  sys8(g(0))(QD): {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.3)


# ── Phase 7: What if the answer involves the ENCODING itself? ────────


def phase_7_encoding_meta():
    print("\n" + "=" * 72)
    print("PHASE 7: Meta-encoding experiments")
    print("  What if the 'kernel' is triggered by specific byte patterns?")
    print("=" * 72)

    # The cheat sheet says:
    # BrownOS[<syscall> <argument> FD <rest> FD] -> BrownOS[<rest> <result> FD]
    #
    # What if there's a DIFFERENT pattern the evaluator recognizes?
    # What if sending bytes that DON'T form a valid term trigger kernel mode?

    # Test: Send just 0x08 0xFF (Var(8) + end)
    print("\n  --- 7a: Minimal terms ---")

    tests_raw = [
        (bytes([0x08, FF]), "just Var(8)"),
        (bytes([0x08, 0x08, FD, FF]), "App(Var(8), Var(8))"),
        (bytes([0x08, FE, FF]), "Lam(Var(8))"),
        (bytes([0x08, FE, 0x00, FD, FF]), "App(Lam(Var(8)), Var(0))"),
        # What about: nested applications with only 0x08?
        (bytes([0x08, 0x08, FD, 0x08, FD, FF]), "App(App(Var(8),Var(8)),Var(8))"),
    ]

    for payload, name in tests_raw:
        out, elapsed = query_raw(payload, timeout_s=6.0)
        result = classify(out, elapsed)
        if "EMPTY" not in result or elapsed > 1.0:
            print(f"  {name}: {result} ({elapsed:.1f}s)")
            if out:
                print(f"    text: {out.decode('latin-1', errors='replace')[:60]!r}")
        time.sleep(0.25)

    # Test: What about sending FD FE FF patterns that are not standard?
    # "Double application" — App encoded differently
    print("\n  --- 7b: What if we send multiple FFs? ---")
    # term1 FF term2 FF — two terms?
    nil = Lam(Lam(Var(0)))
    qd = parse_term(QD + bytes([FF]))

    # First term: sys8(nil)(QD), second term: echo(nil)(QD)
    term1 = encode_term(App(App(Var(8), nil), qd))
    term2 = encode_term(App(App(Var(14), nil), qd))

    payload = term1 + bytes([FF]) + term2 + bytes([FF])
    out, elapsed = query_raw(payload, timeout_s=6.0)
    print(f"  Two terms with two FFs: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.3)


# ── Phase 8: CPS with multiple continuations ────────────────────────


def phase_8_multi_cont():
    print("\n" + "=" * 72)
    print("PHASE 8: sys8 with 3+ arguments (extra continuations)")
    print("  What if sys8 takes MORE args than we think?")
    print("=" * 72)

    # Standard: sys8(arg)(cont) → cont(result)
    # What if sys8 actually takes 3 args? sys8(arg)(auth)(cont)?
    # The third arg could be an authentication token.

    # Test: sys8(nil)(something)(QD)

    auth_candidates = [
        (NIL, "nil"),
        (g(201), "g(201)"),
        (A, "A (backdoor comp)"),
        (B, "B (backdoor comp)"),
        (OMEGA, "ω"),
        (g(0), "g(0) (exception)"),
        (g(4), "g(4) (quote)"),
        (I, "identity"),
        (int_term(42), "int(42)"),
    ]

    for auth, auth_name in auth_candidates:
        term = apps(g(8), NIL, auth, QD_TERM)
        out, elapsed = query_named(term, timeout_s=6.0)
        result = classify(out, elapsed)
        # Skip boring PermDenied (means sys8 consumed 2 args, returned Right(6),
        # and Right(6)(auth)(QD) = auth(6)(QD) or similar)
        print(f"  sys8(nil)({auth_name})(QD): {result}")
        if out:
            text = out.decode("latin-1", errors="replace")
            if text.strip() and "Permission denied" not in text:
                print(f"    text: {text[:80]!r}")
        time.sleep(0.25)


# ── Main ─────────────────────────────────────────────────────────────


def main():
    print("=" * 72)
    print("probe_oracle15_kernel.py — Kernel hypothesis testing")
    print(f"  Target: {HOST}:{PORT}")
    print("=" * 72)

    phase_1_omega_args()
    phase_2_env_shadowing()
    phase_3_raw_encoding()
    phase_4_callcc()
    phase_5_chaining()
    phase_6_exception_kernel()
    phase_7_encoding_meta()
    phase_8_multi_cont()

    print("\n" + "=" * 72)
    print("All phases complete.")
    print("=" * 72)


if __name__ == "__main__":
    main()
