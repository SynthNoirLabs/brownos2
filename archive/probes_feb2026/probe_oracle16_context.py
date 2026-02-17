#!/usr/bin/env python3
"""
probe_oracle16_context.py — Test sys8 with varied CONTEXT (not argument).

Oracle #16 hypotheses:
1. Privileged continuation — use backdoor pair as continuation for sys8
2. Side-effect handshake — run towel/backdoor INSIDE arg evaluation
3. Capability token — extract backdoor result, feed to sys8
4. Quoted code key — pass AST bytes as argument
5. Out-of-range literal — integers > 255

NEW INSIGHT: We've always varied the ARGUMENT but always used QD as continuation.
The cheat sheet second example "?? ?? FD QD FD" — maybe the CONTINUATION matters.
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
QD_TERM = NConst(parse_term(QD + bytes([FF])))

# Scott-encoded booleans / pairs
TRUE = lam("t", lam("f", v("t")))  # K combinator
FALSE = lam("t", lam("f", v("f")))  # KI combinator


# Left x = λl.λr. l(x)
def scott_left(x):
    return lam("l", lam("r", app(v("l"), x)))


# Right x = λl.λr. r(x)
def scott_right(x):
    return lam("l", lam("r", app(v("r"), x)))


def int_term(n):
    return NConst(encode_byte_term(n))


def write_str(s):
    return apps(g(2), NConst(encode_bytes_list(s.encode("latin-1"))), NIL)


# Backdoor components (known from reverse engineering)
# A = λa.λb.(b b)
A_DB = Lam(Lam(App(Var(0), Var(0))))
A = NConst(A_DB)
# B = λa.λb.(a b)
B_DB = Lam(Lam(App(Var(1), Var(0))))
B = NConst(B_DB)
# omega = λx.(x x)
OMEGA_DB = Lam(App(Var(0), Var(0)))
OMEGA = NConst(OMEGA_DB)
# pair = λsel. sel(A)(B)
PAIR = lam("sel", apps(v("sel"), A, B))


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


def query_named(term, timeout_s=8.0):
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


def query_raw(payload, timeout_s=8.0):
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
    if "Encoding failed" in text:
        return "ENC_FAIL"
    return f"DATA:{text[:80]!r}"


# ── Phase 1: Continuation Variation ──────────────────────────────────
# We've ALWAYS used QD as the continuation. What if it matters?


def phase_1_continuation_variation():
    print("=" * 72)
    print("PHASE 1: Vary the CONTINUATION of sys8 (not the argument)")
    print("  We've always used QD. What if the continuation matters?")
    print("=" * 72)

    # 1a: sys8(nil) with identity as continuation
    # g(8)(nil)(λx.x) — if sys8 returns Left(flag), I returns it
    print("\n  --- 1a: sys8(nil)(I) — identity continuation ---")
    term = apps(g(8), NIL, I)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    hex: {out.hex()}")
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 1b: sys8(nil) with backdoor pair as continuation
    # The pair(A,B) when applied as continuation:
    # Right(6)(pair) = pair(6) = (λsel. sel A B)(6) = 6 A B
    # Left(x)(pair)  = pair(x) = (λsel. sel A B)(x) = x A B
    print("\n  --- 1b: sys8(nil)(pair(A,B)) — backdoor pair as continuation ---")
    term = apps(g(8), NIL, PAIR)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    hex: {out.hex()}")
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 1c: sys8(nil) with A (λa.λb.(bb)) as continuation
    print("\n  --- 1c: sys8(nil)(A = λa.λb.bb) ---")
    term = apps(g(8), NIL, A)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    hex: {out.hex()}")
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 1d: sys8(nil) with B (λa.λb.(ab)) as continuation
    print("\n  --- 1d: sys8(nil)(B = λa.λb.ab) ---")
    term = apps(g(8), NIL, B)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    hex: {out.hex()}")
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 1e: sys8(nil) with omega as continuation (might diverge!)
    print("\n  --- 1e: sys8(nil)(ω = λx.xx) — might diverge ---")
    term = apps(g(8), NIL, OMEGA)
    out, elapsed = query_named(term, timeout_s=6.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    hex: {out.hex()}")
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 1f: sys8(nil) with K as continuation → K(Right(6)) = λy.Right(6)
    # Then we can apply QD to that
    print("\n  --- 1f: sys8(nil)(K)(QD) — K captures, then QD observes ---")
    K = lam("x", lam("y", v("x")))
    term = apps(g(8), NIL, K, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    hex: {out[:40].hex()}")
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 1g: sys8(nil) with write directly as continuation
    # write takes 2 args: bytes and cont. So write(Right(6)) = partially applied
    print("\n  --- 1g: sys8(nil)(write) — write as direct continuation ---")
    term = apps(g(8), NIL, g(2))
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    hex: {out[:40].hex()}")
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 1h: sys8(nil) with echo as continuation
    print("\n  --- 1h: sys8(nil)(echo) — echo as direct continuation ---")
    term = apps(g(8), NIL, g(14))
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    hex: {out[:40].hex()}")
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 1i: sys8(nil) with another syscall as continuation
    # sys8(nil)(quote)(QD) — quote the result, then QD observes
    print("\n  --- 1i: sys8(nil)(quote)(QD) — quote as continuation ---")
    term = apps(g(8), NIL, g(4), QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    hex: {out[:40].hex()}")
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 1j: What if continuation must be a specific global?
    # Try ALL globals as continuations
    print("\n  --- 1j: sys8(nil)(g(N)) for key globals ---")
    for gid in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 14, 42, 201]:
        term = apps(g(8), NIL, g(gid))
        out, elapsed = query_named(term, timeout_s=6.0)
        result = classify(out, elapsed)
        print(f"  sys8(nil)(g({gid})): {result}")
        if out and "Permission denied" not in out.decode("latin-1", errors="replace"):
            print(f"    text: {out.decode('latin-1', errors='replace')[:60]!r}")
        time.sleep(0.2)


# ── Phase 2: Side-effect handshake ───────────────────────────────────
# Run another syscall INSIDE the evaluation of sys8's argument


def phase_2_sideeffect():
    print("\n" + "=" * 72)
    print("PHASE 2: Side-effect handshake")
    print("  Run another syscall inside sys8's argument evaluation")
    print("  If eval order matters for permission, this should reveal it")
    print("=" * 72)

    # 2a: arg = (λ_.nil)(towel(nil))
    # Evaluate towel(nil) first (side effect), then discard result, pass nil
    print("\n  --- 2a: sys8((λ_.nil)(g(42)(nil)))(QD) — towel handshake ---")
    # In CBN, the arg to the lambda is NOT evaluated. But sys8 FORCES evaluation
    # of its arg. So we need to make the side-effect happen during forced eval.
    # Actually: sys8 forces eval of arg → arg is App(λ_.nil, App(g(42), nil))
    # Forcing evaluation: reduce App(λ_.nil, ...) → nil (CBN substitutes thunk)
    # BUT: λ_.nil discards the arg, so g(42)(nil) is NEVER evaluated!
    # We need a STRICT binder: (λx. x `seq` nil)
    # Or better: (λx. g(42)(nil)(λ_. nil)) — use CPS to force it
    print("  (Skipping naive attempt — CBN won't force the inner call)")

    # 2a-actual: Use CPS to force towel before producing nil
    # towel(nil)(λresult. nil)
    # This forces towel(nil) to be called, result goes to λresult.nil
    print("\n  --- 2a: g(42)(nil)(λ_.nil) then feed to sys8 ---")
    # This produces: first call towel(nil), get result, then return nil
    forced_towel = apps(g(42), NIL, lam("_towelresult", NIL))
    term = apps(g(8), forced_towel, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 2b: backdoor(nil)(λresult. result(λpair. sys8(pair)(QD))(λerr. write("BD_ERR", nil)))
    # First call backdoor, get Left(pair), extract pair, THEN call sys8 with pair
    print("\n  --- 2b: backdoor(nil) → extract pair → sys8(pair)(QD) ---")
    term = apps(
        g(201),
        NIL,
        lam(
            "bd_result",
            apps(
                v("bd_result"),
                lam(
                    "pair",  # Left handler → got the pair
                    apps(g(8), v("pair"), QD_TERM),
                ),
                lam(
                    "err",  # Right handler
                    write_str("BD_ERR"),
                ),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 2c: backdoor(nil) → extract pair → call pair(K) to get A → sys8(A)(QD)
    print("\n  --- 2c: backdoor → pair(K) → get A → sys8(A)(QD) ---")
    K = lam("x", lam("y", v("x")))
    term = apps(
        g(201),
        NIL,
        lam(
            "bd_result",
            apps(
                v("bd_result"),
                lam(
                    "pair",
                    apps(
                        g(8),
                        apps(v("pair"), K),  # pair(K) = K(A)(B) = A
                        QD_TERM,
                    ),
                ),
                lam("err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 2d: backdoor(nil) → extract pair → use pair as CONTINUATION for sys8
    print("\n  --- 2d: backdoor → pair → sys8(nil)(pair) ---")
    term = apps(
        g(201),
        NIL,
        lam(
            "bd_result",
            apps(
                v("bd_result"),
                lam("pair", apps(g(8), NIL, v("pair"))),
                lam("err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    hex: {out.hex()}")
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 2e: Chain: towel(nil)(λ_. backdoor(nil)(λbd. bd(λp. sys8(p)(QD), λe. ...)))
    print("\n  --- 2e: towel → backdoor → sys8(pair)(QD) full chain ---")
    term = apps(
        g(42),
        NIL,
        lam(
            "_towel",
            apps(
                g(201),
                NIL,
                lam(
                    "bd_result",
                    apps(
                        v("bd_result"),
                        lam("pair", apps(g(8), v("pair"), QD_TERM)),
                        lam("err", write_str("CHAIN_ERR")),
                    ),
                ),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 2f: What if sys8 needs to be called with backdoor result as BOTH arg AND cont?
    print("\n  --- 2f: backdoor → sys8(pair)(pair) ---")
    term = apps(
        g(201),
        NIL,
        lam(
            "bd_result",
            apps(
                v("bd_result"),
                lam("pair", apps(g(8), v("pair"), v("pair"))),
                lam("err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    hex: {out.hex()}")
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)


# ── Phase 3: Capability token (Left wrapper) ─────────────────────────


def phase_3_capability():
    print("\n" + "=" * 72)
    print("PHASE 3: Pass Left-wrapped and Right-wrapped values to sys8")
    print("  Maybe sys8 expects a specific Either wrapper")
    print("=" * 72)

    # 3a: sys8(Left(nil))
    print("\n  --- 3a: sys8(Left(nil))(QD) ---")
    term = apps(g(8), scott_left(NIL), QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 3b: sys8(Right(nil))
    print("\n  --- 3b: sys8(Right(nil))(QD) ---")
    term = apps(g(8), scott_right(NIL), QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 3c: sys8(Left(pair)) — backdoor-like token
    print("\n  --- 3c: sys8(Left(pair(A,B)))(QD) ---")
    term = apps(g(8), scott_left(PAIR), QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 3d: sys8 with the entire backdoor result (Left(pair)) obtained via live call
    # Different from 2b: here we pass the WHOLE Either (Left(pair)), not unwrapped pair
    print("\n  --- 3d: backdoor(nil) → sys8(ENTIRE_EITHER_RESULT)(QD) ---")
    term = apps(g(201), NIL, lam("bd_either", apps(g(8), v("bd_either"), QD_TERM)))
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)


# ── Phase 4: Wire-level experiments ──────────────────────────────────


def phase_4_wire_level():
    print("\n" + "=" * 72)
    print("PHASE 4: Wire-level experiments")
    print("  The cheat sheet says ?? ?? FD QD FD")
    print("  What if we manipulate the FD structure differently?")
    print("=" * 72)

    # Standard: 08 <arg> FD <cont> FD FF
    # = App(cont, App(g(8), arg))

    # 4a: What about 08 FD — sys8 applied to NOTHING before it?
    # This would try to pop two things from the stack but only 08 is there...
    # Actually: stack-based, so we need TWO things before FD.
    # 08 08 FD = App(g(8), g(8)) = sys8(sys8)
    print("\n  --- 4a: sys8(sys8)(QD) — sys8 applied to itself ---")
    payload = bytes([0x08, 0x08, FD]) + QD + bytes([FD, FF])
    out, elapsed = query_raw(payload, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 4b: Three-level: 08 00 FD 08 00 FD QD FD
    # = sys8(nil) → result1, then sys8(nil) → result2, then QD(result2)
    # Wait, that's: App(QD, App(App(g(8), nil), App(g(8), nil)))
    # Actually let me trace the stack:
    # 08 → [g(8)]
    # 00 → [g(8), nil(=Var(0))]   wait, Var(0) is NOT nil. nil is Lam(Lam(Var(0)))
    # Hmm, in the wire format, 00 = Var(0) which is g(0) = exception at top level
    # Let me use proper nil encoding
    nil_enc = encode_term(NIL_DB)  # FE FE 00

    # Proper: syscall(arg) then syscall(arg) then QD continuation
    # Two sys8 calls chained: sys8(nil)(λr1. sys8(nil)(QD))
    print("\n  --- 4b: sys8(nil)(λr1. sys8(nil)(QD)) — two sys8 calls chained ---")
    term = apps(g(8), NIL, lam("r1", apps(g(8), NIL, QD_TERM)))
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 4c: Use raw bytes to construct unusual terms
    # What about putting sys8 in an unusual position?
    # Lam(App(Var(9), Var(0)))(nil)(QD)
    # = (λx. g(8)(x))(nil)(QD) — inline sys8 call within lambda
    print("\n  --- 4c: (λx.g(8)(x))(nil)(QD) — sys8 inside lambda ---")
    term = apps(lam("x", apps(g(8), v("x"))), NIL, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 4d: What if we build the term differently at the wire level?
    # Normally: 08 <nil> FD <QD> FD FF
    # What about: <nil> 08 FD <QD> FD FF
    # Stack: nil, g(8) → FD → App(g(8), nil) — SAME THING due to postfix!
    # Wait no: FD pops x then f: x=g(8), f=nil → App(nil, g(8)) — DIFFERENT!
    print("\n  --- 4d: App(nil, g(8))(QD) — nil applied to g(8) ---")
    payload = nil_enc + bytes([0x08, FD]) + QD + bytes([FD, FF])
    out, elapsed = query_raw(payload, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 4e: What about encoding sys8 as something other than Var(8)?
    # Can we reach g(8) through a different encoding path?
    # g(8) under 1 lambda is Var(9). So: (λx. Var(9)(nil)(QD))(anything)
    # = g(8)(nil)(QD) — same thing, but different wire encoding
    print("\n  --- 4e: (λ_.g(8)(nil)(QD))(nil) — g(8) via shifted index ---")
    term = apps(lam("_", apps(g(8), NIL, QD_TERM)), NIL)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)


# ── Phase 5: Large integers and exotic values ────────────────────────


def phase_5_exotic():
    print("\n" + "=" * 72)
    print("PHASE 5: Exotic arguments — large integers, special encodings")
    print("=" * 72)

    # The encode_byte_term function creates a 9-lambda encoding for 0-255.
    # For integers > 255, we'd need multi-byte encoding.
    # But actually, the cheat sheet says "IDs only 0-255 is False — encoding is additive"
    # This means encode_byte_term(256) should work by adding bit 9 (256).
    # BUT our encoder only goes up to 8 bits. Let's extend it.

    # Actually: let's just test with the standard encoder for values 0-255
    # that we haven't tried with NAMED terms (through the named-term pipeline)

    # 5a: sys8 with True (K combinator λt.λf.t) — different from identity
    print("\n  --- 5a: sys8(True = λt.λf.t)(QD) ---")
    term = apps(g(8), TRUE, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 5b: sys8 with False (KI = λt.λf.f) — same as nil!
    print("\n  --- 5b: sys8(False = λt.λf.f)(QD) ---")
    term = apps(g(8), FALSE, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 5c: sys8 with Church numeral 0 = λf.λx.x (same as False/nil)
    # Church numeral 1 = λf.λx.f(x)
    print("\n  --- 5c: sys8(Church 1 = λf.λx.f(x))(QD) ---")
    church1 = lam("f", lam("x", app(v("f"), v("x"))))
    term = apps(g(8), church1, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 5d: sys8 with the string "solution"
    print("\n  --- 5d: sys8('solution')(QD) ---")
    solution_bytes = NConst(encode_bytes_list(b"solution"))
    term = apps(g(8), solution_bytes, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 5e: sys8 with the string "root"
    print("\n  --- 5e: sys8('root')(QD) ---")
    root_bytes = NConst(encode_bytes_list(b"root"))
    term = apps(g(8), root_bytes, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 5f: sys8 with exception (g(0))
    # This is interesting — g(0) IS exception, what happens when you pass
    # a global as argument? In CBN it would be unevaluated... but syscalls force eval
    print("\n  --- 5f: sys8(g(0))(QD) — exception as argument ---")
    term = apps(g(8), g(0), QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 5g: sys8 with each OTHER global as argument
    print("\n  --- 5g: sys8(g(N))(QD) for various globals ---")
    for gid in [1, 2, 4, 5, 6, 7, 14, 42, 201]:
        term = apps(g(8), g(gid), QD_TERM)
        out, elapsed = query_named(term, timeout_s=6.0)
        result = classify(out, elapsed)
        if "PERM_DENIED" not in result:
            print(f"  sys8(g({gid})): {result}")
            if out:
                print(f"    text: {out.decode('latin-1', errors='replace')[:60]!r}")
        time.sleep(0.15)
    print("  (all tested — non-PermDenied shown above)")
    time.sleep(0.2)

    # 5h: sys8 with SELF (sys8 itself) as argument
    print("\n  --- 5h: sys8(g(8))(QD) — self as argument ---")
    term = apps(g(8), g(8), QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)


# ── Phase 6: "sudo" concept — /bin/sudo is file 15 ──────────────────


def phase_6_sudo():
    print("\n" + "=" * 72)
    print("PHASE 6: sudo exploration")
    print("  /bin/sudo exists (file 15). What if it's relevant?")
    print("  readfile(15) returned empty, but maybe it's callable?")
    print("=" * 72)

    # The filesystem has /bin/sudo (id 15) and /bin/sh (id 14).
    # readfile(15) returned empty content. But what if the FILE ID
    # is used as a capability token?

    # 6a: sys8(int(15))(QD) — "sudo" file ID
    print("\n  --- 6a: sys8(int(15))(QD) — sudo file ID ---")
    term = apps(g(8), int_term(15), QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 6b: What if we read sudo's content and pass it to sys8?
    # readfile(15)(λresult. result(λdata. sys8(data)(QD), λerr. write_err))
    print("\n  --- 6b: readfile(15) → sys8(content)(QD) ---")
    term = apps(
        g(7),
        int_term(15),
        lam(
            "rf_result",
            apps(
                v("rf_result"),
                lam("data", apps(g(8), v("data"), QD_TERM)),
                lam("err", write_str("SUDO_READ_ERR")),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # 6c: What about chaining: name(15)(λ_.sys8(nil)(QD)) — does asking about sudo change state?
    print("\n  --- 6c: name(15)(λname. sys8(name)(QD)) — name of sudo as arg ---")
    term = apps(
        g(6),
        int_term(15),
        lam(
            "name_result",
            apps(
                v("name_result"),
                lam("name_data", apps(g(8), v("name_data"), QD_TERM)),
                lam("err", write_str("NAME_ERR")),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)


# ── Main ─────────────────────────────────────────────────────────────


def main():
    print("=" * 72)
    print("probe_oracle16_context.py — Context variation tests")
    print(f"  Target: {HOST}:{PORT}")
    print("=" * 72)

    phase_1_continuation_variation()
    phase_2_sideeffect()
    phase_3_capability()
    phase_4_wire_level()
    phase_5_exotic()
    phase_6_sudo()

    print("\n" + "=" * 72)
    print("All phases complete.")
    print("=" * 72)


if __name__ == "__main__":
    main()
