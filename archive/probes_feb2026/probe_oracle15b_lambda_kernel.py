#!/usr/bin/env python3
"""
probe_oracle15b_lambda_kernel.py — Test sys8 with lambda probes.

TWO KEY HYPOTHESES:
1. Oracle's idea: sys8 is a loader. Pass λ-term code, it runs in kernel mode.
   The lambda receives capabilities from the kernel.
2. Our discovery: quote is a special form (receives unevaluated args).
   Maybe sys8 also checks the SYNTACTIC structure of its argument.

ALSO: Deeper investigation of quote's special-form nature.
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
    if FF in raw:
        return f"QD:{raw[:30].hex()}"
    return f"DATA:{text[:60]!r}"


# ── Phase 1: Lambda probes for sys8 ─────────────────────────────────


def phase_1_lambda_probes():
    print("=" * 72)
    print("PHASE 1: Pass various λ-terms to sys8 as argument")
    print("  Testing if sys8 is a loader that executes lambda code")
    print("=" * 72)

    # Probe 1: λx. echo(x)(QD)
    # If sys8 is a loader, it calls our lambda with some parameter.
    # echo(x) would return Left(x), QD would quote and write it.
    print("\n  --- 1a: sys8(λx. echo(x)(QD)) ---")
    probe_a = lam("x", apps(g(14), v("x"), QD_TERM))
    term = apps(g(8), probe_a, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        text = out.decode("latin-1", errors="replace")
        print(f"    text: {text[:80]!r}")
        if FF in out:
            print(f"    hex: {out[: out.index(FF) + 1].hex()}")
    time.sleep(0.35)

    # Probe 2: λx. write("GOT_X", nil)
    # If sys8 calls our lambda, we should see "GOT_X"
    print("\n  --- 1b: sys8(λx. write('GOT_X', nil)) ---")
    probe_b = lam("x", write_str("GOT_X"))
    term = apps(g(8), probe_b, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # Probe 3: λx.λy. write("GOT_XY", nil)
    # Maybe sys8 provides TWO arguments to the lambda
    print("\n  --- 1c: sys8(λx.λy. write('GOT_XY', nil)) ---")
    probe_c = lam("x", lam("y", write_str("GOT_XY")))
    term = apps(g(8), probe_c, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # Probe 4: λx.λy.λz. write("GOT_XYZ", nil)
    print("\n  --- 1d: sys8(λx.λy.λz. write('GOT_XYZ', nil)) ---")
    probe_d = lam("x", lam("y", lam("z", write_str("GOT_XYZ"))))
    term = apps(g(8), probe_d, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # Probe 5: identity (λx.x)
    # sys8(I)(QD) — if sys8 calls I with a token, I returns the token,
    # then QD observes it
    print("\n  --- 1e: sys8(λx.x)(QD) — identity ---")
    term = apps(g(8), I, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        text = out.decode("latin-1", errors="replace")
        print(f"    text: {text[:80]!r}")
        if FF in out:
            print(f"    hex: {out[: out.index(FF) + 1].hex()}")
    time.sleep(0.35)

    # Probe 6: K combinator — λx.λy.x
    print("\n  --- 1f: sys8(K = λx.λy.x)(QD) ---")
    K = lam("x", lam("y", v("x")))
    term = apps(g(8), K, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        text = out.decode("latin-1", errors="replace")
        print(f"    text: {text[:80]!r}")
        if FF in out:
            print(f"    hex: {out[: out.index(FF) + 1].hex()}")
    time.sleep(0.35)


# ── Phase 2: Quote special-form investigation ────────────────────────


def phase_2_quote_special_form():
    print("\n" + "=" * 72)
    print("PHASE 2: Quote's special-form nature — deeper investigation")
    print("  CONFIRMED: quote receives UNEVALUATED args (lazy/special)")
    print("  Question: do OTHER syscalls also get unevaluated args?")
    print("=" * 72)

    # We know:
    # quote(I(nil)) = App(I, nil) — NOT nil (unevaluated)
    # quote(echo(nil)) = App(echo, nil) — unevaluated
    # quote(g(8)(nil)) = App(g(8), nil) — unevaluated
    # quote(nil) = nil — trivially already a value

    # Key question: is it QUOTE that's special, or is the evaluator
    # call-by-name globally?

    # Test: echo(I(nil)) — does echo evaluate its argument?
    # If CBN: echo receives App(I, nil) → returns Left(App(I, nil))
    # If CBV: echo receives nil → returns Left(nil)

    print("\n  --- 2a: echo(I(nil)) — does echo evaluate its arg? ---")
    term = apps(
        g(14),  # echo
        apps(I, NIL),  # I(nil) — should reduce to nil in CBV
        lam(
            "result",
            apps(
                v("result"),
                lam(
                    "data",  # Left handler
                    apps(
                        g(4),
                        v("data"),  # quote the result
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
                lam("_err", write_str("ECHO_ERR")),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        text = out.decode("latin-1", errors="replace")
        print(f"    text: {text[:80]!r}")
        if FF in out and b"QF" not in out and b"ECHO_ERR" not in out:
            try:
                # Parse the first QD-terminated sequence
                idx = out.index(FF)
                raw = out[:idx]
                print(f"    hex: {raw.hex()}")
            except:
                pass
    time.sleep(0.35)

    # Test: write(I("hello"), nil) — does write evaluate its arg?
    print("\n  --- 2b: write(I(hello_bytes), nil) — does write evaluate? ---")
    hello_bytes = NConst(encode_bytes_list(b"HELLO"))
    term = apps(g(2), apps(I, hello_bytes), NIL)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # Test: readfile(I(int(11))) — does readfile evaluate arg?
    print("\n  --- 2c: readfile(I(int(11))) — does readfile evaluate? ---")
    term = apps(
        g(7),  # readfile
        apps(I, int_term(11)),  # I(11) — should be 11 in CBV
        lam(
            "result",
            apps(
                v("result"),
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
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        text = out.decode("latin-1", errors="replace")
        print(f"    text: {text[:80]!r}")
    time.sleep(0.35)

    # CRITICAL: sys8(I(nil)) — does sys8 evaluate its arg?
    # If sys8 gets unevaluated App(I, nil) instead of nil, maybe it
    # handles lambdas differently!
    print("\n  --- 2d: sys8(I(nil)) — does sys8 evaluate? ---")
    term = apps(
        g(8),
        apps(I, NIL),  # I(nil) = nil after eval, or App(I, nil) if lazy
        QD_TERM,
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        text = out.decode("latin-1", errors="replace")
        print(f"    text: {text[:80]!r}")
        if FF in out:
            print(f"    hex: {out[: out.index(FF) + 1].hex()}")
    time.sleep(0.35)


# ── Phase 3: Evaluation semantics probes ─────────────────────────────


def phase_3_eval_semantics():
    print("\n" + "=" * 72)
    print("PHASE 3: Evaluation semantics — CBV vs CBN vs lazy")
    print("  Determine if the whole VM is lazy or just quote is special")
    print("=" * 72)

    # If the VM is call-by-name (lazy), then ALL syscalls get unevaluated args.
    # This would mean that sys8's PermDenied might depend on the SHAPE
    # of the unevaluated argument, not its VALUE.

    # Test: (λx. quote(x)(QD)) (I(nil))
    # In CBV: x=nil, quote(nil)=bytes for nil
    # In CBN: x=I(nil) (thunk), quote(I(nil))=bytes for App(I,nil)
    print("\n  --- 3a: (λx. quote(x)(QD))(I(nil)) — CBV vs CBN ---")
    term = apps(
        lam("x", apps(g(4), v("x"), QD_TERM)),
        apps(I, NIL),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out and FF in out:
        parsed = parse_term(out)
        try:
            tag, payload = decode_either(parsed)
            if tag == "Left":
                blist = decode_bytes_list(payload)
                inner = parse_term(blist + bytes([FF]))
                print(f"    quoted: {inner}")
                if isinstance(inner, App):
                    print("    → CBN (received unevaluated App)")
                elif isinstance(inner, Lam):
                    print("    → CBV (received evaluated nil)")
        except Exception as e:
            print(f"    parse error: {e}")
    time.sleep(0.35)

    # Test with a more obvious reduction:
    # (λx. quote(x)(QD)) ((λa.a)(λb.b))
    # CBV: x = λb.b (identity), quote returns identity bytes
    # CBN: x = App(λa.a, λb.b), quote returns app bytes
    print("\n  --- 3b: (λx. quote(x)(QD))((λa.a)(λb.b)) ---")
    term = apps(
        lam("x", apps(g(4), v("x"), QD_TERM)),
        apps(I, I),  # (λx.x)(λx.x) → λx.x in CBV
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out and FF in out:
        parsed = parse_term(out)
        try:
            tag, payload = decode_either(parsed)
            if tag == "Left":
                blist = decode_bytes_list(payload)
                inner = parse_term(blist + bytes([FF]))
                print(f"    quoted: {inner}")
                if isinstance(inner, App):
                    print("    → CBN (received unevaluated App)")
                elif isinstance(inner, Lam):
                    print("    → CBV (received evaluated value)")
        except Exception as e:
            print(f"    parse error: {e}")
    time.sleep(0.35)

    # Test: Direct quote(I(I))(QD) — we KNOW this returns App(I, I)
    # But the INDIRECT test above tells us if beta-reduction evaluates args
    print("\n  --- 3c: Direct quote((λx.x)(λx.x))(QD) ---")
    term = apps(g(4), apps(I, I), QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out and FF in out:
        parsed = parse_term(out)
        try:
            tag, payload = decode_either(parsed)
            if tag == "Left":
                blist = decode_bytes_list(payload)
                inner = parse_term(blist + bytes([FF]))
                print(f"    quoted: {inner}")
        except Exception as e:
            print(f"    parse error: {e}")
    time.sleep(0.35)


# ── Phase 4: Syscall argument structure hypothesis ───────────────────


def phase_4_arg_structure():
    print("\n" + "=" * 72)
    print("PHASE 4: sys8 argument structure hypothesis")
    print("  What if sys8 checks the SYNTACTIC shape of its argument?")
    print("  Try passing structured terms with specific patterns")
    print("=" * 72)

    # If the evaluator is lazy/CBN and sys8 sees the raw term,
    # maybe it needs to see a specific structure.

    # What if the argument needs to be a pair (Scott encoding)?
    # pair(a, b) = λsel. sel a b

    # What if sys8 expects (username, password) pair?
    print("\n  --- 4a: sys8(pair('gizmore', 'ilikephp')) ---")
    username = NConst(encode_bytes_list(b"gizmore"))
    password = NConst(encode_bytes_list(b"ilikephp"))
    pair = lam("sel", apps(v("sel"), username, password))

    term = apps(g(8), pair, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        text = out.decode("latin-1", errors="replace")
        print(f"    text: {text[:80]!r}")
    time.sleep(0.35)

    # What if the argument needs to be a specific integer?
    # We tested int(8) already. But what about other specific values?
    print("\n  --- 4b: sys8 with various integer arguments ---")
    for n in [0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 14, 15, 42, 65, 88, 201, 255]:
        term = apps(g(8), int_term(n), QD_TERM)
        out, elapsed = query_named(term, timeout_s=6.0)
        result = classify(out, elapsed)
        if "PERM_DENIED" not in result:
            print(f"  sys8(int({n})): {result}")
            if out:
                print(f"    text: {out.decode('latin-1', errors='replace')[:60]!r}")
        time.sleep(0.15)
    print("  (all tested — any non-PermDenied results shown above)")
    time.sleep(0.2)

    # What if sys8 expects a byte-list that IS a valid BrownOS program?
    # Like passing QD's bytes as a byte-list argument
    print("\n  --- 4c: sys8(byte_list(QD_bytes)) ---")
    qd_bytes_list = NConst(encode_bytes_list(QD))
    term = apps(g(8), qd_bytes_list, QD_TERM)
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # What if the byte-list needs to include FF?
    print("\n  --- 4d: sys8(byte_list with 0xFF) ---")
    # Can we even make a byte-list containing 0xFF?
    # encode_byte_term(255) should work — it's just 9-lambda encoded
    try:
        prog_bytes = bytes([0x08, 0x00, 0xFE, 0xFE, 0xFD, 0xFF])
        prog_list = NConst(encode_bytes_list(prog_bytes))
        term = apps(g(8), prog_list, QD_TERM)
        out, elapsed = query_named(term, timeout_s=8.0)
        print(f"  sys8(list with FF): {classify(out, elapsed)}")
        if out:
            print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    except Exception as e:
        print(f"  Error creating byte list: {e}")
    time.sleep(0.35)

    # What if the argument needs to be a QUOTED term (byte-list from quote)?
    # i.e., quote something, then pass the byte-list to sys8
    print("\n  --- 4e: quote(I)(λresult. result(λbytes. sys8(bytes)(QD), ...)) ---")
    term = apps(
        g(4),
        I,  # quote(identity)
        lam(
            "qresult",
            apps(
                v("qresult"),
                lam(
                    "bytes",  # Left: got quoted bytes
                    apps(
                        g(8),
                        v("bytes"),  # pass to sys8
                        lam(
                            "s8result",
                            apps(
                                v("s8result"),
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
                lam("_err", write_str("QERR")),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  quote(I) → sys8(bytes): {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # KEY TEST: sys8 with its OWN quoted bytes as argument
    # quote(g(8)) → [0x08] → sys8([0x08])
    print("\n  --- 4f: quote(g(8))(λbytes. sys8(bytes)(QD)) ---")
    term = apps(
        g(4),
        g(8),  # quote(g(8)) → byte list [0x08]
        lam(
            "qresult",
            apps(
                v("qresult"),
                lam(
                    "bytes",  # Left: [0x08]
                    apps(
                        g(8),
                        v("bytes"),
                        lam(
                            "s8result",
                            apps(
                                v("s8result"),
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
                lam("_err", write_str("QERR")),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  quote(g(8)) → sys8(bytes): {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)


# ── Phase 5: What if the evaluator is CBN? ───────────────────────────


def phase_5_cbn_implications():
    print("\n" + "=" * 72)
    print("PHASE 5: If evaluator is CBN — exploit unevaluated args")
    print("  sys8 might check if arg is Lam, App, Var structure")
    print("=" * 72)

    # If CBN: sys8(arg)(cont) where arg is an UNEVALUATED expression.
    # The evaluator might pattern-match on arg's structure:
    # - If arg = Lam(...) → execute as kernel code
    # - If arg = App(...) → check some condition
    # - If arg = Var(n) → check global/permission

    # But we already tested Lam (A, B, omega, identity, K) — all PermDenied.

    # UNLESS: the lambda needs to have a SPECIFIC BODY STRUCTURE.

    # What if sys8 needs: λk. k(arg) where k is a continuation?
    # Or: λ. Var(0) (applying the bound var to nothing = just returning it)

    # Dloser said "the input codes" (plural) and their "meaning" is key.
    # "Input codes" could mean the bytes we send. Each byte IS a code.
    # The "meaning" could be their interpretation by the evaluator.

    # What if there's a specific BYTE PATTERN that the evaluator
    # intercepts before parsing? Like a magic number?

    # Test: send raw bytes that don't form valid lambda terms
    print("\n  --- 5a: Raw byte experiments (invalid terms) ---")

    raw_tests = [
        # What about FD FE sequences?
        (bytes([FE, FD, FF]), "FE FD FF — Lam then App?"),
        # Multiple FEs
        (bytes([FE, FE, FE, 0x00, FF]), "FE FE FE 00 FF"),
        # Just FE FF
        (bytes([FE, FF]), "FE FF — incomplete lambda?"),
        # 08 FE FF — Var(8) under lambda?
        (bytes([0x08, FE, FF]), "08 FE FF — Lam(Var(8))"),
        # What about FC (252) — last valid Var before special bytes
        (
            bytes([0xFC, 0x00, FE, FE, FD, QD[0]]) + QD[1:] + bytes([FD, FF]),
            "Var(252)(nil)(QD)",
        ),
    ]

    for payload, name in raw_tests:
        out, elapsed = query_raw(payload, timeout_s=6.0)
        result = classify(out, elapsed)
        print(f"  {name}: {result}")
        if out:
            print(f"    text: {out.decode('latin-1', errors='replace')[:60]!r}")
        time.sleep(0.2)

    # The big idea: what if 0xFC (Var(252)) is NOT "not implemented"
    # but has a special role?
    # We tested: g(252)(nil)(QD) → NotImpl. But what about g(252)(lam)?
    print("\n  --- 5b: g(252) with lambda arguments ---")
    for gid in [252, 251, 250, 249, 248]:
        probe = lam("x", write_str(f"G{gid}"))
        term = apps(g(gid), probe, QD_TERM)
        out, elapsed = query_named(term, timeout_s=6.0)
        result = classify(out, elapsed)
        if "NOT_IMPL" not in result:
            print(f"  g({gid})(λx.write)(QD): {result}")
            if out:
                print(f"    text: {out.decode('latin-1', errors='replace')[:60]!r}")
        time.sleep(0.15)
    print("  (all tested — non-NotImpl results shown above)")


# ── Main ─────────────────────────────────────────────────────────────


def main():
    print("=" * 72)
    print("probe_oracle15b_lambda_kernel.py — Lambda probe & eval semantics")
    print(f"  Target: {HOST}:{PORT}")
    print("=" * 72)

    phase_1_lambda_probes()
    phase_2_quote_special_form()
    phase_3_eval_semantics()
    phase_4_arg_structure()
    phase_5_cbn_implications()

    print("\n" + "=" * 72)
    print("All phases complete.")
    print("=" * 72)


if __name__ == "__main__":
    main()
