#!/usr/bin/env python3
"""
probe_oracle12_safe.py — Oracle #12 recommendations.

Key insight: Our QD-based tooling LIES when results contain Var(253+),
because quote() returns "Encoding failed!" without trailing 0xFF, causing
recv-until-FF to hang/timeout. This masks real behavior.

This probe uses ONLY safe observers (write + error_string, no quote/QD)
to avoid false negatives.

Tests:
  Phase 1: File ID 8 exact classification (readdir, readfile, name)
  Phase 2: Gap file IDs (7, 10, 12, 13, etc.)
  Phase 3: Echo-manufactured Var(253+) composed with sys8 (safe observer)
  Phase 4: Forbidden vars as OPERATORS
  Phase 5: sys8 with non-standard argument shapes
"""

from __future__ import annotations

import socket
import time
import hashlib
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


# ── Named-term helpers ─────────────────────────────────────────────


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
    term: object  # already de Bruijn


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


def int_term(n):
    """Named-term wrapper for encode_byte_term."""
    return NConst(encode_byte_term(n))


# Extended integer encoding for values > 255 (Var(9) = weight 256)
def int_term_ext(val):
    """Build integer with extended weights (Var(9)=256)."""
    weights = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128, 9: 256}
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
        return None
    term = expr
    for _ in range(9):
        term = Lam(term)
    return NConst(term)


# ── Network ─────────────────────────────────────────────────────────


def recv_all(sock, timeout_s=5.0):
    """Receive everything available (not just until FF)."""
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


def query_raw(payload, timeout_s=5.0):
    """Send payload, recv ALL bytes (not just until FF)."""
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
        return (
            f"ERR:{e}".encode(),
            time.monotonic() - start if "start" in dir() else 0.0,
        )


def query_named(term, timeout_s=5.0):
    """Query with named term → (raw_bytes, elapsed)."""
    payload = encode_term(to_db(term)) + bytes([FF])
    return query_raw(payload, timeout_s=timeout_s)


def classify(raw, elapsed):
    """Classify response without assuming FF-termination."""
    if not raw:
        if elapsed >= 4.5:
            return "TIMEOUT"
        return f"EMPTY({elapsed:.2f}s)"
    text = raw.decode("latin-1", errors="replace")
    if text.startswith("Encoding failed"):
        return f"ENC_FAIL({elapsed:.2f}s)"
    if text.startswith("Invalid term"):
        return f"INVALID_TERM({elapsed:.2f}s)"
    if text.startswith("Term too big"):
        return f"TOO_BIG({elapsed:.2f}s)"
    if "Permission denied" in text:
        return f"PERM_DENIED({elapsed:.2f}s)"
    if "Not implemented" in text:
        return f"NOT_IMPL({elapsed:.2f}s)"
    if "Invalid argument" in text:
        return f"INVALID_ARG({elapsed:.2f}s)"
    if "No such" in text:
        return f"NO_SUCH({elapsed:.2f}s)"
    if "Not a directory" in text:
        return f"NOT_DIR({elapsed:.2f}s)"
    if "Not a file" in text:
        return f"NOT_FILE({elapsed:.2f}s)"
    if "Not so fast" in text:
        return f"RATE_LIMIT({elapsed:.2f}s)"
    # Check for known markers
    for marker in ["L!", "R!", "LEFT!", "RIGHT!", "GOT!", "ERR:", "DIR:", "FILE:"]:
        if marker in text:
            return f"MARKER:{marker}({elapsed:.2f}s) text={text[:60]!r}"
    if FF in raw:
        return f"FF_TERM({elapsed:.2f}s) hex={raw[:40].hex()}"
    return f"OTHER({elapsed:.2f}s) text={text[:80]!r}"


# ── Safe Observer (NO quote, NO QD) ─────────────────────────────────


def write_str(s):
    """Write a literal string then call nil continuation."""
    return apps(g(2), NConst(encode_bytes_list(s.encode("latin-1"))), NIL)


def safe_obs():
    """
    Safe observer for syscall results. Uses only write + error_string.
    No quote/QD, so no "Encoding failed!" false negatives.

    λresult. result(
        λpayload. write("L:", nil),     -- Left handler
        λerrcode. error_string(errcode, λes. es(
            λstr. write(str, nil),      -- Got error string
            λ_. write("?", nil)         -- error_string failed
        ))
    )
    """
    return lam(
        "result",
        apps(
            v("result"),
            # Left handler: write "L:" marker
            lam("payload", write_str("L:")),
            # Right handler: resolve error code
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
                            lam("_e", write_str("?")),
                        ),
                    ),
                ),
            ),
        ),
    )


def safe_obs_with_content():
    """
    Safe observer that tries to WRITE the Left payload as bytes.
    For file content, this will output the actual bytes.
    For non-byte payloads, it may produce garbage or nothing.

    λresult. result(
        λpayload. write(payload, nil),  -- Left: try to write payload as bytes
        λerrcode. error_string(errcode, λes. es(
            λstr. write(str, nil),
            λ_. write("?", nil)
        ))
    )
    """
    return lam(
        "result",
        apps(
            v("result"),
            lam("payload", apps(g(2), v("payload"), NIL)),
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
                            lam("_e", write_str("?")),
                        ),
                    ),
                ),
            ),
        ),
    )


def safe_obs_readdir():
    """
    Safe observer for readdir results.
    Left = list of child IDs. We write "DIR:" then try to decode a few IDs.
    Actually, let's just write "DIR:" to know it succeeded.
    """
    return lam(
        "result",
        apps(
            v("result"),
            lam("_children", write_str("DIR:OK")),
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
                            lam("_e", write_str("?")),
                        ),
                    ),
                ),
            ),
        ),
    )


OBS = safe_obs()
OBS_CONTENT = safe_obs_with_content()
OBS_DIR = safe_obs_readdir()


# ── Phase 1: File ID 8 exact classification ──────────────────────────


def phase_1_file_id_8():
    print("=" * 72)
    print("PHASE 1: File ID 8 ('solution') — exact type classification")
    print("=" * 72)

    # 1a: name(8)
    term = apps(g(6), int_term(8), OBS_CONTENT)
    out, elapsed = query_named(term)
    print(f"  name(8): {classify(out, elapsed)}")
    if out:
        print(f"    raw text: {out.decode('latin-1', errors='replace')!r}")
    time.sleep(0.35)

    # 1b: readfile(8) with safe observer
    term = apps(g(7), int_term(8), OBS)
    out, elapsed = query_named(term)
    print(f"  readfile(8) [safe_obs]: {classify(out, elapsed)}")
    if out:
        print(f"    raw text: {out.decode('latin-1', errors='replace')!r}")
    time.sleep(0.35)

    # 1c: readdir(8) — THIS IS THE KEY TEST
    term = apps(g(5), int_term(8), OBS_DIR)
    out, elapsed = query_named(term)
    print(f"  readdir(8) [safe_obs]: {classify(out, elapsed)}")
    if out:
        print(f"    raw text: {out.decode('latin-1', errors='replace')!r}")
    time.sleep(0.35)

    # 1d: readdir(8) with QD (for comparison)
    term = apps(
        g(5),
        int_term(8),
        lam(
            "result",
            apps(
                g(4),
                v("result"),
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
    )
    out, elapsed = query_named(term)
    print(f"  readdir(8) [quote]: {classify(out, elapsed)}")
    if out:
        print(f"    hex: {out[:60].hex()}")
    time.sleep(0.35)

    # 1e: readfile(8) try to write content directly
    term = apps(g(7), int_term(8), OBS_CONTENT)
    out, elapsed = query_named(term)
    print(f"  readfile(8) [content]: {classify(out, elapsed)}")
    if out:
        print(f"    raw text: {out.decode('latin-1', errors='replace')!r}")
    time.sleep(0.35)


# ── Phase 2: Gap file IDs ────────────────────────────────────────────


def phase_2_gap_ids():
    print("\n" + "=" * 72)
    print("PHASE 2: Gap file IDs — scanning IDs not in directory tree")
    print("=" * 72)

    # Known filesystem IDs:
    # 0,1,2,3,4,5,6,9,11,14,15,16,22,25,39,43,46,50,65,88,256
    # Gaps in low range: 7, 8, 10, 12, 13, 17-21, 23-24, 26-38, 40-42, 44-45, 47-49

    gap_ids = [
        7,
        8,
        10,
        12,
        13,
        17,
        18,
        19,
        20,
        21,
        23,
        24,
        26,
        27,
        28,
        29,
        30,
        31,
        32,
        33,
        34,
        35,
        36,
        37,
        38,
        40,
        41,
        42,
        44,
        45,
        47,
        48,
        49,
        51,
        52,
        53,
        54,
        55,
        56,
        57,
        58,
        59,
        60,
    ]

    print(f"  Checking {len(gap_ids)} gap IDs with name()...")

    for fid in gap_ids:
        term = apps(g(6), int_term(fid), OBS_CONTENT)
        out, elapsed = query_named(term)
        result = classify(out, elapsed)
        if (
            "NO_SUCH" not in result
            and "EMPTY" not in result
            and "?" not in (out.decode("latin-1", errors="replace") if out else "")
        ):
            # Found something!
            text = out.decode("latin-1", errors="replace") if out else ""
            print(f"  *** ID {fid}: {result}")
            if text:
                print(f"      text: {text!r}")

            # If it has a name, try readdir and readfile
            term_rf = apps(g(7), int_term(fid), OBS_CONTENT)
            out_rf, el_rf = query_named(term_rf)
            print(f"      readfile({fid}): {classify(out_rf, el_rf)}")
            if out_rf:
                rf_text = out_rf.decode("latin-1", errors="replace")
                print(f"        text: {rf_text[:80]!r}")
            time.sleep(0.25)

            term_rd = apps(g(5), int_term(fid), OBS_DIR)
            out_rd, el_rd = query_named(term_rd)
            print(f"      readdir({fid}): {classify(out_rd, el_rd)}")
            time.sleep(0.25)
        else:
            pass  # silent for non-existent
        time.sleep(0.15)

    print("  Gap scan complete.")


# ── Phase 3: Echo-manufactured Var(253+) with safe observer ──────────


def phase_3_echo_forbidden():
    print("\n" + "=" * 72)
    print("PHASE 3: Echo-manufactured Var(253+) → sys8 (safe observer)")
    print("=" * 72)

    print("\n  --- 3a: Echo results fed directly to sys8 (safe obs, no quote) ---")

    # echo(g(251)) → Left(payload). Under 2 lambdas, payload has Var(253)=FD inside.
    # We DON'T extract the Left content — we pass the ENTIRE Either to sys8.
    for echo_arg in [249, 250, 251, 252]:
        # echo(g(N), λraw. sys8(raw, safe_obs))
        term = apps(g(14), g(echo_arg), lam("raw", apps(g(8), v("raw"), OBS)))
        out, elapsed = query_named(term, timeout_s=8.0)
        print(f"  echo(g({echo_arg})) → raw → sys8(raw, OBS): {classify(out, elapsed)}")
        if out:
            print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
        time.sleep(0.35)

    print("\n  --- 3b: Echo result UNWRAPPED then fed to sys8 ---")

    # echo(g(251)) → Left(payload). UNWRAP the Left, get the payload.
    # Under the Left's 2 lambdas, Var(253) exists. When we extract via
    # Left(x)(handler)(dummy) = handler(x), de Bruijn shift cancels.
    # But the RUNTIME TERM may still hold the forbidden var internally.
    for echo_arg in [249, 250, 251, 252]:
        term = apps(
            g(14),
            g(echo_arg),
            lam(
                "echo_res",
                apps(
                    v("echo_res"),
                    # Left handler: got the inner payload → pass to sys8
                    lam("inner", apps(g(8), v("inner"), OBS)),
                    # Right handler: shouldn't happen for echo
                    lam("_err", write_str("ECHO_ERR")),
                ),
            ),
        )
        out, elapsed = query_named(term, timeout_s=8.0)
        print(
            f"  echo(g({echo_arg})) → unwrap → sys8(inner, OBS): {classify(out, elapsed)}"
        )
        if out:
            print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
        time.sleep(0.35)

    print("\n  --- 3c: Double echo → sys8 (accumulate forbidden vars) ---")

    # echo(g(251)) → Left(X). echo(X) → Left(Y). Y has even deeper forbidden vars.
    for echo_arg in [250, 251, 252]:
        term = apps(
            g(14),
            g(echo_arg),
            lam("r1", apps(g(14), v("r1"), lam("r2", apps(g(8), v("r2"), OBS)))),
        )
        out, elapsed = query_named(term, timeout_s=8.0)
        print(f"  echo^2(g({echo_arg})) → sys8(r2, OBS): {classify(out, elapsed)}")
        if out:
            print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
        time.sleep(0.35)

    print("\n  --- 3d: Echo result as CONTINUATION for sys8 ---")

    for echo_arg in [249, 250, 251, 252]:
        term = apps(g(14), g(echo_arg), lam("raw", apps(g(8), NIL, v("raw"))))
        out, elapsed = query_named(term, timeout_s=8.0)
        result = classify(out, elapsed)
        print(f"  echo(g({echo_arg})) → sys8(nil, raw): {result}")
        if out and "OTHER" in result:
            print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
        time.sleep(0.35)


# ── Phase 4: Forbidden vars as OPERATORS ─────────────────────────────


def phase_4_forbidden_as_operators():
    print("\n" + "=" * 72)
    print("PHASE 4: Echo-manufactured terms used as OPERATORS (syscall pos)")
    print("=" * 72)

    print("\n  --- 4a: echo(g(N)) unwrap → use payload AS syscall ---")

    # echo(g(6)) → Left(g(6)). Unwrap → we get g(6) back (shifted).
    # But echo(g(251)) → Left(something_with_Var253).
    # If we UNWRAP and USE AS SYSCALL: inner(arg, cont)...
    # Var(253) in syscall position would reference global 251... which is g(251)?
    # Actually de Bruijn: under continuation lambdas, it shifts again.

    for echo_arg in [6, 7, 8, 14, 42, 201, 250, 251, 252]:
        # echo(g(N)) → unwrap → use as syscall with nil arg and safe obs
        term = apps(
            g(14),
            g(echo_arg),
            lam(
                "echo_res",
                apps(
                    v("echo_res"),
                    # Left handler: got inner, use it as a syscall
                    lam("inner", apps(v("inner"), NIL, OBS)),
                    lam("_err", write_str("ECHO_ERR")),
                ),
            ),
        )
        out, elapsed = query_named(term, timeout_s=8.0)
        result = classify(out, elapsed)
        # For known syscalls this should produce known results:
        # echo(g(6)) → g(6) → name(nil) → should be some result
        # echo(g(8)) → g(8) → sys8(nil) → should still be PermDenied
        print(f"  echo(g({echo_arg})) → unwrap → inner(nil, OBS): {result}")
        if out and len(out) > 0:
            text = out.decode("latin-1", errors="replace")[:80]
            if text.strip():
                print(f"    text: {text!r}")
        time.sleep(0.35)

    print("\n  --- 4b: echo(g(N)) raw (NOT unwrapped) used as syscall ---")

    # The raw echo result is Left(payload) = λl.λr.l(payload).
    # Calling this as a "syscall": Left(payload)(arg)(cont) = cont(payload)? No...
    # Left(x)(a)(b) = a(x). So: Left(payload)(nil)(OBS) = nil(payload) = ...
    # nil = λa.λb.b. nil(payload) = λb.b. Then OBS? → (λb.b)(OBS) = OBS.
    # OBS then needs a result... hmm, OBS is called with no args = stuck.

    # Actually: Left(x)(a)(b) = a(x). So raw(nil)(OBS) = nil(payload).
    # nil(payload) = (λc.λn.n)(payload) = λn.n. This is identity.
    # Then we need to figure out what happens next in the CPS chain.

    # Let me try: raw as syscall, with actual integer arg instead of nil
    for echo_arg in [8, 251, 252]:
        # raw(int_term(0), OBS) → Left(payload)(0)(OBS) = 0(payload) → stuck?
        # Actually 0 = encode_byte_term(0) = λ^9.Var(0). Applied to payload:
        # strips one lambda → λ^8.Var(0). More complex.
        # Let me try identity as arg: (λx.x)
        ID = NConst(Lam(Var(0)))
        term = apps(g(14), g(echo_arg), lam("raw", apps(v("raw"), ID, OBS)))
        out, elapsed = query_named(term, timeout_s=6.0)
        result = classify(out, elapsed)
        print(f"  echo(g({echo_arg})) → raw(I, OBS): {result}")
        if out:
            text = out.decode("latin-1", errors="replace")[:60]
            if text.strip():
                print(f"    text: {text!r}")
        time.sleep(0.35)

    print("\n  --- 4c: Use the cheat sheet literally with computed terms ---")
    print("  Cheat sheet: ?? ?? FD QD FD")
    print("  'Don't be too literal with ??s' — try non-Var terms as syscall")

    # What if the syscall position is a LAMBDA, not a Var?
    # E.g.: (λx.x)(arg)(cont) = arg(cont) — identity in syscall position
    # This would make the argument be called with the continuation!
    # So if arg = g(8), then: I(g(8))(cont) = g(8)(cont) → partial application
    # Then g(8)(cont) needs another arg...

    # What about: sys8 is a 2-arg function: sys8(arg)(cont).
    # What if we use a DIFFERENT calling convention?
    # What if we put sys8 in the argument position?
    # ?? = g(14) (echo), ??= g(8) → echo(g(8), cont) = cont(Left(g(8)))
    # Then we extract g(8) from the Left and call it differently?

    # More interesting: What if the ?? ?? FD QD FD pattern is:
    # some_term g(8) FD QD FD = (some_term g(8)) QD → some_term(g(8))(QD)
    # What if some_term is the backdoor pair or omega?

    # omega(g(8)) = (λx.xx)(g(8)) = g(8)(g(8))
    # g(8)(g(8)) → sys8 with arg=g(8), but no continuation!
    # sys8(g(8)) → partial (waiting for cont)
    # Then QD becomes the cont: sys8(g(8))(QD) = QD(Right(6))

    # Actually this is just sys8(g(8), QD) which we've tested.

    # Let's try: backdoor components A and B in syscall position
    # First get them:
    # backdoor(nil) → Left(pair). pair(fst)(snd) = fst(A)(B)(snd).
    # Wait: pair = λx.λy.((x A) B). So pair(fst)(snd) = ((fst A) B).
    # Note: snd is IGNORED! pair(fst)(snd) = fst(A)(B).

    # Let's extract A and B and use THEM as syscalls
    # A = λa.λb.(b b), B = λa.λb.(a b)

    # A(arg)(cont) = cont(cont). So A as syscall: A(nil)(OBS) = OBS(OBS).
    # OBS(OBS) = OBS applied to itself... that's interesting.

    # B(arg)(cont) = arg(cont). So B as syscall: B(nil)(OBS) = nil(OBS) = OBS? No.
    # nil = λa.λb.b. nil(OBS) = λb.b. This is identity.
    # Then this identity is the "result" but there's no more CPS chain.

    # B(g(8))(OBS) = g(8)(OBS). g(8)(OBS) → sys8(OBS) partial, needs 2nd arg.
    # But wait: sys8 takes (arg)(cont). sys8(OBS) = waiting for cont.
    # That's sys8 with OBS as the argument! Not standard calling convention.

    # Hmm. Let's test B(g(8))(OBS) directly.

    # Extract backdoor pair components:
    term = apps(
        g(201),
        NIL,
        lam(
            "bd",
            apps(
                v("bd"),
                lam(
                    "pair",  # Left handler
                    apps(
                        apps(
                            v("pair"),
                            lam(
                                "A",
                                lam(
                                    "B",
                                    # Now we have A and B. Use B as syscall.
                                    # B(g(8))(OBS) = g(8)(OBS)
                                    # but this is sys8(OBS) needing cont
                                    # So let's apply more: B(g(8))(OBS) then more
                                    # Actually: B(nil, OBS) = nil(OBS) = identity
                                    # Let's try: A as syscall with nil and OBS
                                    apps(v("A"), NIL, OBS),
                                ),
                            ),
                        ),
                        NIL,  # second arg to pair (ignored)
                    ),
                ),
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  A(nil, OBS) via backdoor: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # B as syscall
    term = apps(
        g(201),
        NIL,
        lam(
            "bd",
            apps(
                v("bd"),
                lam(
                    "pair",
                    apps(
                        apps(v("pair"), lam("A", lam("B", apps(v("B"), NIL, OBS)))),
                        NIL,
                    ),
                ),
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  B(nil, OBS) via backdoor: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # A(int_term(8), OBS) — A with file ID 8 as argument
    term = apps(
        g(201),
        NIL,
        lam(
            "bd",
            apps(
                v("bd"),
                lam(
                    "pair",
                    apps(
                        apps(
                            v("pair"),
                            lam("A", lam("B", apps(v("A"), int_term(8), OBS))),
                        ),
                        NIL,
                    ),
                ),
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  A(int(8), OBS) via backdoor: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # B(int_term(8), OBS) — B(8, OBS) = 8(OBS). int(8) applied to OBS...
    term = apps(
        g(201),
        NIL,
        lam(
            "bd",
            apps(
                v("bd"),
                lam(
                    "pair",
                    apps(
                        apps(
                            v("pair"),
                            lam("A", lam("B", apps(v("B"), int_term(8), OBS))),
                        ),
                        NIL,
                    ),
                ),
                lam("_err", write_str("BD_ERR")),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  B(int(8), OBS) via backdoor: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)


# ── Phase 5: Direct readdir(8) children exploration ─────────────────


def phase_5_readdir8_deep():
    """If readdir(8) succeeds, enumerate its children."""
    print("\n" + "=" * 72)
    print("PHASE 5: Deep readdir(8) — if it's a directory, walk its children")
    print("=" * 72)

    # readdir(8) → Left(list) → iterate and name each child
    # Safe observer that writes the first few child IDs

    # First: just check if readdir(8) returns Left at all
    term = apps(
        g(5),
        int_term(8),
        lam(
            "result",
            apps(
                v("result"),
                lam("children", write_str("DIR_LEFT")),
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
    out, elapsed = query_named(term, timeout_s=6.0)
    result = classify(out, elapsed)
    print(f"  readdir(8) → Left/Right check: {result}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')!r}")
    time.sleep(0.35)

    if "DIR_LEFT" in (out.decode("latin-1", errors="replace") if out else ""):
        print("  *** readdir(8) returned Left! It IS a directory!")
        # Now get the children via QD
        term = apps(
            g(5),
            int_term(8),
            lam(
                "result",
                apps(
                    g(4),
                    v("result"),
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
        )
        out, elapsed = query_named(term, timeout_s=6.0)
        print(f"  readdir(8) quoted: {classify(out, elapsed)}")
        if out:
            print(f"    hex: {out[:80].hex()}")


# ── Phase 6: sys8 with various non-standard args ────────────────────


def phase_6_nonstandard_sys8():
    print("\n" + "=" * 72)
    print("PHASE 6: sys8 with non-standard argument shapes")
    print("=" * 72)

    # "Don't be too literal with the ??s"
    # What if sys8's argument should be something specific?

    # Test: sys8 with the password "ilikephp" as bytes
    term = apps(g(8), NConst(encode_bytes_list(b"ilikephp")), OBS)
    out, elapsed = query_named(term, timeout_s=6.0)
    print(f"  sys8('ilikephp', OBS): {classify(out, elapsed)}")
    time.sleep(0.35)

    # Test: sys8 with the backdoor nil (00 FE FE)
    term = apps(g(8), NIL, OBS)
    out, elapsed = query_named(term, timeout_s=6.0)
    print(f"  sys8(nil, OBS): {classify(out, elapsed)}")
    time.sleep(0.35)

    # Test: sys8 with identity
    ID = NConst(Lam(Var(0)))
    term = apps(g(8), ID, OBS)
    out, elapsed = query_named(term, timeout_s=6.0)
    print(f"  sys8(I, OBS): {classify(out, elapsed)}")
    time.sleep(0.35)

    # Test: sys8 with the integer 201 (backdoor syscall number)
    term = apps(g(8), int_term(201), OBS)
    out, elapsed = query_named(term, timeout_s=6.0)
    print(f"  sys8(201, OBS): {classify(out, elapsed)}")
    time.sleep(0.35)

    # Test: sys8 with K (true) and KI (false) — Scott booleans
    K = NConst(Lam(Lam(Var(1))))
    KI = NConst(Lam(Lam(Var(0))))

    term = apps(g(8), K, OBS)
    out, elapsed = query_named(term, timeout_s=6.0)
    print(f"  sys8(K=true, OBS): {classify(out, elapsed)}")
    time.sleep(0.35)

    term = apps(g(8), KI, OBS)
    out, elapsed = query_named(term, timeout_s=6.0)
    print(f"  sys8(KI=false, OBS): {classify(out, elapsed)}")
    time.sleep(0.35)

    # Test: sys8 with file ID 8 (integer 8)
    term = apps(g(8), int_term(8), OBS)
    out, elapsed = query_named(term, timeout_s=6.0)
    print(f"  sys8(int(8), OBS): {classify(out, elapsed)}")
    time.sleep(0.35)

    # Test: sys8 with g(8) itself as argument (self-reference)
    term = apps(g(8), g(8), OBS)
    out, elapsed = query_named(term, timeout_s=6.0)
    print(f"  sys8(g(8), OBS): {classify(out, elapsed)}")
    time.sleep(0.35)

    # Test: omega as argument
    omega = NConst(App(Lam(App(Var(0), Var(0))), Lam(App(Var(0), Var(0)))))
    # Actually omega diverges. Let's use the COMPONENTS instead.
    # ω = λx.(x x)
    omega_comb = NConst(Lam(App(Var(0), Var(0))))
    term = apps(g(8), omega_comb, OBS)
    out, elapsed = query_named(term, timeout_s=6.0)
    print(f"  sys8(ω, OBS): {classify(out, elapsed)}")
    time.sleep(0.35)


# ── Phase 7: Scan all readable files, hash candidates ───────────────


def phase_7_hash_hunt():
    print("\n" + "=" * 72)
    print("PHASE 7: Extract all file contents, hash candidates")
    print("=" * 72)

    target_hash = "9252ed65ffac2aa763adb21ef72c0178f1d83286"

    def sha1_chain(s, rounds=56154):
        h = s.encode() if isinstance(s, str) else s
        for _ in range(rounds):
            h = hashlib.sha1(h).hexdigest().encode()
        return h.decode()

    # Read all known file IDs with content
    file_ids = [11, 46, 65, 88, 256]
    file_names = {
        11: "passwd",
        46: "access.log",
        65: ".history",
        88: "mail",
        256: "wtf",
    }

    all_candidates = set()

    for fid in file_ids:
        term = apps(
            g(7), int_term(fid) if fid <= 255 else int_term_ext(fid), OBS_CONTENT
        )
        out, elapsed = query_named(term, timeout_s=6.0)
        if out:
            text = out.decode("latin-1", errors="replace")
            # Strip trailing FF if present
            if text and text[-1] == "\xff":
                text = text[:-1]
            print(f"  File {fid} ({file_names.get(fid, '?')}): {len(text)} bytes")
            print(f"    content: {text[:80]!r}")

            # Add entire content as candidate
            all_candidates.add(text)
            all_candidates.add(text.strip())
            # Add each line
            for line in text.splitlines():
                all_candidates.add(line)
                all_candidates.add(line.strip())
                # Add individual tokens
                for token in line.split():
                    all_candidates.add(token)
                    all_candidates.add(token.strip(":"))
        time.sleep(0.35)

    # Add known string candidates
    extras = [
        "ilikephp",
        "gizmore",
        "dloser",
        "BrownOS",
        "brownos",
        "Permission denied",
        "omega",
        "towel",
        "42",
        "wtf",
        "Uhm... yeah... no...",
        "Uhm... yeah... no...\n",
        "solution",
        "backdoor",
        "kernel",
        "interrupt",
        "Oh, go choke on a towel!",
        "lambda",
        "Lambda",
        "GZKc.2/VQffio",
        "mailer",
        "root",
        "boss@evil.com",
        "mailer@brownos",
        "dloser@brownos",
        "sodu deluser dloser",
        "sudo deluser dloser",
        # Derived from backdoor: A B and omega
        "λx.(x x)",
        "(λx.(x x))(λx.(x x))",
        "\\x.(x x)",
        "(\\x.(x x))(\\x.(x x))",
        # Error strings
        "Exception",
        "Not implemented",
        "Invalid argument",
        "No such directory or file",
        "Not a directory",
        "Not a file",
        "Not so fast!",
        # Filesystem paths
        "/bin/solution",
        "bin/solution",
        "/etc/passwd",
        "/home/gizmore/.history",
        "/var/spool/mail/dloser",
    ]
    all_candidates.update(extras)

    # Also try case variations
    case_extras = set()
    for c in list(all_candidates):
        if isinstance(c, str):
            case_extras.add(c.lower())
            case_extras.add(c.upper())
    all_candidates.update(case_extras)

    print(f"\n  Testing {len(all_candidates)} candidates against target hash...")

    found = False
    for cand in sorted(all_candidates):
        if not cand or not isinstance(cand, str):
            continue
        try:
            h = sha1_chain(cand)
            if h == target_hash:
                print(f"  *** MATCH FOUND: {cand!r}")
                found = True
                break
        except:
            pass

    if not found:
        print("  No hash matches found in this batch.")
        # Also try with \n appended
        for cand in sorted(all_candidates):
            if not cand or not isinstance(cand, str):
                continue
            try:
                h = sha1_chain(cand + "\n")
                if h == target_hash:
                    print(f"  *** MATCH FOUND (with \\n): {cand + chr(10)!r}")
                    found = True
                    break
            except:
                pass

    if not found:
        print("  Still no matches.")


# ── Main ─────────────────────────────────────────────────────────────


def main():
    print("=" * 72)
    print("probe_oracle12_safe.py — Oracle #12 paradigm shift")
    print(f"  Using SAFE observers (no quote/QD) to avoid false negatives")
    print(f"  Target: {HOST}:{PORT}")
    print("=" * 72)

    phase_1_file_id_8()
    phase_2_gap_ids()
    phase_3_echo_forbidden()
    phase_4_forbidden_as_operators()
    phase_5_readdir8_deep()
    phase_6_nonstandard_sys8()
    phase_7_hash_hunt()

    print("\n" + "=" * 72)
    print("All phases complete.")
    print("=" * 72)


if __name__ == "__main__":
    main()
