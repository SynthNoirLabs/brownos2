#!/usr/bin/env python3
"""
probe_oracle13_values.py — Probe globals as VALUES, not just syscalls.

Key insight: The cheat sheet says `?? ?? FD QD FD` = `(X Y)` observed by QD.
dloser says "don't be too literal with the ??s" and "the second example is useful
for figuring out crucial properties."

This means: evaluate (g(n) g(m)) or (g(n) value) and observe the STRUCTURE
of the result. Not CPS syscall calling — just raw application and observation.

Also: test echo payloads as CALLABLES — call them directly with args.
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
)

HOST = "wc3.wechall.net"
PORT = 61221


# ── Named-term helpers (compact) ────────────────────────────────────


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
        return f"ENC_FAIL"
    if text.startswith("Invalid term"):
        return f"INVALID_TERM"
    if "Permission denied" in text:
        return f"PERM_DENIED"
    if "Not implemented" in text:
        return f"NOT_IMPL"
    if "Invalid argument" in text:
        return f"INVALID_ARG"
    if "No such" in text:
        return f"NO_SUCH"
    if "Not a dir" in text:
        return f"NOT_DIR"
    if "Not a file" in text:
        return f"NOT_FILE"
    if "Not so fast" in text:
        return f"RATE_LIM"
    if FF in raw:
        # QD-terminated response — try to parse
        return f"QD:{raw[:30].hex()}"
    return f"DATA:{text[:50]!r}"


# ── QD for structured observation ────────────────────────────────────

# QD observes by quoting and writing the result term.
# The pattern `?? ?? FD QD FD` means: evaluate (X Y), pass result to QD.
# QD = λresult. quote(result, λeither. either(λbytes. write(bytes, g(0)), g(0)))


def qd_observe(term):
    """Wrap a term with QD observation: term(QD) — i.e., term applied to QD as cont."""
    return apps(term, NConst(parse_term(QD + bytes([FF]))))


# ── Phase 1: ??(g(n)) observed by QD — globals as VALUES ────────────


def phase_1_globals_as_values():
    print("=" * 72)
    print("PHASE 1: g(n)(g(m)) — probe globals applied to each other")
    print("  Pattern: X Y FD QD FD = ((X Y) QD)")
    print("=" * 72)

    # For each known syscall global, apply it to another global and observe.
    # This tests what the global IS when treated as a plain function.

    known = [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]
    test_args = [NIL, g(0), g(8), g(14), g(201)]
    test_arg_names = ["nil", "g(0)", "g(8)", "g(14)", "g(201)"]

    QD_TERM = NConst(parse_term(QD + bytes([FF])))

    for syscall_id in known:
        for arg, arg_name in zip(test_args, test_arg_names):
            # ((g(n) arg) QD) — this is the ?? ?? FD QD FD pattern
            term = apps(g(syscall_id), arg, QD_TERM)
            out, elapsed = query_named(term, timeout_s=6.0)
            result = classify(out, elapsed)

            # Only print interesting results (skip known patterns)
            if syscall_id == 8 and "PERM_DENIED" in result:
                continue  # Known
            if "NOT_IMPL" in result:
                continue  # Known for unused globals
            if "TIMEOUT" in result and syscall_id == 0:
                continue  # Known: g(0) swallows

            print(f"  g({syscall_id})({arg_name}) via QD → {result}")
            if out and "QD:" in result:
                # Try to parse the QD result
                try:
                    parsed = parse_term(out)
                    tag, payload = decode_either(parsed)
                    print(f"    parsed: {tag}({payload})")
                except:
                    pass
            time.sleep(0.2)


# ── Phase 2: Raw value probes for each global ───────────────────────


def phase_2_raw_value_probes():
    print("\n" + "=" * 72)
    print("PHASE 2: Probe each known global as value (not CPS syscall)")
    print("  Apply to 0, 1, 2 args and observe behavior")
    print("=" * 72)

    QD_TERM = NConst(parse_term(QD + bytes([FF])))

    # g(n) with 0 args: just observe g(n) itself via QD
    # This means: QD(g(n)) — but QD is a continuation, it calls quote(g(n))
    # Actually QD applied TO g(n) means: QD takes one arg (result), and result = g(n)
    # So: quote(g(n), λeither. either(λbytes. write(bytes, g(0)), g(0)))
    # This should quote the global reference and write its bytecode.

    print("\n  --- 2a: quote(g(n)) — what IS each global as a term? ---")

    for n in [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
        # quote(g(n), λresult. result(λbytes. write(bytes, nil), λerr. write("QF", nil)))
        term = apps(
            g(4),
            g(n),
            lam(
                "result",
                apps(
                    v("result"),
                    lam("bytes", apps(g(2), v("bytes"), NIL)),
                    lam("_err", write_str("QF")),
                ),
            ),
        )
        out, elapsed = query_named(term, timeout_s=6.0)
        result = classify(out, elapsed)
        if out and "QF" not in out.decode("latin-1", errors="replace"):
            print(f"  quote(g({n})): {result}")
            if "DATA" in result or "QD:" in result:
                print(f"    hex: {out[:40].hex()}")
        else:
            print(f"  quote(g({n})): {result}")
        time.sleep(0.2)

    print("\n  --- 2b: g(n)(nil)(nil) — apply globals to 2x nil ---")

    for n in [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
        term = apps(g(n), NIL, NIL)
        out, elapsed = query_named(term, timeout_s=6.0)
        result = classify(out, elapsed)
        if "EMPTY" not in result and "TIMEOUT" not in result:
            print(f"  g({n})(nil)(nil): {result}")
            if out:
                print(f"    text: {out.decode('latin-1', errors='replace')[:60]!r}")
        time.sleep(0.2)

    print("\n  --- 2c: g(n)(nil)(nil)(nil) — 3 args ---")

    for n in [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
        term = apps(g(n), NIL, NIL, NIL)
        out, elapsed = query_named(term, timeout_s=6.0)
        result = classify(out, elapsed)
        if "EMPTY" not in result and "TIMEOUT" not in result:
            print(f"  g({n})(nil)(nil)(nil): {result}")
            if out:
                print(f"    text: {out.decode('latin-1', errors='replace')[:60]!r}")
        time.sleep(0.2)


# ── Phase 3: Echo payloads as CALLABLES ──────────────────────────────


def phase_3_echo_callables():
    print("\n" + "=" * 72)
    print("PHASE 3: Echo payloads as callables")
    print("  echo(g(N)) → unwrap → call payload(arg1)(arg2)...")
    print("=" * 72)

    # echo(g(N)) → Left(payload). Unwrap Left → payload.
    # Then CALL payload with various args and observe.

    # Key insight: echo returns the input verbatim. But at runtime,
    # the "payload" inside the Left wrapper is the original term.
    # When we unwrap with Left handler (λpayload. body), we get the original g(N).
    # So echo(g(N)) unwrap → g(N). Calling g(N)(nil)(OBS) = standard syscall.
    # BUT: what if we DON'T unwrap, and instead manipulate the Either structure?

    # More interesting: what if echo on a COMPLEX term returns something
    # that we can decompose differently?

    # Let's try: echo(some lambda term) → unwrap → call as function
    print("\n  --- 3a: echo(λx.x) → unwrap → call ---")
    ID = NConst(Lam(Var(0)))

    term = apps(
        g(14),
        ID,
        lam(
            "echo_res",
            apps(
                v("echo_res"),
                lam(
                    "payload",  # Left handler: call payload with args
                    apps(v("payload"), write_str("ID_CALLED")),
                ),
                lam("_err", write_str("ECHO_ERR")),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=6.0)
    print(f"  echo(I) → unwrap → I(write('ID_CALLED')): {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # echo(g(8)) → unwrap → payload = g(8) → call g(8) NOT as CPS syscall
    # g(8)(write_str("X")) — apply to a write term directly
    print("\n  --- 3b: echo(g(8)) → unwrap → call with write directly ---")
    term = apps(
        g(14),
        g(8),
        lam(
            "echo_res",
            apps(
                v("echo_res"),
                lam("payload", apps(v("payload"), write_str("SYS8_RAW"))),
                lam("_err", write_str("ECHO_ERR")),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=6.0)
    print(f"  echo(g(8)) → unwrap → g(8)(write('SYS8_RAW')): {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.35)

    # Now the KEY test: echo on FORBIDDEN VAR RANGE
    # echo(g(251)) → Left(Var(253) under 2 lambdas)
    # If we DON'T unwrap the Either, but instead APPLY the Either to specific handlers...
    # Left(Var(253)) applied as left_handler(Var(253)):
    # where left_handler is a function that calls the payload as a syscall

    print("\n  --- 3c: echo(g(251)) → unwrap → call payload with nil + safe obs ---")
    # This should be same as g(251)(nil, OBS) = NotImplemented. Let's verify.

    for echo_arg in [249, 250, 251, 252]:
        term = apps(
            g(14),
            g(echo_arg),
            lam(
                "echo_res",
                apps(
                    v("echo_res"),
                    lam(
                        "payload",
                        apps(
                            v("payload"),
                            NIL,
                            lam(
                                "result",
                                apps(
                                    v("result"),
                                    lam("_l", write_str("LEFT")),
                                    lam(
                                        "errcode",
                                        apps(
                                            g(1),
                                            v("errcode"),
                                            lam(
                                                "es",
                                                apps(
                                                    v("es"),
                                                    lam(
                                                        "str", apps(g(2), v("str"), NIL)
                                                    ),
                                                    lam("_", write_str("?")),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                    lam("_err", write_str("ECHO_ERR")),
                ),
            ),
        )
        out, elapsed = query_named(term, timeout_s=6.0)
        print(
            f"  echo(g({echo_arg})) → unwrap → payload(nil, obs): {classify(out, elapsed)}"
        )
        if out:
            print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
        time.sleep(0.35)


# ── Phase 4: Second cheat sheet pattern literally ────────────────────


def phase_4_cheat_sheet_literal():
    print("\n" + "=" * 72)
    print("PHASE 4: '?? ?? FD QD FD' — trying NON-GLOBAL terms as ??")
    print("  'Don't be too literal with ??s' — use lambdas, apps, etc.")
    print("=" * 72)

    QD_TERM = NConst(parse_term(QD + bytes([FF])))

    # What if the FIRST ?? is a lambda?
    # (λx.sys8(x)) nil FD QD FD = ((λx.sys8(x)) nil QD)
    # = sys8(nil)(QD) = QD(Right(6)). Same old.

    # What if both ??s are lambda terms?
    # (λx.x) g(8) FD QD FD = g(8)(QD) = QD(Right(??))
    # Actually g(8) takes 2 args. g(8)(QD) = partial. Needs another arg.
    # Then that partial is applied to... nothing. Wait, the pattern is:
    # X Y FD QD FD = (X Y) QD. So ((X Y) QD).

    # What if X = QD and Y = g(8)?
    # (QD g(8)) QD = QD(g(8)) applied to second QD?
    # Actually: apps(QD_TERM, g(8), QD_TERM)
    # = QD(g(8))(QD). QD takes one arg (result).
    # QD(g(8)) = quote(g(8), λeither. either(λbytes. write(bytes, g(0)), g(0)))
    # This would quote g(8) and write its bytecode.
    # Then the second QD is applied to the result of that write...
    # But write returns nil continuation, so g(0)...

    # Actually, the key is: QD IS a continuation. `?? ?? FD QD FD` means:
    # apply ?? to ?? to get a VALUE, then pass that VALUE to QD as continuation.
    # QD then quotes the value and writes the bytes.

    # So: what if we use g(14) (echo) as the syscall?
    # g(14) g(8) FD QD FD = echo(g(8), QD) → QD(Left(g(8)))
    # This is: quote(Left(g(8)), write). Should give us the quoted Left(g(8)).

    interesting_pairs = [
        # (syscall, arg)
        (g(14), g(8)),  # echo(g(8))
        (g(14), g(14)),  # echo(echo)
        (g(14), g(201)),  # echo(backdoor)
        (g(14), g(42)),  # echo(towel)
        (g(14), g(0)),  # echo(exception handler)
        (g(14), g(4)),  # echo(quote)
        (g(14), g(2)),  # echo(write)
        # (non-syscall, g(8))
        (NIL, g(8)),  # nil(g(8))
        (NConst(Lam(Var(0))), g(8)),  # I(g(8)) = g(8)
        # (g(8), various)
        (g(8), g(8)),  # sys8(sys8) — partial, needs cont
        (g(8), g(14)),  # sys8(echo) — PermDenied presumably
        (g(8), g(201)),  # sys8(backdoor) — PermDenied
    ]
    pair_names = [
        "echo(g(8))",
        "echo(echo)",
        "echo(backdoor)",
        "echo(towel)",
        "echo(g(0))",
        "echo(quote)",
        "echo(write)",
        "nil(g(8))",
        "I(g(8))",
        "sys8(sys8)",
        "sys8(echo)",
        "sys8(backdoor)",
    ]

    for (x, y), name in zip(interesting_pairs, pair_names):
        term = apps(x, y, QD_TERM)
        out, elapsed = query_named(term, timeout_s=6.0)
        result = classify(out, elapsed)
        print(f"  (({name}) QD): {result}")
        if out and ("QD:" in result or "DATA:" in result):
            # Try to parse
            try:
                if FF in out:
                    parsed = parse_term(out)
                    tag, payload = decode_either(parsed)
                    if tag:
                        print(f"    → {tag}(..)")
            except:
                pass
            hex_str = out[:40].hex()
            print(f"    hex: {hex_str}")
        time.sleep(0.25)


# ── Phase 5: What does echo(g(8)) CONTAIN? ───────────────────────────


def phase_5_echo_sys8_structure():
    print("\n" + "=" * 72)
    print("PHASE 5: What does echo(g(8)) contain?")
    print("  echo returns Left(input). For g(8), what structure does this have?")
    print("=" * 72)

    # echo(g(8), QD) → QD(Left(g(8)))
    # QD quotes Left(g(8)) and writes bytes.
    # Left(g(8)) = λl.λr.l(g(8))
    # Under 2 lambdas, g(8) = Var(10) (8 + 2).
    # So Left(g(8)) = Lam(Lam(App(Var(1), Var(10))))
    # Encoding: 01 0A FD FE FE
    # This SHOULD be quotable since Var(10) < 253.

    QD_TERM = NConst(parse_term(QD + bytes([FF])))

    term = apps(g(14), g(8), QD_TERM)
    out, elapsed = query_named(term, timeout_s=6.0)
    print(f"  echo(g(8)) via QD: {classify(out, elapsed)}")
    if out and FF in out:
        hex_str = out[: out.index(FF) + 1].hex()
        print(f"    hex: {hex_str}")
        try:
            parsed = parse_term(out)
            print(f"    parsed: {parsed}")
            tag, payload = decode_either(parsed)
            print(f"    decoded: {tag}({payload})")
        except Exception as e:
            print(f"    parse error: {e}")
    time.sleep(0.35)

    # Now echo each known syscall and see what quote says about them
    print("\n  --- echo(g(n)) for all known syscalls → quoted structure ---")

    for n in [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
        term = apps(g(14), g(n), QD_TERM)
        out, elapsed = query_named(term, timeout_s=6.0)
        result = classify(out, elapsed)
        if out and FF in out:
            hex_data = out[: out.index(FF) + 1].hex()
            try:
                parsed = parse_term(out)
                tag, payload = decode_either(parsed)
                print(f"  echo(g({n:3d})): {tag}, payload = {payload}")
            except:
                print(f"  echo(g({n:3d})): {result}, hex = {hex_data[:40]}")
        else:
            print(f"  echo(g({n:3d})): {result}")
        time.sleep(0.2)


# ── Phase 6: Read access.log before and after sys8 ──────────────────


def phase_6_access_log_diff():
    print("\n" + "=" * 72)
    print("PHASE 6: access.log before/after sys8")
    print("=" * 72)

    # Read access.log
    term = apps(
        g(7),
        int_term(46),
        lam(
            "result",
            apps(
                v("result"),
                lam("bytes", apps(g(2), v("bytes"), NIL)),
                lam("_err", write_str("RF_ERR")),
            ),
        ),
    )
    out1, _ = query_named(term, timeout_s=6.0)
    print(f"  access.log (before): {out1.decode('latin-1', errors='replace')[:60]!r}")
    time.sleep(0.35)

    # Now: read access.log, call sys8, read access.log again (in same program)
    term = apps(
        g(7),
        int_term(46),
        lam(
            "log1",  # log1 = Either from first read
            apps(
                g(8),
                NIL,
                lam(
                    "sys8_res",  # sys8 result (ignored)
                    apps(
                        g(7),
                        int_term(46),
                        lam(
                            "log2",  # log2 = Either from second read
                            # Write both logs
                            apps(
                                v("log1"),
                                lam(
                                    "bytes1",
                                    apps(
                                        g(2),
                                        v("bytes1"),
                                        lam(
                                            "_",
                                            apps(
                                                v("log2"),
                                                lam(
                                                    "bytes2",
                                                    apps(g(2), v("bytes2"), NIL),
                                                ),
                                                lam("_e", write_str("LOG2_ERR")),
                                            ),
                                        ),
                                    ),
                                ),
                                lam("_e", write_str("LOG1_ERR")),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    out, elapsed = query_named(term, timeout_s=8.0)
    print(f"  access.log (before+after sys8): {classify(out, elapsed)}")
    if out:
        text = out.decode("latin-1", errors="replace")
        print(f"    content: {text[:120]!r}")
    time.sleep(0.35)


# ── Phase 7: Does space's QD without FF really just timeout? ────────


def phase_7_space_test():
    print("\n" + "=" * 72)
    print("PHASE 7: space's demo — QD without FF vs with FF")
    print("=" * 72)

    # QD bytes without FF (what space sent)
    qd_no_ff = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

    # QD bytes WITH FF
    qd_with_ff = qd_no_ff + bytes([FF])

    # Test without FF (should timeout)
    print("  Sending QD WITHOUT FF (expect timeout)...")
    out, elapsed = query_raw(qd_no_ff, timeout_s=8.0)
    print(f"    result: {classify(out, elapsed)} (elapsed: {elapsed:.1f}s)")
    time.sleep(0.35)

    # Test WITH FF
    print("  Sending QD WITH FF...")
    out, elapsed = query_raw(qd_with_ff, timeout_s=8.0)
    print(f"    result: {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')[:60]!r}")
    time.sleep(0.35)

    # QD as a standalone term (without syscall wrapping)
    # QD = λresult. quote(result, λeither. either(λbytes. write(bytes, g(0)), g(0)))
    # As a standalone expression, QD is just a lambda. It doesn't DO anything
    # until applied to an argument. Sending it + FF should result in no output.

    # But what about: QD applied to QD? QD(QD)?
    # QD(QD) = quote(QD, continuation). This quotes the QD term itself.
    qd_term = parse_term(QD + bytes([FF]))
    term = App(qd_term, qd_term)  # QD(QD)
    payload = encode_term(term) + bytes([FF])
    out, elapsed = query_raw(payload, timeout_s=6.0)
    print(f"  QD(QD): {classify(out, elapsed)}")
    if out:
        print(f"    hex: {out[:60].hex()}")
    time.sleep(0.35)


# ── Main ─────────────────────────────────────────────────────────────


def main():
    print("=" * 72)
    print("probe_oracle13_values.py — Globals as VALUES, echo as callable")
    print(f"  Target: {HOST}:{PORT}")
    print("=" * 72)

    phase_1_globals_as_values()
    phase_2_raw_value_probes()
    phase_3_echo_callables()
    phase_4_cheat_sheet_literal()
    phase_5_echo_sys8_structure()
    phase_6_access_log_diff()
    phase_7_space_test()

    print("\n" + "=" * 72)
    print("All phases complete.")
    print("=" * 72)


if __name__ == "__main__":
    main()
