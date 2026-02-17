#!/usr/bin/env python3
"""
Deep 3-leaf analysis.

The Oracle's key insight: in CPS, sys8 receives BOTH arg and continuation.
"3 leaves" = ((A B) C) where A, B, C are global Var references.
The continuation C might be what sys8 checks!

Also: "interrupt and transfer parameters to kernel" = echo IS the interrupt.

Strategy: Test ALL meaningful 3-leaf programs with very careful output analysis.
Don't just classify as silent/R — capture EVERYTHING including timing.

ALSO: Test the hypothesis that echo must be used to produce something BEFORE
calling sys8, in a chain. "3 leafs" might mean 3 CPS operations chained.
"""

from __future__ import annotations

import socket
import struct
import time

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def query_raw_careful(
    payload: bytes, timeout_s: float = 10.0
) -> tuple[bytes, float, bool]:
    """Send payload, carefully capture ALL output, timing, and connection state."""
    start = time.monotonic()
    try:
        sock = socket.create_connection((HOST, PORT), timeout=timeout_s)
        sock.sendall(payload)
        # DON'T half-close! Keep connection open to see if server sends more.
        sock.settimeout(timeout_s)
        out = b""
        chunks = []
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                out += chunk
                chunks.append((time.monotonic() - start, chunk))
            except socket.timeout:
                break
        elapsed = time.monotonic() - start
        # Check if server closed connection
        server_closed = len(chunks) > 0 and chunks[-1][1] == b""
        sock.close()
        return out, elapsed, server_closed
    except Exception as e:
        return f"ERROR:{e}".encode(), time.monotonic() - start, False


def query_raw_halfclose(payload: bytes, timeout_s: float = 10.0) -> tuple[bytes, float]:
    """Send payload with half-close, for comparison."""
    start = time.monotonic()
    try:
        sock = socket.create_connection((HOST, PORT), timeout=timeout_s)
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        sock.settimeout(timeout_s)
        out = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                out += chunk
            except socket.timeout:
                break
        elapsed = time.monotonic() - start
        sock.close()
        return out, elapsed
    except Exception as e:
        return f"ERROR:{e}".encode(), time.monotonic() - start


def describe(data: bytes) -> str:
    if not data:
        return "EMPTY"
    if data.startswith(b"Invalid term!"):
        return "INVALID"
    if data.startswith(b"Term too big!"):
        return "TOO_BIG"
    if data.startswith(b"Encoding failed!"):
        return "ENC_FAIL"
    # Try to interpret as text
    try:
        text = data.decode("ascii")
        if text.isprintable():
            return f"TEXT:{text!r}"
    except:
        pass
    return f"HEX:{data.hex()} ({len(data)}b)"


def main():
    print("=" * 70)
    print("DEEP 3-LEAF ANALYSIS")
    print("=" * 70)

    # ================================================================
    # SECTION 1: ALL meaningful 3-leaf left-assoc: ((A B) C)
    # ================================================================
    print("\n[1] Left-associative 3-leaf: ((A B) C) = A B FD C FD FF")
    print("    Format: ((sys A) B C) where A/B vary")

    # Key syscalls to test
    syscalls = {
        0x00: "0/undef",
        0x01: "1/errstr",
        0x02: "2/write",
        0x04: "4/quote",
        0x05: "5/readdir",
        0x06: "6/name",
        0x07: "7/readfile",
        0x08: "8/target",
        0x0E: "14/echo",
        0x2A: "42/towel",
        0xC9: "201/backdoor",
    }

    # Test ALL combinations where at least one position is sys8
    results = []
    for a_val, a_name in syscalls.items():
        for b_val, b_name in syscalls.items():
            for c_val, c_name in syscalls.items():
                if 8 not in (a_val, b_val, c_val):
                    continue

                # Left assoc: ((a b) c)
                payload_l = bytes([a_val, b_val, FD, c_val, FD, FF])
                out_l, elapsed_l = query_raw_halfclose(payload_l, timeout_s=8.0)
                desc_l = describe(out_l)

                # Right assoc: (a (b c))
                payload_r = bytes([a_val, b_val, c_val, FD, FD, FF])
                out_r, elapsed_r = query_raw_halfclose(payload_r, timeout_s=8.0)
                desc_r = describe(out_r)

                # Only print non-trivial results
                l_interesting = desc_l not in ("EMPTY", "INVALID")
                r_interesting = desc_r not in ("EMPTY", "INVALID")

                if l_interesting:
                    print(
                        f"  *** (({a_name} {b_name}) {c_name}) = {payload_l.hex()} -> {desc_l} ({elapsed_l:.1f}s)"
                    )
                    results.append(("L", a_val, b_val, c_val, out_l, desc_l))

                if r_interesting:
                    print(
                        f"  *** ({a_name} ({b_name} {c_name})) = {payload_r.hex()} -> {desc_r} ({elapsed_r:.1f}s)"
                    )
                    results.append(("R", a_val, b_val, c_val, out_r, desc_r))

                time.sleep(0.03)

    print(f"\n  Total interesting: {len(results)}")
    for assoc, a, b, c, out, desc in results:
        print(f"    {assoc}: ({a},{b},{c}) -> {desc}")

    # ================================================================
    # SECTION 2: Focused tests with write-based observation
    # ================================================================
    print("\n[2] Focused 3-leaf tests: ((sys8 echo) write) and variants")

    # ((sys8 echo) write) = 08 0E FD 02 FD FF
    # If sys8(echo) returns Left(x), then (write Left(x)) tries to write.
    # Left(x) = λl.λr.(l x). write expects a byte list. Silent if mismatch.
    # If sys8(echo) returns Right(6), then (write Right(6)) tries to write.
    # Right(6) = λl.λr.(r 6). write expects a byte list. Silent too.

    special_3leaf = [
        ("((sys8 echo) write)", bytes([0x08, 0x0E, FD, 0x02, FD, FF])),
        ("((sys8 echo) echo)", bytes([0x08, 0x0E, FD, 0x0E, FD, FF])),
        ("((sys8 echo) quote)", bytes([0x08, 0x0E, FD, 0x04, FD, FF])),
        ("((sys8 echo) sys8)", bytes([0x08, 0x0E, FD, 0x08, FD, FF])),
        ("((echo sys8) write)", bytes([0x0E, 0x08, FD, 0x02, FD, FF])),
        ("((echo sys8) echo)", bytes([0x0E, 0x08, FD, 0x0E, FD, FF])),
        ("((echo sys8) sys8)", bytes([0x0E, 0x08, FD, 0x08, FD, FF])),
        ("((echo sys8) backdoor)", bytes([0x0E, 0x08, FD, 0xC9, FD, FF])),
        ("((backdoor sys8) write)", bytes([0xC9, 0x08, FD, 0x02, FD, FF])),
        ("((sys8 backdoor) write)", bytes([0x08, 0xC9, FD, 0x02, FD, FF])),
        ("(sys8 (echo sys8))", bytes([0x08, 0x0E, 0x08, FD, FD, FF])),
        ("(sys8 (echo echo))", bytes([0x08, 0x0E, 0x0E, FD, FD, FF])),
        ("(echo (sys8 echo))", bytes([0x0E, 0x08, 0x0E, FD, FD, FF])),
        ("(echo (sys8 write))", bytes([0x0E, 0x08, 0x02, FD, FD, FF])),
        # Also test with BOTH no half-close and half-close
        ("((sys8 echo) write) NO-HALFCLOSE", bytes([0x08, 0x0E, FD, 0x02, FD, FF])),
    ]

    for name, payload in special_3leaf:
        if "NO-HALFCLOSE" in name:
            out, elapsed, _ = query_raw_careful(payload, timeout_s=8.0)
        else:
            out, elapsed = query_raw_halfclose(payload, timeout_s=8.0)
        desc = describe(out)
        interesting = desc not in ("EMPTY", "INVALID")
        tag = "***" if interesting else "   "
        print(f"  {tag} {name:45s} -> {desc} ({elapsed:.1f}s)")
        time.sleep(0.1)

    # ================================================================
    # SECTION 3: 3-leaf with QD as continuation
    # ================================================================
    print("\n[3] sys8 with echo as arg, QD as continuation")
    # ((sys8 echo) QD) — this is NOT 3 leaves, QD is complex
    # But let's see if sys8(echo_function) returns something different
    payload = bytes([0x08, 0x0E, FD]) + QD + bytes([FD, FF])
    out, elapsed = query_raw_halfclose(payload, timeout_s=8.0)
    desc = describe(out)
    print(f"  ((sys8 echo) QD) -> {desc} ({elapsed:.1f}s)")

    # Also: ((sys8 Var(14)) QD) vs ((sys8 nil) QD) — should be the same
    # echo as arg = Var(14)
    for arg, aname in [
        (0x0E, "echo=Var(14)"),
        (0x00, "nil_ref=Var(0)"),
        (0xC9, "backdoor=Var(201)"),
    ]:
        payload = bytes([0x08, arg, FD]) + QD + bytes([FD, FF])
        out, elapsed = query_raw_halfclose(payload, timeout_s=8.0)
        # Try to parse
        desc = describe(out)
        if out and 0xFF in out:
            try:
                from solve_brownos_answer import (
                    parse_term,
                    decode_either,
                    decode_byte_term,
                )

                term = parse_term(out)
                tag, payload_term = decode_either(term)
                if tag == "Right":
                    code = decode_byte_term(payload_term)
                    desc = f"Right({code})"
                elif tag == "Left":
                    desc = f"Left({payload_term})"
            except Exception as e:
                desc = f"{desc} [parse_err: {e}]"
        print(f"  ((sys8 {aname}) QD) -> {desc} ({elapsed:.1f}s)")
        time.sleep(0.1)

    # ================================================================
    # SECTION 4: Chain: echo(something) -> use result as sys8's CONTINUATION
    # ================================================================
    print("\n[4] echo -> extract -> use as sys8 continuation")

    # The idea: echo(X) gives Left(X). Extract X. Use X as continuation to sys8.
    # ((sys8 nil) X) where X came from echo.
    # In CPS, this means sys8 would pass its result to X.

    # What if we echo the write syscall? echo(write) -> Left(write). Extract -> write.
    # Then ((sys8 nil) write) — sys8 passes Right(6) to write.
    # (write Right(6)) = write(λl.λr.r(6)) — not a byte list, silent.

    # What about echo(QD)? echo(QD_term) -> Left(QD_term). Extract -> QD.
    # Then ((sys8 nil) QD_extracted) — same as normal QD usage.
    # This should give the SAME result as ((sys8 nil) QD).

    # BUT: what if the echo wrapper changes something about how QD behaves?
    # What if echo "blesses" the continuation?

    # Build this with named terms
    from probe_mail_focus import (
        DISC8,
        NIL,
        NConst,
        apps,
        classify,
        g,
        lam,
        query_named,
        v,
        write_marker,
        int_term,
        app,
    )
    from solve_brownos_answer import (
        encode_bytes_list,
        encode_term,
        parse_term as parse_t,
    )

    QD_TERM = NConst(parse_t(QD))

    def write_str(s):
        return apps(g(2), NConst(encode_bytes_list(s.encode())), NIL)

    def extract_echo(seed, var_name, tail_builder):
        return apps(
            g(14),
            seed,
            lam(
                "r",
                apps(
                    v("r"),
                    lam(var_name, tail_builder(v(var_name))),
                    lam("_e", write_str("E")),
                ),
            ),
        )

    # 4a: echo(QD) -> extract -> use as sys8 continuation
    run_term = extract_echo(QD_TERM, "qd_extracted", lambda qd: apps(g(8), NIL, qd))
    out = query_named(run_term, timeout_s=10.0)
    desc = describe(out)
    print(f"  echo(QD)->qd', sys8(nil) cont=qd' -> {desc}")
    time.sleep(0.1)

    # 4b: echo(disc8) -> extract -> use as sys8 continuation
    # DISC8 writes "L" or "R"
    disc_term = lam(
        "res", apps(v("res"), lam("_l", write_str("L")), lam("_r", write_str("R")))
    )
    run_term2 = extract_echo(disc_term, "disc_extracted", lambda d: apps(g(8), NIL, d))
    out2 = query_named(run_term2, timeout_s=10.0)
    desc2 = describe(out2)
    print(f"  echo(disc)->disc', sys8(nil) cont=disc' -> {desc2}")
    time.sleep(0.1)

    # 4c: echo the ENTIRE CPS call to sys8
    # echo(((sys8 nil) disc)) — echo wraps the whole computation result
    run_term3 = apps(
        g(14),
        apps(g(8), NIL, DISC8),
        lam(
            "r",
            apps(
                v("r"), lam("_l", write_str("ECHO-L")), lam("_r", write_str("ECHO-R"))
            ),
        ),
    )
    out3 = query_named(run_term3, timeout_s=10.0)
    desc3 = describe(out3)
    print(f"  echo(sys8(nil) disc) -> disc' -> {desc3}")
    time.sleep(0.1)

    # ================================================================
    # SECTION 5: The "interrupt" hypothesis
    # ================================================================
    print("\n[5] Echo as interrupt: echo INSIDE sys8's evaluation")

    # What if sys8's argument should be a term that, when sys8 tries to
    # normalize it, triggers an echo syscall internally?
    # Like: sys8(((echo X) cont)) — the argument contains a pending syscall call

    # In CPS, the argument to sys8 would be ((echo X) cont).
    # When sys8 tries to normalize this, it would:
    # 1. See App(App(Var(14), X), cont)
    # 2. If the normalizer evaluates syscalls during normalization of args...
    # 3. echo(X) would fire, returning Left(X) to cont
    # 4. cont(Left(X)) would produce some value
    # 5. THAT value is what sys8 actually receives

    # This means sys8 might receive the result of echo, processed by cont.
    # If cont = identity: sys8 receives Left(X)
    # If cont = Left-extractor: sys8 receives X
    # We tested both. But what about cont = write?

    # Actually, this is exactly what we've been testing with extract_echo.
    # The VM evaluates lazily or eagerly?
    # If LAZY: sys8 receives a thunk for ((echo X) cont) and inspects it
    # If EAGER: sys8 receives whatever ((echo X) cont) evaluates to

    # Let's test: pass an UNEVALUATED echo call as the argument
    # This requires that the argument is NOT in normal form

    # In the wire format, ((echo nil) identity) = 0E 00 FE FE FD 00 FE FD
    # As a sub-expression, this is the argument to sys8:
    # ((sys8 ((echo nil) id)) disc) = complex payload

    # This is what extract_echo already does! But let me try a different approach:
    # Build the argument as a raw sub-term that contains an echo call

    from solve_brownos_answer import Var, Lam, App, encode_term as enc_t

    # arg = ((echo nil) identity) — an echo call with identity continuation
    # At top level: echo = Var(14), nil = Lam(Lam(Var(0))), id = Lam(Var(0))
    nil_t = Lam(Lam(Var(0)))
    id_t = Lam(Var(0))

    # But wait: inside the argument to sys8, the depth changes.
    # Actually in ((sys8 arg) cont), arg is at the same depth as sys8.
    # So Var(14) = echo is correct.

    arg_echo_nil = App(App(Var(14), nil_t), id_t)  # ((echo nil) id)

    # Full: ((sys8 ((echo nil) id)) QD)
    full_term = App(App(Var(8), arg_echo_nil), parse_t(QD))
    payload_test = enc_t(full_term) + bytes([FF])
    out5, elapsed5 = query_raw_halfclose(payload_test, timeout_s=10.0)
    desc5 = describe(out5)
    print(f"  ((sys8 ((echo nil) id)) QD) -> {desc5} ({elapsed5:.1f}s)")

    # Also: ((sys8 ((echo echo) id)) QD) — echo(echo)
    arg_echo_echo = App(App(Var(14), Var(14)), id_t)
    full_term2 = App(App(Var(8), arg_echo_echo), parse_t(QD))
    payload_test2 = enc_t(full_term2) + bytes([FF])
    out5b, elapsed5b = query_raw_halfclose(payload_test2, timeout_s=10.0)
    desc5b = describe(out5b)
    print(f"  ((sys8 ((echo echo) id)) QD) -> {desc5b} ({elapsed5b:.1f}s)")
    time.sleep(0.1)

    # ================================================================
    # SECTION 6: Double-CPS: echo wraps sys8's call
    # ================================================================
    print("\n[6] Double-CPS: use echo to wrap the entire sys8 call")

    # ((echo ((sys8 nil) id)) disc) — echo the result of sys8
    # sys8(nil) -> Right(6) -> (id Right(6)) -> Right(6)
    # echo(Right(6)) -> Left(Right(6))
    # disc receives Left(Right(6))
    # Left handler fires with payload = Right(6)
    # Then we can examine Right(6) more carefully

    run_term6 = apps(
        g(14),
        apps(g(8), NIL, lam("x", v("x"))),  # echo(sys8(nil)->id->result)
        lam(
            "r",
            apps(
                v("r"),
                lam(
                    "payload",
                    apps(
                        g(4),
                        v("payload"),
                        lam(
                            "qr",
                            apps(
                                v("qr"),
                                lam("qb", apps(g(2), v("qb"), NIL)),
                                lam("_qe", write_str("QE")),
                            ),
                        ),
                    ),
                ),
                lam("_e", write_str("ECHO-R")),
            ),
        ),
    )
    out6 = query_named(run_term6, timeout_s=12.0)
    desc6 = describe(out6)
    print(f"  echo(sys8(nil)->id->res) -> extract -> quote -> write: {desc6}")
    if out6 and 0xFF in out6:
        # Parse the quoted term
        try:
            # Find the bytecode portion (before text markers)
            idx = out6.index(0xFF)
            bytecode = out6[: idx + 1]
            term = parse_t(bytecode)
            tag, p = decode_either(term)
            if tag == "Right":
                code = decode_byte_term(p)
                print(f"    Decoded: Right({code})")
            else:
                print(f"    Decoded: Left({p})")
        except Exception as e:
            print(f"    Parse failed: {e}")
    time.sleep(0.1)

    print("\n" + "=" * 70)
    print("DEEP 3-LEAF ANALYSIS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
