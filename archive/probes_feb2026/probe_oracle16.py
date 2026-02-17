#!/usr/bin/env python3
"""
probe_oracle16.py — Oracle #16 recommended probes.

Now that we know the VM is LAZY, we can use Ω as a strictness oracle.

3 probe strategies:
1. Arity ladder for sys8: does it need 3+ args?
2. Strictness fingerprinting: what does sys8 actually inspect in its argument?
3. Church-boolean sweep: find "data" globals misclassified as NotImplemented
"""

from __future__ import annotations

import socket
import time

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
    decode_byte_term,
)

HOST = "wc3.wechall.net"
PORT = 61221


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


def shift_free_vars(term, delta, cutoff=0):
    if isinstance(term, Var):
        if term.i >= cutoff:
            return Var(term.i + delta)
        return term
    if isinstance(term, Lam):
        return Lam(shift_free_vars(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(
            shift_free_vars(term.f, delta, cutoff),
            shift_free_vars(term.x, delta, cutoff),
        )
    return term


def make_shifted_qd(n):
    """QD with free variables shifted by +n."""
    qd_term = parse_term(QD + bytes([FF]))
    return shift_free_vars(qd_term, n)


def send_and_classify(term_or_payload, timeout_s=6.0, label=""):
    """Send a term, return (raw_output, elapsed, classification)."""
    if isinstance(term_or_payload, bytes):
        payload = term_or_payload
    else:
        payload = encode_term(term_or_payload) + bytes([FF])

    out, elapsed = query_raw(payload, timeout_s=timeout_s)

    if not out:
        if elapsed >= timeout_s - 0.5:
            return out, elapsed, "TIMEOUT"
        return out, elapsed, f"EMPTY({elapsed:.1f}s)"

    text = out.decode("latin-1", errors="replace")
    if text.startswith("Encoding failed"):
        return out, elapsed, "ENC_FAIL"
    if text.startswith("Invalid term"):
        return out, elapsed, "INVALID_TERM"
    if text.startswith("Term too big"):
        return out, elapsed, "TOO_BIG"
    if FF in out:
        try:
            parsed = parse_term(out)
            tag, payload_data = decode_either(parsed)
            if tag == "Left":
                try:
                    bs = decode_bytes_list(payload_data)
                    return (
                        out,
                        elapsed,
                        f"Left:{bs.decode('latin-1', errors='replace')!r}",
                    )
                except:
                    return out, elapsed, f"Left({payload_data})"
            else:
                try:
                    err = decode_byte_term(payload_data)
                    return out, elapsed, f"Right({err})"
                except:
                    return out, elapsed, f"Right({payload_data})"
        except:
            return out, elapsed, f"QD_RAW:{out[:30].hex()}"
    return out, elapsed, f"DATA:{text[:60]!r}"


# ── Constants ─────────────────────────────────────────────────────────

NIL = Lam(Lam(Var(0)))  # Scott nil = λc.λn. n
OMEGA_HALF = Lam(App(Var(0), Var(0)))  # λx. x x
OMEGA = App(OMEGA_HALF, OMEGA_HALF)  # Ω = (λx.xx)(λx.xx) — diverges
QD_TERM = parse_term(QD + bytes([FF]))

# Backdoor pair components (known from prior work)
A_TERM = Lam(Lam(App(Var(0), Var(0))))  # λa.λb. b b
B_TERM = Lam(Lam(App(Var(1), Var(0))))  # λa.λb. a b

# Church pair constructor: λa.λb.λf. f a b
PAIR = Lam(Lam(Lam(App(App(Var(0), Var(2)), Var(1)))))


def church_pair(a, b):
    """Build (Pair a b) = λf. f a b"""
    # (PAIR a b) would need beta reduction; instead build directly:
    # λf. f a b  (with a,b shifted under 1 lambda)
    a_shifted = shift_free_vars(a, 1)
    b_shifted = shift_free_vars(b, 1)
    return Lam(App(App(Var(0), a_shifted), b_shifted))


# ── Probe 1: Arity ladder for sys8 ───────────────────────────────────


def probe_1_arity_ladder():
    print("=" * 72)
    print("PROBE 1: sys8 arity ladder")
    print("  Does sys8 need more than 2 args? Test with 2, 3, 4 args.")
    print("  Also test continuation in different positions.")
    print("=" * 72)

    tokens = [
        ("nil", NIL),
        ("int(0)", encode_byte_term(0)),
        ("A=λab.bb", A_TERM),
        ("B=λab.ab", B_TERM),
    ]

    for tok_name, tok in tokens:
        print(f"\n  --- Token: {tok_name} ---")

        # Standard 2-arg CPS: ((g(8) tok) QD)
        term = App(App(Var(8), tok), QD_TERM)
        _, elapsed, cls = send_and_classify(term)
        print(f"    ((g8 {tok_name}) QD)                   → {cls} ({elapsed:.1f}s)")
        time.sleep(0.2)

        # 3-arg: (((g(8) tok) nil) QD)
        term = App(App(App(Var(8), tok), NIL), QD_TERM)
        _, elapsed, cls = send_and_classify(term)
        print(f"    (((g8 {tok_name}) nil) QD)             → {cls} ({elapsed:.1f}s)")
        time.sleep(0.2)

        # 4-arg: ((((g(8) tok) nil) nil) QD)
        term = App(App(App(App(Var(8), tok), NIL), NIL), QD_TERM)
        _, elapsed, cls = send_and_classify(term)
        print(f"    ((((g8 {tok_name}) nil) nil) QD)       → {cls} ({elapsed:.1f}s)")
        time.sleep(0.2)

        # k in 2nd position: (((g(8) tok) QD) nil)
        term = App(App(App(Var(8), tok), QD_TERM), NIL)
        _, elapsed, cls = send_and_classify(term)
        print(f"    (((g8 {tok_name}) QD) nil)             → {cls} ({elapsed:.1f}s)")
        time.sleep(0.2)

        # k in 3rd position: ((((g(8) tok) nil) QD) nil)
        term = App(App(App(App(Var(8), tok), NIL), QD_TERM), NIL)
        _, elapsed, cls = send_and_classify(term)
        print(f"    ((((g8 {tok_name}) nil) QD) nil)       → {cls} ({elapsed:.1f}s)")
        time.sleep(0.2)

    # Also test: what if sys8 needs TWO meaningful args before the continuation?
    # ((g(8) tok1 tok2) QD) for various tok1, tok2 combos
    print("\n  --- Two-arg combos before QD ---")
    combos = [
        ("nil", "nil", NIL, NIL),
        ("nil", "int(0)", NIL, encode_byte_term(0)),
        ("int(0)", "nil", encode_byte_term(0), NIL),
        ("A", "B", A_TERM, B_TERM),
        ("B", "A", B_TERM, A_TERM),
        (
            "'ilikephp'(short)",
            encode_bytes_list(b"il"),
            NIL,
            NIL,
        ),  # too big for full string
    ]
    for name1, name2, t1, t2 in combos:
        term = App(App(App(Var(8), t1), t2), QD_TERM)
        payload = encode_term(term) + bytes([FF])
        if len(payload) > 2000:
            print(f"    ((g8 {name1} {name2}) QD): SKIP (too big)")
            continue
        _, elapsed, cls = send_and_classify(term)
        print(f"    ((g8 {name1} {name2}) QD): {cls} ({elapsed:.1f}s)")
        time.sleep(0.2)


# ── Probe 2: Strictness fingerprinting ────────────────────────────────


def probe_2_strictness():
    print("\n" + "=" * 72)
    print("PROBE 2: Strictness fingerprinting with Ω")
    print("  Which parts of the argument does sys8 actually inspect?")
    print("  If a probe with Ω in position X timeouts, sys8 forces X.")
    print("  If it returns Right(6) quickly, sys8 does NOT inspect X.")
    print("=" * 72)

    # Test sys8 with Ω as the argument directly
    print("\n  --- 2a: sys8(Ω) — does sys8 force its argument at all? ---")
    term = App(App(Var(8), OMEGA), QD_TERM)
    _, elapsed, cls = send_and_classify(term, timeout_s=8.0)
    print(f"    sys8(Ω): {cls} ({elapsed:.1f}s)")
    if "TIMEOUT" in cls:
        print("    >>> sys8 FORCES its argument! It inspects the value.")
    elif "Right(6)" in cls:
        print("    >>> sys8 does NOT force its argument (lazy check on type/tag only)")
    time.sleep(0.3)

    # Test with pairs containing Ω in different positions
    print("\n  --- 2b: sys8(pair(Ω, nil)) — does it inspect left of pair? ---")
    term = App(App(Var(8), church_pair(OMEGA, NIL)), QD_TERM)
    _, elapsed, cls = send_and_classify(term, timeout_s=8.0)
    print(f"    sys8(pair(Ω, nil)): {cls} ({elapsed:.1f}s)")
    time.sleep(0.3)

    print("\n  --- 2c: sys8(pair(nil, Ω)) — does it inspect right of pair? ---")
    term = App(App(Var(8), church_pair(NIL, OMEGA)), QD_TERM)
    _, elapsed, cls = send_and_classify(term, timeout_s=8.0)
    print(f"    sys8(pair(nil, Ω)): {cls} ({elapsed:.1f}s)")
    time.sleep(0.3)

    # What about Scott Either-wrapped Ω?
    # Left(Ω) = λl.λr. l Ω
    left_omega = Lam(Lam(App(Var(1), shift_free_vars(OMEGA, 2))))
    print("\n  --- 2d: sys8(Left(Ω)) — does it unwrap Either and force? ---")
    term = App(App(Var(8), left_omega), QD_TERM)
    _, elapsed, cls = send_and_classify(term, timeout_s=8.0)
    print(f"    sys8(Left(Ω)): {cls} ({elapsed:.1f}s)")
    time.sleep(0.3)

    # Right(Ω)
    right_omega = Lam(Lam(App(Var(0), shift_free_vars(OMEGA, 2))))
    print("\n  --- 2e: sys8(Right(Ω)) ---")
    term = App(App(Var(8), right_omega), QD_TERM)
    _, elapsed, cls = send_and_classify(term, timeout_s=8.0)
    print(f"    sys8(Right(Ω)): {cls} ({elapsed:.1f}s)")
    time.sleep(0.3)

    # Scott list with Ω as head: cons(Ω, nil) = λc.λn. c Ω nil
    cons_omega = Lam(
        Lam(App(App(Var(1), shift_free_vars(OMEGA, 2)), shift_free_vars(NIL, 2)))
    )
    print("\n  --- 2f: sys8(cons(Ω, nil)) — list with divergent head ---")
    term = App(App(Var(8), cons_omega), QD_TERM)
    _, elapsed, cls = send_and_classify(term, timeout_s=8.0)
    print(f"    sys8(cons(Ω, nil)): {cls} ({elapsed:.1f}s)")
    time.sleep(0.3)

    # Integer-shaped term with Ω inside: 9 lambdas, body = Ω (under 9 lambdas)
    # This looks like an integer but diverges if the VM tries to evaluate the body
    fake_int = OMEGA
    for _ in range(9):
        fake_int = Lam(fake_int)
    print("\n  --- 2g: sys8(9-lambda-wrapped Ω) — looks like int, body diverges ---")
    term = App(App(Var(8), fake_int), QD_TERM)
    _, elapsed, cls = send_and_classify(term, timeout_s=8.0)
    print(f"    sys8(λ^9.Ω): {cls} ({elapsed:.1f}s)")
    time.sleep(0.3)

    # Also test other syscalls for comparison
    print("\n  --- 2h: Comparison — other syscalls with Ω ---")
    for n, name in [(5, "readdir"), (6, "name"), (7, "readfile")]:
        term = App(App(Var(n), OMEGA), QD_TERM)
        _, elapsed, cls = send_and_classify(term, timeout_s=8.0)
        print(f"    {name}(Ω): {cls} ({elapsed:.1f}s)")
        time.sleep(0.25)


# ── Probe 3: Church-boolean sweep ─────────────────────────────────────


def probe_3_church_boolean_sweep():
    print("\n" + "=" * 72)
    print("PROBE 3: Church-boolean / selector sweep of ALL globals")
    print("  Test if any g(n) acts as a selector (Church true/false/etc)")
    print("  Pattern: ((g(n) marker_A) marker_B) observed via write")
    print("=" * 72)

    # Marker terms that write distinct strings
    # marker_A: when selected, writes "A" to socket
    # marker_B: when selected, writes "B" to socket

    # Build: write("A", nil) and write("B", nil)
    # These are CPS: ((g(2) bytes) nil)
    # But we need them as THUNKS that get applied to something.

    # Actually, for a Church boolean test:
    # Church true = λt.λf. t
    # Church false = λt.λf. f
    #
    # So if g(n) is Church true: ((g(n) A) B) = A
    # If g(n) is Church false: ((g(n) A) B) = B
    #
    # But A and B need to be terms that produce observable output when reached.
    # Since the VM is lazy, we need A and B to be ACTIONS.
    #
    # Let's use: A = write_marker("T"), B = write_marker("F")
    # where write_marker(s) = ((g(2) encoded_s) nil)

    # Actually simpler: just use QD to observe what ((g(n) A) B) reduces to.
    # A = some distinct term, B = some distinct term
    # Then QD will quote the result.

    # Use: A = int(65) = 'A' byte, B = int(66) = 'B' byte
    # Then observe: ((g(n) A) B) via QD — if it selects A, we see int(65)

    A_marker = encode_byte_term(65)  # represents 'A'
    B_marker = encode_byte_term(66)  # represents 'B'
    C_marker = encode_byte_term(67)  # represents 'C'

    # For each global, test:
    # 1-selector: (g(n) A) via QD — does it return something with A?
    # 2-selector: ((g(n) A) B) via QD
    # 3-selector: (((g(n) A) B) C) via QD

    print("\n  --- 3a: 2-arg selector test: ((g(n) int(65)) int(66)) via QD ---")
    print("  Looking for globals that select A(65) or B(66) instead of errors")

    interesting = []

    for n in range(253):
        # Skip known syscalls (we know their behavior)
        if n in {0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201}:
            continue

        # ((g(n) A) B) observed by QD
        # But we need QD as the observer. How?
        # Actually, we want to see what ((g(n) A) B) IS as a term.
        # Use quote: g(4)( ((g(n) A) B), λresult. result(λbytes. g(2)(bytes, nil), λerr. nil) )
        # This is getting complex. Simpler: use the ?? ?? FD QD FD pattern.
        # (g(n) A) = X, then X B = Y, then Y observed by... hmm.

        # Actually even simpler:
        # ((((g(n) A) B) to something) QD) — but we don't know the arity.
        #
        # Let's just try: (((g(n) A) B) QD)
        # If g(n) is a 2-arg selector, this gives us QD applied to the selected value.
        # QD(A_marker) = quote+write the int(65) term.

        term = App(App(App(Var(n), A_marker), B_marker), QD_TERM)
        payload = encode_term(term) + bytes([FF])
        if len(payload) > 2000:
            continue

        out, elapsed, cls = send_and_classify(term, timeout_s=4.0)

        # Filter: skip "standard" NotImpl responses
        if "Right(1)" in cls:
            continue
        if "EMPTY" in cls and elapsed < 2.0:
            continue
        if "TIMEOUT" in cls:
            continue

        print(f"    g({n:3d}): {cls} ({elapsed:.1f}s)")
        interesting.append(n)
        time.sleep(0.15)

    if interesting:
        print(f"\n  Interesting globals: {interesting}")
    else:
        print("\n  No non-standard responses found in 2-arg selector test")

    # Now test 3-arg selector: ((((g(n) A) B) C) QD)
    print("\n  --- 3b: 3-arg selector test: (((g(n) A) B) C) via QD ---")

    for n in range(253):
        if n in {0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201}:
            continue

        term = App(App(App(App(Var(n), A_marker), B_marker), C_marker), QD_TERM)
        payload = encode_term(term) + bytes([FF])
        if len(payload) > 2000:
            continue

        out, elapsed, cls = send_and_classify(term, timeout_s=4.0)

        if "Right(1)" in cls:
            continue
        if "EMPTY" in cls and elapsed < 2.0:
            continue
        if "TIMEOUT" in cls:
            continue

        print(f"    g({n:3d}): {cls} ({elapsed:.1f}s)")
        time.sleep(0.15)

    # Also specifically test known syscalls as selectors (unusual usage)
    print("\n  --- 3c: Known syscalls as selectors ---")
    for n in [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
        # ((g(n) A) B) via QD — using A_marker, B_marker
        term = App(App(App(Var(n), A_marker), B_marker), QD_TERM)
        _, elapsed, cls = send_and_classify(term, timeout_s=6.0)
        if "TIMEOUT" not in cls and "EMPTY" not in cls:
            print(f"    g({n:3d}) as 2-selector: {cls} ({elapsed:.1f}s)")
        else:
            print(f"    g({n:3d}) as 2-selector: {cls} ({elapsed:.1f}s)")
        time.sleep(0.2)


# ── Probe 4: Quick sweep — 1-arg application of all globals ──────────


def probe_4_one_arg_sweep():
    print("\n" + "=" * 72)
    print("PROBE 4: 1-arg application of all globals via QD")
    print("  (g(n) nil) observed by QD — NOT CPS, just 1 arg")
    print("=" * 72)

    for n in range(253):
        if n in {0}:  # skip g(0) which swallows
            continue

        # (g(n) nil) via QD: ((g(n) nil) QD)
        # Wait, this IS the CPS pattern: g(n)(nil)(QD). Same as before.
        # For a TRUE 1-arg test, we need to observe g(n)(nil) as a value.
        # Use quote to observe: g(4)( (g(n) nil), continuation)
        # But g(4) is itself CPS... so: ((g(4) (g(n) nil)) QD)
        # = quote((g(n) nil), QD) = QD(Left(bytes_of(g(n)(nil))))

        # This tells us what (g(n) nil) LOOKS LIKE as a term (its quote)
        term = App(App(Var(4), App(Var(n), NIL)), QD_TERM)
        payload = encode_term(term) + bytes([FF])
        if len(payload) > 2000:
            continue

        out, elapsed, cls = send_and_classify(term, timeout_s=4.0)

        # We expect most to return the quoted form of their partial application
        # or an error. Look for anything unusual.
        if "TIMEOUT" in cls or ("EMPTY" in cls and elapsed < 2.0):
            continue

        # Filter: if it's just a single byte (the global is opaque), skip
        # quote(g(n)(nil)) for NotImpl globals might give us interesting structure
        if n not in {1, 2, 4, 5, 6, 7, 8, 14, 42, 201}:
            # Only print non-standard globals with interesting results
            if "Right(1)" not in cls:
                print(f"    quote(g({n:3d})(nil)): {cls} ({elapsed:.1f}s)")
                if out and FF in out:
                    print(f"      hex: {out[:40].hex()}")

        time.sleep(0.1)

    # Also: for known syscalls, what does quote(g(n)(nil)) look like?
    print("\n  --- Known syscalls: quote(g(n)(nil)) ---")
    for n in [1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
        term = App(App(Var(4), App(Var(n), NIL)), QD_TERM)
        _, elapsed, cls = send_and_classify(term, timeout_s=6.0)
        print(f"    quote(g({n:3d})(nil)): {cls} ({elapsed:.1f}s)")
        if _ and FF in _:
            hexdata = _[: _.index(FF) + 1].hex()
            print(f"      hex: {hexdata[:60]}")
        time.sleep(0.2)


# ── Main ─────────────────────────────────────────────────────────────


def main():
    print("=" * 72)
    print("probe_oracle16.py — Arity, strictness, and selector probes")
    print(f"  Target: {HOST}:{PORT}")
    print("=" * 72)
    print()

    probe_1_arity_ladder()
    probe_2_strictness()
    probe_3_church_boolean_sweep()
    probe_4_one_arg_sweep()

    print("\n" + "=" * 72)
    print("All probes complete.")
    print("=" * 72)


if __name__ == "__main__":
    main()
