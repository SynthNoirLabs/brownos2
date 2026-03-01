#!/usr/bin/env python3
"""
probe_llm_v15.py — Test LLM v15 proposals (5 directions):
  Dir 1: Offline hash brute-force (novel candidates only)
  Dir 2: "Encoding failed!" via echo+quote CPS chain
  Dir 3: Syntactic success — quote(sys8)(QD) and quote on various syscalls
  Dir 4: Hidden tail extractor — drop chars from sys42 and sys1(6) strings
  Dir 5: Backdoor pair hex as flag — quote the backdoor pair
"""

from __future__ import annotations

import hashlib
import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    encode_term,
    encode_byte_term,
    parse_term,
    decode_either,
    decode_byte_term,
    decode_bytes_list,
)

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
QD_TERM = parse_term(QD_BYTES)

NIL = Lam(Lam(Var(0)))


def g(i: int) -> Var:
    return Var(i)


def shift_term(term, delta, cutoff=0):
    """Shift free variables in term by delta."""
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_term(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_term(term.f, delta, cutoff), shift_term(term.x, delta, cutoff))
    raise TypeError(f"Unknown term type: {type(term)}")


def query_raw(payload: bytes, timeout_s: float = 5.0) -> bytes:
    """Send payload to BrownOS, return raw response bytes."""
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
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
                    if FF in chunk:
                        break
                except socket.timeout:
                    break
            return out
    except Exception as e:
        return b"ERR:" + str(e).encode()


def run_named(name: str, term: object, delay: float = 0.5) -> bytes:
    """Encode term, send to server, print result."""
    payload = encode_term(term) + bytes([FF])
    print(f"\n--- {name} ---")
    print(f"  Payload ({len(payload)}b): {payload.hex()}")

    if len(payload) > 2000:
        print(f"  SKIP: Payload too large ({len(payload)}b > 2000b limit)")
        return b""

    time.sleep(delay)
    resp = query_raw(payload)

    if not resp:
        print(f"  Result: EMPTY")
    elif resp.startswith(b"ERR:"):
        print(f"  Result: {resp.decode()}")
    else:
        hex_str = resp.hex()
        # Try ASCII interpretation
        try:
            text = resp.decode("ascii")
            print(f"  Result: ASCII={text!r} ({len(resp)}b)")
        except UnicodeDecodeError:
            print(f"  Result: HEX={hex_str[:200]} ({len(resp)}b)")

        # Try to parse as FF-terminated term
        if FF in resp:
            try:
                term_resp = parse_term(resp[: resp.index(FF) + 1])
                tag, payload_inner = decode_either(term_resp)
                if tag == "Left":
                    try:
                        bs = decode_bytes_list(payload_inner)
                        text = bs.decode("utf-8", "replace")
                        print(f"  Decoded: Left(string={text!r})")
                    except Exception:
                        print(f"  Decoded: Left(<non-string>)")
                elif tag == "Right":
                    try:
                        code = decode_byte_term(payload_inner)
                        print(f"  Decoded: Right({code})")
                    except Exception:
                        print(f"  Decoded: Right(<non-int>)")
            except Exception:
                pass
    return resp


def main():
    print("=" * 70)
    print("PROBE v15: Testing LLM v15 Directions (5 total)")
    print("=" * 70)

    # ================================================================
    # DIRECTION 1: Offline hash brute-force (NOVEL candidates only)
    # Run locally, no network needed
    # ================================================================
    print("\n" + "=" * 70)
    print("DIRECTION 1: Offline Hash Brute-Force (novel candidates)")
    print("=" * 70)

    TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
    ROUNDS = 56154

    # Only candidates NOT in our existing probe_exact_hash.py
    novel_candidates = [
        # LLM's proposed backdoor hex (their claimed encoding — WRONG but test anyway)
        "01010000fdfefe000100fdfefefdfefdfefeff",
        "01010000FDFEFE000100FDFEFEFDFEFDFEFEFF",
        # Correct backdoor pair bytecode (our calculation)
        "000000fdfefefd0100fdfefefdfe",
        "000000FDFEFEFD0100FDFEFEFDFE",
        # Left(sys8) bytecodes (LLM's claim)
        "0108fdfefeff",
        "010AFDFEFEFF",
        # Left(sys8) = what quote(sys8) actually returns (just byte 08)
        "08",
        # Encoding failed! variants
        "Encoding failed!",
        "Encoding failed",
        "encoding failed!",
        "encoding failed",
        "ENCODING FAILED!",
        "Invalid term!",
        "Invalid term",
        "invalid term!",
        # Nicolaas Govert de Bruijn
        "Nicolaas Govert de Bruijn",
        "nicolaas govert de bruijn",
        # De Brown (brown = bruijn pun)
        "De Brown",
        "de brown",
        "DeBrown",
        "debrown",
        # "Dark magic" quote
        "dark magic",
        "Dark Magic",
        # Raw pair bytecodes as strings
        "0000fdfefe",  # A bytecode
        "0100fdfefe",  # B bytecode
        # Backdoor pair as text
        "pair(A,B)",
        "\\s.s(\\a.\\b.bb)(\\a.\\b.ab)",
        # l3st3r and space (solver names)
        "l3st3r",
        "space",
        # Combined: echo + special bytes
        "echo",
        "Echo",
        "253",
        "FD FE FF",
        "FDFEFF",
        # The actual sys8 bytecode
        "08",
        # sys8(nil) payload
        "0800fefefdff",
        # Possibility: answer is a number
        "3",
        "three",
        "Three",
        # Just "Left" or "Right"
        "Left(6)",
        "Left 6",
        # omega variations
        "ωω",
        "omega omega",
        "\\x.xx",
        # Permission + granted combo
        "Permission granted",
        "permission granted",
        "Access granted",
        "access granted",
    ]

    print(f"Testing {len(novel_candidates)} novel candidates...")
    found = False
    for i, cand in enumerate(novel_candidates):
        h = cand.encode("utf-8")
        for _ in range(ROUNDS):
            h = hashlib.sha1(h).hexdigest().encode("ascii")
        if h.decode("ascii") == TARGET:
            print(f"\n[+] FLAG FOUND: {cand!r}")
            found = True
            break
        if (i + 1) % 10 == 0:
            print(f"  ...tested {i + 1}/{len(novel_candidates)}")

    if not found:
        print(f"[-] No match in {len(novel_candidates)} novel candidates.")

    # ================================================================
    # DIRECTION 2: "Encoding failed!" via echo+quote CPS chain
    # echo(V_N)(λr. quote(r)(QD_shifted))
    # ================================================================
    print("\n" + "=" * 70)
    print("DIRECTION 2: Echo+Quote CPS chain — 'Encoding failed!' tests")
    print("=" * 70)

    # Test echo(V_N) → quote(result) for various N near the boundary
    # Under the CPS continuation λr:
    #   r = Var(0)
    #   quote = Var(4+1) = Var(5) (shifted by 1 lambda)
    #   QD_shifted = shift(QD, 1)
    qd_s1 = shift_term(QD_TERM, 1)

    for v_idx in [249, 250, 251, 252]:
        # echo(V_idx)(λr. quote(r)(QD_s1))
        inner = Lam(App(App(Var(5), Var(0)), qd_s1))
        term = App(App(g(14), Var(v_idx)), inner)
        run_named(f"echo_V{v_idx}_then_quote", term)

    # Also test: what if we DON'T use QD but a Bad QD for quote's result?
    # echo(V251)(λr. quote(r)(bad_qd_shifted))
    # Bad QD extracts Left payload and writes raw ASCII
    left_branch_bq = Lam(App(App(Var(4 + 2), Var(0)), Lam(Lam(Var(0)))))
    right_branch_bq = Lam(Lam(Lam(Var(0))))
    bad_qd = Lam(App(App(Var(0), left_branch_bq), right_branch_bq))
    bad_qd_s1 = shift_term(bad_qd, 1)

    for v_idx in [249, 250, 251, 252]:
        inner_bad = Lam(App(App(Var(5), Var(0)), bad_qd_s1))
        term = App(App(g(14), Var(v_idx)), inner_bad)
        run_named(f"echo_V{v_idx}_then_quote_badqd", term)

    # Direct test: sys4(sys14(V251)) as the LLM literally wrote it
    # This is App(Var(4), App(Var(14), Var(251))) — malformed CPS but test anyway
    term_literal = App(Var(4), App(Var(14), Var(251)))
    run_named("sys4_sys14_V251_literal_no_cont", term_literal)

    # With QD as continuation:
    term_literal_qd = App(App(Var(4), App(Var(14), Var(251))), QD_TERM)
    run_named("sys4_of_partial_echo_QD", term_literal_qd)

    # ================================================================
    # DIRECTION 3: Syntactic Success — quote various syscalls
    # quote(Var(8))(QD) — what does the serialized form of Var(8) look like?
    # ================================================================
    print("\n" + "=" * 70)
    print("DIRECTION 3: Quote various syscalls/terms — Syntactic Success")
    print("=" * 70)

    # quote(Var(8))(QD) — serialize the raw variable reference to sys8
    run_named("quote_var8", App(App(g(4), g(8)), QD_TERM))

    # quote(Var(14))(QD) — serialize echo
    run_named("quote_var14", App(App(g(4), g(14)), QD_TERM))

    # quote(Var(201))(QD) — serialize backdoor reference
    run_named("quote_var201", App(App(g(4), g(201)), QD_TERM))

    # quote(Var(42))(QD) — serialize towel
    run_named("quote_var42", App(App(g(4), g(42)), QD_TERM))

    # quote(nil)(QD) — serialize nil
    run_named("quote_nil", App(App(g(4), NIL), QD_TERM))

    # quote(App(Var(8), nil))(QD) — serialize sys8 partial application
    run_named("quote_sys8_nil", App(App(g(4), App(g(8), NIL)), QD_TERM))

    # ================================================================
    # DIRECTION 4: Hidden Tail Extractor
    # Use Bad QD to check for hidden data in sys42 and sys1(6) strings
    # Approach: drop N chars using Scott list operations, then print
    # ================================================================
    print("\n" + "=" * 70)
    print("DIRECTION 4: Hidden Tail Extractor — drop chars from strings")
    print("=" * 70)

    # Instead of the LLM's complex 24x unrolled dropper, use a simpler approach:
    # Apply the string (Scott list) directly to extract its tail.
    # A Scott cons cell: λc.λn. c head tail
    # Applied to (λh.λt. t) and nil: (cons (λh.λt.t) nil) = tail
    #
    # But this only drops ONE element. To drop N, we need recursion or unrolling.
    # Let's try a modest approach: drop a few and see if there's anything.

    # First: check sys42(nil)(bad_qd) — what does bad_qd give us for towel?
    run_named("sys42_nil_bad_qd", App(App(g(42), NIL), bad_qd))

    # Now: sys42(nil)(continuation that drops first 24 chars then prints rest)
    # Build: λresult. result (λtowel_str. [drop 24 from towel_str then print rest]) (λerr. nil)
    #
    # drop24_and_print = iterate 24 times: λL. L (λh.λt. t) nil
    # then: sys2(remaining)(nil)
    #
    # This is complex. Let's try a continuation that applies the result (Left(str))
    # to extract str, then drops elements.
    #
    # Simpler: use CPS chain:
    #   sys42(nil)(λresult. result
    #     (λstr. str (λh.λtail. tail (λh2.λtail2. ... sys2(tailN)(nil)... )) nil)
    #     (λerr. nil))
    #
    # Each drop adds 2 lambdas (λh.λt). After 24 drops we'd be at depth ~50+.
    # This will be HUGE. Let's try a smaller number first — drop 5 chars.

    # Alternative: Just try to get the TAIL of the towel string by using
    # a "skip and print" continuation.
    #
    # Actually, the most efficient test: use Bad QD on sys42 but with a
    # continuation that skips the Left/Right dispatch and just calls sys2
    # on whatever comes AFTER applying it. If there's hidden data, it would
    # be in the structure.

    # Let's build a "drop N then print" for small N values
    # drop_and_print(N) = λlist. [apply (λh.λt. t) N times to list] → sys2(result)(nil)

    # For N=24 (towel string length), build iteratively:
    # Start with the innermost: λlist_final. sys2(list_final)(nil_shifted)
    # Then wrap: λlist. list (λh.λt. [inner](t)) nil

    # Actually let me take a completely different approach.
    # The simplest test: call sys42(nil) with a continuation that extracts
    # the Left payload, then passes it to a "get tail after N drops" and prints.

    # Let's just do 3 tests at different drop counts: 24, 25, 26
    # Using unrolled drop.

    # Build drop_one: λL. L (λh.λt. t) nil
    # Careful with de Bruijn indices:
    # Under λL: L=V0
    #   L applied to (λh.λt. t) and nil
    #   (λh.λt. t) = Lam(Lam(Var(0)))  — inner t is V0
    #   nil = Lam(Lam(Var(0)))           — same structure
    # So: drop_one = Lam(App(App(Var(0), Lam(Lam(Var(0)))), Lam(Lam(Var(0)))))

    drop_one = Lam(App(App(Var(0), Lam(Lam(Var(0)))), Lam(Lam(Var(0)))))

    # Build drop_N by composing: drop_N(L) = drop_one(drop_one(...drop_one(L)...))
    # drop_N = λL. drop_one(drop_one(...(L)))
    # But each drop_one needs to be shifted for the nesting depth!
    # Actually since drop_one is a CLOSED term (no free vars), no shifting needed.

    # drop_N(L) = compose drop_one N times applied to L
    # As a lambda: drop_24 = λL. drop_one(drop_one(... drop_one(L) ...))
    # = λL. App(drop_one, App(drop_one, ... App(drop_one, Var(0)) ...))

    for drop_count in [24, 25, 30]:
        # Build the body: iterated application of drop_one to Var(0)
        body = Var(0)  # L
        for _ in range(drop_count):
            body = App(drop_one, body)
        drop_n = Lam(body)

        # Now: sys42(nil)(λresult. result (λstr. sys2(drop_N(str))(nil_s)) (λerr. nil_s))
        # Under λresult (depth 1): result=V0, sys2=V(2+1)=V3
        # Under λresult.λstr (depth 2): str=V0, sys2=V(2+2)=V4
        # nil_s inside depth 2: Lam(Lam(Var(0))) — closed, no shift

        # The left handler (depth 2): sys2(drop_N(str))(nil)
        # drop_N is closed, no shift needed
        inner_app = App(drop_n, Var(0))  # drop_N(str)
        left_h = Lam(App(App(Var(4), inner_app), Lam(Lam(Var(0)))))
        right_h = Lam(Lam(Lam(Var(0))))  # nil
        cont = Lam(App(App(Var(0), left_h), right_h))

        term = App(App(g(42), NIL), cont)

        # Check payload size
        enc = encode_term(term) + bytes([FF])
        if len(enc) > 2000:
            print(f"\n--- sys42_drop{drop_count}_print ---")
            print(f"  SKIP: Payload too large ({len(enc)}b > 2000b limit)")
        else:
            run_named(f"sys42_drop{drop_count}_print", term)

    # Same for sys1(6) — "Permission denied" is 17 chars
    for drop_count in [17, 18, 20]:
        body = Var(0)
        for _ in range(drop_count):
            body = App(drop_one, body)
        drop_n = Lam(body)

        # sys1(int(6))(λresult. result (λstr. sys2(drop_N(str))(nil)) (λerr. nil))
        left_h = Lam(App(App(Var(4), App(drop_n, Var(0))), Lam(Lam(Var(0)))))
        right_h = Lam(Lam(Lam(Var(0))))
        cont = Lam(App(App(Var(0), left_h), right_h))

        term = App(App(g(1), encode_byte_term(6)), cont)

        enc = encode_term(term) + bytes([FF])
        if len(enc) > 2000:
            print(f"\n--- sys1_6_drop{drop_count}_print ---")
            print(f"  SKIP: Payload too large ({len(enc)}b > 2000b limit)")
        else:
            run_named(f"sys1_6_drop{drop_count}_print", term)

    # ================================================================
    # DIRECTION 5: Quote the backdoor pair — sys201(nil)(λpair. quote(pair)(QD))
    # ================================================================
    print("\n" + "=" * 70)
    print("DIRECTION 5: Quote the backdoor pair")
    print("=" * 70)

    # CPS: sys201(nil)(λresult. result (λpair. quote(pair)(QD_s2)) (λerr. nil))
    # Unwrap the Either first, then quote the raw pair
    # Under λresult (d=1): result=V0, quote=V(4+1)=V5
    # Under λresult.λpair (d=2): pair=V0, quote=V(4+2)=V6
    qd_s2 = shift_term(QD_TERM, 2)

    left_h_5 = Lam(App(App(Var(6), Var(0)), shift_term(QD_TERM, 3)))
    # Wait — QD needs to be shifted by 3 (under λresult + λleft_handler + [inside left])
    # Actually: depth from top to pair handler = 2 (λresult, λpair)
    # quote = Var(4+2) = Var(6)
    # QD shifted by 2
    left_h_5 = Lam(App(App(Var(6), Var(0)), qd_s2))
    right_h_5 = Lam(Lam(Lam(Var(0))))
    unwrap_5 = Lam(App(App(Var(0), left_h_5), right_h_5))
    term_quote_pair = App(App(g(201), NIL), unwrap_5)
    run_named("sys201_quote_pair_unwrapped", term_quote_pair)

    # Also: quote the raw Left(pair) WITHOUT unwrapping
    # sys201(nil)(λresult. quote(result)(QD_s1))
    term_quote_left_pair = App(App(g(201), NIL), Lam(App(App(Var(5), Var(0)), qd_s1)))
    run_named("sys201_quote_left_pair", term_quote_left_pair)

    # Also: Bad QD version to get raw ASCII of quoted pair
    term_quote_pair_bad = App(
        App(g(201), NIL),
        Lam(
            App(
                App(
                    Var(0),  # result = Left(pair), dispatch
                    Lam(
                        App(
                            App(Var(6), Var(0)),  # quote(pair)
                            shift_term(bad_qd, 2),
                        )
                    ),  # bad_qd as cont for quote
                ),
                Lam(Lam(Lam(Var(0)))),  # error handler = nil
            )
        ),
    )
    run_named("sys201_quote_pair_bad_qd", term_quote_pair_bad)

    # ================================================================
    # BONUS: Hash-test any new strings we discover
    # ================================================================
    print("\n" + "=" * 70)
    print("DIRECTION 5b: Hash-test backdoor pair bytecodes")
    print("=" * 70)

    # Compute the correct backdoor pair bytecode
    A_comb = Lam(Lam(App(Var(0), Var(0))))
    B_comb = Lam(Lam(App(Var(1), Var(0))))
    pair_term = Lam(App(App(Var(0), A_comb), B_comb))

    pair_bytes = encode_term(pair_term)
    print(f"  Pair bytecode: {pair_bytes.hex()}")
    print(f"  Pair bytecode (uppercase): {pair_bytes.hex().upper()}")

    # A bytecode
    a_bytes = encode_term(A_comb)
    b_bytes = encode_term(B_comb)
    print(f"  A bytecode: {a_bytes.hex()}")
    print(f"  B bytecode: {b_bytes.hex()}")

    # Test these as hash candidates
    bytecode_candidates = [
        pair_bytes.hex(),
        pair_bytes.hex().upper(),
        a_bytes.hex(),
        a_bytes.hex().upper(),
        b_bytes.hex(),
        b_bytes.hex().upper(),
        # With FF terminator
        (pair_bytes + bytes([FF])).hex(),
        # Left-wrapped pair bytecode
        (bytes([0x01]) + pair_bytes + bytes([FD, FE, FE])).hex(),
    ]

    for cand in bytecode_candidates:
        h = cand.encode("utf-8")
        for _ in range(ROUNDS):
            h = hashlib.sha1(h).hexdigest().encode("ascii")
        if h.decode("ascii") == TARGET:
            print(f"\n[+] FLAG FOUND: {cand!r}")
            return
        else:
            print(f"  [-] No match: {cand!r}")

    print("\n" + "=" * 70)
    print("PROBE v15 COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
