#!/usr/bin/env python3
"""
probe_llm_v14.py — Test LLM v14 proposals:
  Direction 4: "Bad QD" ASCII extractor sweeping sys1(N) for hidden error strings
  Direction 5: sys42(backdoor_pair) with both standard QD and Bad QD
  Bonus: sys8(nil) with standard QD (IP auth sanity check)
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    encode_term,
    encode_byte_term,
    encode_bytes_list,
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

# Standard QD from challenge cheat sheet
QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
QD_TERM = parse_term(QD_BYTES)

# nil = λλ.V0
NIL = Lam(Lam(Var(0)))


def g(i: int) -> Var:
    """Global variable reference (syscall or builtin at index i)."""
    return Var(i)


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


def run_named(name: str, term: object, delay: float = 0.4) -> bytes:
    """Encode term, send to server, print result."""
    payload = encode_term(term) + bytes([FF])
    print(f"\n--- {name} ---")
    print(f"  Payload ({len(payload)}b): {payload.hex()}")

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
            print(f"  Result: HEX={hex_str[:120]} ({len(resp)}b)")

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
    print("PROBE v14: Bad QD ASCII Extractor + sys42(backdoor) + IP auth check")
    print("=" * 70)

    # ================================================================
    # PART 0: IP Auth sanity check — sys8(nil)(QD)
    # If IP matters, this might suddenly return Left(flag) instead of Right(6)
    # ================================================================
    print("\n" + "=" * 70)
    print("PART 0: IP Auth Sanity Check — sys8(nil)(QD)")
    print("=" * 70)

    # Standard: ((sys8 nil) QD)
    term_ip_check = App(App(g(8), NIL), QD_TERM)
    run_named("sys8_nil_QD_ipcheck", term_ip_check)

    # ================================================================
    # PART 1: "Bad QD" — ASCII extractor continuation
    # Bad QD = λx. x (λleft_val. ((sys2 left_val) nil)) (λright_val. nil)
    # If x = Left(string), dispatches to left branch → sys2(string)(nil) → prints raw ASCII
    # If x = Right(err), dispatches to right branch → nil → silent
    # ================================================================
    print("\n" + "=" * 70)
    print("PART 1: Bad QD ASCII Extractor — sys1(N) sweep")
    print("=" * 70)

    # Build Bad QD:
    # λx. ((x (λleft_val. ((sys2 left_val) nil_shifted))) (λright_val. nil_shifted))
    #
    # Under λx:                V0 = x
    # Under λx.λleft_val:      V0 = left_val, V1 = x, V3 = sys2
    # Under λx.λright_val:     V0 = right_val, V1 = x
    #
    # nil inside 2 lambdas (λx, λleft_val) = Lam(Lam(Var(0)))
    # sys2 inside 2 lambdas = Var(2+2) = Var(4)... wait, no.
    # Globals don't shift. g(2) = Var(2) at top level.
    # Under λx: g(2) = Var(3)
    # Under λx.λleft_val: g(2) = Var(4)
    #
    # Actually — globals DO shift because they are free variables in the term,
    # and de Bruijn indices for free variables increase under each lambda.
    #
    # Wait — in this VM, Var(N) for N >= number_of_enclosing_lambdas refers to
    # the global at index (N - number_of_enclosing_lambdas).
    # So Var(2) at top level = global 2 = sys2.
    # Under 1 lambda: global 2 = Var(3).
    # Under 2 lambdas: global 2 = Var(4).
    #
    # Let's build it step by step using the simpler approach:
    # Bad QD = λresult. result (λval. ((sys2_shifted val) nil_inner)) (λerr. nil_inner2)
    #
    # Under λresult (depth 1):
    #   result = Var(0)
    #   sys2 = Var(2+1) = Var(3)
    #
    # Left branch: λval (depth 2 from top):
    #   val = Var(0)
    #   sys2 = Var(2+2) = Var(4)
    #   nil = Lam(Lam(Var(0)))  — nil is a closed term, doesn't need shifting
    #   body: App(App(Var(4), Var(0)), Lam(Lam(Var(0))))
    #
    # Right branch: λerr (depth 2 from top):
    #   body: Lam(Lam(Var(0)))  — just nil, do nothing

    left_branch = Lam(App(App(Var(4), Var(0)), Lam(Lam(Var(0)))))
    right_branch = Lam(Lam(Lam(Var(0))))  # nil (ignore error)
    bad_qd = Lam(App(App(Var(0), left_branch), right_branch))

    # Test: sys1(N)(bad_qd) for various N
    # sys1 = error string lookup. Known: 0=Exception, 1=NotImpl, 2=InvalidArg,
    # 3=NoSuchFile, 4=NotDir, 5=NotFile, 6=PermDenied, 7=RateLimit
    # Let's sweep wider: 0-15, then some special values

    test_ns = list(range(16)) + [42, 56, 100, 128, 201, 253, 254, 255]
    # Remove duplicates
    test_ns = sorted(set(test_ns))

    for n in test_ns:
        # ((sys1 int(N)) bad_qd)
        term = App(App(g(1), encode_byte_term(n)), bad_qd)
        run_named(f"sys1({n})_bad_qd", term)

    # ================================================================
    # PART 2: Also try sys1(N) with STANDARD QD for comparison
    # This will show the serialized term form instead of raw ASCII
    # ================================================================
    print("\n" + "=" * 70)
    print("PART 2: sys1(N) with Standard QD — comparison (selected values)")
    print("=" * 70)

    for n in [8, 9, 10, 42, 201, 253, 254, 255]:
        term = App(App(g(1), encode_byte_term(n)), QD_TERM)
        run_named(f"sys1({n})_std_qd", term)

    # ================================================================
    # PART 3: sys42(backdoor_pair) — "3-Leaf Decoy Interaction"
    # The idea: sys42's C++ hook might check if arg == Left(pair)
    # Leaf count: sys42(1) + sys201(1) + nil(1) = 3 leaves
    #
    # But we need a continuation! So we need:
    #   ((sys42 ((sys201 nil) (λpair. pair))) QD)
    # Wait, that's more than 3 leaves.
    #
    # Actually the LLM says the term is: sys42(sys201(nil))(bad_qd)
    # But sys201(nil) is NOT a 1-step call — it's CPS.
    # sys201(nil)(cont) returns Left(pair) to cont.
    # So we need to chain: sys201(nil)(λpair. sys42(pair)(QD_shifted))
    #
    # Let me build it both ways:
    # A) Naive: ((sys42 ((sys201 nil) id)) QD) — but sys201 CPS means this is wrong
    # B) Correct CPS chain: ((sys201 nil) (λresult. ((sys42 result) QD_shifted)))
    # ================================================================
    print("\n" + "=" * 70)
    print("PART 3: sys42 with backdoor pair — Decoy Interaction")
    print("=" * 70)

    # B) Correct CPS: sys201(nil)(λresult. sys42(result)(QD_shifted))
    # Under λresult (depth 1):
    #   result = Var(0)
    #   sys42 = Var(42+1) = Var(43)
    #   QD needs shifting by 1
    #
    # We need to shift QD_TERM by 1 (add 1 to all free vars)
    def shift_term(term, delta, cutoff=0):
        """Shift free variables in term by delta, with cutoff for bound vars."""
        if isinstance(term, Var):
            if term.i >= cutoff:
                return Var(term.i + delta)
            return term
        if isinstance(term, Lam):
            return Lam(shift_term(term.body, delta, cutoff + 1))
        if isinstance(term, App):
            return App(
                shift_term(term.f, delta, cutoff), shift_term(term.x, delta, cutoff)
            )
        raise TypeError(f"Unknown term type: {type(term)}")

    qd_shifted_1 = shift_term(QD_TERM, 1)

    # sys201(nil) → continuation λresult. sys42(result)(QD_shifted)
    inner_cont = Lam(App(App(Var(43), Var(0)), qd_shifted_1))
    term_decoy_cps = App(App(g(201), NIL), inner_cont)
    run_named("sys42_backdoor_cps", term_decoy_cps)

    # Also try with bad_qd as continuation for sys42
    bad_qd_shifted_1 = shift_term(bad_qd, 1)
    inner_cont_bad = Lam(App(App(Var(43), Var(0)), bad_qd_shifted_1))
    term_decoy_bad = App(App(g(201), NIL), inner_cont_bad)
    run_named("sys42_backdoor_bad_qd", term_decoy_bad)

    # C) Also try the UNWRAPPED pair → sys42
    # sys201 returns Left(pair). So result = Left(pair).
    # We should unwrap the Either first:
    # sys201(nil)(λeither. either (λpair. sys42(pair)(QD_shifted2)) (λerr. nil))
    qd_shifted_2 = shift_term(QD_TERM, 2)
    left_handler = Lam(App(App(Var(44), Var(0)), shift_term(QD_TERM, 3)))
    # Var(44) = sys42 shifted by 3 (under λeither, λpair, plus original depth)
    # Wait, let me recalculate:
    # Top level: sys42 = Var(42)
    # Under λeither (CPS cont for sys201): sys42 = Var(43)
    # Under λeither.λpair (left handler): sys42 = Var(44)
    # QD shifted by 3 (under λresult from sys201 cont, λeither applied, λpair)
    # Actually QD is at depth 0 at top. Under 3 lambdas: shift by 3.
    # Hmm, there's only 2 lambdas: λeither and λpair. So shift by 2.
    # Wait — the CPS continuation for sys201 is already 1 lambda. Then the either
    # dispatch adds another lambda for the left handler. So that's 2 total.
    # sys42 at depth 2 = Var(42+2) = Var(44). QD shifted by 2.

    left_handler_unwrap = Lam(App(App(Var(44), Var(0)), qd_shifted_2))
    right_handler_unwrap = Lam(Lam(Lam(Var(0))))  # nil
    unwrap_cont = Lam(App(App(Var(0), left_handler_unwrap), right_handler_unwrap))
    term_decoy_unwrap = App(App(g(201), NIL), unwrap_cont)
    run_named("sys42_backdoor_unwrapped", term_decoy_unwrap)

    # ================================================================
    # PART 4: Direct sys42 tests with various args (standard QD)
    # ================================================================
    print("\n" + "=" * 70)
    print("PART 4: sys42 with various args (standard QD)")
    print("=" * 70)

    # sys42(nil)(QD) — the standard towel call
    run_named("sys42_nil", App(App(g(42), NIL), QD_TERM))

    # sys42(A)(QD) where A = λλ.(V0 V0)
    A_comb = Lam(Lam(App(Var(0), Var(0))))
    run_named("sys42_A", App(App(g(42), A_comb), QD_TERM))

    # sys42(B)(QD) where B = λλ.(V1 V0)
    B_comb = Lam(Lam(App(Var(1), Var(0))))
    run_named("sys42_B", App(App(g(42), B_comb), QD_TERM))

    # sys42(pair)(QD) where pair = λs.(s A B)
    pair_term = Lam(App(App(Var(0), A_comb), B_comb))
    run_named("sys42_pair_direct", App(App(g(42), pair_term), QD_TERM))

    # ================================================================
    # PART 5: Echo interactions — echo(Var(252)) and quote the result
    # ================================================================
    print("\n" + "=" * 70)
    print("PART 5: Echo + Quote edge cases")
    print("=" * 70)

    # echo(Var(252))(QD) — does this create Var(254)?
    run_named("echo_252", App(App(g(14), Var(252)), QD_TERM))

    # echo(Var(250))(QD) — creates Var(252)?
    run_named("echo_250", App(App(g(14), Var(250)), QD_TERM))

    # echo(Var(0))(QD) — baseline
    run_named("echo_0", App(App(g(14), Var(0)), QD_TERM))

    # quote(Left(Var(253)))(QD) — should give "Encoding failed!"
    # We need to construct Left(Var(253)) = Lam(Lam(App(Var(1), Var(255))))
    # Wait — Var(253) at top. Under 2 lambdas (Left wrapper): Var(253+2) = Var(255)
    left_253 = Lam(Lam(App(Var(1), Var(255))))
    run_named("quote_left_v253", App(App(g(4), left_253), QD_TERM))

    print("\n" + "=" * 70)
    print("PROBE v14 COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
