#!/usr/bin/env python3
"""
probe_llm_v16.py — Test LLM v16 proposals:
  1. echo(sys201(nil))(sys2)  — 3-leaf: echo wraps backdoor pair, pass to write
  2. echo(sys201(nil))(sys2) with QD continuation
  3. sys201(nil)(sys2)        — pair applied directly to write (pair acts as selector)
  4. sys201(nil) → pair → pair(sys2)(nil) — destructure: sys2(A)(B)
  5. echo(sys201(nil))(sys8)  — same as #1 but with sys8 instead of sys2
  6. Hash test semantic candidates
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

QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
QD_TERM = parse_term(QD_BYTES)

NIL = Lam(Lam(Var(0)))


# Convenience
def g(i: int) -> Var:
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


def run_named(name: str, term: object, delay: float = 0.5) -> bytes:
    """Encode term, send to server, print result."""
    payload = encode_term(term) + bytes([FF])
    print(f"\n--- {name} ---")
    print(f"  Term: {term}")
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
            except Exception as ex:
                print(f"  Parse error: {ex}")

    return resp


def hash_test(candidate: str) -> bool:
    """Test if iterated SHA1 of candidate matches target."""
    TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
    h = candidate.encode("utf-8")
    for _ in range(56154):
        h = hashlib.sha1(h).digest()
    result = h.hex()
    match = result == TARGET
    print(
        f"  hash^56154({candidate!r}) = {result[:20]}... {'MATCH!!!' if match else 'no match'}"
    )
    return match


def hash_test_bytes(label: str, raw: bytes) -> bool:
    """Test if iterated SHA1 of raw bytes matches target."""
    TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
    h = raw
    for _ in range(56154):
        h = hashlib.sha1(h).digest()
    result = h.hex()
    match = result == TARGET
    print(
        f"  hash^56154({label}) = {result[:20]}... {'MATCH!!!' if match else 'no match'}"
    )
    return match


def main() -> None:
    print("=" * 60)
    print("LLM v16 PROBE — Testing echo(backdoor)(write) and variants")
    print("=" * 60)

    # ================================================================
    # Test 1: echo(sys201(nil))(sys2) — The main v16 payload
    # AST: App(App(Var(14), App(Var(201), NIL)), Var(2))
    # This is a "bare" term — no CPS continuation. The VM beta-reduces:
    #   echo(sys201(nil)) → echo(Left(pair)) → Left(Left(pair))
    #   Then Left(Left(pair)) applied to Var(2):
    #     Left(Left(pair)) = λl.λr. l (Left(pair))
    #     Applied to Var(2): λr. Var(2)(Left(pair))
    #     Applied to nothing... this is partial application, result is a lambda
    # But the server evaluates to WHNF, so we'll see what comes back.
    # ================================================================
    echo_backdoor_write = App(App(g(14), App(g(201), NIL)), g(2))
    run_named("T1: echo(sys201(nil))(sys2) — bare, no QD", echo_backdoor_write)

    # ================================================================
    # Test 2: Same but with QD continuation
    # CPS: ((echo ((sys201 nil) id_cont)) write_cont)
    # Actually, let's do the CPS-correct version:
    # ((sys14 ((sys201 nil QD_continuation) echo_cont)) write_cont)
    # But that's complex. Let's try the simpler:
    # ((echo(sys201(nil))(sys2)) QD) — wrap with QD at the end
    # ================================================================
    echo_backdoor_write_qd = App(App(App(g(14), App(g(201), NIL)), g(2)), QD_TERM)
    run_named("T2: echo(sys201(nil))(sys2)(QD) — with QD", echo_backdoor_write_qd)

    # ================================================================
    # Test 3: Proper CPS chain:
    # sys201(nil) → pair, then echo(pair) → Left(pair), then sys2(Left(pair))(QD)
    # In CPS: ((sys201 nil) (λpair. ((sys14 pair) (λecho_result. ((sys2 echo_result) QD)))))
    # pair is Var(0) inside first lambda, echo_result is Var(0) inside second
    # ================================================================
    # Inner: ((sys2 Var(0)) QD_shifted)
    # QD needs to be shifted by +2 (we're under 2 lambdas)
    def shift_term(term, delta, cutoff=0):
        if isinstance(term, Var):
            return Var(term.i + delta) if term.i >= cutoff else term
        if isinstance(term, Lam):
            return Lam(shift_term(term.body, delta, cutoff + 1))
        if isinstance(term, App):
            return App(
                shift_term(term.f, delta, cutoff), shift_term(term.x, delta, cutoff)
            )
        raise TypeError(f"Unknown: {type(term)}")

    qd_shifted_2 = shift_term(QD_TERM, 2)
    inner_write = App(App(g(2), Var(0)), qd_shifted_2)  # ((sys2 echo_result) QD+2)

    qd_shifted_1 = shift_term(QD_TERM, 1)
    inner_echo = App(
        App(g(14), Var(0)), Lam(inner_write)
    )  # ((echo pair) (λ. write_chain))

    cps_chain = App(
        App(g(201), NIL), Lam(inner_echo)
    )  # ((sys201 nil) (λpair. echo_chain))
    run_named("T3: CPS chain — sys201→echo→sys2→QD", cps_chain)

    # ================================================================
    # Test 4: pair applied directly to sys2
    # sys201(nil) → pair = λs. s A B
    # pair(sys2) = sys2 A B = write(A)(B)
    # CPS: ((sys201 nil) (λpair. ((pair sys2_shifted) QD_shifted)))
    # Actually pair(sys2) = ((λs. s A B) sys2) = sys2 A B
    # But sys2 is CPS: sys2(bytestring)(continuation)
    # So sys2(A)(B) tries to write A (non-string!) with B as continuation
    # ================================================================
    inner_pair_write = App(App(Var(0), shift_term(g(2), 1)), shift_term(QD_TERM, 1))
    pair_to_write = App(App(g(201), NIL), Lam(inner_pair_write))
    run_named(
        "T4: sys201(nil)→pair→pair(sys2)(QD) — destructure pair into write",
        pair_to_write,
    )

    # ================================================================
    # Test 5: echo(sys201(nil))(sys8) — same idea but with sys8
    # Maybe the pair-as-cons idea works for sys8?
    # ================================================================
    echo_backdoor_sys8 = App(App(g(14), App(g(201), NIL)), g(8))
    run_named("T5: echo(sys201(nil))(sys8) — bare, no QD", echo_backdoor_sys8)

    # Test 5b: With QD
    echo_backdoor_sys8_qd = App(App(App(g(14), App(g(201), NIL)), g(8)), QD_TERM)
    run_named("T5b: echo(sys201(nil))(sys8)(QD) — with QD", echo_backdoor_sys8_qd)

    # ================================================================
    # Test 6: CPS chain echo→sys8
    # sys201(nil)→pair, echo(pair)→Left(pair), sys8(Left(pair))→???
    # ================================================================
    inner_sys8 = App(App(g(8), Var(0)), qd_shifted_2)  # ((sys8 echo_result) QD+2)
    inner_echo_sys8 = App(
        App(g(14), Var(0)), Lam(inner_sys8)
    )  # ((echo pair) (λ. sys8_chain))
    cps_chain_sys8 = App(App(g(201), NIL), Lam(inner_echo_sys8))
    run_named("T6: CPS chain — sys201→echo→sys8→QD", cps_chain_sys8)

    # ================================================================
    # Test 7: Direct write of backdoor pair (no echo)
    # sys201(nil)→pair, sys2(pair)(QD)
    # ================================================================
    inner_direct_write = App(App(g(2), Var(0)), shift_term(QD_TERM, 1))
    direct_write = App(App(g(201), NIL), Lam(inner_direct_write))
    run_named("T7: CPS — sys201→sys2(pair)→QD — direct write pair", direct_write)

    # ================================================================
    # Test 8: Quote the backdoor pair, then write it
    # sys201(nil)→pair, sys4(pair)→Left(bytecode), sys2(bytecode)(QD)
    # ================================================================
    inner_write_quoted = App(App(g(2), Var(0)), shift_term(QD_TERM, 2))
    inner_quote = App(App(g(4), Var(0)), Lam(inner_write_quoted))
    quote_then_write = App(App(g(201), NIL), Lam(inner_quote))
    run_named(
        "T8: CPS — sys201→sys4(pair)→sys2(bytecode)→QD — quote then write",
        quote_then_write,
    )

    # ================================================================
    # HASH TESTS — Semantic candidates from LLM v16
    # ================================================================
    print("\n" + "=" * 60)
    print("HASH TESTS — Semantic candidates")
    print("=" * 60)

    string_candidates = [
        "Mockingbird",
        "mockingbird",
        "Identity",
        "identity",
        "omega",
        "Omega",
        "M I",
        "MI",
        r"\x.xx",
        r"\x. x x",
        "\\x.xx",
        "\\x. x x",
        "λx.xx",
        "λx. x x",
        "Left(pair)",
        "Left pair",
        "sys201",
        "backdoor",
        "pair",
        "dark magic",
        "Dark Magic",
        "echo",
        "Echo",
        "self-application",
        "self application",
        "Y combinator",
        "Y",
        "fix",
        "Fix",
        "Ω",
        "ω",
        "little omega",
        "big omega",
        "M",  # Mockingbird = M combinator = λx.xx
        "B",  # B combinator
        "S",  # S combinator
        "I",  # Identity
        "K",  # Constant
        "W",  # Warbler = λxy.xyy
        "SKK",
        "SII",
    ]

    byte_candidates = [
        ("A bytecode: 00 00 FD FE FE", bytes.fromhex("0000fdfefe")),
        ("B bytecode: 01 00 FD FE FE", bytes.fromhex("0100fdfefe")),
        ("pair bytecode", bytes.fromhex("000000fdfefefd0100fdfefefdfe")),
        ("omega bytecode: 00 00 FD FE", bytes.fromhex("0000fdfe")),
        ("0x08", bytes([0x08])),
        ("00 FE FE (nil)", bytes.fromhex("00fefe")),
        ("FD (app marker)", bytes([0xFD])),
        (
            "0E C9 00 FE FE FD FD 02 FD (corrected v16 payload)",
            bytes.fromhex("0ec900fefefdfd02fd"),
        ),
    ]

    found_match = False
    for candidate in string_candidates:
        if hash_test(candidate):
            found_match = True
            print(f"\n  *** MATCH FOUND: {candidate!r} ***\n")

    for label, raw in byte_candidates:
        if hash_test_bytes(label, raw):
            found_match = True
            print(f"\n  *** MATCH FOUND: {label} ***\n")

    if not found_match:
        print("\n  No hash matches found among semantic candidates.")

    print("\n" + "=" * 60)
    print("DONE")
    print("=" * 60)


if __name__ == "__main__":
    main()
