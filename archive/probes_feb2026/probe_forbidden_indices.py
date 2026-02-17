#!/usr/bin/env python3
"""
Probe BrownOS sys8 with "forbidden index" arguments (de Bruijn indices 253-255).

Key insight: indices 253 (FD), 254 (FE), 255 (FF) cannot be encoded on the wire
directly, but CAN be created inside the VM through beta-reduction/shifting.
Our previous observations ALWAYS used quote (syscall 4) via QD, which would fail
silently ("Encoding failed!") on any result containing these indices.

This probe:
1. Builds a quote-FREE debug continuation to observe results
2. Manufactures forbidden-index terms via beta-reduction
3. Tests sys8 with these terms
4. Uses PRE/POST sentinels to detect silent successes
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FD,
    FE,
    FF,
    encode_term,
    encode_byte_term,
    encode_bytes_list,
    parse_term,
    decode_either,
    decode_bytes_list,
)

HOST = "wc3.wechall.net"
PORT = 61221

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

# --- Named term builder (from probe_mail_focus.py) ---


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


def shift_db(term: object, delta: int, cutoff: int = 0) -> object:
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_db(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_db(term.f, delta, cutoff), shift_db(term.x, delta, cutoff))
    return term


def to_db(term: object, env: tuple[str, ...] = ()) -> object:
    if isinstance(term, NVar):
        try:
            return Var(env.index(term.name))
        except ValueError as exc:
            raise ValueError(f"Unbound name: {term.name}") from exc
    if isinstance(term, NGlob):
        return Var(term.index + len(env))
    if isinstance(term, NLam):
        return Lam(to_db(term.body, (term.param,) + env))
    if isinstance(term, NApp):
        return App(to_db(term.f, env), to_db(term.x, env))
    if isinstance(term, NConst):
        return shift_db(term.term, len(env))
    raise TypeError(f"Unsupported: {type(term)}")


def g(i: int) -> NGlob:
    return NGlob(i)


def v(n: str) -> NVar:
    return NVar(n)


def lam(p: str, b: object) -> NLam:
    return NLam(p, b)


def app(f: object, x: object) -> NApp:
    return NApp(f, x)


def apps(*ts: object) -> object:
    out = ts[0]
    for t in ts[1:]:
        out = app(out, t)
    return out


NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)


def int_n(n: int) -> NConst:
    return NConst(encode_byte_term(n))


def str_term(s: str) -> NConst:
    return NConst(encode_bytes_list(s.encode()))


# --- Network ---


def recv_all(sock: socket.socket, timeout_s: float) -> bytes:
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


def query_raw(payload: bytes, timeout_s: float = 5.0, retries: int = 3) -> bytes:
    delay = 0.15
    for attempt in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s=timeout_s)
        except Exception:
            time.sleep(delay)
            delay = min(delay * 2.0, 2.0)
    return b""


def send_named(term: object, timeout_s: float = 5.0) -> bytes:
    payload = encode_term(to_db(term)) + bytes([FF])
    return query_raw(payload, timeout_s=timeout_s)


def classify(out: bytes) -> str:
    if not out:
        return "EMPTY"
    if out.startswith(b"Invalid term!"):
        return "INVALID"
    if out.startswith(b"Encoding failed!"):
        return "ENCFAIL"
    if out.startswith(b"Term too big!"):
        return "TOOBIG"
    try:
        text = out.decode("ascii", errors="replace")
        if text.isprintable() or all(c in "\r\n\t" or c.isprintable() for c in text):
            return f"TEXT:{text[:80]}"
    except Exception:
        pass
    return f"HEX:{out[:40].hex()}"


# ==========================================================================
# PHASE 1: Quote-free debug continuation (DBG)
# ==========================================================================
#
# DBG: λresult. result (λleftval. write("L")) (λrightval. error_string(rightval, λerrbytes. write(errbytes)))
#
# On Left(x):  prints "L" to socket
# On Right(n): prints the error string for error code n
#
# This avoids syscall 0x04 (quote) entirely!


def make_dbg_either() -> object:
    """
    Quote-free Either observer.
    On Left(x): writes "L:<some marker>"
    On Right(n): calls error_string(n) then writes the result string
    """
    # For Right branch: error_string(n) -> Left(str) -> write(str)
    right_branch = lam(
        "errcode",
        apps(
            g(1),
            v("errcode"),
            lam(
                "es_result",
                apps(
                    v("es_result"),
                    lam(
                        "errstr", apps(g(2), v("errstr"), NIL)
                    ),  # write the error string
                    lam("es_err", NIL),  # error_string itself failed (shouldn't happen)
                ),
            ),
        ),
    )

    # For Left branch: write "L" marker
    left_branch = lam("leftval", apps(g(2), str_term("L"), NIL))

    # Either discriminator: λresult. result left_handler right_handler
    return lam("result", apps(v("result"), left_branch, right_branch))


def make_dbg_left_write() -> object:
    """
    Quote-free Either observer - on Left(x), assumes x is a byte string and writes it.
    On Right(n), writes the error string.
    """
    right_branch = lam(
        "errcode",
        apps(
            g(1),
            v("errcode"),
            lam(
                "es_result",
                apps(
                    v("es_result"),
                    lam("errstr", apps(g(2), v("errstr"), NIL)),
                    lam("es_err", NIL),
                ),
            ),
        ),
    )

    left_branch = lam("leftval", apps(g(2), v("leftval"), NIL))

    return lam("result", apps(v("result"), left_branch, right_branch))


def make_sentinel_wrap(
    inner_term: object, pre: str = "PRE|", post: str = "|POST"
) -> object:
    """
    Wraps a term so it writes PRE before and POST after.
    write(pre, λ_. inner_term → ... → write(post, nil))

    But since inner_term already includes its own continuation, we need to
    chain: write(pre) -> inner_eval -> write(post)
    """
    # Write POST after inner completes
    # inner_term should end with a continuation that writes POST
    return apps(
        g(2),
        str_term(pre),
        lam(
            "_pre",
            inner_term,  # inner_term should handle its own output
        ),
    )


def main():
    print("=" * 60)
    print("PROBE: Forbidden Indices & Quote-Free Observation")
    print("=" * 60)

    DBG = make_dbg_either()
    DBG_WRITE = make_dbg_left_write()

    # ------------------------------------------------------------------
    # PHASE 1: Sanity check DBG on known syscalls
    # ------------------------------------------------------------------
    print("\n--- PHASE 1: Sanity check DBG (quote-free observer) ---")

    # Test 1a: towel (0x2A) - should return Left("Oh, go choke on a towel!")
    print("\n[1a] towel(nil) with DBG_WRITE:")
    out = send_named(apps(g(0x2A), NIL, DBG_WRITE))
    print(f"  -> {classify(out)}")

    # Test 1b: name(0) - should return Left("/")
    print("\n[1b] name(0) with DBG_WRITE:")
    out = send_named(apps(g(6), int_n(0), DBG_WRITE))
    print(f"  -> {classify(out)}")

    # Test 1c: sys8(nil) with DBG - should show "Permission denied"
    print("\n[1c] sys8(nil) with DBG (error string observer):")
    out = send_named(apps(g(8), NIL, DBG))
    print(f"  -> {classify(out)}")

    # Test 1d: sys8(nil) with QD for comparison
    print("\n[1d] sys8(nil) with QD (standard):")
    out = send_named(apps(g(8), NIL, NConst(parse_term(QD + bytes([FF])))))
    print(f"  -> {classify(out)}")
    time.sleep(0.1)

    # ------------------------------------------------------------------
    # PHASE 2: PRE/POST sentinel to detect if sys8 ever succeeds silently
    # ------------------------------------------------------------------
    print("\n--- PHASE 2: PRE/POST sentinel pattern ---")

    # Pattern: write("PRE|") → sys8(arg) → λresult. write("|POST")
    # If sys8 calls its continuation, we get PRE|...|POST
    # If sys8 doesn't call continuation (hangs/crashes), we get PRE| only

    post_cont = lam("_result", apps(g(2), str_term("|POST"), NIL))

    tests_sentinel = [
        ("nil", NIL),
        ("int_0", int_n(0)),
        ("int_42", int_n(42)),
    ]

    for name, arg in tests_sentinel:
        term = apps(g(2), str_term("PRE|"), lam("_", apps(g(8), arg, post_cont)))
        out = send_named(term)
        print(f"  sys8({name}): {classify(out)}")
        time.sleep(0.1)

    # ------------------------------------------------------------------
    # PHASE 3: Manufacture forbidden-index terms via beta-reduction
    # ------------------------------------------------------------------
    print("\n--- PHASE 3: Forbidden index terms via beta-reduction ---")

    # Strategy: Create a term that, after beta-reduction inside the VM,
    # contains Var(253), Var(254), or Var(255).
    #
    # Method 1: (λx. x) applied to a Var that, under enough lambdas,
    # will shift to 253+.
    #
    # Actually, the trick is: if we place Var(252) inside a lambda that
    # gets applied in a context where it shifts up, we get 253+.
    #
    # Simpler approach: use echo syscall on globals 251, 252.
    # echo(g(251)) returns Left(payload) where payload = g(251) shifted by +2
    # under the Left wrapper = Var(253) in the raw term.
    # If we DON'T unwrap via quote, we pass this as-is to sys8.
    #
    # echo(g(251)) → Left(val_with_253) → use val_with_253 as sys8 arg

    # Method: echo(g(N)) → result → result(λleftval. sys8(leftval, DBG))(λrightval. write("E"))

    def echo_into_sys8(echo_arg_idx: int, use_dbg: object) -> object:
        """echo(g(N)) → result → on Left(x): sys8(x, dbg)"""
        return apps(
            g(0x0E),
            g(echo_arg_idx),
            lam(
                "echo_result",
                apps(
                    v("echo_result"),
                    lam("leftval", apps(g(8), v("leftval"), use_dbg)),
                    lam("rightval", apps(g(2), str_term("ECHO_ERR"), NIL)),
                ),
            ),
        )

    # Test with echo of "safe" globals first (as control)
    for idx in [0, 1, 2, 4, 8, 14, 42]:
        out = send_named(echo_into_sys8(idx, DBG))
        print(f"  echo(g({idx})) → sys8(Left_val): {classify(out)}")
        time.sleep(0.1)

    print()

    # NOW test with "dangerous" globals near the boundary
    for idx in [250, 251, 252]:
        out = send_named(echo_into_sys8(idx, DBG))
        print(f"  echo(g({idx})) → sys8(Left_val): {classify(out)}")
        time.sleep(0.1)

    # ------------------------------------------------------------------
    # PHASE 4: Direct forbidden-index construction via shifting
    # ------------------------------------------------------------------
    print("\n--- PHASE 4: Direct forbidden-index construction ---")

    # Approach: Build terms where after beta-reduction, a variable
    # that was Var(252) gets shifted to Var(253+).
    #
    # Term: (λx. λdummy. x) Var(252)
    # After beta: λdummy. Var(252) -- but wait, Var(252) is free so it
    # shifts to Var(253) inside the lambda!
    # Actually no -- (λx. λd. x) applied to Var(252):
    # body = λd. x where x is bound to Var(252)
    # After substitution: λd. Var(252) -- but Var(252) was free,
    # so inside the new lambda it refers to the same thing shifted: Var(253)
    # Wait, let me think again. In de Bruijn:
    # (λ. λ. Var(1)) Var(252) → substitute Var(0)→Var(252) in λ.Var(1)
    # Var(1) in body of outer lambda: after removing outer lambda,
    # Var(1) refers to the argument, so it becomes Var(252).
    # But it's still under one lambda (the inner one), so the free
    # Var(252) correctly refers to global 252 from inside that lambda.
    #
    # Actually the key question is: does the VM's syscall dispatch happen
    # on the reduced term? If sys8 sees the RAW unreduced application tree,
    # the indices are as-written. If it reduces first, they could shift.
    #
    # Let's try a different approach: build the argument AS a closure.
    # sys8( (λ. Var(253+shift)) ) -- but we can't write Var(253) on wire!
    #
    # The ONLY way to get forbidden indices into the VM is through
    # echo syscall or through variable capture/shifting during reduction.

    # Method: Use echo to capture a Left-wrapped high-index global,
    # then DON'T unwrap the Either -- pass the WHOLE Either to sys8.
    # The Either Left(x) = λl.λr.(l x) where x has the forbidden index.

    # Also try: pass the Left-wrapped value through identity first
    # to see if reduction exposes the inner term

    # Method 2: Use a Scott pair to extract and pass through

    # echo(g(251)) gives Left(val) where val internally is Var(253)
    # If we extract val via: result(λleft. left)(λright. right),
    # does the extracted value retain the forbidden index?

    # Let's try: echo(g(251)) → result → result (λx.x) (λx.x)
    # This extracts the Left payload directly, which should be a term
    # with internal Var(253). Then we chain that into sys8.

    def echo_extract_into_sys8(echo_arg_idx: int, use_dbg: object) -> object:
        """echo(g(N)) → extract Left payload → sys8(payload, dbg)"""
        return apps(
            g(0x0E),
            g(echo_arg_idx),
            lam(
                "echo_result",
                # Extract: result (λx. sys8(x, dbg)) (λerr. write("E"))
                apps(
                    v("echo_result"),
                    lam("payload", apps(g(8), v("payload"), use_dbg)),
                    lam("err", apps(g(2), str_term("E"), NIL)),
                ),
            ),
        )

    for idx in [250, 251, 252]:
        out = send_named(echo_extract_into_sys8(idx, DBG))
        print(f"  echo(g({idx})) extract → sys8(payload): {classify(out)}")
        time.sleep(0.1)

    # ------------------------------------------------------------------
    # PHASE 5: sys8 with the WHOLE Left-wrapped echo result (not extracted)
    # ------------------------------------------------------------------
    print("\n--- PHASE 5: sys8 with whole Left-wrapped echo result ---")

    def echo_whole_into_sys8(echo_arg_idx: int, use_dbg: object) -> object:
        """echo(g(N)) → sys8(whole_either_result, dbg)"""
        return apps(
            g(0x0E),
            g(echo_arg_idx),
            lam("echo_result", apps(g(8), v("echo_result"), use_dbg)),
        )

    for idx in [0, 1, 2, 4, 8, 14, 42, 201, 250, 251, 252]:
        out = send_named(echo_whole_into_sys8(idx, DBG))
        print(f"  echo(g({idx})) whole → sys8: {classify(out)}")
        time.sleep(0.1)

    # ------------------------------------------------------------------
    # PHASE 6: Backdoor pair components with forbidden indices
    # ------------------------------------------------------------------
    print("\n--- PHASE 6: Backdoor pair + forbidden-index combinations ---")

    # Get backdoor pair, then apply it to echo'd high-index globals
    # backdoor(nil) → Left(pair) → echo(g(251)) → Left(v253) →
    # pair(v253) = ((v253 A) B) → sys8(result, dbg)

    def backdoor_pair_with_echo_arg(echo_idx: int, use_dbg: object) -> object:
        """backdoor(nil) → pair → echo(g(N)) → val → sys8(pair(val), dbg)"""
        return apps(
            g(201),
            NIL,
            lam(
                "bd_result",
                apps(
                    v("bd_result"),
                    lam(
                        "pair",  # Left branch: got the pair
                        apps(
                            g(0x0E),
                            g(echo_idx),
                            lam(
                                "echo_result",
                                apps(
                                    v("echo_result"),
                                    lam(
                                        "eval",  # Left from echo
                                        apps(g(8), apps(v("pair"), v("eval")), use_dbg),
                                    ),
                                    lam("eerr", apps(g(2), str_term("EE"), NIL)),
                                ),
                            ),
                        ),
                    ),
                    lam("bd_err", apps(g(2), str_term("BE"), NIL)),
                ),
            ),
        )

    for idx in [250, 251, 252]:
        out = send_named(backdoor_pair_with_echo_arg(idx, DBG))
        print(f"  bd_pair(echo(g({idx}))): {classify(out)}")
        time.sleep(0.1)

    # ------------------------------------------------------------------
    # PHASE 7: Systematic ?? ?? FD QD FD exploration
    # ------------------------------------------------------------------
    print("\n--- PHASE 7: Systematic g(i)(g(j)) with QD ---")
    print("  (The 'second example' from cheat sheet: ?? ?? FD QD FD)")

    # The author hints this pattern reveals "crucial properties"
    # Let's try self-application: g(i)(g(i)) and cross-application g(i)(g(j))
    # for all active syscall indices

    active_globals = [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]

    # Self-application with QD
    print("\n  Self-application g(i)(g(i)) with QD:")
    for i in active_globals:
        term = apps(g(i), g(i), NConst(parse_term(QD + bytes([FF]))))
        out = send_named(term, timeout_s=5.0)
        result = classify(out)
        if result != "EMPTY":
            print(f"    g({i})(g({i})) → {result}")
        time.sleep(0.08)

    # Cross-application between active syscalls
    print("\n  Cross-application g(i)(g(j)) with QD (non-empty only):")
    for i in active_globals:
        for j in active_globals:
            if i == j:
                continue
            term = apps(g(i), g(j), NConst(parse_term(QD + bytes([FF]))))
            out = send_named(term, timeout_s=5.0)
            result = classify(out)
            if result != "EMPTY":
                print(f"    g({i})(g({j})) → {result}")
            time.sleep(0.05)

    # ------------------------------------------------------------------
    # PHASE 8: g(0) investigation (the "kernel"?)
    # ------------------------------------------------------------------
    print("\n--- PHASE 8: g(0) deep investigation ---")

    # g(0) is not a syscall (no Right(1)), not stuck in all cases
    # What if g(0) IS the kernel and needs specific arguments?

    # Test g(0) with various arguments and DBG
    test_args = [
        ("nil", NIL),
        ("int_0", int_n(0)),
        ("int_8", int_n(8)),
        ("g(8)", g(8)),
        ("g(201)", g(201)),
        ("str_ilikephp", str_term("ilikephp")),
    ]

    for name, arg in test_args:
        # g(0)(arg)(DBG)
        term = apps(g(0), arg, DBG)
        out = send_named(term, timeout_s=5.0)
        print(f"  g(0)({name})(DBG): {classify(out)}")
        time.sleep(0.1)

    # g(0) with sentinel
    for name, arg in test_args[:3]:
        post_cont2 = lam("_result", apps(g(2), str_term("|POST"), NIL))
        term = apps(g(2), str_term("PRE|"), lam("_", apps(g(0), arg, post_cont2)))
        out = send_named(term, timeout_s=5.0)
        print(f"  PRE|g(0)({name})|POST: {classify(out)}")
        time.sleep(0.1)

    print("\n" + "=" * 60)
    print("PROBE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
