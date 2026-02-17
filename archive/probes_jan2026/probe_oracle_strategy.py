#!/usr/bin/env python3
"""
ORACLE STRATEGY PROBE

Based on Oracle's analysis:
1. Echo creates "index capture" - Var(253-255) reference hidden globals
2. "3 leafs" = ((v253 v254) v255) or (v253 (v254 v255))
3. Need a "no-quote debugger" continuation that doesn't use quote
4. Test if v253 is a callable capability

Key insight: Don't shift back when extracting - intentionally retarget to hidden globals.
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
PORT = 61221
FD, FE, FF = 0xFD, 0xFE, 0xFF


@dataclass(frozen=True)
class Var:
    i: int


@dataclass(frozen=True)
class Lam:
    body: object


@dataclass(frozen=True)
class App:
    f: object
    x: object


def encode_term(term) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unknown: {type(term)}")


def query(payload: bytes, timeout_s: float = 8.0) -> bytes:
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(timeout_s)
            out = b""
            start = time.time()
            while time.time() - start < timeout_s:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out += chunk
                except socket.timeout:
                    break
            return out
    except Exception as e:
        return f"ERROR: {e}".encode()


# Basic terms
nil = Lam(Lam(Var(0)))  # λλ.V0
identity = Lam(Var(0))  # λ.V0


def make_church(n):
    """Create Church numeral for byte encoding."""
    expr = Var(0)
    for idx, weight in [
        (8, 128),
        (7, 64),
        (6, 32),
        (5, 16),
        (4, 8),
        (3, 4),
        (2, 2),
        (1, 1),
    ]:
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_string(s: str):
    """Encode a string as a Scott list of bytes."""

    def encode_byte(n):
        expr = Var(0)
        for idx, weight in [
            (8, 128),
            (7, 64),
            (6, 32),
            (5, 16),
            (4, 8),
            (3, 4),
            (2, 2),
            (1, 1),
        ]:
            if n & weight:
                expr = App(Var(idx), expr)
        term = expr
        for _ in range(9):
            term = Lam(term)
        return term

    def cons(h, t):
        return Lam(Lam(App(App(Var(1), h), t)))

    cur = nil
    for b in reversed(s.encode()):
        cur = cons(encode_byte(b), cur)
    return cur


def shift(term, delta, cutoff=0):
    """Shift de Bruijn indices by delta for indices >= cutoff."""
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    return term


def build_no_quote_debugger(depth_offset=0):
    """
    Build a debugger continuation that doesn't use quote.

    On Right(n): call error_string(n) then write it
    On Left(x): write marker "L" then try to write x if it's bytes

    Continuation receives Either at Var(0).
    Syscalls at depth: write=2+offset, error_string=1+offset
    """
    # Syscall indices at top level
    write_idx = 2 + depth_offset
    error_idx = 1 + depth_offset

    # For Right branch: stringify error code then write
    # Right(n) = λl.λr. r n
    # So we need to handle: result is at Var(0), apply to handlers

    # Left handler: writes "L" then nil (success marker)
    left_handler = Lam(  # receives x
        App(App(Var(write_idx + 1), encode_string("L")), nil)
    )

    # Right handler: writes error code as string
    # error_string(n) returns Left(bytes) -> write it
    right_handler = Lam(  # receives error code n at Var(0)
        App(
            App(Var(error_idx + 1), Var(0)),  # error_string(n)
            Lam(  # error result
                App(
                    App(
                        Var(0),  # Either
                        Lam(App(App(Var(write_idx + 3), Var(0)), nil)),  # Left: write
                    ),
                    Lam(
                        App(App(Var(write_idx + 3), encode_string("?")), nil)
                    ),  # Right: write "?"
                )
            ),
        )
    )

    # Apply result to handlers: (result left_handler right_handler)
    debugger = Lam(  # result at Var(0)
        App(App(Var(0), left_handler), right_handler)
    )

    return debugger


def test_extract_v253_no_shift():
    """
    Extract Var(253) from echo WITHOUT shifting back.

    echo(251) -> Left(Var(253))
    Left = λl.λr. l payload -> payload at depth+2

    If we extract payload WITHOUT shifting, it still references global 253.
    """
    print("=" * 70)
    print("TEST 1: Extract Var(253) without shifting back")
    print("=" * 70)

    # Build: echo(251) -> extract payload -> use directly with syscall 8
    # The key insight: DON'T shift the extracted value

    # Continuation for echo: handles Left(payload) where payload = Var(253)
    # Inside this λ, we're at depth 1 from echo continuation
    # Var(0) = echo result (Either)
    # To extract: (result identity error_handler)
    # Then use extracted payload directly

    # After extraction, Var(0) = the payload (Var(253) at runtime)
    # Syscalls: at depth 2 from top (echo cont + extraction cont)
    # syscall8 = Var(8 + 2) = Var(10)

    # Use no-quote debugger at depth 2
    debugger = build_no_quote_debugger(depth_offset=2)

    # Extraction: (echo_result identity err_handler) -> payload
    # Then: (syscall8 payload) debugger

    extraction_cont = Lam(  # echo result at Var(0)
        App(
            App(Var(0), identity),  # extract Left payload
            Lam(  # error handler - print "E"
                App(App(Var(4), encode_string("E")), nil)
            ),
        )
    )

    # But wait - this just extracts, doesn't use with syscall8
    # Let me rebuild properly

    # echo(251) -> λcont. (echoResult cont)
    # cont receives Left(Var(253))
    # Inside cont: result = Var(0)
    # To extract: (Var(0) λpayload. USE_PAYLOAD λerr. HANDLE_ERR)

    # USE_PAYLOAD: payload at Var(0), syscall8 at Var(8+1)=Var(9)
    # Call: ((syscall8 payload) debugger)

    debugger_shifted = shift(debugger, 1)  # shift for inner lambda

    use_payload = Lam(  # payload at Var(0)
        App(
            App(Var(9), Var(0)),  # (syscall8 payload)
            debugger_shifted,
        )
    )

    handle_err = Lam(  # error at Var(0)
        App(App(Var(4), encode_string("E")), nil)  # write "E"
    )

    cont = Lam(  # echo result at Var(0)
        App(App(Var(0), use_payload), handle_err)
    )

    # Full program: ((echo 251) cont)
    payload = bytes([0x0E, 251, FD]) + encode_term(cont) + bytes([FD, FF])

    print(f"Payload hex: {payload.hex()}")
    resp = query(payload)
    print(f"Response: {resp}")
    if resp:
        print(f"Hex: {resp.hex()}")

    return resp


def test_3leaf_v253_v254_v255():
    """
    Test the "3 leafs" pattern: ((v253 v254) v255) as syscall 8 argument.

    Need to chain echoes:
    - echo(251) -> Var(253)
    - echo(252) -> Var(254)
    - echo(253) fails, so we need double echo: echo(echo(251)) for Var(255)?

    Actually: echo(n) -> Left(Var(n+2))
    So: echo(253) would give Left(Var(255)), but 253 parses as FD...

    Alternative: Use echo twice on 251 to get Var(255)?
    No - echo takes a term argument, not the result of previous echo.

    Let's try: echo(251) for v253, echo(252) for v254
    For v255: need to chain echoes inside continuations
    """
    print("\n" + "=" * 70)
    print("TEST 2: Build ((v253 v254) v255) as syscall 8 argument")
    print("=" * 70)

    # This is complex - need to:
    # 1. echo(251) -> extract v253
    # 2. echo(252) -> extract v254
    # 3. For v255, chain: echo(251) -> extract v253 -> echo(v253) -> v255

    # Actually, to use v253 as an argument to echo, we can't because
    # echo expects a de Bruijn index at top level

    # But we can build the term inside a deep continuation:
    # After extracting v253 and v254, we have them as Var(0) and Var(1)
    # We need Var(255) = Var(253 + 2) = echo(Var(253))
    # But Var(253) is just a runtime value, can we pass it to echo?

    # In CPS: ((echo extractedV253) λv255. USE)
    # Where extractedV253 is bound to some Var(n)

    # This requires nested echoes in continuations

    # Let me try a simpler version first:
    # Just test ((v253 v254) v0) - using nil as third leaf

    debugger = build_no_quote_debugger(depth_offset=3)
    debugger_s = shift(debugger, 3)

    # echo(251) -> extract v253
    # echo(252) -> extract v254
    # Build ((v253 v254) nil) and pass to syscall8

    # After two extractions: v253 at Var(1), v254 at Var(0)
    # 3-leaf term: ((Var(1) Var(0)) nil)

    three_leaf = App(App(Var(1), Var(0)), nil)

    inner_cont = Lam(  # v254 at Var(0), v253 at Var(1)
        App(
            App(Var(10), three_leaf),  # syscall8 at depth 2+8
            debugger_s,
        )
    )

    # Extract v254 from echo(252)
    middle_cont = Lam(  # echo252 result at Var(0), v253 at Var(1)
        App(
            App(Var(0), inner_cont),  # extract Left
            Lam(App(App(Var(5), encode_string("E2")), nil)),
        )
    )

    # After extracting v253, call echo(252)
    after_v253 = Lam(  # v253 at Var(0)
        App(
            App(Var(0x0E + 1), Var(252)),  # echo(252), echo at depth 1
            middle_cont,
        )
    )

    # Extract v253 from echo(251)
    outer_cont = Lam(  # echo251 result at Var(0)
        App(App(Var(0), after_v253), Lam(App(App(Var(4), encode_string("E1")), nil)))
    )

    payload = bytes([0x0E, 251, FD]) + encode_term(outer_cont) + bytes([FD, FF])

    print(f"Testing ((v253 v254) nil) as syscall8 argument")
    print(f"Payload hex: {payload.hex()[:80]}...")
    resp = query(payload)
    print(f"Response: {resp}")
    if resp:
        print(f"Hex: {resp.hex()}")

    return resp


def test_v253_as_callable():
    """
    Test if v253 is a callable (hidden syscall).

    ((v253 nil) debugger) - treat v253 as a syscall
    """
    print("\n" + "=" * 70)
    print("TEST 3: Treat Var(253) as callable syscall")
    print("=" * 70)

    debugger = build_no_quote_debugger(depth_offset=1)
    debugger_s = shift(debugger, 1)

    # After extracting v253: it's at Var(0)
    # Try: ((v253 nil) debugger)

    use_as_syscall = Lam(  # v253 at Var(0)
        App(
            App(Var(0), nil),  # (v253 nil)
            debugger_s,
        )
    )

    outer_cont = Lam(  # echo result at Var(0)
        App(App(Var(0), use_as_syscall), Lam(App(App(Var(4), encode_string("E")), nil)))
    )

    payload = bytes([0x0E, 251, FD]) + encode_term(outer_cont) + bytes([FD, FF])

    print(f"Testing ((v253 nil) debugger)")
    resp = query(payload)
    print(f"Response: {resp}")
    if resp:
        print(f"Hex: {resp.hex()}")

    return resp


def test_v253_applied_to_syscall8():
    """
    Test: (v253 syscall8) - apply v253 to syscall reference
    """
    print("\n" + "=" * 70)
    print("TEST 4: Apply v253 TO syscall8 reference")
    print("=" * 70)

    debugger = build_no_quote_debugger(depth_offset=1)
    debugger_s = shift(debugger, 1)

    # After extracting v253: it's at Var(0)
    # syscall8 is Var(8+1) = Var(9)
    # Try: ((v253 syscall8) debugger)

    use_v253 = Lam(  # v253 at Var(0)
        App(
            App(Var(0), Var(9)),  # (v253 syscall8)
            debugger_s,
        )
    )

    outer_cont = Lam(  # echo result at Var(0)
        App(App(Var(0), use_v253), Lam(App(App(Var(4), encode_string("E")), nil)))
    )

    payload = bytes([0x0E, 251, FD]) + encode_term(outer_cont) + bytes([FD, FF])

    print(f"Testing ((v253 syscall8) debugger)")
    resp = query(payload)
    print(f"Response: {resp}")
    if resp:
        print(f"Hex: {resp.hex()}")

    return resp


def test_v253_as_continuation():
    """
    Oracle alternative: maybe the capability is in continuation position.

    ((syscall8 nil) v253) - use v253 as continuation
    """
    print("\n" + "=" * 70)
    print("TEST 5: Use v253 as syscall8's CONTINUATION")
    print("=" * 70)

    # After extracting v253: it's at Var(0)
    # syscall8 is Var(9)
    # Try: ((syscall8 nil) v253)

    use_as_cont = Lam(  # v253 at Var(0)
        App(
            App(Var(9), nil),  # (syscall8 nil)
            Var(0),  # v253 as continuation
        )
    )

    outer_cont = Lam(  # echo result at Var(0)
        App(App(Var(0), use_as_cont), Lam(App(App(Var(4), encode_string("E")), nil)))
    )

    payload = bytes([0x0E, 251, FD]) + encode_term(outer_cont) + bytes([FD, FF])

    print(f"Testing ((syscall8 nil) v253)")
    resp = query(payload)
    print(f"Response: {resp}")
    if resp:
        print(f"Hex: {resp.hex()}")

    return resp


def main():
    print("ORACLE STRATEGY PROBE")
    print("Based on deep analysis of index capture trick")
    print()

    test_extract_v253_no_shift()
    time.sleep(0.3)

    test_3leaf_v253_v254_v255()
    time.sleep(0.3)

    test_v253_as_callable()
    time.sleep(0.3)

    test_v253_applied_to_syscall8()
    time.sleep(0.3)

    test_v253_as_continuation()

    print("\n" + "=" * 70)
    print("ORACLE STRATEGY PROBE COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
