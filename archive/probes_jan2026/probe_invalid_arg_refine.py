#!/usr/bin/env python3
"""
REFINING THE "INVALID ARGUMENT" BREAKTHROUGH

Test 1 returned "Invalid argument" (error 2) instead of "Permission denied" (error 3)!
This means syscall 8 IS processing Var(253) differently - it gets further before rejecting.

What does syscall 8 expect? Looking at other syscalls:
- syscall 7 (read): takes path (string)
- syscall 6 (opendir): takes path (string)
- syscall 8 (unknown): takes ???

Theory: syscall 8 might want a PAIR (path, something) or a specific structure.

Let's test different argument structures with Var(253):
1. Var(253) alone - gives "Invalid argument" ✓
2. Pair(Var(253), nil)
3. Pair(Var(253), Var(253))
4. List containing Var(253)
5. Var(253) applied to something

Also test: What if we need MULTIPLE special vars together?
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
nil = Lam(Lam(Var(0)))  # λλ.V0 (Scott nil / Right unit)
identity = Lam(Var(0))  # λ.V0


# Pair constructor: λx.λy.λf. f x y
def make_pair(a, b):
    """Scott pair: λf. f a b"""
    return Lam(App(App(Var(0), a), b))


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


def build_simple_debugger(depth_offset=0):
    """
    Simple debugger: on success write "S", on error write error string.
    """
    write_idx = 2 + depth_offset
    error_idx = 1 + depth_offset

    # Left handler: write "S" for success
    left_handler = Lam(App(App(Var(write_idx + 1), encode_string("S")), nil))

    # Right handler: convert error to string and write
    right_handler = Lam(  # error code at Var(0)
        App(
            App(Var(error_idx + 1), Var(0)),  # error_string(code)
            Lam(  # error string result at Var(0)
                App(
                    App(
                        Var(0), Lam(App(App(Var(write_idx + 3), Var(0)), nil))
                    ),  # Left: write string
                    Lam(
                        App(App(Var(write_idx + 3), encode_string("?")), nil)
                    ),  # Right: write "?"
                )
            ),
        )
    )

    return Lam(App(App(Var(0), left_handler), right_handler))


def test_syscall8_with_extracted_v253(arg_builder, test_name):
    """
    Generic test: extract v253 via echo(251), then pass built arg to syscall8.

    arg_builder: function(v253_var) -> term to pass to syscall8
                 v253_var will be Var(0) in the extraction context
    """
    print(f"\n{'=' * 70}")
    print(f"TEST: {test_name}")
    print("=" * 70)

    debugger = build_simple_debugger(depth_offset=1)
    debugger_s = shift(debugger, 1)

    # After extracting v253: it's at Var(0)
    # syscall8 is at Var(8+1) = Var(9)

    # Build the argument using v253 at Var(0)
    arg = arg_builder(Var(0))

    use_payload = Lam(  # v253 at Var(0)
        App(
            App(Var(9), arg),  # (syscall8 arg)
            debugger_s,
        )
    )

    handle_err = Lam(App(App(Var(4), encode_string("E")), nil))

    cont = Lam(  # echo result at Var(0)
        App(App(Var(0), use_payload), handle_err)
    )

    payload = bytes([0x0E, 251, FD]) + encode_term(cont) + bytes([FD, FF])

    print(f"Payload size: {len(payload)} bytes")
    resp = query(payload)
    print(f"Response: {resp}")
    if resp:
        print(f"Hex: {resp.hex()}")
    return resp


def test_syscall8_with_two_extracted_vars(arg_builder, test_name, inner_echo_arg=252):
    """
    Extract v253 AND v254 via chained echoes, then build arg.

    arg_builder: function(v253_var, v254_var) -> term
                 v253 will be Var(1), v254 will be Var(0) in innermost context
    """
    print(f"\n{'=' * 70}")
    print(f"TEST: {test_name}")
    print("=" * 70)

    debugger = build_simple_debugger(depth_offset=2)
    debugger_s = shift(debugger, 2)

    # Inner: v253 at Var(1), v254 at Var(0)
    # syscall8 at depth 2: Var(8+2) = Var(10)

    arg = arg_builder(Var(1), Var(0))

    inner_use = Lam(  # v254 at Var(0), v253 at Var(1)
        App(
            App(Var(10), arg),  # (syscall8 arg)
            debugger_s,
        )
    )

    inner_err = Lam(App(App(Var(5), encode_string("E2")), nil))

    # After extracting v253, call echo(inner_echo_arg) then extract v254
    middle_cont = Lam(  # echo252 result at Var(0), v253 at Var(1)
        App(App(Var(0), inner_use), inner_err)
    )

    after_v253 = Lam(  # v253 at Var(0)
        App(
            App(Var(0x0E + 1), Var(inner_echo_arg)),  # echo(inner_echo_arg)
            middle_cont,
        )
    )

    outer_err = Lam(App(App(Var(4), encode_string("E1")), nil))

    outer_cont = Lam(  # echo251 result at Var(0)
        App(App(Var(0), after_v253), outer_err)
    )

    payload = bytes([0x0E, 251, FD]) + encode_term(outer_cont) + bytes([FD, FF])

    print(f"Payload size: {len(payload)} bytes")
    resp = query(payload)
    print(f"Response: {resp}")
    if resp:
        print(f"Hex: {resp.hex()}")
    return resp


def main():
    print("REFINING THE 'INVALID ARGUMENT' BREAKTHROUGH")
    print("Syscall 8 accepts v253 differently - it returns error 2 instead of 3!")
    print()

    # Test 1: Baseline - v253 alone (should give "Invalid argument")
    test_syscall8_with_extracted_v253(lambda v253: v253, "Baseline: v253 alone")
    time.sleep(0.3)

    # Test 2: Pair(v253, nil) - maybe it wants a pair?
    test_syscall8_with_extracted_v253(
        lambda v253: make_pair(v253, nil), "Pair(v253, nil)"
    )
    time.sleep(0.3)

    # Test 3: Pair(nil, v253) - order might matter
    test_syscall8_with_extracted_v253(
        lambda v253: make_pair(nil, v253), "Pair(nil, v253)"
    )
    time.sleep(0.3)

    # Test 4: (v253 nil) - apply v253 to nil
    test_syscall8_with_extracted_v253(
        lambda v253: App(v253, nil), "(v253 nil) - apply to nil"
    )
    time.sleep(0.3)

    # Test 5: (v253 v253) - apply v253 to itself
    test_syscall8_with_extracted_v253(
        lambda v253: App(v253, v253), "(v253 v253) - self-application"
    )
    time.sleep(0.3)

    # Test 6: Pair(v253, v253)
    test_syscall8_with_extracted_v253(
        lambda v253: make_pair(v253, v253), "Pair(v253, v253)"
    )
    time.sleep(0.3)

    # Test 7: List with v253 as head
    test_syscall8_with_extracted_v253(
        lambda v253: Lam(Lam(App(App(Var(1), v253), nil))),  # cons(v253, nil) shifted
        "Cons(v253, nil) - list with v253",
    )
    time.sleep(0.3)

    # Test 8: Two vars - Pair(v253, v254)
    test_syscall8_with_two_extracted_vars(
        lambda v253, v254: make_pair(v253, v254), "Pair(v253, v254)"
    )
    time.sleep(0.3)

    # Test 9: Two vars - (v253 v254)
    test_syscall8_with_two_extracted_vars(
        lambda v253, v254: App(v253, v254), "(v253 v254) - apply v253 to v254"
    )
    time.sleep(0.3)

    # Test 10: Two vars - (v254 v253) - reversed
    test_syscall8_with_two_extracted_vars(
        lambda v253, v254: App(v254, v253), "(v254 v253) - reversed application"
    )
    time.sleep(0.3)

    # Test 11: Maybe syscall 8 wants a specific path string WITH v253 prepended?
    # Like v253 is a prefix or modifier
    path_etc = encode_string("/etc")
    test_syscall8_with_extracted_v253(
        lambda v253: make_pair(v253, shift(path_etc, 1)),
        "Pair(v253, '/etc') - v253 as path modifier",
    )
    time.sleep(0.3)

    # Test 12: v253 applied to a path
    test_syscall8_with_extracted_v253(
        lambda v253: App(v253, shift(encode_string("/etc"), 1)),
        "(v253 '/etc') - v253 applied to path",
    )

    print("\n" + "=" * 70)
    print("TESTS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
