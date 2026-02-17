#!/usr/bin/env python3
"""
BrownOS Interactive-Mode Probe

Oracle insight: We've been half-closing the socket every time (shutdown(SHUT_WR)),
which would prevent any interactive/multi-term protocol from working.

Hypothesis: syscall 8 might:
1. Read additional bytes/terms from the TCP stream after the first term
2. Not call the continuation on success (success = no output or non-FF output)
3. Need a tiny function (3 leaves) as argument, not a data value

Tests:
A. No half-close + send post-FF data (passwords, etc.)
B. Multi-term per connection (first term calls sys8, second term does something)
C. Detect success by absence of continuation call (use marker writes)
D. Test with 3-leaf function combinators
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


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


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        if term.i >= 0xFD:
            raise ValueError(f"Cannot encode Var({term.i})")
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported: {type(term)}")


def encode_byte_term(n: int) -> object:
    expr: object = Var(0)
    for idx, weight in (
        (1, 1),
        (2, 2),
        (3, 4),
        (4, 8),
        (5, 16),
        (6, 32),
        (7, 64),
        (8, 128),
    ):
        if n & weight:
            expr = App(Var(idx), expr)
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_bytes_list(bs: bytes) -> object:
    nil: object = Lam(Lam(Var(0)))

    def cons(h: object, t: object) -> object:
        return Lam(Lam(App(App(Var(1), h), t)))

    cur: object = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


nil = Lam(Lam(Var(0)))
I = Lam(Var(0))  # identity
K = Lam(Lam(Var(1)))  # constant
KI = App(K, I)  # λx.λy.y = false
A = Lam(Lam(App(Var(0), Var(0))))  # λab.(bb)
B = Lam(Lam(App(Var(1), Var(0))))  # λab.(ab)


def raw_connect(timeout_s=10.0):
    """Create a raw connection without half-close."""
    sock = socket.create_connection((HOST, PORT), timeout=timeout_s)
    sock.settimeout(timeout_s)
    return sock


def recv_all(sock, timeout_s=5.0):
    """Receive everything available within timeout."""
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
    return out


def recv_until_ff_or_timeout(sock, timeout_s=5.0):
    """Receive until FF or timeout, return (data, got_ff)."""
    sock.settimeout(timeout_s)
    out = b""
    got_ff = False
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
            if FF in chunk:
                got_ff = True
                break
        except socket.timeout:
            break
    return out, got_ff


# ============================================================
# TEST A: No half-close + send post-FF data
# ============================================================
def test_a_no_halfclose():
    """
    Send ((syscall8 nil) QD) without half-closing.
    Then send additional data (passwords) and see if anything changes.
    """
    print("\n=== TEST A: No Half-Close + Post-FF Data ===\n")

    term = App(
        App(Var(0x08), nil), Lam(Var(0))
    )  # ((sys8 nil) (λx.x))  - identity continuation
    payload = encode_term(term) + bytes([FF])

    # Passwords and commands to try after the first term
    post_data = [
        b"ilikephp\n",
        b"ilikephp",
        b"gizmore\n",
        b"dloser\n",
        b"su dloser\n",
        b"sudo su dloser\n",
        b"\x00\xfe\xfe\xff",  # nil + FF
        bytes([0x08, 0x00, FD]) + QD + bytes([FD, FF]),  # another sys8 call
    ]

    for i, extra in enumerate(post_data):
        try:
            sock = raw_connect()
            sock.sendall(payload)  # Send the first term
            time.sleep(0.5)

            # Check if anything came back before sending more
            resp1, got_ff1 = recv_until_ff_or_timeout(sock, timeout_s=1.0)
            if resp1:
                print(f"  [{i}] Pre-extra response: {resp1[:40].hex()} ff={got_ff1}")

            # Now send additional data WITHOUT half-close
            sock.sendall(extra)
            time.sleep(0.3)

            # Check for response
            resp2, got_ff2 = recv_until_ff_or_timeout(sock, timeout_s=3.0)
            status = "EMPTY"
            if resp2:
                try:
                    text = resp2.decode("latin-1", errors="replace")
                    status = f"{len(resp2)}b ff={got_ff2}: {text[:60]}"
                except:
                    status = f"{len(resp2)}b ff={got_ff2}: {resp2[:40].hex()}"
            print(f"  [{i}] extra={extra[:20]!r}: {status}")
            sock.close()
        except Exception as e:
            print(f"  [{i}] extra={extra[:20]!r}: ERROR {e}")
        time.sleep(0.3)


# ============================================================
# TEST B: Multi-term per connection
# ============================================================
def test_b_multi_term():
    """
    Send sys8 term, then send a second term (like QD applied to something)
    on the same connection.
    """
    print("\n=== TEST B: Multi-Term Per Connection ===\n")

    # First term: just sys8 with identity continuation (no QD print)
    term1 = App(App(Var(0x08), nil), I)
    payload1 = encode_term(term1) + bytes([FF])

    # Second terms to try
    second_terms = [
        (
            "QD applied to nil",
            bytes([0x04, 0x00, FE, FE, FD]) + QD + bytes([FD, FF]),
        ),  # quote nil → write
        (
            "write PING",
            bytes([0x02])
            + encode_term(encode_bytes_list(b"PING"))
            + bytes([FD, 0x00, FE, FE, FD, FF]),
        ),
        (
            "readfile(46) access.log",
            bytes([0x07])
            + encode_term(encode_byte_term(46))
            + bytes([FD])
            + QD
            + bytes([FD, FF]),
        ),
        ("sys8 nil QD", bytes([0x08, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])),
    ]

    for name, payload2 in second_terms:
        try:
            sock = raw_connect()
            sock.sendall(payload1)
            time.sleep(0.5)

            resp1, ff1 = recv_until_ff_or_timeout(sock, timeout_s=1.0)
            if resp1:
                print(f"  After term1: {resp1[:30].hex()} ff={ff1}")

            # Send second term
            sock.sendall(payload2)
            time.sleep(0.3)

            resp2, ff2 = recv_until_ff_or_timeout(sock, timeout_s=3.0)
            status = "EMPTY"
            if resp2:
                try:
                    text = resp2.decode("latin-1", errors="replace")
                    status = f"{len(resp2)}b ff={ff2}: {text[:60]}"
                except:
                    status = f"{len(resp2)}b ff={ff2}: {resp2[:40].hex()}"
            print(f"  [{name}]: {status}")
            sock.close()
        except Exception as e:
            print(f"  [{name}]: ERROR {e}")
        time.sleep(0.3)


# ============================================================
# TEST C: Success detection without QD
# ============================================================
def test_c_success_detection():
    """
    Call sys8 with marker writes in both branches.
    If Left branch executes, we write "L"; if Right branch, we write "R".
    If NEITHER is printed, sys8 might succeed without calling continuation.
    """
    print("\n=== TEST C: Success Detection via Branch Markers ===\n")

    # Build: ((sys8 arg) discriminator)
    # discriminator = λresult. ((result on_left) on_right)
    # on_left = λpayload. ((write "L") nil)
    # on_right = λcode. ((write "R") nil)
    # All at depth 1 (inside λresult)

    def build_disc(sys_num, arg, depth=0):
        """Build ((sys arg) disc) where disc writes L on Left, R on Right."""
        # write is at global position 2
        # At depth d+1 (inside λresult): write = Var(2+d+1)
        # At depth d+2 (inside on_left or on_right): write = Var(2+d+2)
        write_var = 2 + depth + 2
        L_bytes = encode_bytes_list(b"L")
        R_bytes = encode_bytes_list(b"R")

        # on_left at depth d+2: λpayload. ((write "L") nil)
        on_left = App(App(Var(write_var), L_bytes), nil)
        on_left_lam = Lam(on_left)

        # on_right at depth d+2: λcode. ((write "R") nil)
        on_right = App(App(Var(write_var), R_bytes), nil)
        on_right_lam = Lam(on_right)

        # discriminator at depth d+1: λresult. ((V0 on_left) on_right)
        disc_body = App(App(Var(0), on_left_lam), on_right_lam)
        disc = Lam(disc_body)

        # Full: ((sys arg) disc)
        return App(App(Var(sys_num), arg), disc)

    # Test various arguments
    args = [
        ("nil", nil),
        ("I", I),
        ("K", K),
        ("KI", KI),
        ("A", A),
        ("B", B),
        ("omega=(A B)", App(A, B)),
        ("(B A)", App(B, A)),
    ]

    for name, arg in args:
        try:
            term = build_disc(0x08, arg)
            payload = encode_term(term) + bytes([FF])

            sock = raw_connect()
            sock.sendall(payload)
            # DON'T half-close
            resp, got_ff = recv_until_ff_or_timeout(sock, timeout_s=4.0)

            if not resp:
                status = "NO OUTPUT (possible success?)"
            elif b"L" in resp and b"R" not in resp:
                status = f"*** LEFT (SUCCESS!) *** raw={resp[:40].hex()}"
            elif b"R" in resp:
                status = f"RIGHT (denied) raw={resp[:20].hex()}"
            elif b"Invalid term!" in resp:
                status = "Invalid term!"
            else:
                status = f"OTHER: {resp[:40].hex()}"

            print(f"  sys8({name}): {status}")
            sock.close()
        except Exception as e:
            print(f"  sys8({name}): ERROR {e}")
        time.sleep(0.25)


# ============================================================
# TEST D: 3-leaf function combinators
# ============================================================
def test_d_3leaf_functions():
    """
    The author says "My record is 3 leafs".
    Test all small terms with exactly 3 leaf nodes (Var nodes).
    These are FUNCTIONS, not data values.

    3-leaf patterns:
    - ((a b) c) = App(App(Var(x), Var(y)), Var(z))
    - (a (b c)) = App(Var(x), App(Var(y), Var(z)))
    - λ.((a b) c) = Lam(App(App(Var(x), Var(y)), Var(z)))
    - λ.(a (b c)) = Lam(App(Var(x), App(Var(y), Var(z))))
    - λ.λ.((a b) c) etc.
    """
    print("\n=== TEST D: 3-Leaf Function Combinators ===\n")

    # Relevant var indices for 3-leaf terms as arguments to sys8:
    # At top level: 0=V0, 1=V1 (but these are unbound at top level)
    # Under lambdas in the term: bound variables
    # For sys8's argument (a closed term), we need lambdas wrapping it

    # Let's test closed 3-leaf terms:
    # λ.λ.((V0 V1) V0) = 00 01 FD 00 FD FE FE  (3 leaves: V0, V1, V0)
    # λ.λ.((V1 V0) V0) etc.
    # λ.λ.(V0 (V1 V0))
    # λ.λ.(V1 (V0 V0))
    # λ.λ.((V0 V0) V1)
    # λ.λ.(V0 (V0 V1))

    # Also single lambda:
    # λ.((V0 V0) V0) = self-application squared?

    terms_2lam = []
    for pattern in ["aab", "aba", "baa", "bba", "bab", "abb"]:
        # a=V0, b=V1 for 2-lam terms
        for shape in ["((x y) z)", "(x (y z))"]:
            mapping = {"a": Var(0), "b": Var(1)}
            x, y, z = mapping[pattern[0]], mapping[pattern[1]], mapping[pattern[2]]
            if shape == "((x y) z)":
                body = App(App(x, y), z)
            else:
                body = App(x, App(y, z))
            term = Lam(Lam(body))
            terms_2lam.append(
                (
                    f"λλ.{shape.replace('x', pattern[0]).replace('y', pattern[1]).replace('z', pattern[2])}",
                    term,
                )
            )

    # Single lambda versions
    terms_1lam = []
    for p in ["aaa"]:
        x = y = z = Var(0)
        terms_1lam.append(("λ.((V0 V0) V0)", Lam(App(App(x, y), z))))
        terms_1lam.append(("λ.(V0 (V0 V0))", Lam(App(x, App(y, z)))))

    all_terms = terms_2lam + terms_1lam

    # Deduplicate by encoding
    seen = set()
    unique_terms = []
    for name, term in all_terms:
        enc = encode_term(term)
        if enc not in seen:
            seen.add(enc)
            unique_terms.append((name, term, enc))

    print(f"  Testing {len(unique_terms)} unique 3-leaf terms\n")

    for name, term, enc in unique_terms:
        try:
            # Use discriminator (L/R markers) instead of QD
            full = App(App(Var(0x08), term), Lam(Var(0)))  # identity continuation
            payload = encode_term(full) + bytes([FF])

            sock = raw_connect()
            sock.sendall(payload)
            resp, got_ff = recv_until_ff_or_timeout(sock, timeout_s=3.0)

            if not resp:
                status = "SILENT"
            elif b"Invalid term!" in resp:
                status = "Invalid term!"
            elif b"Encoding failed!" in resp:
                status = "Encoding failed!"
            else:
                status = f"{resp[:40].hex()} ff={got_ff}"

            # Also test with QD
            full_qd = App(App(Var(0x08), term), Lam(Lam(Var(0))))
            # Actually use QD properly
            full_qd = bytes([0x08]) + enc + bytes([FD]) + QD + bytes([FD, FF])
            sock2 = raw_connect()
            sock2.sendall(full_qd)
            resp2, ff2 = recv_until_ff_or_timeout(sock2, timeout_s=3.0)
            qd_status = "EMPTY" if not resp2 else resp2[:20].hex()

            print(f"  {name} [{enc.hex()}]: silent={status}, qd={qd_status}")

            sock.close()
            sock2.close()
        except Exception as e:
            print(f"  {name}: ERROR {e}")
        time.sleep(0.3)


# ============================================================
# TEST E: sys8 with no continuation at all
# ============================================================
def test_e_no_continuation():
    """
    What if sys8 should be called WITHOUT a continuation?
    Just (sys8 arg) with no second application.
    Or with multiple args: (((sys8 arg1) arg2) arg3)
    """
    print("\n=== TEST E: sys8 Without/With Multiple Continuations ===\n")

    # Pattern 1: Just (sys8 arg) - no continuation
    args = [nil, I, K, A, B, App(A, B)]
    arg_names = ["nil", "I", "K", "A", "B", "omega"]

    print("  --- No continuation: (sys8 arg) ---")
    for name, arg in zip(arg_names, args):
        try:
            term = App(Var(0x08), arg)
            payload = encode_term(term) + bytes([FF])
            sock = raw_connect()
            sock.sendall(payload)
            resp = recv_all(sock, timeout_s=3.0)
            status = "EMPTY" if not resp else f"{len(resp)}b: {resp[:30].hex()}"
            print(f"  (sys8 {name}): {status}")
            sock.close()
        except Exception as e:
            print(f"  (sys8 {name}): ERROR {e}")
        time.sleep(0.25)

    # Pattern 2: (((sys8 arg1) arg2) arg3) - 3 args
    print("\n  --- Three args: (((sys8 A) B) QD) ---")
    combos = [
        ("A,B,QD", A, B),
        ("B,A,QD", B, A),
        ("nil,nil,QD", nil, nil),
        ("I,nil,QD", I, nil),
        ("K,nil,QD", K, nil),
    ]
    for cname, arg1, arg2 in combos:
        try:
            # Use QD as third arg to capture output
            term = App(App(App(Var(0x08), arg1), arg2), Lam(Var(0)))
            payload = encode_term(term) + bytes([FF])
            sock = raw_connect()
            sock.sendall(payload)
            resp = recv_all(sock, timeout_s=4.0)
            status = "EMPTY" if not resp else f"{len(resp)}b: {resp[:30]}"
            print(f"  (((sys8 {cname})): {status}")
            sock.close()
        except Exception as e:
            print(f"  (((sys8 {cname})): ERROR {e}")
        time.sleep(0.25)


# ============================================================
# TEST F: Backdoor chain → sys8 (runtime values)
# ============================================================
def test_f_backdoor_chain_interactive():
    """
    Use backdoor to get pair at runtime, then feed to sys8.
    But this time: DON'T half-close, and send extra data after.
    """
    print("\n=== TEST F: Backdoor → sys8 (no half-close) ===\n")

    # Build: ((backdoor nil) λeither.
    #           ((either (λpair. ((sys8 pair) marker_disc))) ignore_right))
    # But without half-close, and then send extra data

    # CPS chain inline:
    # ((0xC9 nil) λeither. ((either λpair.((sys8 pair) I)) λerr.I))
    # Under λeither (depth 1):
    #   sys8 = Var(9), backdoor = Var(202)
    # Under λeither.λpair (depth 2):
    #   sys8 = Var(10)
    # Under λeither.λerr (depth 2):
    #   doesn't matter

    inner_left = Lam(App(App(Var(10), Var(0)), I))  # λpair.((sys8 pair) I)
    inner_right = Lam(I)  # λerr.I - ignore
    handler_body = App(App(Var(0), inner_left), inner_right)
    handler = Lam(handler_body)

    full_term = App(App(Var(0xC9), nil), handler)
    payload = encode_term(full_term) + bytes([FF])

    passwords = [b"ilikephp\n", b"ilikephp", b"\n", b"gizmore\n", b"dloser\n"]

    for pw in passwords:
        try:
            sock = raw_connect()
            sock.sendall(payload)
            time.sleep(0.5)

            resp1 = b""
            try:
                sock.settimeout(1.0)
                resp1 = sock.recv(4096)
            except socket.timeout:
                pass

            if resp1:
                print(f"  Pre-pw: {resp1[:30].hex()}")

            sock.sendall(pw)
            time.sleep(0.5)

            resp2 = recv_all(sock, timeout_s=3.0)
            status = "EMPTY" if not resp2 else f"{len(resp2)}b: {resp2[:40]}"
            print(f"  pw={pw!r}: {status}")
            sock.close()
        except Exception as e:
            print(f"  pw={pw!r}: ERROR {e}")
        time.sleep(0.3)


def main():
    print("=" * 70)
    print("BrownOS Interactive-Mode Probe")
    print("=" * 70)

    test_a_no_halfclose()
    test_b_multi_term()
    test_c_success_detection()
    test_d_3leaf_functions()
    test_e_no_continuation()
    test_f_backdoor_chain_interactive()

    print("\n" + "=" * 70)
    print("PROBE COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
