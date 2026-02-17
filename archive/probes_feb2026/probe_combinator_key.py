#!/usr/bin/env python3
"""
BrownOS Combinator Key Probe

The backdoor gives us A and B. What if the "key" to syscall 8 is a specific
combination of these combinators?

A = λab.(b b) - ignores first arg, self-applies second
B = λab.(a b) - applies first to second

Combinations to try:
- (A B) = ω = λx.(x x) - omega combinator
- (B A)
- (A A)
- (B B)
- A, B alone
- (A (B A)), (B (A B)), etc.

Also: what about Y combinator? Y = λf.(λx.f(xx))(λx.f(xx))
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
            raise ValueError(f"Cannot encode Var({term.i}) - reserved byte")
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported term: {type(term)}")


def parse_term(data: bytes) -> object:
    stack = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            if len(stack) < 2:
                return None
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            if not stack:
                return None
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    return stack[0] if stack else None


def query_raw(payload: bytes, timeout_s: float = 8.0) -> bytes:
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
        return b""


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def strip_lams(term, n):
    cur = term
    for _ in range(n):
        if not isinstance(cur, Lam):
            return None
        cur = cur.body
    return cur


def eval_bitset_expr(expr) -> int:
    if isinstance(expr, Var):
        return WEIGHTS.get(expr.i, 0)
    if isinstance(expr, App) and isinstance(expr.f, Var):
        return WEIGHTS.get(expr.f.i, 0) + eval_bitset_expr(expr.x)
    return 0


def decode_int_term(term) -> int:
    body = strip_lams(term, 9)
    if body:
        return eval_bitset_expr(body)
    return -1


def decode_either(term):
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        return None, None
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var):
        if body.f.i == 1:
            return "Left", body.x
        elif body.f.i == 0:
            return "Right", body.x
    return None, None


def decode_string(term) -> str:
    chars = []
    cur = term
    while True:
        inner = strip_lams(cur, 2)
        if inner is None:
            break
        if isinstance(inner, Var) and inner.i == 0:
            break
        if isinstance(inner, App) and isinstance(inner.f, App):
            head_app = inner.f
            if isinstance(head_app.f, Var) and head_app.f.i == 1:
                char_term = head_app.x
                ch = decode_int_term(char_term)
                if ch >= 0:
                    chars.append(chr(ch) if 0x20 <= ch < 0x7F else f"\\x{ch:02x}")
                cur = inner.x
                continue
        break
    return "".join(chars)


nil = Lam(Lam(Var(0)))
qd_term = parse_term(QD + bytes([FF]))

# Backdoor combinators
A = Lam(Lam(App(Var(0), Var(0))))  # λab.(b b)
B = Lam(Lam(App(Var(1), Var(0))))  # λab.(a b)

# Derived combinators
omega = App(A, B)  # ω = λx.(x x)
AA = App(A, A)
BB = App(B, B)
BA = App(B, A)
AB = App(A, B)  # same as omega

# More complex combinations
ABA = App(A, BA)
BAB = App(B, AB)
AAA = App(A, AA)
BBB = App(B, BB)


def test_syscall8(name: str, arg: object) -> str:
    """Test syscall8 with given argument and QD continuation."""
    term = App(App(Var(0x08), arg), qd_term)
    payload = encode_term(term) + bytes([FF])
    response = query_raw(payload)

    if not response:
        return "NO OUTPUT"
    if b"Invalid term!" in response:
        return "Invalid term!"
    if b"Encoding failed!" in response:
        return "Encoding failed!"
    if FF not in response:
        return f"RAW: {response[:30]}"

    resp_term = parse_term(response)
    if not resp_term:
        return f"Parse failed"

    tag, payload_term = decode_either(resp_term)
    if tag == "Right":
        err = decode_int_term(payload_term)
        errors = {
            0: "Exception",
            1: "NotImpl",
            2: "InvalidArg",
            3: "NoSuchFile",
            4: "NotDir",
            5: "NotFile",
            6: "PermDenied",
            7: "RateLimit",
        }
        return f"Right({err})={errors.get(err, '?')}"
    elif tag == "Left":
        # SUCCESS! Try to decode
        try:
            content = decode_string(payload_term)
            return f"LEFT! content={repr(content[:50])}"
        except:
            return f"LEFT! (complex payload)"
    return f"Unknown structure"


def main():
    print("BrownOS Combinator Key Probe")
    print("=" * 70)

    print("\n[1] Basic combinator arguments")

    tests = [
        ("nil", nil),
        ("A", A),
        ("B", B),
        ("(A B) = omega", omega),
        ("(B A)", BA),
        ("(A A)", AA),
        ("(B B)", BB),
    ]

    for name, arg in tests:
        result = test_syscall8(name, arg)
        print(f"  syscall8({name}): {result}")
        time.sleep(0.25)

    print("\n[2] Nested combinations")

    nested = [
        ("(A (A B))", App(A, AB)),
        ("(B (A B))", App(B, AB)),
        ("(A (B A))", App(A, BA)),
        ("(B (B A))", App(B, BA)),
        ("((A B) A)", App(AB, A)),
        ("((A B) B)", App(AB, B)),
        ("((A B) (A B))", App(AB, AB)),  # omega omega - might hang!
    ]

    for name, arg in nested:
        if "omega omega" in name.lower() or name == "((A B) (A B))":
            print(f"  syscall8({name}): SKIPPED (would hang)")
            continue
        result = test_syscall8(name, arg)
        print(f"  syscall8({name}): {result}")
        time.sleep(0.25)

    print("\n[3] Using identity and other standard combinators")

    # I = λx.x (identity)
    I = Lam(Var(0))
    # K = λxy.x (constant)
    K = Lam(Lam(Var(1)))
    # S = λxyz.xz(yz)
    S = Lam(Lam(Lam(App(App(Var(2), Var(0)), App(Var(1), Var(0))))))

    standard = [
        ("I (identity)", I),
        ("K (constant)", K),
        ("S", S),
        ("(S K K)", App(App(S, K), K)),  # SKK = I
        ("(K A)", App(K, A)),
        ("(K B)", App(K, B)),
    ]

    for name, arg in standard:
        result = test_syscall8(name, arg)
        print(f"  syscall8({name}): {result}")
        time.sleep(0.25)

    print("\n[4] What about using backdoor RESULT directly?")
    print("    CPS chain: backdoor -> extract -> syscall8")

    # ((backdoor nil) (λeither. ((either (λpair. ((syscall8 pair) QD))) (λe. e))))
    # Under λeither: backdoor=Var(202), syscall8=Var(9)
    # Under λeither.λpair: syscall8=Var(10)

    # Simpler: use the pair's first projection (A) or second projection (B)
    # Or apply the pair to something

    # fst = λp. p (λxy.x)
    # (fst pair) extracts A
    # (snd pair) extracts B

    # Actually, pair = λf. f A B
    # So (pair syscall8) = syscall8 A B = ((syscall8 A) B)
    # And (pair I) = I A B = A (since I returns its arg, which is A, then B is next)
    # Wait no: (pair I) = (λf. f A B) I = I A B = (I A) B = A B = omega

    print("\n    (pair I) = (λf. f A B) I = I A B = A B = omega")
    print("    (pair K) = K A B = A")
    print("    (pair (K I)) = (K I) A B = I B = B")

    # Let's test what happens when we chain backdoor properly
    # and pass different selectors

    print("\n[5] Full backdoor chain with selectors")

    # Build the chain: ((backdoor nil) handler)
    # where handler extracts something from the pair and passes to syscall8

    # handler = λeither. ((either
    #                       (λpair. ((syscall8 (pair selector)) QD))
    #                     ) ignore_right)

    # For selector = I: (pair I) = omega
    # For selector = K: (pair K) = A
    # For selector = (K I): (pair (K I)) = B

    selectors = [
        ("I -> omega", I),
        ("K -> A", K),
        ("(K I) -> B", App(K, I)),
    ]

    for sel_name, selector in selectors:
        # Build the handler
        # Under λeither.λpair (depth 2):
        # - syscall8 = Var(10)
        # - Var(0) = pair
        # - selector needs to be a closed term

        pair_applied = App(Var(0), selector)  # (pair selector)
        syscall_call = App(App(Var(10), pair_applied), Lam(Var(0)))  # ignore result
        left_handler = Lam(syscall_call)
        right_handler = Lam(Lam(Var(0)))
        either_body = App(App(Var(0), left_handler), right_handler)
        handler = Lam(either_body)

        full_term = App(App(Var(0xC9), nil), handler)
        payload = encode_term(full_term) + bytes([FF])
        response = query_raw(payload)

        result = "NO OUTPUT" if not response else f"{len(response)} bytes"
        print(f"    backdoor -> (pair {sel_name}) -> syscall8: {result}")
        time.sleep(0.3)

    print("\n[6] Testing if argument position matters")
    print("    What if syscall8 needs TWO specific args?")

    # Try syscall8(A)(B) vs syscall8(B)(A) etc
    two_arg_tests = [
        ("((syscall8 A) B)", App(App(Var(0x08), A), B)),
        ("((syscall8 B) A)", App(App(Var(0x08), B), A)),
        ("((syscall8 omega) nil)", App(App(Var(0x08), omega), nil)),
        ("((syscall8 nil) omega)", App(App(Var(0x08), nil), omega)),
    ]

    for name, term in two_arg_tests:
        # Without QD
        payload = encode_term(term) + bytes([FF])
        response = query_raw(payload, timeout_s=3.0)
        without = "NO OUTPUT" if not response else f"{len(response)}b"

        # With QD
        full = App(term, qd_term)
        payload = encode_term(full) + bytes([FF])
        response = query_raw(payload)

        with_qd = "NO OUTPUT"
        if response and FF in response:
            resp_term = parse_term(response)
            tag, _ = decode_either(resp_term)
            if tag == "Left":
                with_qd = "LEFT!"
            elif tag == "Right":
                with_qd = "Right"
            else:
                with_qd = "other"

        print(f"    {name}: no_QD={without}, with_QD={with_qd}")
        time.sleep(0.2)

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("All syscall8 calls return Right(6) = PermDenied")
    print("The backdoor gives us (A, B) but using them doesn't help... yet")
    print("")
    print("NEXT: Try using echo-manufactured Var(253)/Var(254)")
    print("      Or find a completely different approach")


if __name__ == "__main__":
    main()
