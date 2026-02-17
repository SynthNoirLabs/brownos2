#!/usr/bin/env python3
"""
Investigate the unusual results from ((syscall8 A) A) and similar patterns.

Key observation: These returned structures that are NOT Right(6)!
This might be a breakthrough.
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
        print(f"Error: {e}")
        return b""


def term_to_string(term, depth=0) -> str:
    """Pretty print a term."""
    indent = "  " * depth
    if isinstance(term, Var):
        return f"Var({term.i})"
    elif isinstance(term, Lam):
        return f"λ.{term_to_string(term.body, depth)}"
    elif isinstance(term, App):
        return f"({term_to_string(term.f, depth)} {term_to_string(term.x, depth)})"
    return str(term)


nil = Lam(Lam(Var(0)))
qd_term = parse_term(QD + bytes([FF]))

# Known combinators
A = Lam(Lam(App(Var(0), Var(0))))  # λab.(b b)
B = Lam(Lam(App(Var(1), Var(0))))  # λab.(a b)


def main():
    print("Investigating Unusual Results")
    print("=" * 70)

    # Test 1: ((syscall8 A) A) - this gave unusual output
    print("\n[1] ((syscall8 A) A) with QD")

    term = App(App(Var(0x08), A), A)
    full_term = App(term, qd_term)
    payload = encode_term(full_term) + bytes([FF])

    print(f"Payload: {payload.hex()}")
    response = query_raw(payload)
    print(f"Response hex: {response.hex() if response else 'NONE'}")

    if response and FF in response:
        resp_term = parse_term(response)
        print(f"Parsed: {term_to_string(resp_term)}")

        # Check structure
        print(f"\nStructure analysis:")
        if isinstance(resp_term, Lam):
            print(f"  Top level: Lambda")
            if isinstance(resp_term.body, Lam):
                print(f"  Second level: Lambda")
                inner = resp_term.body.body
                if isinstance(inner, App) and isinstance(inner.f, Var):
                    if inner.f.i == 1:
                        print(f"  -> This is LEFT!")
                    elif inner.f.i == 0:
                        print(f"  -> This is RIGHT")
            else:
                print(f"  Second level: {type(resp_term.body).__name__}")
                print(f"  -> NOT standard Either (only 1 lambda)")

    time.sleep(0.3)

    # Test 2: Without QD - what does ((syscall8 A) A) alone return?
    print("\n[2] ((syscall8 A) A) WITHOUT QD")

    term = App(App(Var(0x08), A), A)
    payload = encode_term(term) + bytes([FF])

    print(f"Payload: {payload.hex()}")
    response = query_raw(payload)
    print(f"Response: {repr(response) if response else 'NO OUTPUT'}")
    time.sleep(0.3)

    # Test 3: What if we use identity instead of A as continuation?
    print("\n[3] Compare: ((syscall8 A) identity) vs ((syscall8 A) A)")

    identity = Lam(Var(0))

    # With identity
    term = App(App(Var(0x08), A), identity)
    full_term = App(term, qd_term)
    payload = encode_term(full_term) + bytes([FF])
    response = query_raw(payload)
    print(f"((syscall8 A) id) + QD: {response.hex()[:60] if response else 'NONE'}...")

    if response and FF in response:
        resp_term = parse_term(response)
        print(f"  Parsed: {term_to_string(resp_term)[:80]}...")
    time.sleep(0.3)

    # Test 4: ((syscall8 (B B)) A) also gave unusual output
    print("\n[4] ((syscall8 (B B)) A) with QD")

    BB = App(B, B)
    term = App(App(Var(0x08), BB), A)
    full_term = App(term, qd_term)
    payload = encode_term(full_term) + bytes([FF])

    response = query_raw(payload)
    print(f"Response hex: {response.hex() if response else 'NONE'}")

    if response and FF in response:
        resp_term = parse_term(response)
        print(f"Parsed: {term_to_string(resp_term)}")
    time.sleep(0.3)

    # Test 5: Systematically test different continuations for syscall8(A)
    print("\n[5] syscall8(A) with various continuations")

    continuations = [
        ("nil", nil),
        ("identity", Lam(Var(0))),
        ("A", A),
        ("B", B),
        ("(A B)", App(A, B)),  # omega
        ("(B A)", App(B, A)),
    ]

    for name, cont in continuations:
        term = App(App(Var(0x08), A), cont)

        # Test without QD first
        payload = encode_term(term) + bytes([FF])
        response = query_raw(payload, timeout_s=3.0)
        without_qd = "NO OUTPUT" if not response else f"{len(response)} bytes"

        # Test with QD
        full_term = App(term, qd_term)
        payload = encode_term(full_term) + bytes([FF])
        response = query_raw(payload)

        with_qd = "NO OUTPUT"
        if response and FF in response:
            resp_term = parse_term(response)
            # Quick check if it's standard Right(6)
            if isinstance(resp_term, Lam) and isinstance(resp_term.body, Lam):
                inner = resp_term.body.body
                if isinstance(inner, App) and isinstance(inner.f, Var):
                    if inner.f.i == 0:
                        with_qd = "Right(...)"
                    elif inner.f.i == 1:
                        with_qd = "LEFT!"
                    else:
                        with_qd = f"Var({inner.f.i})"
                else:
                    with_qd = "Complex"
            else:
                with_qd = "Non-Either"

        print(f"  syscall8(A) + {name}: without_QD={without_qd}, with_QD={with_qd}")
        time.sleep(0.2)

    # Test 6: The echo-manufactured special values
    print("\n[6] Using echo to manufacture special values")

    # echo(251) → Left(Var(253))
    # We need to chain: ((echo 251) handler) where handler extracts Var(253)
    # and uses it somehow

    # Let's build this CPS chain:
    # ((echo Var(251)) (λeither. ((either (λv. use_v)) ignore)))

    # Using v as syscall8's argument:
    # λv. ((syscall8 v) QD_adjusted)

    # Under λeither.λv: syscall8 = Var(10)
    # QD needs adjustment... let's use identity for now

    use_v = Lam(App(App(Var(10), Var(0)), Lam(Var(0))))  # λv. ((syscall8 v) id)
    right_handler = Lam(Lam(Var(0)))  # ignore errors
    either_body = App(App(Var(0), use_v), right_handler)
    either_handler = Lam(either_body)

    # ((echo 251) either_handler)
    term = App(App(Var(0x0E), Var(251)), either_handler)
    payload = encode_term(term) + bytes([FF])

    print(f"echo(251) -> syscall8(Var(253)):")
    print(f"  Payload: {payload.hex()}")
    response = query_raw(payload)
    print(
        f"  Response: {'NO OUTPUT' if not response else response.hex() if len(response) < 50 else f'{len(response)} bytes'}"
    )
    time.sleep(0.3)

    # Test 7: What about using Var(253) directly in different positions?
    print("\n[7] Echo chain: use Var(253) as continuation")

    # λv. ((syscall8 nil) v) - use v as continuation
    use_v_as_cont = Lam(App(App(Var(9), nil), Var(0)))  # syscall8=9 under λeither.λv
    either_handler2 = Lam(App(App(Var(0), use_v_as_cont), right_handler))

    term = App(App(Var(0x0E), Var(251)), either_handler2)
    payload = encode_term(term) + bytes([FF])

    print(f"echo(251) -> ((syscall8 nil) Var(253)):")
    print(f"  Payload: {payload.hex()}")
    response = query_raw(payload)
    print(
        f"  Response: {'NO OUTPUT' if not response else response.hex() if len(response) < 50 else f'{len(response)} bytes'}"
    )

    print("\n" + "=" * 70)
    print("KEY OBSERVATIONS:")
    print("=" * 70)


if __name__ == "__main__":
    main()
