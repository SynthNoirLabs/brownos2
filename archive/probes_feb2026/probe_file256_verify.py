#!/usr/bin/env python3
"""
Verify file 256 encoding and access.
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


def query_raw(payload: bytes, timeout_s: float = 5.0) -> bytes:
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


def encode_byte_term(n: int) -> object:
    """Encode an integer as a 9-lambda term using additive bitset."""
    expr = Var(0)  # Start with V0 (weight 0)

    # For each bit position, if set, wrap with App(Var(idx), ...)
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

    # For values > 255, we can repeat weights
    # 256 = 128 + 128, so we need (V8 (V8 V0))
    remaining = n - (n & 255)  # Get overflow
    while remaining >= 128:
        expr = App(Var(8), expr)
        remaining -= 128

    # Wrap in 9 lambdas
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


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


qd_term = parse_term(QD + bytes([FF]))


def main():
    print("File 256 Verification")
    print("=" * 60)

    # First, verify our encoding of 256
    term_256 = encode_byte_term(256)
    encoded = encode_term(term_256)
    print(f"encode_byte_term(256) -> {encoded.hex()}")

    # Decode it back to verify
    parsed = parse_term(encoded + bytes([FF]))
    decoded = decode_int_term(parsed)
    print(f"Decodes back to: {decoded}")

    if decoded != 256:
        print("ERROR: Encoding mismatch!")
        print("Let me fix the encoding...")

        # Manual encoding for 256 = 128 + 128
        # Body should be: (V8 (V8 V0))
        expr = App(Var(8), App(Var(8), Var(0)))
        term_256_fixed = expr
        for _ in range(9):
            term_256_fixed = Lam(term_256_fixed)

        encoded_fixed = encode_term(term_256_fixed)
        print(f"Fixed encode_byte_term(256) -> {encoded_fixed.hex()}")

        # Use the fixed version
        term_256 = term_256_fixed

    print("\n" + "=" * 60)
    print("Testing file operations on ID 256...")

    # name(256)
    print("\nname(256):")
    term = App(App(Var(0x06), term_256), qd_term)
    payload = encode_term(term) + bytes([FF])
    print(f"  Payload: {payload.hex()}")
    response = query_raw(payload)
    print(f"  Response: {response.hex() if response else 'NONE'}")

    if response and FF in response:
        resp_term = parse_term(response)
        tag, payload_term = decode_either(resp_term)
        print(f"  Tag: {tag}")
        if tag == "Left":
            name = decode_string(payload_term)
            print(f"  Name: {repr(name)}")
        elif tag == "Right":
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
            print(f"  Error: {err} = {errors.get(err, 'Unknown')}")

    time.sleep(0.3)

    # readfile(256)
    print("\nreadfile(256):")
    term = App(App(Var(0x07), term_256), qd_term)
    payload = encode_term(term) + bytes([FF])
    print(f"  Payload: {payload.hex()}")
    response = query_raw(payload)
    print(f"  Response: {response.hex() if response else 'NONE'}")

    if response and FF in response:
        resp_term = parse_term(response)
        tag, payload_term = decode_either(resp_term)
        print(f"  Tag: {tag}")
        if tag == "Left":
            content = decode_string(payload_term)
            print(f"  Content: {repr(content)}")
        elif tag == "Right":
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
            print(f"  Error: {err} = {errors.get(err, 'Unknown')}")

    time.sleep(0.3)

    # Also test a few other IDs in the range
    print("\n" + "=" * 60)
    print("Scanning IDs 255-260...")

    for file_id in range(255, 261):
        # Build the term for this ID
        if file_id <= 255:
            term_id = encode_byte_term(file_id)
        else:
            # For IDs > 255, build manually
            extra = file_id - 255
            expr = App(
                Var(8),
                App(
                    Var(7),
                    App(
                        Var(6),
                        App(
                            Var(5),
                            App(Var(4), App(Var(3), App(Var(2), App(Var(1), Var(0))))),
                        ),
                    ),
                ),
            )  # 255
            for _ in range(extra):
                expr = App(Var(8), expr)  # Add 128 each time... wait this is wrong

            # Let me think: 256 = 128 + 128 = V8 + V8
            # So body = (V8 (V8 V0))
            # For 257 = 128 + 128 + 1 = (V8 (V8 (V1 V0)))
            # etc.

            base = file_id & 255  # Low byte
            extra_128s = (file_id - base) // 128

            expr = Var(0)
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
                if base & weight:
                    expr = App(Var(idx), expr)
            for _ in range(extra_128s):
                expr = App(Var(8), expr)

            term_id = expr
            for _ in range(9):
                term_id = Lam(term_id)

        term = App(App(Var(0x06), term_id), qd_term)
        payload = encode_term(term) + bytes([FF])
        response = query_raw(payload, timeout_s=2.0)

        result = "NO OUTPUT"
        if response and FF in response:
            resp_term = parse_term(response)
            tag, payload_term = decode_either(resp_term)
            if tag == "Right":
                err = decode_int_term(payload_term)
                result = f"Right({err})"
            elif tag == "Left":
                name = decode_string(payload_term)
                result = f"Left({repr(name)})"

        print(f"  name({file_id}): {result}")
        time.sleep(0.15)


if __name__ == "__main__":
    main()
