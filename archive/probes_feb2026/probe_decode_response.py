#!/usr/bin/env python3
"""
Decode the response from ((syscall8 syscall8) QD) and explore related patterns.
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
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
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


def decode_either(term):
    """Decode Scott-encoded Either."""
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        return None, None
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var):
        if body.f.i == 1:
            return "Left", body.x
        elif body.f.i == 0:
            return "Right", body.x
    return None, None


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
    if isinstance(expr, App):
        if isinstance(expr.f, Var):
            return WEIGHTS.get(expr.f.i, 0) + eval_bitset_expr(expr.x)
    return 0


def decode_int_term(term) -> int:
    """Decode a 9-lambda integer term."""
    body = strip_lams(term, 9)
    if body:
        return eval_bitset_expr(body)
    return -1


def main():
    print("Decoding BrownOS response analysis")
    print("=" * 60)

    # Re-run the test that gave us output
    print("\nTest: ((syscall8 syscall8) QD)")
    syscall8 = Var(0x08)
    qd_term = parse_term(QD + bytes([FF]))
    term = App(App(syscall8, syscall8), qd_term)
    payload = encode_term(term) + bytes([FF])

    response = query_raw(payload)
    print(f"Raw response: {response.hex()}")

    if FF in response:
        term_resp = parse_term(response)
        print(f"Parsed term: {term_resp}")

        tag, payload_term = decode_either(term_resp)
        print(f"Either tag: {tag}")

        if tag == "Right" and payload_term:
            err_code = decode_int_term(payload_term)
            print(f"Error code: {err_code}")
            # Error codes: 0=Exception, 1=NotImpl, 2=InvalidArg, 3=NoSuchFile,
            #             4=NotDir, 5=NotFile, 6=PermDenied, 7=RateLimit
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
            print(f"Error meaning: {errors.get(err_code, 'Unknown')}")

    time.sleep(0.5)

    # Now let's test syscall8 with various arguments to find what DOESN'T return Right(6)
    print("\n" + "=" * 60)
    print("Scanning syscall8 with various globals as arguments...")

    interesting = []

    for i in range(0, 16):
        term = App(App(Var(0x08), Var(i)), qd_term)
        payload = encode_term(term) + bytes([FF])
        response = query_raw(payload, timeout_s=3.0)

        result = "NO OUTPUT"
        if response and FF in response:
            term_resp = parse_term(response)
            tag, payload_term = decode_either(term_resp)
            if tag == "Right":
                err = decode_int_term(payload_term)
                result = f"Right({err})"
            elif tag == "Left":
                result = "Left(...)"
                interesting.append((i, response))
        elif response:
            result = f"RAW: {response[:20]}..."

        print(f"  syscall8(Var({i})) = {result}")
        time.sleep(0.2)

    # Test with nil as well
    nil = Lam(Lam(Var(0)))
    term = App(App(Var(0x08), nil), qd_term)
    payload = encode_term(term) + bytes([FF])
    response = query_raw(payload)

    result = "NO OUTPUT"
    if response and FF in response:
        term_resp = parse_term(response)
        tag, payload_term = decode_either(term_resp)
        if tag == "Right":
            err = decode_int_term(payload_term)
            result = f"Right({err})"
        elif tag == "Left":
            result = "Left(...)"
            interesting.append(("nil", response))

    print(f"  syscall8(nil) = {result}")

    print("\n" + "=" * 60)
    print("Interesting results (Left returns):")
    for item, resp in interesting:
        print(f"  {item}: {resp.hex()}")

    # Now let's try building something that might trigger success
    # What if the answer involves using the file ID for /bin/solution?
    # /bin/solution might be file ID 8 (matching syscall 8?)

    print("\n" + "=" * 60)
    print("Testing if there's a file with ID 8 (matching syscall 8)...")

    # readfile(8)
    def encode_byte_term(n: int) -> object:
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
            if n & weight:
                expr = App(Var(idx), expr)
        term = expr
        for _ in range(9):
            term = Lam(term)
        return term

    # Syscall 7 = readfile
    file_id_8 = encode_byte_term(8)
    term = App(App(Var(0x07), file_id_8), qd_term)
    payload = encode_term(term) + bytes([FF])
    response = query_raw(payload)

    print(f"readfile(8): {response.hex() if response else 'NO OUTPUT'}")
    if response and FF in response:
        term_resp = parse_term(response)
        tag, payload_term = decode_either(term_resp)
        print(f"  -> {tag}")
        if tag == "Right":
            err = decode_int_term(payload_term)
            print(f"  Error: {err}")

    # name(8)
    term = App(App(Var(0x06), file_id_8), qd_term)
    payload = encode_term(term) + bytes([FF])
    response = query_raw(payload)

    print(f"name(8): {response.hex() if response else 'NO OUTPUT'}")


if __name__ == "__main__":
    main()
