#!/usr/bin/env python3
"""
Probe backdoor (0xC9) with password "ilikephp" encoded as Scott byte list.

Hypothesis: backdoor(nil) returns Left(pair(A,B)), but maybe we need to
authenticate with the password first, or pass it as a Scott byte list.

Tests:
1. backdoor(encode_bytes_list(b"ilikephp"))(QD)
2. backdoor with shorter strings
3. backdoor(nil) then sys8 with the result
4. sys8 with password string directly
5. backdoor with crypt hash
6. sys8 with password string
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass


HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD  # application
FE = 0xFE  # lambda
FF = 0xFF  # end-of-code marker

# Quick Debug continuation from the challenge cheat sheet.
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


def recv_until_ff(sock: socket.socket, timeout_s: float = 3.0) -> bytes:
    sock.settimeout(timeout_s)
    out = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        out += chunk
        if FF in chunk:
            break
    if FF not in out:
        raise RuntimeError(
            "Did not receive FF-terminated output; got truncated response"
        )
    return out[: out.index(FF) + 1]


def query(payload: bytes, retries: int = 5, timeout_s: float = 3.0) -> bytes:
    delay = 0.15
    last_err: Exception | None = None
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_until_ff(sock, timeout_s=timeout_s)
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed to query {HOST}:{PORT}") from last_err


def parse_term(data: bytes) -> object:
    stack: list[object] = []
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
    if len(stack) != 1:
        raise ValueError(f"Invalid parse: stack size {len(stack)}")
    return stack[0]


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported term node: {type(term)}")


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def encode_byte_term(n: int) -> object:
    expr: object = Var(0)  # base 0
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
    # Scott list of byte-terms.
    nil: object = Lam(Lam(Var(0)))

    def cons(h: object, t: object) -> object:
        return Lam(Lam(App(App(Var(1), h), t)))

    cur: object = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


def format_result(raw: bytes) -> str:
    """Format raw response as hex dump."""
    if not raw:
        return "(empty)"
    hex_str = " ".join(f"{b:02x}" for b in raw[:100])
    if len(raw) > 100:
        hex_str += f" ... ({len(raw)} bytes total)"
    return hex_str


def main() -> None:
    print("=" * 80)
    print("BACKDOOR PASSWORD PROBE")
    print("=" * 80)
    print()

    # Test 1: backdoor(encode_bytes_list(b"ilikephp"))(QD)
    print("TEST 1: backdoor(encode_bytes_list(b'ilikephp'))(QD)")
    print("-" * 80)
    try:
        password_term = encode_bytes_list(b"ilikephp")
        payload = (
            bytes([0xC9])
            + encode_term(password_term)
            + bytes([FD])
            + QD
            + bytes([FD, FF])
        )
        print(f"Payload size: {len(payload)} bytes")
        if len(payload) < 2000:
            result = query(payload)
            print(f"Result: {format_result(result)}")
        else:
            print("PAYLOAD TOO BIG - skip")
    except Exception as e:
        print(f"ERROR: {e}")
    print()
    time.sleep(0.5)

    # Test 2: backdoor with shorter strings
    print("TEST 2: backdoor with shorter strings")
    print("-" * 80)
    for pwd in [b"i", b"il", b"php", b"pw", b"ok", b"su", b"root"]:
        try:
            pwd_term = encode_bytes_list(pwd)
            payload = (
                bytes([0xC9])
                + encode_term(pwd_term)
                + bytes([FD])
                + QD
                + bytes([FD, FF])
            )
            print(f"backdoor({pwd!r}): payload={len(payload)} bytes", end=" ")
            if len(payload) < 2000:
                result = query(payload)
                print(f"→ {format_result(result)}")
            else:
                print("TOO BIG - skip")
            time.sleep(0.5)
        except Exception as e:
            print(f"ERROR: {e}")
    print()

    # Test 3: backdoor(nil) first, then sys8 with the result
    print("TEST 3: backdoor(nil) → extract pair → pass to sys8")
    print("-" * 80)
    try:
        # backdoor(nil)(QD)
        bd_payload = bytes([0xC9, 0x00, 0xFE, 0xFE, 0xFD]) + QD + bytes([0xFD, 0xFF])
        print(f"backdoor(nil) payload: {len(bd_payload)} bytes")
        bd_raw = query(bd_payload)
        print(f"backdoor(nil) result: {format_result(bd_raw)}")

        time.sleep(0.5)

        if bd_raw and 0xFF in bd_raw:
            bd_term_bytes = bd_raw[: bd_raw.index(0xFF)]
            print(f"Extracted term bytes: {len(bd_term_bytes)} bytes")

            # Now pass these exact bytes as the argument to sys8
            payload2 = (
                bytes([0x08]) + bd_term_bytes + bytes([0xFD]) + QD + bytes([0xFD, 0xFF])
            )
            print(f"sys8(bd_output) payload: {len(payload2)} bytes")
            if len(payload2) < 2000:
                result2 = query(payload2)
                print(f"sys8(bd_output) result: {format_result(result2)}")
            else:
                print("PAYLOAD TOO BIG - skip")
    except Exception as e:
        print(f"ERROR: {e}")
    print()
    time.sleep(0.5)

    # Test 4: sys8 with password string directly
    print("TEST 4: sys8(encode_bytes_list(b'ilikephp'))(QD)")
    print("-" * 80)
    try:
        pwd_term = encode_bytes_list(b"ilikephp")
        payload = (
            bytes([0x08]) + encode_term(pwd_term) + bytes([FD]) + QD + bytes([FD, FF])
        )
        print(f"Payload size: {len(payload)} bytes")
        if len(payload) < 2000:
            result = query(payload)
            print(f"Result: {format_result(result)}")
        else:
            print("PAYLOAD TOO BIG - skip")
    except Exception as e:
        print(f"ERROR: {e}")
    print()
    time.sleep(0.5)

    # Test 5: backdoor with crypt hash
    print("TEST 5: backdoor(encode_bytes_list(b'GZKc.2/VQffio'))(QD)")
    print("-" * 80)
    try:
        crypt_term = encode_bytes_list(b"GZKc.2/VQffio")
        payload = (
            bytes([0xC9]) + encode_term(crypt_term) + bytes([FD]) + QD + bytes([FD, FF])
        )
        print(f"Payload size: {len(payload)} bytes")
        if len(payload) < 2000:
            result = query(payload)
            print(f"Result: {format_result(result)}")
        else:
            print("PAYLOAD TOO BIG - skip")
    except Exception as e:
        print(f"ERROR: {e}")
    print()
    time.sleep(0.5)

    # Test 6: sys8 with crypt hash
    print("TEST 6: sys8(encode_bytes_list(b'GZKc.2/VQffio'))(QD)")
    print("-" * 80)
    try:
        crypt_term = encode_bytes_list(b"GZKc.2/VQffio")
        payload = (
            bytes([0x08]) + encode_term(crypt_term) + bytes([FD]) + QD + bytes([FD, FF])
        )
        print(f"Payload size: {len(payload)} bytes")
        if len(payload) < 2000:
            result = query(payload)
            print(f"Result: {format_result(result)}")
        else:
            print("PAYLOAD TOO BIG - skip")
    except Exception as e:
        print(f"ERROR: {e}")
    print()

    print("=" * 80)
    print("PROBE COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
