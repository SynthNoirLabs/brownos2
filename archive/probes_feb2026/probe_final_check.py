#!/usr/bin/env python3
"""
Final checks for BrownOS answer.

1. Re-verify hidden file 256 content
2. Check if syscall 8 has direct output (not CPS)
3. Try calling syscall 8 with the "key" from mail (nil = 00 FE FE)
4. Test if answer is in the response BEFORE QD processes it
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


# Helpers
WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


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


def main():
    print("BrownOS Final Checks")
    print("=" * 60)

    # 1. Re-verify hidden file 256
    print("\n[1] Reading hidden file 256...")
    file_term = encode_byte_term(256)
    term = App(App(Var(0x07), file_term), qd_term)
    payload = encode_term(term) + bytes([FF])

    response = query_raw(payload)
    print(f"Raw response: {response.hex() if response else 'NONE'}")

    if response and FF in response:
        resp_term = parse_term(response)
        tag, payload_term = decode_either(resp_term)
        print(f"Tag: {tag}")
        if tag == "Left":
            content = decode_string(payload_term)
            print(f"Content: {repr(content)}")
    time.sleep(0.3)

    # Also get the name
    print("\n[2] Getting name of file 256...")
    term = App(App(Var(0x06), file_term), qd_term)
    payload = encode_term(term) + bytes([FF])
    response = query_raw(payload)
    if response and FF in response:
        resp_term = parse_term(response)
        tag, payload_term = decode_either(resp_term)
        if tag == "Left":
            name = decode_string(payload_term)
            print(f"Name: {repr(name)}")
    time.sleep(0.3)

    # 3. What if syscall 8 directly writes output?
    # Instead of ((syscall8 arg) continuation), try just (syscall8 nil)
    print("\n[3] Testing syscall 8 without continuation...")

    # Just (syscall8 nil)
    term = App(Var(0x08), nil)
    payload = encode_term(term) + bytes([FF])
    print(f"Payload: {payload.hex()}")
    response = query_raw(payload, timeout_s=5.0)
    print(f"Response: {repr(response) if response else 'NO OUTPUT'}")
    time.sleep(0.3)

    # Just syscall8 alone
    print("\nJust Var(8):")
    payload = bytes([0x08, FF])
    response = query_raw(payload, timeout_s=3.0)
    print(f"Response: {repr(response) if response else 'NO OUTPUT'}")
    time.sleep(0.3)

    # 4. What about using the mail hint literally?
    # Mail says: "start with 00 FE FE" - this is nil
    # But what if we combine it differently?
    print("\n[4] Testing literal mail hint patterns...")

    # 08 00 FE FE FF - syscall 8 applied to nil-bytes literally
    print("08 00 FE FE FF:")
    payload = bytes([0x08, 0x00, FE, FE, FF])
    response = query_raw(payload, timeout_s=3.0)
    print(f"  Response: {repr(response) if response else 'NO OUTPUT'}")
    time.sleep(0.2)

    # What about C9 (backdoor) + 08 (syscall8)?
    print("\nC9 00 FE FE FD 08 FF (backdoor then syscall8):")
    payload = bytes([0xC9, 0x00, FE, FE, FD, 0x08, FF])
    response = query_raw(payload, timeout_s=3.0)
    print(f"  Response: {repr(response) if response else 'NO OUTPUT'}")
    if response:
        print(f"  Hex: {response.hex()}")
    time.sleep(0.2)

    # 5. The key insight: maybe success IS "no output"
    # Let's verify what "success" looks like for a known working syscall
    print("\n[5] What does success look like?")

    # readfile(11) = /etc/passwd - should succeed
    print("\nreadfile(11) with identity continuation:")
    identity = Lam(Var(0))
    file11 = encode_byte_term(11)
    term = App(App(Var(0x07), file11), identity)
    payload = encode_term(term) + bytes([FF])
    response = query_raw(payload, timeout_s=3.0)
    print(f"  Response: {'NO OUTPUT' if not response else f'{len(response)} bytes'}")
    time.sleep(0.2)

    # readfile(11) with nil continuation
    print("\nreadfile(11) with nil continuation:")
    term = App(App(Var(0x07), file11), nil)
    payload = encode_term(term) + bytes([FF])
    response = query_raw(payload, timeout_s=3.0)
    print(f"  Response: {'NO OUTPUT' if not response else f'{len(response)} bytes'}")
    time.sleep(0.2)

    # 6. Check if there's any pattern that produces output from syscall 8
    print("\n[6] Exhaustive syscall 8 argument search...")

    interesting_args = [
        ("nil", nil),
        ("identity", Lam(Var(0))),
        ("true", Lam(Lam(Var(1)))),
        ("false", Lam(Lam(Var(0)))),
        ("0", encode_byte_term(0)),
        ("1", encode_byte_term(1)),
        ("8", encode_byte_term(8)),
        ("42", encode_byte_term(42)),
        ("201", encode_byte_term(201)),
        ("255", encode_byte_term(255)),
    ]

    for name, arg in interesting_args:
        term = App(App(Var(0x08), arg), qd_term)
        payload = encode_term(term) + bytes([FF])
        response = query_raw(payload, timeout_s=3.0)

        result = "NO OUTPUT"
        if response:
            if FF in response:
                resp_term = parse_term(response)
                tag, payload_term = decode_either(resp_term)
                if tag == "Right":
                    err = decode_int_term(payload_term)
                    result = f"Right({err})"
                elif tag == "Left":
                    result = "Left(...) SUCCESS!"
            else:
                result = f"RAW: {response[:30]}"

        print(f"  syscall8({name}): {result}")
        time.sleep(0.15)

    # 7. Final theory: What if the answer is literally "8"?
    # Or the bytecode representing the solution?
    print("\n[7] Summary of findings:")
    print("- Syscall 8 ALWAYS returns Right(6) = PermDenied with QD")
    print("- Without QD, syscall 8 returns NO OUTPUT")
    print("- 'No output' is normal for valid programs")
    print("- The backdoor gives us omega combinator")
    print("")
    print("MOST LIKELY ANSWERS (to try on WeChall):")
    print("1. omega")
    print("2. towel")
    print("3. wtf")
    print("4. 8")
    print("5. Permission denied")
    print("6. The actual bytecode: 0800fefe")


if __name__ == "__main__":
    main()
