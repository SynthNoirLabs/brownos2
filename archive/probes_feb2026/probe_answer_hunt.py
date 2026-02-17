#!/usr/bin/env python3
"""
BrownOS Answer Hunt - Focus on finding the actual WeChall answer.

Key Insights from Session:
1. "No output" is NORMAL for valid inputs - not indicative of failure
2. Syscall 8 returns Right(6) with QD, but NO OUTPUT without QD
3. Backdoor gives us (A, B) where (A B) = omega = λx.(x x)
4. The answer might NOT be about making syscall 8 succeed

Strategy:
1. Test if "no output" payloads have any observable side effects
2. Look for strings/data that might BE the answer
3. Check if the answer is thematic (omega, backdoor-related)
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


# Helpers for integer encoding
WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def encode_byte_term(n: int) -> object:
    """Encode an integer as a 9-lambda term."""
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
    if isinstance(expr, App):
        if isinstance(expr.f, Var):
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
    """Decode Scott list of byte-terms."""
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


def read_file(file_id: int) -> str | None:
    """Read a file and decode its content."""
    qd_term = parse_term(QD + bytes([FF]))
    file_term = encode_byte_term(file_id)
    term = App(App(Var(0x07), file_term), qd_term)
    payload = encode_term(term) + bytes([FF])

    response = query_raw(payload)
    if not response or FF not in response:
        return None

    resp_term = parse_term(response)
    tag, payload_term = decode_either(resp_term)
    if tag == "Left":
        return decode_string(payload_term)
    return None


def main():
    print("BrownOS Answer Hunt")
    print("=" * 60)

    # First, let's see if there are any strings we haven't fully decoded
    # that might contain the answer

    print("\n[1] Re-reading key files for answer clues...")

    # Read the mail spool
    print("\nMail spool (file 88):")
    mail = read_file(88)
    if mail:
        print(mail)
    time.sleep(0.3)

    # Read the history file
    print("\nHistory (file 65):")
    history = read_file(65)
    if history:
        print(history)
    time.sleep(0.3)

    # Read the hidden file
    print("\nHidden file 256 (wtf):")
    wtf = read_file(256)
    if wtf:
        print(wtf)
    time.sleep(0.3)

    # Test syscall 0x2A (towel)
    print("\n[2] Syscall 0x2A (towel string):")
    qd_term = parse_term(QD + bytes([FF]))
    term = App(App(Var(0x2A), nil), qd_term)
    payload = encode_term(term) + bytes([FF])
    response = query_raw(payload)
    if response and FF in response:
        resp_term = parse_term(response)
        tag, payload_term = decode_either(resp_term)
        if tag == "Left":
            towel_str = decode_string(payload_term)
            print(f"Towel string: {towel_str}")
    time.sleep(0.3)

    # Now let's test the "3 leaf" minimal payload
    # and see if we can detect any side effects
    print("\n[3] Testing minimal '3 leaf' payload for side effects...")

    # Read access log BEFORE
    print("Reading access.log before test...")
    log_before = read_file(46)
    print(f"  Before: {log_before[:50] if log_before else 'N/A'}...")
    time.sleep(0.5)

    # Send minimal 3-leaf payload: 08 00 FD 00 FD FF
    print("Sending minimal payload: 08 00 FD 00 FD FF")
    minimal_payload = bytes([0x08, 0x00, FD, 0x00, FD, FF])
    response = query_raw(minimal_payload, timeout_s=3.0)
    print(f"  Response: {'NO OUTPUT' if not response else response.hex()}")
    time.sleep(0.5)

    # Read access log AFTER
    print("Reading access.log after test...")
    log_after = read_file(46)
    print(f"  After: {log_after[:50] if log_after else 'N/A'}...")

    if log_before != log_after:
        print("  ** ACCESS LOG CHANGED! **")
    else:
        print("  Log unchanged (but might be different connection)")

    # Test various other "no output" payloads and check for state changes
    print("\n[4] Testing backdoor-based payloads...")

    # Build backdoor combinators
    A = Lam(Lam(App(Var(0), Var(0))))  # λab.(b b)
    B = Lam(Lam(App(Var(1), Var(0))))  # λab.(a b)

    # ((syscall8 A) B) - this returned NO OUTPUT
    term = App(App(Var(0x08), A), B)
    payload = encode_term(term) + bytes([FF])
    print(f"((syscall8 A) B): payload = {payload.hex()}")
    response = query_raw(payload, timeout_s=3.0)
    print(f"  Result: {'NO OUTPUT' if not response else response.hex()}")
    time.sleep(0.3)

    # Now add QD to see what happens
    print("\nAdding QD to the same call to see the actual result...")
    term_with_qd = App(App(Var(0x08), A), qd_term)
    payload_with_qd = encode_term(term_with_qd) + bytes([FF])
    response = query_raw(payload_with_qd)
    if response and FF in response:
        resp_term = parse_term(response)
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
            print(f"  Result: Right({err}) = {errors.get(err, 'Unknown')}")
        elif tag == "Left":
            print(f"  Result: Left(...) = SUCCESS?")
    time.sleep(0.3)

    # Key insight: What if the "3 leaf" comment refers to the structure?
    # 08 00 FD 00 FD = ((Var(8) Var(0)) Var(0))
    # This has exactly 3 Var nodes (leaves in the AST)

    print("\n[5] Analyzing the 3-leaf structure...")
    print("((Var(8) Var(0)) Var(0)) has exactly 3 leaves:")
    print("  - Var(8) = syscall reference")
    print("  - Var(0) = first Var(0) = argument?")
    print("  - Var(0) = second Var(0) = continuation?")
    print("")
    print("Var(0) at top level might reference some global...")
    print("Let's see what Var(0) does in different contexts.")

    # What happens with just Var(0)?
    print("\nTesting Var(0) alone:")
    payload = bytes([0x00, FF])
    response = query_raw(payload, timeout_s=2.0)
    print(f"  Var(0): {'NO OUTPUT' if not response else response}")

    print("\nTesting ((Var(0) nil) QD):")
    term = App(App(Var(0), nil), qd_term)
    payload = encode_term(term) + bytes([FF])
    response = query_raw(payload, timeout_s=3.0)
    print(f"  Result: {'NO OUTPUT' if not response else response.hex()}")

    # Could the answer be the hex encoding of the minimal payload?
    print("\n[6] Possible WeChall answers based on analysis:")
    print("")
    print("Tier 1 - Thematic (backdoor reveals omega):")
    print("  - omega")
    print("  - ω")
    print("  - Ω")
    print("  - selfapply")
    print("")
    print("Tier 2 - Service strings:")
    print("  - towel")
    print("  - wtf")
    print("  - ilikephp")
    print("")
    print("Tier 3 - Minimal bytecode:")
    print("  - 0800fd00fdff")
    print("  - 08 00 FD 00 FD FF")
    print("  - ((8 0) 0)")
    print("")
    print("Tier 4 - Combinator related:")
    print("  - A")
    print("  - B")
    print("  - AB")
    print("  - (A B)")
    print("")

    # Let's also check if there's a syscall we haven't fully tested
    print("\n[7] Final check: syscalls 251-252 (near reserved bytes)...")
    for sc in [251, 252]:
        term = App(App(Var(sc), nil), qd_term)
        payload = encode_term(term) + bytes([FF])
        response = query_raw(payload, timeout_s=3.0)
        result = "NO OUTPUT"
        if response and FF in response:
            resp_term = parse_term(response)
            tag, payload_term = decode_either(resp_term)
            if tag == "Right":
                err = decode_int_term(payload_term)
                result = f"Right({err})"
            elif tag == "Left":
                result = "Left(...)"
        print(f"  syscall {sc}: {result}")
        time.sleep(0.2)


if __name__ == "__main__":
    main()
