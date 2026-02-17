#!/usr/bin/env python3
"""
Search for a "solution" file or any file we might have missed.
The challenge says "investigate the service" - the answer might be in a file!
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
    expr = Var(0)
    base = n & 255
    extra_128s = (n - base) // 128
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


def get_name(file_id: int) -> str | None:
    """Get the name of a file by ID."""
    file_term = encode_byte_term(file_id)
    term = App(App(Var(0x06), file_term), qd_term)
    payload = encode_term(term) + bytes([FF])
    response = query_raw(payload)

    if not response or FF not in response:
        return None

    resp_term = parse_term(response)
    tag, payload_term = decode_either(resp_term)
    if tag == "Left":
        return decode_string(payload_term)
    return None


def read_file(file_id: int) -> str | None:
    """Read a file by ID."""
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
    print("BrownOS Solution File Search")
    print("=" * 60)

    # First, let's check all files in /bin (directory 1)
    print("\n[1] Listing /bin directory contents...")

    # We know these IDs from previous exploration:
    # /bin = 1, /bin/false = 16, /bin/sh = 14, /bin/sudo = 15
    # But is there more? Let's check files 12-20

    print("\nScanning file IDs 10-25 for names:")
    for fid in range(10, 26):
        name = get_name(fid)
        if name:
            print(f"  ID {fid}: {repr(name)}")
        time.sleep(0.15)

    # Check if there's a "solution" anywhere
    print("\n[2] Looking for 'solution' file...")
    print("    Scanning IDs 0-100 for 'solution'...")

    found_solution = None
    for fid in range(0, 101):
        name = get_name(fid)
        if name and "solution" in name.lower():
            print(f"  FOUND! ID {fid}: {repr(name)}")
            found_solution = fid
        time.sleep(0.1)

    if found_solution:
        print(f"\n[3] Reading solution file (ID {found_solution})...")
        content = read_file(found_solution)
        print(f"Content: {repr(content)}")
    else:
        print("  No 'solution' file found in IDs 0-100")

    # Let's also check special IDs
    print("\n[4] Checking special IDs (200-210, 250-260)...")

    special_ids = list(range(200, 211)) + list(range(250, 261)) + [256, 512, 1000]
    for fid in special_ids:
        name = get_name(fid)
        if name:
            print(f"  ID {fid}: {repr(name)}")
            content = read_file(fid)
            if content:
                print(f"    Content: {repr(content[:50])}...")
        time.sleep(0.12)

    # Re-read all known important files
    print("\n[5] Re-reading all important files for clues...")

    important_files = [
        (11, "/etc/passwd"),
        (65, ".history"),
        (88, "mail/dloser"),
        (46, "access.log"),
        (256, "wtf"),
    ]

    for fid, desc in important_files:
        content = read_file(fid)
        print(f"\n--- {desc} (ID {fid}) ---")
        if content:
            print(content)
        else:
            print("(empty or error)")
        time.sleep(0.2)

    # Check syscall 0x2A more carefully
    print("\n[6] Syscall 0x2A (the 'towel' string)...")
    nil = Lam(Lam(Var(0)))
    term = App(App(Var(0x2A), nil), qd_term)
    payload = encode_term(term) + bytes([FF])
    response = query_raw(payload)

    if response and FF in response:
        resp_term = parse_term(response)
        tag, payload_term = decode_either(resp_term)
        if tag == "Left":
            towel = decode_string(payload_term)
            print(f"Towel string: {repr(towel)}")
            print(f"This might be a hint! 'towel' reference to Hitchhiker's Guide?")

    print("\n" + "=" * 60)
    print("POTENTIAL ANSWERS TO SUBMIT TO WECHALL:")
    print("=" * 60)
    print("1. omega       - (A B) from backdoor = ω combinator")
    print("2. towel       - from syscall 0x2A")
    print("3. 42          - Hitchhiker's Guide reference (towel hint)")
    print("4. wtf         - hidden file 256 name")
    print("5. ilikephp    - gizmore's password")
    print("6. dloser      - challenge author, user in system")
    print("7. backdoor    - what we discovered")
    print("8. Permission denied - what syscall 8 returns")


if __name__ == "__main__":
    main()
