#!/usr/bin/env python3
"""
Scan file IDs beyond our previous range (0-1024).
Also try negative-ish IDs and very large IDs.
The Oracle suggests extending to -512..4096.

Also: re-read ALL known files and check for any content we might have missed.
And: try readfile with the BACKDOOR PAIR as argument (not just integers).
"""

import socket
import time
import sys
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE
FF = 0xFF


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


def encode_term(term):
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def encode_byte_term(n: int):
    """Encode integer n as a 9-lambda Church-style byte term."""
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


def encode_int_additive(n: int):
    """Encode integer n using additive weights, supporting n > 255."""
    if n < 256:
        return encode_byte_term(n)
    # For larger values, use repeated weight applications
    expr = Var(0)
    remaining = n
    for idx, weight in reversed(list(enumerate([0, 1, 2, 4, 8, 16, 32, 64, 128]))):
        if idx == 0:
            continue
        while remaining >= weight:
            expr = App(Var(idx), expr)
            remaining -= weight
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


QD_HEX = "0500fd000500fd03fdfefd02fdfefdfe"


def parse_qd():
    stack = []
    for b in bytes.fromhex(QD_HEX):
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
    return stack[0]


QD = parse_qd()


def send_raw(payload_bytes: bytes, timeout_s: float = 5.0) -> bytes:
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload_bytes)
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
                except socket.timeout:
                    break
            return out
    except Exception as e:
        return f"ERROR: {e}".encode()


def call_syscall(syscall_num, argument):
    """Call a syscall with QD continuation."""
    program = App(App(Var(syscall_num), argument), QD)
    payload = encode_term(program) + bytes([FF])
    return send_raw(payload)


def parse_term_bytes(data):
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
    if len(stack) != 1:
        return None
    return stack[0]


def decode_either(term):
    if isinstance(term, Lam) and isinstance(term.body, Lam):
        body = term.body.body
        if isinstance(body, App) and isinstance(body.f, Var):
            if body.f.i == 1:
                return ("Left", body.x)
            elif body.f.i == 0:
                return ("Right", body.x)
    return ("Unknown", term)


def decode_bytes_list(term):
    """Decode Scott byte list to bytes."""
    out = []
    cur = term
    for _ in range(100000):
        if not isinstance(cur, Lam) or not isinstance(cur.body, Lam):
            break
        body = cur.body.body
        if isinstance(body, Var) and body.i == 0:
            return bytes(out)  # nil = end of list
        if isinstance(body, App) and isinstance(body.f, App):
            if isinstance(body.f.f, Var) and body.f.f.i == 1:
                head = body.f.x
                tail = body.x
                # Decode head as byte
                b = eval_byte(head)
                if b is not None:
                    out.append(b)
                else:
                    out.append(ord("?"))
                cur = tail
                continue
        break
    return bytes(out) if out else None


def eval_byte(term):
    """Evaluate a 9-lambda byte term to an integer."""
    cur = term
    for _ in range(9):
        if not isinstance(cur, Lam):
            return None
        cur = cur.body
    return eval_bitset(cur)


def eval_bitset(expr):
    if isinstance(expr, Var):
        return WEIGHTS.get(expr.i, None)
    if isinstance(expr, App):
        if isinstance(expr.f, Var):
            w = WEIGHTS.get(expr.f.i)
            if w is None:
                return None
            rest = eval_bitset(expr.x)
            if rest is None:
                return None
            return w + rest
    return None


# ============================================================
print("=" * 70)
print("PHASE 1: Re-read ALL known files for exact content")
print("=" * 70)

known_files = {
    11: "/etc/passwd",
    65: "/home/gizmore/.history",
    88: "/var/spool/mail/dloser",
    46: "/var/log/brownos/access.log",
    256: "wtf (hidden)",
    16: "/bin/false",
    14: "/bin/sh",
    15: "/bin/sudo",
}

for fid, path in known_files.items():
    time.sleep(0.45)
    resp = call_syscall(7, encode_int_additive(fid))
    if not resp:
        print(f"  [{fid}] {path}: EMPTY")
        continue
    term = parse_term_bytes(resp)
    if term is None:
        print(f"  [{fid}] {path}: PARSE ERROR: {resp.hex()[:60]}")
        continue
    tag, payload = decode_either(term)
    if tag == "Left":
        content = decode_bytes_list(payload)
        if content is not None:
            text = content.decode("utf-8", "replace")
            print(f"  [{fid}] {path}: ({len(content)} bytes)")
            for line in text.split("\n"):
                print(f"    | {line}")
        else:
            print(f"  [{fid}] {path}: Left but can't decode bytes list")
    else:
        print(f"  [{fid}] {path}: {tag}")

# ============================================================
print("\n" + "=" * 70)
print("PHASE 2: Scan file IDs 1025-2048 with name()")
print("=" * 70)

novel_ids = []
for fid in range(1025, 2049):
    time.sleep(0.35)
    resp = call_syscall(6, encode_int_additive(fid))
    if not resp:
        continue  # EMPTY = no such file
    term = parse_term_bytes(resp)
    if term is None:
        continue
    tag, payload = decode_either(term)
    if tag == "Left":
        content = decode_bytes_list(payload)
        if content:
            text = content.decode("utf-8", "replace")
            print(f"  [ID {fid}] name = {repr(text)}")
            novel_ids.append(fid)
    # Right = error, skip silently
    if fid % 100 == 0:
        print(f"  ... scanned up to {fid}")
        sys.stdout.flush()

# ============================================================
print("\n" + "=" * 70)
print("PHASE 3: Scan file IDs 2049-4096 with name()")
print("=" * 70)

for fid in range(2049, 4097):
    time.sleep(0.35)
    resp = call_syscall(6, encode_int_additive(fid))
    if not resp:
        continue
    term = parse_term_bytes(resp)
    if term is None:
        continue
    tag, payload = decode_either(term)
    if tag == "Left":
        content = decode_bytes_list(payload)
        if content:
            text = content.decode("utf-8", "replace")
            print(f"  [ID {fid}] name = {repr(text)}")
            novel_ids.append(fid)
    if fid % 200 == 0:
        print(f"  ... scanned up to {fid}")
        sys.stdout.flush()

# ============================================================
print("\n" + "=" * 70)
print(f"SUMMARY: Found {len(novel_ids)} novel file IDs beyond 1024")
print("=" * 70)
for fid in novel_ids:
    print(f"  ID {fid}")

# Read content of any novel files
for fid in novel_ids:
    time.sleep(0.45)
    resp = call_syscall(7, encode_int_additive(fid))
    if not resp:
        print(f"  [{fid}] readfile: EMPTY")
        continue
    term = parse_term_bytes(resp)
    if term is None:
        print(f"  [{fid}] readfile: PARSE ERROR")
        continue
    tag, payload = decode_either(term)
    if tag == "Left":
        content = decode_bytes_list(payload)
        if content:
            text = content.decode("utf-8", "replace")
            print(f"  [{fid}] content ({len(content)} bytes): {repr(text[:200])}")
    else:
        print(f"  [{fid}] readfile: {tag}")
