#!/usr/bin/env python3
"""Probe unexplored BrownOS syscalls and file IDs."""

from __future__ import annotations

import socket
import time
import hashlib
import sys
from dataclasses import dataclass


# ── Connection constants ──────────────────────────────────────────────
HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD  # application
FE = 0xFE  # lambda
FF = 0xFF  # end-of-code marker

# Quick Debug continuation
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


# ── Term dataclasses ──────────────────────────────────────────────────
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


# ── Parse / Encode ────────────────────────────────────────────────────
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


# ── Byte encoding / decoding ─────────────────────────────────────────
WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def strip_lams(term: object, n: int) -> object:
    cur = term
    for _ in range(n):
        if not isinstance(cur, Lam):
            raise ValueError("Not enough leading lambdas")
        cur = cur.body
    return cur


def eval_bitset_expr(expr: object) -> int:
    if isinstance(expr, Var):
        return WEIGHTS[expr.i]
    if isinstance(expr, App):
        if not isinstance(expr.f, Var):
            raise ValueError("Unexpected function position (expected Var)")
        return WEIGHTS[expr.f.i] + eval_bitset_expr(expr.x)
    raise ValueError(f"Unexpected expr node: {type(expr)}")


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
    nil: object = Lam(Lam(Var(0)))

    def cons(h: object, t: object) -> object:
        return Lam(Lam(App(App(Var(1), h), t)))

    cur: object = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


def decode_either(term: object) -> tuple[str, object]:
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not an Either")
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var) and body.f.i in (0, 1):
        return ("Left" if body.f.i == 1 else "Right", body.x)
    raise ValueError("Unexpected Either shape")


def decode_byte_term(term: object) -> int:
    body = strip_lams(term, 9)
    return eval_bitset_expr(body)


def uncons_scott_list(term: object) -> tuple[object, object] | None:
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not a Scott list node")
    body = term.body.body
    if isinstance(body, Var) and body.i == 0:
        return None
    if (
        isinstance(body, App)
        and isinstance(body.f, App)
        and isinstance(body.f.f, Var)
        and body.f.f.i == 1
    ):
        return body.f.x, body.x
    raise ValueError("Unexpected Scott list node shape")


def decode_bytes_list(term: object) -> bytes:
    out: list[int] = []
    cur = term
    for _ in range(1_000_000):
        res = uncons_scott_list(cur)
        if res is None:
            return bytes(out)
        head, cur = res
        out.append(decode_byte_term(head))
    raise RuntimeError("List too long (possible loop)")


# ── Safe query (tolerates timeouts) ──────────────────────────────────
def safe_query(payload, timeout_s=5.0, retries=3):
    """Query that returns raw bytes, empty bytes on timeout."""
    delay = 0.3
    for attempt in range(retries):
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
                        if 0xFF in chunk:
                            break
                    except socket.timeout:
                        break
                return out
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(delay)
                delay *= 2
            else:
                return b""
    return b""


def call_syscall_raw(syscall_num, arg_term):
    """CPS call: ((g(num) arg) QD) + FF, returns raw bytes."""
    payload = (
        bytes([syscall_num])
        + encode_term(arg_term)
        + bytes([FD])
        + QD
        + bytes([FD, FF])
    )
    return safe_query(payload)


def safe_decode(raw):
    """Try to parse and decode a QD response."""
    if not raw or FF not in raw:
        return "EMPTY", None, raw.hex() if raw else ""
    try:
        term = parse_term(raw)
        tag, payload = decode_either(term)
        if tag == "Left":
            try:
                text = decode_bytes_list(payload).decode("utf-8", "replace")
                return "Left", text, raw[: raw.index(FF) + 1].hex()
            except:
                return (
                    "Left(complex)",
                    str(payload)[:80],
                    raw[: raw.index(FF) + 1].hex(),
                )
        else:
            try:
                err_code = decode_byte_term(payload)
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
                return (
                    f"Right({err_code})",
                    errors.get(err_code, "Unknown"),
                    raw[: raw.index(FF) + 1].hex(),
                )
            except:
                return (
                    "Right(complex)",
                    str(payload)[:80],
                    raw[: raw.index(FF) + 1].hex(),
                )
    except Exception as e:
        return f"ERROR({e})", None, raw.hex() if raw else ""


# ── Answer hash check ────────────────────────────────────────────────
TARGET_HASH = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
HASH_ITERS = 56154


def check_answer(candidate):
    """Check if candidate matches the answer hash."""
    cur = candidate.encode("utf-8")
    for _ in range(HASH_ITERS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET_HASH


def test(label, syscall_num, arg_term):
    """Run a test and print results."""
    raw = call_syscall_raw(syscall_num, arg_term)
    tag, decoded, hexdata = safe_decode(raw)
    flag = ""
    # Flag anything unexpected
    if tag not in [
        "EMPTY",
        "Right(0)",
        "Right(1)",
        "Right(2)",
        "Right(3)",
        "Right(4)",
        "Right(5)",
        "Right(6)",
        "Right(7)",
    ]:
        flag = " *** INTERESTING ***"
    print(f"  [{label}] {tag}: {decoded}{flag}")
    if hexdata and len(hexdata) < 200:
        print(f"    hex: {hexdata}")
    time.sleep(0.5)
    return tag, decoded, raw


# ── Helpers ───────────────────────────────────────────────────────────
nil_term = Lam(Lam(Var(0)))


def ebt(n):
    """Shorthand for encode_byte_term returning a term object."""
    return encode_byte_term(n)


# ── Main ──────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("BrownOS Novel Paths Probe")
    print("=" * 60)

    # CATEGORY A: Syscall 42 (towel)
    print("\n--- CATEGORY A: Syscall 42 (towel) ---")
    test("A1 towel(nil)", 0x2A, nil_term)
    test("A2 towel(byte(42))", 0x2A, ebt(42))
    test("A3 towel(byte(0))", 0x2A, ebt(0))
    test("A4 towel(byte(8))", 0x2A, ebt(8))

    # CATEGORY B: Syscall 6 (name) for known IDs
    print("\n--- CATEGORY B: Syscall 6 (name) - known IDs ---")
    known_ids = [0, 1, 2, 3, 4, 5, 6, 9, 11, 14, 15, 16, 22, 25, 39, 43, 46, 50, 65, 88]
    for fid in known_ids:
        test(f"B name({fid})", 0x06, ebt(fid))

    # CATEGORY C: Scan for hidden files (IDs 89-130)
    print("\n--- CATEGORY C: name() scan for hidden files (89-130) ---")
    for fid in range(89, 131):
        tag, decoded, raw = test(f"C name({fid})", 0x06, ebt(fid))
        if tag.startswith("Left"):
            print(f"    *** FOUND FILE AT ID {fid}: {decoded} ***")
            # Try to read it
            tag2, decoded2, raw2 = test(f"C read({fid})", 0x07, ebt(fid))
            if tag2.startswith("Left"):
                print(f"    *** FILE CONTENT: {decoded2[:200]} ***")

    # CATEGORY D: readfile for unknown IDs 7,8,10,12,13
    print("\n--- CATEGORY D: readfile for mystery IDs ---")
    for fid in [7, 8, 10, 12, 13]:
        test(f"D read({fid})", 0x07, ebt(fid))
        test(f"D name({fid})", 0x06, ebt(fid))

    # CATEGORY E: Syscall 1 (errorString) for all error codes
    print("\n--- CATEGORY E: errorString for codes 0-10 ---")
    for n in range(0, 11):
        test(f"E errorString({n})", 0x01, ebt(n))

    # CATEGORY F: Deep backdoor handshake
    print("\n--- CATEGORY F: Deep backdoor handshake ---")
    A_term = Lam(Lam(App(Var(0), Var(0))))  # λa.λb.bb
    B_term = Lam(Lam(App(Var(1), Var(0))))  # λa.λb.ab

    test("F1 backdoor(A)", 0xC9, A_term)
    test("F2 backdoor(B)", 0xC9, B_term)
    test("F3 backdoor(A(B))", 0xC9, App(A_term, B_term))
    test("F4 backdoor(B(A))", 0xC9, App(B_term, A_term))
    test("F5 backdoor(byte(42))", 0xC9, ebt(42))
    test("F6 backdoor(byte(8))", 0xC9, ebt(8))

    # CATEGORY G: Hash candidates from service outputs
    print("\n--- CATEGORY G: Hash candidate testing ---")
    # Get towel output
    towel_raw = call_syscall_raw(0x2A, nil_term)
    time.sleep(0.5)

    candidates = {
        "nil": "nil",
        "towel": "towel",
        "42": "42",
        "Don't Panic": "Don't Panic",
        "dont panic": "dont panic",
        "Don't panic": "Don't panic",
        "gizmore": "gizmore",
        "dloser": "dloser",
        "brownos": "brownos",
        "BrownOS": "BrownOS",
        "lambda": "lambda",
        "Lambda": "Lambda",
        "backdoor": "backdoor",
        "permission denied": "permission denied",
        "Permission denied": "Permission denied",
        "00fefe": "00fefe",
        "00 FE FE": "00 FE FE",
        "0xC9": "0xC9",
        "201": "201",
        "syscall": "syscall",
    }

    # Add towel output as candidate
    if towel_raw and FF in towel_raw:
        try:
            towel_term = parse_term(towel_raw)
            towel_tag, towel_payload = decode_either(towel_term)
            if towel_tag == "Left":
                towel_text = decode_bytes_list(towel_payload).decode("utf-8", "replace")
                candidates[f"towel_output:{towel_text}"] = towel_text
                # Also try without trailing newline
                candidates[f"towel_stripped:{towel_text.strip()}"] = towel_text.strip()
        except:
            pass
        candidates["towel_hex:" + towel_raw[: towel_raw.index(FF) + 1].hex()] = (
            towel_raw[: towel_raw.index(FF) + 1].hex()
        )

    for label, cand in candidates.items():
        if cand:
            match = check_answer(cand)
            status = "*** MATCH! ***" if match else "no"
            print(f"  [G {label}] = {status}")

    print("\n" + "=" * 60)
    print("PROBE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
