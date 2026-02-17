#!/usr/bin/env python3
"""Read all BrownOS files and test every line/word as hash candidate."""

from __future__ import annotations

import hashlib
import time
import socket
from dataclasses import dataclass


HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD  # application
FE = 0xFE  # lambda
FF = 0xFF  # end-of-code marker

# Quick Debug continuation from the challenge cheat sheet.
# It prints (via syscall 2) the bytecode for the syscall result (via syscall 4),
# terminated by FF, so we can parse the result term on the client side.
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
    # Scott list of byte-terms.
    nil: object = Lam(Lam(Var(0)))

    def cons(h: object, t: object) -> object:
        return Lam(Lam(App(App(Var(1), h), t)))

    cur: object = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


def decode_either(term: object) -> tuple[str, object]:
    # Scott Either:
    # Left x  = λl.λr. l x  -> λ.λ.(1 x)
    # Right y = λl.λr. r y  -> λ.λ.(0 y)
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
    # nil  = λc.λn. n      -> λ.λ.0
    # cons = λc.λn. c h t  -> λ.λ.(1 h t)
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


def call_syscall(syscall_num: int, argument: object) -> object:
    payload = (
        bytes([syscall_num])
        + encode_term(argument)
        + bytes([FD])
        + QD
        + bytes([FD, FF])
    )
    out = query(payload)
    return parse_term(out)


TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ITERATIONS = 56154


def check_hash(s):
    """Check if string matches target hash after ITERATIONS of sha1."""
    cur = s.encode("utf-8")
    for _ in range(ITERATIONS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET


def read_file(fid):
    """Read file by ID, return decoded text or None."""
    try:
        term = call_syscall(0x07, encode_byte_term(fid))
        tag, payload = decode_either(term)
        if tag == "Left":
            return decode_bytes_list(payload).decode("utf-8", "replace")
    except Exception as e:
        print(f"    Error reading file {fid}: {e}")
    return None


def main():
    # Read all known readable files
    files = {
        11: "passwd",
        46: "access.log",
        65: ".history",
        88: "dloser_mail",
    }

    all_candidates = set()

    for fid, name in files.items():
        print(f"\nReading file {fid} ({name})...")
        time.sleep(0.5)
        content = read_file(fid)
        if content:
            print(f"  Length: {len(content)} chars")
            print(f"  Content: {content[:200]!r}")

            # Add full content
            all_candidates.add(content)
            all_candidates.add(content.strip())

            # Add each line
            for line in content.splitlines():
                all_candidates.add(line)
                all_candidates.add(line.strip())

                # Add each word
                for word in line.split():
                    all_candidates.add(word)
                    all_candidates.add(word.strip(".:;,!?()[]{}\"'"))

                # Add colon-separated fields (for passwd)
                for field in line.split(":"):
                    all_candidates.add(field)
                    all_candidates.add(field.strip())
        else:
            print(f"  Failed to read file {fid}")

    # Also read towel output
    print("\nReading towel output (syscall 0x2A)...")
    time.sleep(0.5)
    try:
        term = call_syscall(0x2A, Lam(Lam(Var(0))))
        tag, payload = decode_either(term)
        if tag == "Left":
            towel_text = decode_bytes_list(payload).decode("utf-8", "replace")
            print(f"  Towel length: {len(towel_text)} chars")
            print(f"  Towel content: {towel_text[:200]!r}")
            all_candidates.add(towel_text)
            all_candidates.add(towel_text.strip())
            for word in towel_text.split():
                all_candidates.add(word)
        else:
            print(f"  Towel returned Right (error)")
    except Exception as e:
        print(f"  Error reading towel: {e}")

    # Remove empty strings
    all_candidates.discard("")

    print(f"\nTotal unique candidates: {len(all_candidates)}")
    print("Testing hash candidates...")

    t0 = time.time()
    for i, cand in enumerate(sorted(all_candidates)):
        if check_hash(cand):
            print(f"\n*** MATCH: {cand!r} ***")
            return True
        if (i + 1) % 50 == 0:
            elapsed = time.time() - t0
            print(f"  [{i + 1}/{len(all_candidates)}] ({elapsed:.1f}s)")

    print(f"\nDone in {time.time() - t0:.1f}s. NO MATCH.")
    return False


if __name__ == "__main__":
    main()
