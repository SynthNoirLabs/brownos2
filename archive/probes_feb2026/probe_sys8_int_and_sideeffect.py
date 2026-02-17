#!/usr/bin/env python3
"""Probe syscall 8 with properly-encoded 9-lambda integer arguments 0-255,
then check the filesystem for side effects."""

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


def query(payload: bytes, retries: int = 5, timeout_s: float = 5.0) -> bytes:
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


def decode_dirlist(term: object) -> list[tuple[str, int]]:
    """Decode 3-way Scott directory listing.
    Returns list of (type, id) where type is 'dir' or 'file'."""
    entries: list[tuple[str, int]] = []
    cur = term
    for _ in range(10_000):
        if not isinstance(cur, Lam):
            break
        inner = strip_lams(cur, 3)
        if isinstance(inner, Var) and inner.i == 0:
            break  # nil
        if isinstance(inner, App) and isinstance(inner.f, App):
            selector = inner.f.f
            id_term = inner.f.x
            rest = inner.x
            if isinstance(selector, Var):
                entry_type = "dir" if selector.i == 2 else "file"
                try:
                    entry_id = decode_byte_term(id_term)
                except Exception:
                    entry_id = -1
                entries.append((entry_type, entry_id))
                cur = rest
                continue
        break
    return entries


def format_result(tag: str, payload: object) -> str:
    """Format an Either result for display."""
    if tag == "Right":
        try:
            code = decode_byte_term(payload)
            error_names = {
                0: "Exception",
                1: "NotImpl",
                2: "InvalidArg",
                3: "NoSuchFile",
                4: "NotDir",
                5: "NotFile",
                6: "PermDenied",
                7: "RateLimit",
            }
            return f"Right({code}) = {error_names.get(code, '???')}"
        except Exception:
            return f"Right(<undecoded>)"
    else:
        try:
            bs = decode_bytes_list(payload)
            return f"Left(bytes={bs!r})"
        except Exception:
            return f"Left(<non-bytes term>)"


def main() -> None:
    print("=" * 70)
    print("PROBE: sys8 with properly-encoded integers 0-255")
    print("=" * 70)

    # ----------------------------------------------------------------
    # Part A: Test sys8 with integers 0-255
    # ----------------------------------------------------------------
    print("\n--- Part A: sys8(int(N)) for N=0..255 ---\n")

    breakthroughs: list[tuple[int, str]] = []
    errors: list[tuple[int, str]] = []
    results_summary: dict[str, int] = {}

    for n in range(256):
        try:
            int_term = encode_byte_term(n)
            result_term = call_syscall(0x08, int_term)
            tag, payload = decode_either(result_term)
            result_str = format_result(tag, payload)

            # Track result distribution
            results_summary[result_str] = results_summary.get(result_str, 0) + 1

            # Check if NOT Right(6) -- that would be a breakthrough
            is_perm_denied = False
            if tag == "Right":
                try:
                    code = decode_byte_term(payload)
                    if code == 6:
                        is_perm_denied = True
                except Exception:
                    pass

            if not is_perm_denied:
                print(f"!!! BREAKTHROUGH !!! N={n} returned {result_str}")
                breakthroughs.append((n, result_str))

            if n % 25 == 0:
                print(f"  [progress] N={n:3d}/255  last={result_str}")

        except Exception as e:
            err_msg = f"ERROR: {e}"
            errors.append((n, err_msg))
            if n % 25 == 0:
                print(f"  [progress] N={n:3d}/255  {err_msg}")

        time.sleep(0.4)

    print(f"\n--- Part A Results ---")
    print(f"Results distribution:")
    for res, count in sorted(results_summary.items(), key=lambda x: -x[1]):
        print(f"  {res}: {count} times")
    print(f"Breakthroughs: {len(breakthroughs)}")
    for n, res in breakthroughs:
        print(f"  N={n}: {res}")
    print(f"Errors: {len(errors)}")
    for n, err in errors[:10]:
        print(f"  N={n}: {err}")

    # ----------------------------------------------------------------
    # Part B: Check filesystem for side effects
    # ----------------------------------------------------------------
    print("\n\n--- Part B: Checking filesystem for side effects ---\n")

    # Check key directories
    dir_checks = [
        (0, "/"),
        (5, "/var/log"),
        (22, "/home"),
    ]
    for dir_id, dir_name in dir_checks:
        try:
            result_term = call_syscall(0x05, encode_byte_term(dir_id))
            tag, payload = decode_either(result_term)
            if tag == "Left":
                entries = decode_dirlist(payload)
                print(f"  readdir({dir_id}) [{dir_name}]: {entries}")
            else:
                print(
                    f"  readdir({dir_id}) [{dir_name}]: {format_result(tag, payload)}"
                )
        except Exception as e:
            print(f"  readdir({dir_id}) [{dir_name}]: ERROR {e}")
        time.sleep(0.4)

    # Check for new files by probing name(id) for ids 89-100
    print(f"\n  Probing name(id) for ids 89-100 (looking for new entries):")
    for fid in range(89, 101):
        try:
            result_term = call_syscall(0x06, encode_byte_term(fid))
            tag, payload = decode_either(result_term)
            result_str = format_result(tag, payload)
            if tag == "Left":
                print(f"    name({fid}): {result_str}  <-- EXISTS!")
            else:
                # Only print non-NoSuchFile errors
                try:
                    code = decode_byte_term(payload)
                    if code != 3:  # 3 = NoSuchFile
                        print(f"    name({fid}): {result_str}")
                except Exception:
                    print(f"    name({fid}): {result_str}")
        except Exception as e:
            print(f"    name({fid}): ERROR {e}")
        time.sleep(0.4)

    # ----------------------------------------------------------------
    # Summary
    # ----------------------------------------------------------------
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Total sys8 tests: 256 (integers 0-255)")
    print(f"  Breakthroughs (non-Right(6)): {len(breakthroughs)}")
    if breakthroughs:
        for n, res in breakthroughs:
            print(f"    N={n}: {res}")
    else:
        print("    None -- all returned Right(6) = Permission denied")
    print(f"  Network errors: {len(errors)}")
    print("=" * 70)


if __name__ == "__main__":
    main()
