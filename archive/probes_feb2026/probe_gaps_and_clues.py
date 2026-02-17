#!/usr/bin/env python3
"""
probe_gaps_and_clues.py — Check filesystem gap IDs and explore overlooked areas.

Known filesystem IDs from readdir: 0,1,2,3,4,5,6,9,11,14,15,16,22,25,39,43,46,50,65,88,256
Gap IDs NOT in any readdir: 7,8,10,12,13,17-21,23-24,26-38,40-42,44-45,47-49,51-64,66-87,89-255

We test name() and readfile() for ALL gap IDs 0-100 to find hidden entries.
Also: what does sys8 correspond to in the filesystem? Is id 8 special?
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


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def recv_all(sock: socket.socket, timeout_s: float = 5.0) -> bytes:
    sock.settimeout(timeout_s)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    return out


def query(payload: bytes, retries: int = 3, timeout_s: float = 5.0) -> bytes:
    delay = 0.2
    last_err: Exception | None = None
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s=timeout_s)
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed to query") from last_err


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


def encode_byte_term(n: int) -> object:
    expr: object = Var(0)
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


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        if term.i > 0xFC:
            raise ValueError(f"Var({term.i}) too large")
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported: {type(term)}")


def strip_lams(term: object, n: int) -> object:
    cur = term
    for _ in range(n):
        if not isinstance(cur, Lam):
            raise ValueError("Not enough leading lambdas")
        cur = cur.body
    return cur


def eval_bitset_expr(expr: object) -> int:
    if isinstance(expr, Var):
        return WEIGHTS.get(expr.i, -1)
    if isinstance(expr, App):
        if not isinstance(expr.f, Var):
            return -1
        w = WEIGHTS.get(expr.f.i, -1)
        if w < 0:
            return -1
        sub = eval_bitset_expr(expr.x)
        if sub < 0:
            return -1
        return w + sub
    return -1


def decode_either(term: object) -> tuple[str, object] | None:
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        return None
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var) and body.f.i in (0, 1):
        return ("Left" if body.f.i == 1 else "Right", body.x)
    return None


def decode_byte_term(term: object) -> int:
    try:
        body = strip_lams(term, 9)
        return eval_bitset_expr(body)
    except Exception:
        return -1


def uncons_scott_list(term: object) -> tuple[object, object] | None:
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        return None
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
    return None


def decode_bytes_list(term: object) -> bytes | None:
    out = []
    cur = term
    for _ in range(100000):
        res = uncons_scott_list(cur)
        if res is None:
            if isinstance(cur, Lam) and isinstance(cur.body, Lam):
                return bytes(out)
            return None
        head, cur = res
        b = decode_byte_term(head)
        if b < 0:
            return None
        out.append(b)
    return None


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


def main():
    known_dir_ids = {
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        9,
        11,
        14,
        15,
        16,
        22,
        25,
        39,
        43,
        46,
        50,
        65,
        88,
    }

    err_names = {
        0: "Exception",
        1: "NotImpl",
        2: "InvalidArg",
        3: "NoSuchFile",
        4: "NotDir",
        5: "NotFile",
        6: "PermDenied",
        7: "RateLimit",
    }

    # =====================================================================
    # PHASE 1: name() for all IDs 0-100, focusing on gaps
    # =====================================================================
    print("=" * 70)
    print("PHASE 1: name(id) for id=0..100")
    print("=" * 70)

    found_names = {}

    for fid in range(101):
        id_term = encode_byte_term(fid)
        try:
            result = call_syscall(0x06, id_term)
            either = decode_either(result)
            if either:
                tag, payload = either
                if tag == "Left":
                    bs = decode_bytes_list(payload)
                    if bs is not None:
                        name = bs.decode("utf-8", errors="replace")
                        marker = "  " if fid in known_dir_ids else "**"
                        found_names[fid] = name
                        print(f"  {marker} id={fid:3d}: name='{name}'")
                    else:
                        print(f"  ?? id={fid:3d}: Left(non-bytes)")
                else:
                    code = decode_byte_term(payload)
                    ename = err_names.get(code, f"?{code}")
                    if code != 3:  # Only show non-"NoSuchFile" errors
                        print(f"     id={fid:3d}: Right({code})={ename}")
            else:
                print(f"     id={fid:3d}: unexpected shape")
        except Exception as e:
            print(f"     id={fid:3d}: ERR: {e}")
        time.sleep(0.12)

    print(f"\n  Found {len(found_names)} named entries in 0..100")
    print(
        f"  Gap IDs with names: {[fid for fid in found_names if fid not in known_dir_ids]}"
    )

    # =====================================================================
    # PHASE 2: readfile() for gap IDs that have names
    # =====================================================================
    gap_ids_with_names = [fid for fid in found_names if fid not in known_dir_ids]

    if gap_ids_with_names:
        print("\n" + "=" * 70)
        print("PHASE 2: readfile(id) for gap IDs that have names")
        print("=" * 70)

        for fid in gap_ids_with_names:
            id_term = encode_byte_term(fid)
            try:
                result = call_syscall(0x07, id_term)
                either = decode_either(result)
                if either:
                    tag, payload = either
                    if tag == "Left":
                        bs = decode_bytes_list(payload)
                        if bs is not None:
                            text = bs.decode("utf-8", errors="replace")
                            print(f"  id={fid:3d} ('{found_names[fid]}'): '{text}'")
                        else:
                            print(
                                f"  id={fid:3d} ('{found_names[fid]}'): Left(non-bytes)"
                            )
                    else:
                        code = decode_byte_term(payload)
                        ename = err_names.get(code, f"?{code}")
                        print(
                            f"  id={fid:3d} ('{found_names[fid]}'): Right({code})={ename}"
                        )
                else:
                    print(f"  id={fid:3d}: unexpected shape")
            except Exception as e:
                print(f"  id={fid:3d}: ERR: {e}")
            time.sleep(0.15)

    # =====================================================================
    # PHASE 3: readdir() for gap IDs (might be hidden directories)
    # =====================================================================
    if gap_ids_with_names:
        print("\n" + "=" * 70)
        print("PHASE 3: readdir(id) for gap IDs")
        print("=" * 70)

        for fid in gap_ids_with_names:
            id_term = encode_byte_term(fid)
            try:
                result = call_syscall(0x05, id_term)
                either = decode_either(result)
                if either:
                    tag, payload = either
                    if tag == "Left":
                        print(f"  id={fid:3d} ('{found_names[fid]}'): IS A DIRECTORY!")
                        # Try to decode directory entries
                        # 3-way list: nil=λ.λ.λ.V0, dir=λ.λ.λ.(V2 id rest), file=λ.λ.λ.(V1 id rest)
                        cur = payload
                        entries = []
                        for _ in range(100):
                            try:
                                inner = strip_lams(cur, 3)
                            except Exception:
                                break
                            if isinstance(inner, Var) and inner.i == 0:
                                break  # nil
                            if (
                                isinstance(inner, App)
                                and isinstance(inner.f, App)
                                and isinstance(inner.f.f, Var)
                            ):
                                tag_v = inner.f.f.i
                                entry_id = decode_byte_term(inner.f.x)
                                entry_type = (
                                    "dir"
                                    if tag_v == 2
                                    else "file"
                                    if tag_v == 1
                                    else f"?{tag_v}"
                                )
                                entries.append((entry_id, entry_type))
                                cur = inner.x
                            else:
                                break
                        for eid, etype in entries:
                            ename = found_names.get(eid, "?")
                            print(f"    {etype}: id={eid} name='{ename}'")
                    else:
                        code = decode_byte_term(payload)
                        ename = err_names.get(code, f"?{code}")
                        if code != 4:  # Skip "not a directory" — expected for files
                            print(
                                f"  id={fid:3d} ('{found_names[fid]}'): Right({code})={ename}"
                            )
                else:
                    print(f"  id={fid:3d}: unexpected shape")
            except Exception as e:
                print(f"  id={fid:3d}: ERR: {e}")
            time.sleep(0.15)

    # =====================================================================
    # PHASE 4: Specifically check IDs that match syscall numbers
    # Are syscall numbers = filesystem IDs?
    # =====================================================================
    print("\n" + "=" * 70)
    print("PHASE 4: Correlation — syscall number vs filesystem ID")
    print("=" * 70)

    syscalls = {
        1: "error_string",
        2: "write",
        4: "quote",
        5: "readdir",
        6: "name",
        7: "readfile",
        8: "TARGET",
        14: "echo",
        42: "towel",
        201: "backdoor",
    }

    for sc_num, sc_name in sorted(syscalls.items()):
        fs_name = found_names.get(sc_num, "(not found)")
        print(f"  syscall {sc_num:3d} ({sc_name:15s}) => fs name: '{fs_name}'")

    # =====================================================================
    # PHASE 5: What does echo ACTUALLY return for various interesting terms?
    # The author says "the different outputs betray some core structures"
    # =====================================================================
    print("\n" + "=" * 70)
    print("PHASE 5: echo(term) — examining what echo reveals about globals")
    print("=" * 70)

    # Echo returns Left(term) — effectively identity.
    # When we look at echo(Var(n)) through QD, the Left wrapper adds 2 to indices.
    # So echo(Var(n)) → Left(Var(n)), which QD prints as Var(n+2).
    # But what about echo(global_function)? If the global is a lambda, echo returns it.
    # For a syscall global, it might return the underlying implementation!

    # We already saw: echo(Var(n)) → Left(Var(n+2)) which is just Var(n) shifted.
    # But what if we do echo(sys8) differently — apply echo to a term that
    # USES sys8 internally?

    # Let's try: echo(λx. sys8_shifted x)
    # Under 1 lambda: sys8 = Var(9)
    # echo(λx. 9 0 FD) = echo(λ.(App(V9,V0)))
    # QD prints the Left payload = λ.(App(V11, V2)) — shifted by 2 for Left wrapper

    test_term = Lam(App(Var(9), Var(0)))  # λx. (sys8_shifted x)
    test_enc = encode_term(test_term)
    payload = bytes([0x0E]) + test_enc + bytes([FD]) + QD + bytes([FD, FF])
    try:
        raw = query(payload)
        if raw and FF in raw:
            term = parse_term(raw)
            either = decode_either(term)
            if either:
                tag, payload_term = either
                print(f"  echo(λx.sys8(x)): {tag}({term_summary(payload_term)})")
    except Exception as e:
        print(f"  echo(λx.sys8(x)): ERR: {e}")
    time.sleep(0.15)

    # Echo of QD itself
    qd_term = parse_term(QD + bytes([FF]))
    qd_enc = encode_term(qd_term)
    payload = bytes([0x0E]) + qd_enc + bytes([FD]) + QD + bytes([FD, FF])
    try:
        raw = query(payload)
        if raw and FF in raw:
            term = parse_term(raw)
            either = decode_either(term)
            if either:
                tag, payload_term = either
                print(f"  echo(QD): {tag}({term_summary(payload_term)[:80]})")
    except Exception as e:
        print(f"  echo(QD): ERR: {e}")

    print("\nDone!")


def term_summary(term: object, depth: int = 0) -> str:
    if depth > 8:
        return "..."
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{term_summary(term.body, depth + 1)}"
    if isinstance(term, App):
        return f"({term_summary(term.f, depth + 1)} {term_summary(term.x, depth + 1)})"
    return "?"


if __name__ == "__main__":
    main()
