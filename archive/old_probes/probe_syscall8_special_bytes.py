#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import time
from dataclasses import dataclass
from typing import Iterable

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    decode_byte_term,
    decode_bytes_list,
    decode_either,
    encode_bytes_list,
    encode_term,
    parse_term,
)
from solve_brownos_answer import QD as QD_BYTES


FD = 0xFD
FF = 0xFF


QD_TERM: object = parse_term(QD_BYTES)
SILENT_CONT: object = Lam(Var(0))  # \x. x  (no socket output)


@dataclass(frozen=True)
class ParsedTerm:
    start: int
    end: int
    term: object
    summary: str


def recv_all(sock: socket.socket, timeout_s: float, max_bytes: int) -> bytes:
    sock.settimeout(timeout_s)
    out = bytearray()
    while len(out) < max_bytes:
        try:
            chunk = sock.recv(min(4096, max_bytes - len(out)))
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    return bytes(out)


def query_raw(host: str, port: int, payload: bytes, timeout_s: float, max_bytes: int) -> bytes:
    with socket.create_connection((host, port), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return recv_all(sock, timeout_s=timeout_s, max_bytes=max_bytes)


def summarize_term(term: object) -> str:
    try:
        tag, payload = decode_either(term)
    except Exception:
        return f"{term!r}"

    if tag == "Right":
        try:
            code = decode_byte_term(payload)
        except Exception:
            return "Right(<non-int>)"
        return f"Right({code})"

    # Left
    try:
        bs = decode_bytes_list(payload)
        preview = bs[:80].decode("utf-8", "replace")
        return f"Left(bytes:{len(bs)}:{preview!r})"
    except Exception:
        return "Left(<non-bytes>)"


def find_ff_terminated_terms(resp: bytes, *, max_candidates: int = 20_000) -> list[ParsedTerm]:
    terms: list[ParsedTerm] = []
    ff_positions = [i for i, b in enumerate(resp) if b == FF]
    if not ff_positions:
        return terms

    checked = 0
    for start in range(len(resp)):
        for ff in ff_positions:
            if ff < start:
                continue
            checked += 1
            if checked > max_candidates:
                return terms
            candidate = resp[start : ff + 1]
            try:
                term = parse_term(candidate)
            except Exception:
                continue
            terms.append(ParsedTerm(start=start, end=ff + 1, term=term, summary=summarize_term(term)))
            break
    return terms


def build_program(syscall: int, arg: object, cont: object) -> bytes:
    # ((syscall arg) cont)
    term = App(App(Var(syscall), arg), cont)
    return encode_term(term) + bytes([FF])


def iter_test_vectors() -> Iterable[tuple[str, bytes]]:
    # "special bytes" in the BrownOS wire encoding are FD (App), FE (Lam), FF (end marker).
    yield ("empty", b"")
    yield ("fd", bytes([0xFD]))
    yield ("fe", bytes([0xFE]))
    yield ("ff", bytes([0xFF]))
    yield ("fd_fe_ff", bytes([0xFD, 0xFE, 0xFF]))
    yield ("00_fe_fe_ff(nil_bytecode)", bytes([0x00, 0xFE, 0xFE, 0xFF]))
    yield ("08_ff(var8_bytecode)", bytes([0x08, 0xFF]))
    yield ("c9_ff(var201_bytecode)", bytes([0xC9, 0xFF]))
    yield ("qd_bytes", QD_BYTES + b"\xFF")


def main() -> None:
    ap = argparse.ArgumentParser(description="Probe syscall 0x08 with byte-lists containing FD/FE/FF.")
    ap.add_argument("--host", default="82.165.133.222", help="Default: wc3.wechall.net IPv4")
    ap.add_argument("--port", type=int, default=61221)
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--max-bytes", type=int, default=200_000)
    ap.add_argument("--delay", type=float, default=0.2)
    ap.add_argument("--cont", choices=("qd", "silent"), default="qd")
    args = ap.parse_args()

    cont = QD_TERM if args.cont == "qd" else SILENT_CONT

    for name, raw in iter_test_vectors():
        arg = encode_bytes_list(raw)
        payload = build_program(0x08, arg, cont)
        t0 = time.monotonic()
        resp = query_raw(args.host, args.port, payload, timeout_s=args.timeout, max_bytes=args.max_bytes)
        dt = time.monotonic() - t0

        print(f"\n== {name} ==")
        print(f"sent: {len(payload)} bytes; recv: {len(resp)} bytes; dt={dt:.3f}s")
        if resp:
            ascii_preview = resp[:200].decode("utf-8", "replace")
            print(f"recv ascii preview: {ascii_preview!r}")
            print(f"recv hex preview: {resp[:200].hex()}{'...' if len(resp) > 200 else ''}")
        else:
            print("recv: <empty>")

        terms = find_ff_terminated_terms(resp)
        if terms:
            # Print only the last few; "interesting" output could include early FF.
            print("ff-terminated terms (last 5):")
            for t in terms[-5:]:
                print(f"  [{t.start}:{t.end}] {t.summary}")
        else:
            print("ff-terminated terms: <none>")

        time.sleep(args.delay)


if __name__ == "__main__":
    main()

