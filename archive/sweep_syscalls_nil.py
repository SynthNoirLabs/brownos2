#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from solve_brownos_answer import App, Lam, Var
from solve_brownos_answer import QD as QD_BYTES
from solve_brownos_answer import decode_byte_term, decode_bytes_list, decode_either, encode_term, parse_term

FD = 0xFD
FF = 0xFF

NIL_TERM: object = Lam(Lam(Var(0)))
QD_TERM: object = parse_term(QD_BYTES)


def shift(term: object, delta: int, cutoff: int = 0) -> object:
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    raise TypeError(f"Unsupported term node: {type(term)}")


def recv_until_close_or_ff(sock: socket.socket, timeout_s: float) -> bytes:
    sock.settimeout(timeout_s)
    out = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
            if FF in chunk:
                break
    except socket.timeout:
        pass
    return out


def query_raw(host: str, port: int, payload: bytes, timeout_s: float, retries: int) -> bytes:
    delay_s = 0.2
    last_err: Exception | None = None
    for _ in range(retries):
        try:
            with socket.create_connection((host, port), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_until_close_or_ff(sock, timeout_s)
        except Exception as exc:
            last_err = exc
            time.sleep(delay_s)
            delay_s = min(delay_s * 2.0, 2.0)
    raise RuntimeError(f"Failed to query {host}:{port}") from last_err


def classify_response(resp: bytes) -> tuple[str, str]:
    if not resp:
        return "silent", ""

    if resp.startswith(b"Invalid term!"):
        return "invalid", "Invalid term!"

    if FF not in resp:
        # Not FF-terminated.
        return "truncated", resp[:200].decode("utf-8", "replace")

    term = parse_term(resp)
    try:
        tag, payload = decode_either(term)
    except Exception:
        return "non_either", str(term)[:200]

    if tag == "Right":
        try:
            code = decode_byte_term(payload)
            return "either_right", f"Right({code})"
        except Exception:
            return "either_right", "Right(<non-int>)"

    # Left
    try:
        bs = decode_bytes_list(payload)
        preview = bs[:120].decode("utf-8", "replace")
        return "either_left", f"Left(bytes:{len(bs)}:{preview!r})"
    except Exception:
        return "either_left", "Left(<non-bytes>)"


@dataclass(frozen=True)
class Row:
    syscall: int
    kind: str
    detail: str
    raw_hex: str


def build_payload(syscall: int) -> bytes:
    # ((syscall NIL) QD)
    term = App(App(Var(syscall), NIL_TERM), shift(QD_TERM, 0))
    return encode_term(term) + bytes([FF])


def main() -> None:
    ap = argparse.ArgumentParser(description="Sweep syscalls 0..252 with NIL argument and QD continuation.")
    ap.add_argument("--host", default="wc3.wechall.net")
    ap.add_argument("--port", type=int, default=61221)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--end", type=int, default=252)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--delay", type=float, default=0.1)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    rows: list[dict[str, Any]] = []

    for s in range(args.start, args.end + 1):
        payload = build_payload(s)
        resp = b""
        try:
            resp = query_raw(args.host, args.port, payload, timeout_s=args.timeout, retries=args.retries)
            kind, detail = classify_response(resp)
        except Exception as e:
            kind, detail = "error", f"{type(e).__name__}: {e}"

        row = Row(syscall=s, kind=kind, detail=detail, raw_hex=resp.hex())
        rows.append(row.__dict__)
        print(f"{s:02x}: {kind} {detail}")
        time.sleep(args.delay)

    if args.out:
        args.out.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
