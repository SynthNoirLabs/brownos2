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


FF = 0xFF

I_TERM: object = Lam(Var(0))
NIL_TERM: object = Lam(Lam(Var(0)))
QD_TERM: object = parse_term(QD_BYTES)


def shift(term: object, delta: int, cutoff: int = 0) -> object:
    """De Bruijn shift (increase free vars >= cutoff by delta)."""

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
    delay_s = 0.15
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


def build_lift_chain(expr: object, lifts_remaining: int, depth: int, final_arg: object) -> object:
    """Historical helper (kept for reference).

    Earlier reversing work treated syscall 0x0E as “lift by +2”. With correct Scott-Either
    semantics, 0x0E behaves like an echo: it returns Left(<payload>) where the payload
    lives under 2 lambdas, so it *looks* shifted when you inspect it, but normal unwrapping
    cancels the shift.

    This builder unwrapped via `e I I`, so it does **not** actually reach new global indices.
    """

    if lifts_remaining == 0:
        qd_shifted = shift(QD_TERM, depth, 0)
        return App(App(expr, final_arg), qd_shifted)

    # Inside `depth` lambdas, globals shift by +depth.
    syscall_0e = Var(0x0E + depth)
    e = Var(0)  # result of 0x0E, expected Either
    next_expr = App(App(e, I_TERM), I_TERM)  # unwrap Left payload

    body = build_lift_chain(next_expr, lifts_remaining - 1, depth + 1, final_arg)
    cont = Lam(body)
    return App(App(syscall_0e, expr), cont)


@dataclass(frozen=True)
class ProbeResult:
    base: int
    lifts: int
    global_index: int
    kind: str
    detail: str
    raw_hex: str


def classify_response(resp: bytes) -> tuple[str, str]:
    if not resp:
        return "silent", ""

    if resp.startswith(b"Invalid term!"):
        return "invalid", "Invalid term!"

    if resp.startswith(b"Encoding failed!"):
        return "invalid", "Encoding failed!"

    if FF not in resp:
        # Not FF-terminated. Could be an ASCII error or partial data.
        return "silent", resp[:200].decode("utf-8", "replace")

    term = parse_term(resp)
    try:
        tag, payload = decode_either(term)
    except Exception:
        return "non_either", str(term)[:200]

    if tag == "Right":
        try:
            code = decode_byte_term(payload)
        except Exception:
            return "either_right", "Right(<non-int>)"
        return "either_right", f"Right({code})"

    # Left
    try:
        bs = decode_bytes_list(payload)
        preview = bs[:120].decode("utf-8", "replace")
        return "either_left", f"Left(bytes:{len(bs)}:{preview!r})"
    except Exception:
        return "either_left", "Left(<non-bytes>)"


def probe_one(
    *,
    host: str,
    port: int,
    base: int,
    lifts: int,
    arg_term: object,
    timeout_s: float,
    retries: int,
) -> ProbeResult:
    expr: object = Var(base)
    term = build_lift_chain(expr, lifts, depth=0, final_arg=arg_term)
    payload = encode_term(term) + bytes([FF])

    resp = query_raw(host, port, payload, timeout_s=timeout_s, retries=retries)
    kind, detail = classify_response(resp)
    return ProbeResult(
        base=base,
        lifts=lifts,
        global_index=base + 2 * lifts,
        kind=kind,
        detail=detail,
        raw_hex=resp.hex(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="(Historical) Early attempt to probe hidden globals via syscall 0x0E. Kept for reference.",
    )
    parser.add_argument("--host", default="wc3.wechall.net")
    parser.add_argument("--port", type=int, default=61221)
    parser.add_argument(
        "--bases",
        default="251,252",
        help="Comma-separated base indices (default: 251,252 for odd/even).",
    )
    parser.add_argument("--start-lifts", type=int, default=0)
    parser.add_argument("--max-lifts", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument(
        "--delay",
        type=float,
        default=0.15,
        help="Delay between probes in seconds (default: 0.15).",
    )
    parser.add_argument("--out", type=Path, default=None, help="Optional JSON output path.")
    parser.add_argument(
        "--stop-on-interesting",
        action="store_true",
        help="Stop on first result that is not Right(1).",
    )

    args = parser.parse_args()
    bases = [int(x.strip(), 0) for x in args.bases.split(",") if x.strip()]

    results: list[dict[str, Any]] = []

    for base in bases:
        for lifts in range(args.start_lifts, args.max_lifts + 1):
            res = probe_one(
                host=args.host,
                port=args.port,
                base=base,
                lifts=lifts,
                arg_term=NIL_TERM,
                timeout_s=args.timeout,
                retries=args.retries,
            )
            results.append(res.__dict__)
            print(f"base={res.base} lifts={res.lifts} g={res.global_index} -> {res.kind} {res.detail}")

            if args.stop_on_interesting and res.detail != "Right(1)":
                break

            time.sleep(args.delay)

    if args.out:
        args.out.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
