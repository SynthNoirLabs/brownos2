#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    decode_byte_term,
    decode_bytes_list,
    decode_either,
    encode_byte_term,
    encode_bytes_list,
    encode_term,
    parse_term,
)
from solve_brownos_answer import QD as QD_BYTES


FF = 0xFF

QD_TERM: object = parse_term(QD_BYTES)
NIL_TERM: object = Lam(Lam(Var(0)))


def recv_all(sock: socket.socket, *, timeout_s: float, max_bytes: int) -> bytes:
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


def query_raw(host: str, port: int, payload: bytes, *, timeout_s: float, max_bytes: int, retries: int) -> bytes:
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
                return recv_all(sock, timeout_s=timeout_s, max_bytes=max_bytes)
        except Exception as exc:
            last_err = exc
            time.sleep(delay_s)
            delay_s = min(delay_s * 2.0, 2.0)
    raise RuntimeError(f"Failed to query {host}:{port}") from last_err


@dataclass(frozen=True)
class ParsedTerm:
    start: int
    end: int
    term: object
    summary: str


def summarize_term(term: object) -> str:
    try:
        tag, payload = decode_either(term)
    except Exception:
        return f"{term!r}"

    if tag == "Right":
        try:
            code = decode_byte_term(payload)
            return f"Right({code})"
        except Exception:
            return "Right(<non-int>)"

    # Left
    try:
        bs = decode_bytes_list(payload)
        preview = bs[:80].decode("utf-8", "replace")
        return f"Left(bytes:{len(bs)}:{preview!r})"
    except Exception:
        return "Left(<non-bytes>)"


def find_ff_terminated_terms(resp: bytes, *, max_candidates: int = 50_000) -> list[ParsedTerm]:
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


def build_program(mode: str, g: int, arg: object) -> bytes:
    if mode == "cps":
        # ((g arg) QD)
        term = App(App(Var(g), arg), QD_TERM)
    elif mode == "print_apply":
        # QD (g arg)
        term = App(QD_TERM, App(Var(g), arg))
    elif mode == "print_value":
        # QD g
        term = App(QD_TERM, Var(g))
    else:
        raise ValueError(f"Unknown mode: {mode}")
    return encode_term(term) + bytes([FF])


def iter_args(specs: list[str]) -> Iterable[tuple[str, object]]:
    for spec in specs:
        if spec == "nil":
            yield ("nil", NIL_TERM)
            continue
        if spec == "int0":
            yield ("int0", encode_byte_term(0))
            continue
        if spec == "int1":
            yield ("int1", encode_byte_term(1))
            continue
        if spec.startswith("int:"):
            n = int(spec.split(":", 1)[1], 0)
            if n < 0:
                raise ValueError("Negative ints are not supported")
            yield (spec, encode_byte_term(n))
            continue
        if spec == "bytes_empty":
            yield ("bytes_empty", encode_bytes_list(b""))
            continue
        if spec.startswith("bytes_hex:"):
            hx = spec.split(":", 1)[1].strip().replace(" ", "")
            yield (spec, encode_bytes_list(bytes.fromhex(hx)))
            continue
        raise ValueError(f"Unknown arg spec: {spec}")


@dataclass(frozen=True)
class Row:
    g: int
    mode: str
    arg: str
    recv_len: int
    dt_s: float
    kind: str
    summary: str
    ff_terms: int
    last_ff_summary: str
    raw_hex_prefix: str
    ascii_prefix: str


def classify(resp: bytes) -> tuple[str, str]:
    if not resp:
        return ("silent", "")
    if resp.startswith(b"Invalid term!"):
        return ("invalid", "Invalid term!")
    if resp.startswith(b"Encoding failed!"):
        return ("encoding_failed", "Encoding failed!")
    if FF not in resp:
        preview = resp[:200].decode("utf-8", "replace")
        return ("no_ff", preview)
    return ("has_ff", "")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Probe global indices under multiple calling conventions and argument shapes.",
    )
    ap.add_argument("--host", default="wc3.wechall.net")
    ap.add_argument("--port", type=int, default=61221)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--end", type=int, default=252)
    ap.add_argument(
        "--modes",
        default="cps,print_apply",
        help="Comma-separated: cps,print_apply,print_value (default: cps,print_apply).",
    )
    ap.add_argument(
        "--args",
        default="nil,int0",
        help="Comma-separated arg specs (default: nil,int0).",
    )
    ap.add_argument("--timeout", type=float, default=0.6)
    ap.add_argument("--max-bytes", type=int, default=200_000)
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--delay", type=float, default=0.05)
    ap.add_argument("--out", type=Path, default=Path("globals_registry.json"))
    ap.add_argument("--resume", action="store_true", help="Resume by skipping existing (g,mode,arg) rows.")
    args = ap.parse_args()

    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    arg_specs = [a.strip() for a in args.args.split(",") if a.strip()]

    out_rows: list[dict] = []
    done_keys: set[tuple[int, str, str]] = set()

    if args.resume and args.out.exists():
        try:
            existing = json.loads(args.out.read_text(encoding="utf-8"))
            if isinstance(existing, list):
                for r in existing:
                    if not isinstance(r, dict):
                        continue
                    try:
                        done_keys.add((int(r["g"]), str(r["mode"]), str(r["arg"])))
                    except Exception:
                        continue
                out_rows = existing
        except Exception:
            pass

    for g in range(args.start, args.end + 1):
        for mode in modes:
            for arg_name, arg_term in iter_args(arg_specs):
                key = (g, mode, arg_name)
                if key in done_keys:
                    continue

                payload = build_program(mode, g, arg_term)
                t0 = time.monotonic()
                resp = query_raw(
                    args.host,
                    args.port,
                    payload,
                    timeout_s=args.timeout,
                    max_bytes=args.max_bytes,
                    retries=args.retries,
                )
                dt = time.monotonic() - t0

                kind, summary = classify(resp)
                ff_terms = 0
                last_ff_summary = ""
                if kind == "has_ff":
                    terms = find_ff_terminated_terms(resp)
                    ff_terms = len(terms)
                    if terms:
                        last_ff_summary = terms[-1].summary

                row = Row(
                    g=g,
                    mode=mode,
                    arg=arg_name,
                    recv_len=len(resp),
                    dt_s=dt,
                    kind=kind,
                    summary=summary,
                    ff_terms=ff_terms,
                    last_ff_summary=last_ff_summary,
                    raw_hex_prefix=resp[:120].hex(),
                    ascii_prefix=resp[:120].decode("utf-8", "replace"),
                )
                out_rows.append(row.__dict__)
                done_keys.add(key)

                print(f"{g:02x} {mode:11s} {arg_name:10s} -> {kind:14s} {last_ff_summary or summary}")
                if args.out:
                    args.out.write_text(json.dumps(out_rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")

                time.sleep(args.delay)


if __name__ == "__main__":
    main()

