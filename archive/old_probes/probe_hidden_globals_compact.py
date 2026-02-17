#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    decode_byte_term,
    decode_bytes_list,
    decode_either,
    encode_term,
    parse_term,
)
from solve_brownos_answer import QD as QD_BYTES


FF = 0xFF

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


def encode_bitset_n(n: int, bits: int) -> object:
    """Binary bitset iterator numeral (not limited to 9 lambdas).

    Returns a term of shape:
      λv_bits … λv1. λv0. <apply selected vi to v0>
    where v1 corresponds to 1, v2 to 2, ..., v_bits to 2^(bits-1).
    """
    expr: object = Var(0)  # v0
    for k in range(bits):
        if n & (1 << k):
            expr = App(Var(k + 1), expr)
    term: object = expr
    for _ in range(bits + 1):
        term = Lam(term)
    return term


def let_(value: object, body: object) -> object:
    """let x = value in body   ==>   (λx. body) value"""
    return App(Lam(body), value)


def apply_many(fn: object, args: list[object]) -> object:
    out = fn
    for a in args:
        out = App(out, a)
    return out


SQUARE: object = Lam(Lam(App(Var(1), App(Var(1), Var(0)))))  # λf.λx. f (f x)

# step = λk.λt. (0x0E t) (λe. e k k)
# Note: inside λk.λt, syscall 0x0E (14) is Var(16).
STEP_BASE: object = Lam(
    Lam(
        App(
            App(Var(16), Var(0)),
            Lam(App(App(Var(0), Var(2)), Var(2))),
        )
    )
)

FINAL_BASE: object = Lam(App(App(Var(0), NIL_TERM), shift(QD_TERM, 1)))


def build_probe_program(*, base_global: int, lifts: int) -> object:
    if lifts < 0:
        raise ValueError("lifts must be >= 0")

    bits = max(1, lifts.bit_length())
    n_term = encode_bitset_n(lifts, bits)

    # Final environment inside `body` (after all bindings):
    #   Var(0)   = f_bits
    #   Var(1)   = f_{bits-1}
    #   ...
    #   Var(bits-1) = f1
    #   Var(bits)   = base0
    #
    # We compute:
    #   cont_n = n_term f_bits ... f1 FINAL
    #   cont_n base0
    depth_total = bits + 1
    final_term = shift(FINAL_BASE, depth_total)
    cont_n = apply_many(n_term, [Var(i) for i in range(bits)] + [final_term])
    body: object = App(cont_n, Var(bits))

    # Bind f_bits .. f2 as: f_k = SQUARE f_{k-1}
    # Each value sees only the outer environment (no access to its own binder), so `Var(0)`
    # correctly refers to the previously bound function (f_{k-1}).
    for _ in range(bits - 1):
        body = let_(App(SQUARE, Var(0)), body)

    # Bind f1 (STEP), shifted by +1 because it is evaluated under the base0 binder.
    body = let_(shift(STEP_BASE, 1), body)

    # Bind base0 and run.
    return App(Lam(body), Var(base_global))


def recv_all(sock: socket.socket, timeout_s: float, max_bytes: int) -> bytes:
    sock.settimeout(timeout_s)
    out = bytearray()
    while len(out) < max_bytes:
        try:
            chunk = sock.recv(min(4096, max_bytes - len(out)))
        except (ConnectionResetError, socket.timeout):
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


@dataclass(frozen=True)
class Result:
    g: int
    base: int
    lifts: int
    payload_len: int
    kind: str
    detail: str


def classify_response(resp: bytes) -> tuple[str, str]:
    if not resp:
        return ("silent", "")
    if resp.startswith(b"Invalid term!"):
        return ("invalid", "Invalid term!")
    if resp.startswith(b"Term too big!"):
        return ("invalid", "Term too big!")
    if resp.startswith(b"Out of memory!"):
        return ("oom", "Out of memory!")
    if resp.startswith(b"Encoding failed!"):
        return ("invalid", "Encoding failed!")
    if FF not in resp:
        return ("raw", resp[:200].decode("utf-8", "replace"))

    term = parse_term(resp[: resp.index(FF) + 1])
    try:
        tag, payload = decode_either(term)
    except Exception:
        return ("non_either", str(term)[:200])

    if tag == "Right":
        try:
            code = decode_byte_term(payload)
            return ("either_right", f"Right({code})")
        except Exception:
            return ("either_right", "Right(<non-int>)")

    # Left
    try:
        bs = decode_bytes_list(payload)
        preview = bs[:120].decode("utf-8", "replace")
        return ("either_left", f"Left(bytes:{len(bs)}:{preview!r})")
    except Exception:
        return ("either_left", "Left(<non-bytes>)")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "(Historical) Attempted high-global probing via a compact 0x0E-based lift construction. "
            "With correct Scott-Either semantics, 0x0E behaves like an echo, so this does not reach new globals."
        ),
    )
    ap.add_argument("--host", default="82.165.133.222", help="Default: wc3.wechall.net IPv4")
    ap.add_argument("--port", type=int, default=61221)
    ap.add_argument("--g", type=int, help="Target global index to probe (>=251).")
    ap.add_argument("--base", type=int, help="Debug: explicit base global index.")
    ap.add_argument("--lifts", type=int, help="Debug: explicit number of +2 lifts.")
    ap.add_argument("--timeout", type=float, default=4.0)
    ap.add_argument("--max-bytes", type=int, default=200_000)
    ap.add_argument("--repeat", type=int, default=1, help="Repeat probe N times (default: 1).")
    ap.add_argument("--delay", type=float, default=0.15, help="Delay between repeats.")
    args = ap.parse_args()

    if args.g is None:
        if args.base is None or args.lifts is None:
            raise SystemExit("Provide either --g, or both --base and --lifts.")
        base = args.base
        lifts = args.lifts
        g = base + 2 * lifts
    else:
        g = args.g
        if g % 2 == 0:
            base = 252
        else:
            base = 251
        lifts = (g - base) // 2
        if base + 2 * lifts != g:
            raise SystemExit("Target g must be reachable by +2 lifts from base 251/252.")

    program = build_probe_program(base_global=base, lifts=lifts)
    payload = encode_term(program) + bytes([FF])

    for i in range(args.repeat):
        resp = query_raw(args.host, args.port, payload, timeout_s=args.timeout, max_bytes=args.max_bytes)
        kind, detail = classify_response(resp)
        res = Result(
            g=g,
            base=base,
            lifts=lifts,
            payload_len=len(payload),
            kind=kind,
            detail=detail,
        )
        print(res)
        if i + 1 < args.repeat:
            time.sleep(args.delay)


if __name__ == "__main__":
    main()
