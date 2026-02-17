#!/usr/bin/env python3
from __future__ import annotations

import socket
import time

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FF,
    encode_byte_term,
    encode_bytes_list,
    encode_term,
)

HOST = "wc3.wechall.net"
PORT = 61221
TIMEOUT_S = 6.0
REQUEST_DELAY_S = 0.2
MAX_PAYLOAD = 2000


def recv_all(sock: socket.socket, timeout_s: float = TIMEOUT_S) -> bytes:
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


def query_raw(payload: bytes, timeout_s: float = TIMEOUT_S) -> tuple[bytes, float]:
    start = time.monotonic()
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            out = recv_all(sock, timeout_s=timeout_s)
        return out, time.monotonic() - start
    except Exception:
        return b"", time.monotonic() - start


def shift(term: object, delta: int, cutoff: int = 0) -> object:
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    return term


def make_scott_list(elements: list[object]) -> object:
    result: object = Lam(Lam(Var(0)))
    for elem in reversed(elements):
        h_shifted = shift(elem, 2)
        t_shifted = shift(result, 2)
        result = Lam(Lam(App(App(Var(1), h_shifted), t_shifted)))
    return result


def build_quote_write_cont() -> object:
    qfail = encode_bytes_list(b"QFAIL\n")
    write_bytes = Lam(App(App(Var(4), Var(0)), Var(2)))
    write_qfail = Lam(App(App(Var(4), shift(qfail, 2)), Var(2)))
    unwrap_qr = Lam(App(App(Var(0), write_bytes), write_qfail))
    return unwrap_qr


def quote_global_bytes(global_idx: int) -> tuple[bytes, float, int]:
    cont = build_quote_write_cont()
    term = App(App(Var(4), Var(global_idx)), cont)
    payload = encode_term(term) + bytes([FF])
    plen = len(payload)
    if plen > MAX_PAYLOAD:
        return b"", 0.0, plen
    out, elapsed = query_raw(payload)
    time.sleep(REQUEST_DELAY_S)
    return out, elapsed, plen


def normalize_wire_bytes(bs: bytes) -> bytes:
    if bs.endswith(bytes([FF])):
        return bs[:-1]
    return bs


def compare(label: str, quoted: bytes, forged: bytes) -> str:
    if not quoted:
        return "EMPTY"
    if quoted.startswith(b"Encoding failed!"):
        return "ENCODING_FAILED"
    if quoted.startswith(b"Invalid term!"):
        return "INVALID_TERM"

    qn = normalize_wire_bytes(quoted)
    fn = normalize_wire_bytes(forged)
    if qn == fn:
        return "MATCH"
    return "MISMATCH"


def main() -> None:
    print("=" * 80)
    print("probe_validate_assumption.py")
    print("Validate quote(g(i)) vs forged Scott list [int(i), int(255)]")
    print("=" * 80)
    print()

    forged_8 = encode_term(
        make_scott_list([encode_byte_term(8), encode_byte_term(255)])
    )
    forged_42 = encode_term(
        make_scott_list([encode_byte_term(42), encode_byte_term(255)])
    )

    out_8, t8, p8 = quote_global_bytes(8)
    out_42, t42, p42 = quote_global_bytes(42)

    cmp_8 = compare("g(8)", out_8, forged_8)
    cmp_42 = compare("g(42)", out_42, forged_42)

    print("[g(8)]")
    print(f"  payload_len: {p8}")
    print(f"  elapsed: {t8:.3f}s")
    print(f"  quote_hex: {out_8.hex() if out_8 else '(empty)'}")
    print(f"  forged_hex: {forged_8.hex()}")
    print(f"  comparison: {cmp_8}")
    print()

    print("[g(42)] CONTROL")
    print(f"  payload_len: {p42}")
    print(f"  elapsed: {t42:.3f}s")
    print(f"  quote_hex: {out_42.hex() if out_42 else '(empty)'}")
    print(f"  forged_hex: {forged_42.hex()}")
    print(f"  comparison: {cmp_42}")
    print()

    final = "MATCH" if (cmp_8 == "MATCH" and cmp_42 == "MATCH") else cmp_8
    print(f"COMPARISON: {final}")


if __name__ == "__main__":
    main()
