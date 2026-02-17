#!/usr/bin/env python3
"""
probe_oracle18.py - Quote-free oracle probes for syscall 8.

Purpose:
- Avoid QD/quote so Left(payload) values containing reserved bytes do not fail with
  "Encoding failed!".
- Distinguish Left vs Right by writing a fixed marker for Left and using
  error_string for Right.

Plan:
1) Run sanity checks first with readfile using the same quote-free continuation.
2) Run the 5 syscall-8 experiments from Oracle #18.
"""

from __future__ import annotations

import socket
import time
from typing import TypeAlias

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FF,
    decode_byte_term,
    decode_bytes_list,
    decode_either,
    encode_byte_term,
    encode_bytes_list,
    encode_term,
    parse_term,
)

HOST = "wc3.wechall.net"
PORT = 61221
REQUEST_DELAY_S = 0.3
MAX_PAYLOAD = 2000

Request: TypeAlias = tuple[str, object]


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


def query_raw(payload: bytes, timeout_s: float = 5.0) -> tuple[bytes, float]:
    start = time.monotonic()
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            result = recv_all(sock, timeout_s=timeout_s)
        elapsed = time.monotonic() - start
        return result, elapsed
    except Exception:
        elapsed = time.monotonic() - start
        return b"", elapsed


def shift_free_vars(term: object, delta: int, cutoff: int = 0) -> object:
    if isinstance(term, Var):
        if term.i >= cutoff:
            return Var(term.i + delta)
        return term
    if isinstance(term, Lam):
        return Lam(shift_free_vars(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(
            shift_free_vars(term.f, delta, cutoff),
            shift_free_vars(term.x, delta, cutoff),
        )
    return term


def build_tag_cont(left_marker: bytes, right_marker: bytes) -> object:
    """
    lambda result.
      result
        (lambda payload. ((g(2) left_marker) g(0)))
        (lambda errcode. ((g(2) right_marker) g(0)))

    Both branches write a fixed marker string then halt via g(0).
    This avoids error_string which may have been the broken path.
    """
    left_marker_term = encode_bytes_list(left_marker)
    right_marker_term = encode_bytes_list(right_marker)

    # Under (result + payload): g(2)->Var(4), g(0)->Var(2)
    left_handler = Lam(App(App(Var(4), shift_free_vars(left_marker_term, 2)), Var(2)))

    # Under (result + errcode): g(2)->Var(4), g(0)->Var(2)
    right_handler = Lam(App(App(Var(4), shift_free_vars(right_marker_term, 2)), Var(2)))

    # Under (result): result->Var(0)
    return Lam(App(App(Var(0), left_handler), right_handler))


def classify_response(out: bytes, elapsed: float, timeout_s: float) -> str:
    if not out:
        if elapsed >= timeout_s - 0.5:
            return "TIMEOUT"
        return f"EMPTY({elapsed:.1f}s)"

    text = out.decode("latin-1", errors="replace")
    if text.startswith("Encoding failed"):
        return "ENC_FAIL"
    if text.startswith("Invalid term"):
        return "INVALID_TERM"
    if text.startswith("Term too big"):
        return "TOO_BIG"

    if FF in out:
        try:
            parsed = parse_term(out)
            tag, payload_data = decode_either(parsed)
            if tag == "Left":
                try:
                    bs = decode_bytes_list(payload_data)
                    return f"Left:{bs.decode('latin-1', errors='replace')!r}"
                except Exception:
                    return f"Left({payload_data})"
            try:
                err = decode_byte_term(payload_data)
                return f"Right({err})"
            except Exception:
                return f"Right({payload_data})"
        except Exception:
            return f"FF_DATA:{out[:40].hex()}"

    return f"DATA:{text!r}"


def send_and_classify(
    term_or_payload: object | bytes,
    timeout_s: float = 6.0,
    label: str = "",
) -> tuple[bytes, bytes, float, str]:
    if isinstance(term_or_payload, bytes):
        payload = term_or_payload
    else:
        payload = encode_term(term_or_payload) + bytes([FF])

    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"{label}: payload too big ({len(payload)} bytes)")

    out, elapsed = query_raw(payload, timeout_s=timeout_s)
    cls = classify_response(out, elapsed, timeout_s=timeout_s)
    return payload, out, elapsed, cls


def run_request(label: str, term: object, timeout_s: float = 6.0) -> None:
    payload, out, elapsed, cls = send_and_classify(
        term, timeout_s=timeout_s, label=label
    )
    print(label)
    print(f"  payload_len: {len(payload)}")
    print(f"  elapsed: {elapsed:.3f}s")
    print(f"  raw_hex: {out.hex() if out else '(empty)'}")
    print(f"  decoded: {cls}")
    time.sleep(REQUEST_DELAY_S)


def build_requests(tag_cont: object) -> tuple[list[Request], list[Request]]:
    nil_term = Lam(Lam(Var(0)))
    tag_cont_shift_1 = shift_free_vars(tag_cont, 1)

    # Used in experiments 3/4/5 under one lambda: lambda x. ((g(8) x) TAG_CONT_shifted)
    sys8_on_bound = Lam(App(App(Var(9), Var(0)), tag_cont_shift_1))

    sanity: list[Request] = [
        (
            "SANITY 1: ((g(7) int(11)) TAG_CONT) - expect LEFT marker",
            App(App(Var(7), encode_byte_term(11)), tag_cont),
        ),
        (
            "SANITY 2: ((g(7) int(99)) TAG_CONT) - expect error string",
            App(App(Var(7), encode_byte_term(99)), tag_cont),
        ),
    ]

    experiments: list[Request] = [
        (
            "EXPERIMENT 1: ((g(8) nil) TAG_CONT)",
            App(App(Var(8), nil_term), tag_cont),
        ),
        (
            "EXPERIMENT 2: ((lambda x. ((g(9) nil) TAG_CONT_shifted)) nil)",
            App(Lam(App(App(Var(9), nil_term), tag_cont_shift_1)), nil_term),
        ),
        (
            "EXPERIMENT 3: ((g(14) int(251)) (lambda echo_result. ((g(9) echo_result) TAG_CONT_shifted)))",
            App(App(Var(14), encode_byte_term(251)), sys8_on_bound),
        ),
        (
            "EXPERIMENT 4: ((g(14) int(252)) (lambda echo_result. ((g(9) echo_result) TAG_CONT_shifted)))",
            App(App(Var(14), encode_byte_term(252)), sys8_on_bound),
        ),
        (
            "EXPERIMENT 5: ((g(14) nil) (lambda either. ((g(9) either) TAG_CONT_shifted)))",
            App(App(Var(14), nil_term), sys8_on_bound),
        ),
    ]

    return sanity, experiments


def choose_marker_and_requests() -> tuple[bytes, bytes, list[Request], list[Request]]:
    for left_m, right_m in ((b"LEFT\n", b"RIGHT\n"), (b"L\n", b"R\n")):
        tag_cont = build_tag_cont(left_m, right_m)
        sanity, experiments = build_requests(tag_cont)
        all_reqs = sanity + experiments
        try:
            for label, term in all_reqs:
                payload = encode_term(term) + bytes([FF])
                if len(payload) > MAX_PAYLOAD:
                    raise ValueError(f"{label}: payload too big ({len(payload)} bytes)")
            return left_m, right_m, sanity, experiments
        except ValueError:
            continue
    raise RuntimeError("All marker options exceed payload limit")


def main() -> None:
    print("=" * 72)
    print("probe_oracle18.py - quote-free syscall 8 probes")
    print(f"  Target: {HOST}:{PORT}")
    print("=" * 72)

    left_m, right_m, sanity, experiments = choose_marker_and_requests()
    print(f"Marker bytes for Left branch: {left_m!r}")
    print(f"Marker bytes for Right branch: {right_m!r}")
    print(f"Inter-request delay: {REQUEST_DELAY_S:.1f}s")
    print()

    print("-" * 72)
    print("Sanity checks (run first)")
    print("-" * 72)
    for label, term in sanity:
        run_request(label, term)

    print("\n" + "-" * 72)
    print("Sys8 experiments")
    print("-" * 72)
    for label, term in experiments:
        run_request(label, term)

    print("\n" + "=" * 72)
    print("All Oracle #18 probes complete.")
    print("=" * 72)


if __name__ == "__main__":
    main()
