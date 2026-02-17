#!/usr/bin/env python3
"""
probe_oracle20.py - Multi-hypothesis oracle probe set for BrownOS syscall 8.

This script keeps the same mechanics as probe_oracle19b.py:
- raw socket one-shot queries
- explicit de Bruijn shifting helper
- fixed marker tag continuation (LEFT/RIGHT) instead of QD

Every experiment prints:
- label
- payload length
- elapsed time
- raw hex
- text (latin-1)
- bucket (LEFT/RIGHT/EMPTY/OTHER)
"""

from __future__ import annotations

import socket
import time

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FF,
    encode_term,
    encode_byte_term,
    encode_bytes_list,
)

HOST = "wc3.wechall.net"
PORT = 61221
TIMEOUT_S = 6.0
REQUEST_DELAY_S = 0.3
MAX_PAYLOAD = 2000

LEFT_MARKER = b"LEFT\n"
RIGHT_MARKER = b"RIGHT\n"


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
        elapsed = time.monotonic() - start
        return out, elapsed
    except Exception:
        elapsed = time.monotonic() - start
        return b"", elapsed


def shift(term: object, delta: int, cutoff: int = 0) -> object:
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    return term


def build_tag_cont() -> object:
    """
    λresult. result (λ_. write(LEFT, g(0))) (λ_. write(RIGHT, g(0)))

    Under λresult.λpayload / λresult.λerr (depth 2):
      g(2) -> Var(4)
      g(0) -> Var(2)
    """
    left_m = encode_bytes_list(LEFT_MARKER)
    right_m = encode_bytes_list(RIGHT_MARKER)
    left_h = Lam(App(App(Var(4), shift(left_m, 2)), Var(2)))
    right_h = Lam(App(App(Var(4), shift(right_m, 2)), Var(2)))
    return Lam(App(App(Var(0), left_h), right_h))


def run(label: str, term: object) -> tuple[int, float, str]:
    payload = encode_term(term) + bytes([FF])
    plen = len(payload)

    print(label)
    print(f"  payload_len: {plen}")

    if plen > MAX_PAYLOAD:
        bucket = "OTHER"
        print("  elapsed: 0.000s")
        print("  raw_hex: (skipped - payload too big)")
        print("  text: '(skipped - payload too big)'")
        print(f"  bucket: {bucket}")
        print()
        return plen, 0.0, bucket

    out, elapsed = query_raw(payload)
    text = out.decode("latin-1", errors="replace") if out else ""

    bucket = "OTHER"
    if LEFT_MARKER in out and RIGHT_MARKER not in out:
        bucket = "LEFT"
    elif RIGHT_MARKER in out and LEFT_MARKER not in out:
        bucket = "RIGHT"
    elif not out:
        bucket = "EMPTY"

    print(f"  elapsed: {elapsed:.3f}s")
    print(f"  raw_hex: {out.hex() if out else '(empty)'}")
    print(f"  text: {text!r}")
    print(f"  bucket: {bucket}")
    print()

    time.sleep(REQUEST_DELAY_S)
    return plen, elapsed, bucket


def main() -> None:
    print("=" * 80)
    print("probe_oracle20.py - Oracle #20 multi-hypothesis probe set")
    print(f"Target: {HOST}:{PORT}")
    print("=" * 80)

    nil = Lam(Lam(Var(0)))
    tc = build_tag_cont()

    left_m = encode_bytes_list(LEFT_MARKER)
    right_m = encode_bytes_list(RIGHT_MARKER)

    groups: list[tuple[str, list[tuple[str, object]]]] = []

    # ------------------------------------------------------------------
    # SANITY
    # ------------------------------------------------------------------
    sanity: list[tuple[str, object]] = []
    sanity.append(
        ("SANITY: g(7)(int(11))(TAG_CONT)", App(App(Var(7), encode_byte_term(11)), tc))
    )
    groups.append(("SANITY", sanity))

    # ------------------------------------------------------------------
    # Group 0: Diagnostic (A3-A5 de Bruijn indexing)
    # ------------------------------------------------------------------
    group0: list[tuple[str, object]] = []

    # D1:
    # g(201)(nil)( λeither.
    #   either
    #     (λpair. pair (λa. λb. g(14)(a)( λecho_r.
    #       echo_r (λdata. write(data, g(0))) (λerr. write("RIGHT", g(0))) )))
    #     (λerr. write("RIGHT", g(0)))
    # )
    right_m_s2 = shift(right_m, 2)
    right_m_s6 = shift(right_m, 6)

    # Under λeither.λpair.λa.λb.λecho_r.λdata (depth 6): g(2)=Var(8), g(0)=Var(6)
    d1_left_data = Lam(App(App(Var(8), Var(0)), Var(6)))
    # Under λeither.λpair.λa.λb.λecho_r.λerr (depth 6): write(RIGHT, g(0))
    d1_left_err = Lam(App(App(Var(8), right_m_s6), Var(6)))
    # Under λeither.λpair.λa.λb.λecho_r (depth 5): echo_r=Var(0)
    d1_echo_cont = Lam(App(App(Var(0), d1_left_data), d1_left_err))
    # Under λeither.λpair.λa.λb (depth 4): g(14)=Var(18), a=Var(1)
    d1_pair_consumer = Lam(Lam(App(App(Var(18), Var(1)), d1_echo_cont)))
    # Under λeither.λpair (depth 2): pair=Var(0)
    d1_left_handler = Lam(App(Var(0), d1_pair_consumer))

    # Under λeither.λerr (depth 2): g(2)=Var(4), g(0)=Var(2)
    d1_err_handler = Lam(App(App(Var(4), right_m_s2), Var(2)))
    # Under λeither (depth 1): either=Var(0)
    d1_cont = Lam(App(App(Var(0), d1_left_handler), d1_err_handler))
    d1_term = App(App(Var(201), nil), d1_cont)
    group0.append(("D1: g(201) + destructure + echo(a) + write(data)", d1_term))

    # D2:
    # g(201)(nil)( λeither.
    #   either
    #     (λpair. pair (λa. λb. write(LEFT, g(0))))
    #     (λerr. write(RIGHT, g(0)))
    # )
    left_m_s4 = shift(left_m, 4)
    d2_pair_consumer = Lam(Lam(App(App(Var(6), left_m_s4), Var(4))))
    d2_left_handler = Lam(App(Var(0), d2_pair_consumer))
    d2_err_handler = Lam(App(App(Var(4), right_m_s2), Var(2)))
    d2_cont = Lam(App(App(Var(0), d2_left_handler), d2_err_handler))
    d2_term = App(App(Var(201), nil), d2_cont)
    group0.append(("D2: g(201) + destructure + inline write(LEFT)", d2_term))

    # D3:
    # Same chain shape as A3 in oracle19b, but replace g(8)(a·b)(TC) with
    # write(LEFT, g(0)) to isolate pair-destructuring path.
    d3_pair_consumer = Lam(Lam(App(App(Var(6), left_m_s4), Var(4))))
    d3_left_handler = Lam(App(Var(0), d3_pair_consumer))
    d3_err_handler = Lam(App(App(Var(4), right_m_s2), Var(2)))
    d3_cont = Lam(App(App(Var(0), d3_left_handler), d3_err_handler))
    d3_term = App(App(Var(201), nil), d3_cont)
    group0.append(("D3: g(201) A3-shape but inline write(LEFT)", d3_term))

    groups.append(("GROUP 0: DIAGNOSTIC", group0))

    # ------------------------------------------------------------------
    # Group 1: Special vars via echo (Oracle Hypothesis 1)
    # ------------------------------------------------------------------
    group1: list[tuple[str, object]] = []

    tc_s1 = shift(tc, 1)
    tc_s2 = shift(tc, 2)

    # Shared echo unwrap continuation:
    # λecho_r. echo_r (λval. g(8)(val)(TC_s2)) (λerr. write(RIGHT, g(0)))
    # Under λecho_r.λval (depth 2): g(8)=Var(10)
    s_left_handler = Lam(App(App(Var(10), Var(0)), tc_s2))
    # Under λecho_r.λerr (depth 2): g(2)=Var(4), g(0)=Var(2)
    s_right_handler = Lam(App(App(Var(4), right_m_s2), Var(2)))
    # Under λecho_r (depth 1): echo_r=Var(0)
    s_unwrap_cont = Lam(App(App(Var(0), s_left_handler), s_right_handler))

    s1_term = App(App(Var(14), Var(252)), s_unwrap_cont)
    group1.append(("S1: echo(g(252)) -> unwrap -> sys8", s1_term))

    s2_term = App(App(Var(14), Var(8)), s_unwrap_cont)
    group1.append(("S2: echo(g(8)) -> unwrap -> sys8", s2_term))

    # S3: echo(g(252)) and pass the whole Either to sys8 without unwrapping.
    # Under λecho_r (depth 1): g(8)=Var(9), echo_r=Var(0), TC shifted by 1.
    s3_cont = Lam(App(App(Var(9), Var(0)), tc_s1))
    s3_term = App(App(Var(14), Var(252)), s3_cont)
    group1.append(("S3: echo(g(252)) -> pass Either directly to sys8", s3_term))

    groups.append(("GROUP 1: SPECIAL VARS VIA ECHO", group1))

    # ------------------------------------------------------------------
    # Group 2: access.log challenge-response (Oracle Hypothesis 3)
    # ------------------------------------------------------------------
    group2: list[tuple[str, object]] = []

    # L1:
    # g(7)(int(46))( λfile_r.
    #   file_r (λdata. g(8)(data)(TC_s2)) (λerr. write(RIGHT, g(0)))
    # )
    l1_left_handler = Lam(App(App(Var(10), Var(0)), tc_s2))
    l1_right_handler = Lam(App(App(Var(4), right_m_s2), Var(2)))
    l1_cont = Lam(App(App(Var(0), l1_left_handler), l1_right_handler))
    l1_term = App(App(Var(7), encode_byte_term(46)), l1_cont)
    group2.append(("L1: readfile(46) -> sys8(data)", l1_term))

    # L2: pair(log_bytes, "ilikephp") then sys8(pair)
    pw_ilike = encode_bytes_list(b"ilikephp")
    # Under λfile_r.λdata (depth 2): build pair = λf. f data pw
    l2_pair = Lam(App(App(Var(0), Var(1)), shift(pw_ilike, 3)))
    l2_left_handler = Lam(App(App(Var(10), l2_pair), tc_s2))
    l2_right_handler = Lam(App(App(Var(4), right_m_s2), Var(2)))
    l2_cont = Lam(App(App(Var(0), l2_left_handler), l2_right_handler))
    l2_term = App(App(Var(7), encode_byte_term(46)), l2_cont)
    group2.append(("L2: readfile(46) -> pair(data,'ilikephp') -> sys8", l2_term))

    # L3: pair(log_bytes, "gizmore") then sys8(pair)
    pw_gizmore = encode_bytes_list(b"gizmore")
    l3_pair = Lam(App(App(Var(0), Var(1)), shift(pw_gizmore, 3)))
    l3_left_handler = Lam(App(App(Var(10), l3_pair), tc_s2))
    l3_right_handler = Lam(App(App(Var(4), right_m_s2), Var(2)))
    l3_cont = Lam(App(App(Var(0), l3_left_handler), l3_right_handler))
    l3_term = App(App(Var(7), encode_byte_term(46)), l3_cont)
    group2.append(("L3: readfile(46) -> pair(data,'gizmore') -> sys8", l3_term))

    groups.append(("GROUP 2: ACCESS.LOG CHALLENGE-RESPONSE", group2))

    # ------------------------------------------------------------------
    # Group 3: Misc ideas
    # ------------------------------------------------------------------
    group3: list[tuple[str, object]] = []

    m1_term = App(App(Var(8), encode_byte_term(0)), tc)
    group3.append(("M1: g(8)(int(0))(TC)", m1_term))

    m2_term = App(App(Var(8), encode_byte_term(42)), tc)
    group3.append(("M2: g(8)(int(42))(TC)", m2_term))

    # M3:
    # g(42)(nil)( λr. r(λtowel. g(8)(towel)(TC_s2))(λe. write(RIGHT, g(0))) )
    m3_left_handler = Lam(App(App(Var(10), Var(0)), tc_s2))
    m3_right_handler = Lam(App(App(Var(4), right_m_s2), Var(2)))
    m3_cont = Lam(App(App(Var(0), m3_left_handler), m3_right_handler))
    m3_term = App(App(Var(42), nil), m3_cont)
    group3.append(("M3: g(42)(nil) -> unwrap -> sys8(towel)", m3_term))

    groups.append(("GROUP 3: MISC", group3))

    total = sum(len(exps) for _, exps in groups)
    print(f"Experiment count: {total}")
    print()

    results: list[tuple[str, int, float, str]] = []

    for group_label, experiments in groups:
        print("-" * 80)
        print(group_label)
        print("-" * 80)
        for label, term in experiments:
            plen, elapsed, bucket = run(label, term)
            results.append((label, plen, elapsed, bucket))

    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"{'LABEL':56s} {'LEN':>6s} {'TIME':>8s} {'BUCKET':>8s}")
    print("-" * 80)
    for label, plen, elapsed, bucket in results:
        print(f"{label:56.56s} {plen:6d} {elapsed:8.3f} {bucket:>8s}")


if __name__ == "__main__":
    main()
