#!/usr/bin/env python3
"""
probe_oracle21.py - Quote inconsistency fix + g(0) exploration + timing + new hypotheses.

Key insight from Oracle #24:
- g(4) (quote) is CPS and returns Either. Our previous quote-after-unwrap code
  was treating quote's callback arg as raw bytes, not unwrapping the Either.
- Fix: chain g(201) Either unwrap -> quote -> quote's Either unwrap -> write.

Groups:
  Q: Quote fix (3 experiments)
  T: Timing with g(0) as continuation (4 experiments)
  S: sys8 with untested globals (3 experiments)
  N: Non-CPS sys8 (2 experiments)
  G: g(0) with backdoor components (3 experiments)
  I: g(0) as index dispatcher for globals 253-255 (3 experiments)
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
REQUEST_DELAY_S = 0.35
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
    """λresult. result (λ_. write(LEFT, g(0))) (λ_. write(RIGHT, g(0)))"""
    left_m = encode_bytes_list(LEFT_MARKER)
    right_m = encode_bytes_list(RIGHT_MARKER)
    # Under λresult.λpayload (depth 2): g(2)=Var(4), g(0)=Var(2)
    left_h = Lam(App(App(Var(4), shift(left_m, 2)), Var(2)))
    right_h = Lam(App(App(Var(4), shift(right_m, 2)), Var(2)))
    return Lam(App(App(Var(0), left_h), right_h))


def run(label: str, term: object, timeout_s: float = TIMEOUT_S) -> tuple[str, float]:
    payload = encode_term(term) + bytes([FF])
    plen = len(payload)
    print(label)
    print(f"  payload_len: {plen}")
    if plen > MAX_PAYLOAD:
        print("  SKIPPED (too big)")
        print()
        return "SKIPPED", 0.0
    out, elapsed = query_raw(payload, timeout_s=timeout_s)
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
    return bucket, elapsed


def main() -> None:
    print("=" * 80)
    print("probe_oracle21.py - Quote fix + g(0) + timing + new hypotheses")
    print(f"Target: {HOST}:{PORT}")
    print("=" * 80)
    print()

    nil = Lam(Lam(Var(0)))
    tc = build_tag_cont()
    results: list[tuple[str, str, float]] = []

    # ------------------------------------------------------------------
    # SANITY
    # ------------------------------------------------------------------
    print("--- SANITY ---")
    r, t = run("SANITY: g(7)(int(11))(TC)", App(App(Var(7), encode_byte_term(11)), tc))
    results.append(("SANITY", r, t))

    # ==================================================================
    # GROUP Q: QUOTE INCONSISTENCY FIX
    #
    # The key fix: g(4) (quote) returns Either, so we must unwrap it
    # just like we unwrap g(201)'s Either.
    # ==================================================================
    print("--- GROUP Q: QUOTE FIX ---")

    qfail_bytes = encode_bytes_list(b"QFAIL\n")
    rfail_bytes = encode_bytes_list(b"RFAIL\n")

    # ------------------------------------------------------------------
    # Q1: Quote WHOLE pair after Either unwrap from g(201)
    #
    # g(201)(nil)(λe.                         depth 1
    #   e
    #     (λpair.                             depth 2: pair=0, g(4)=Var(6)
    #       g(4)(pair)(λqr.                   depth 3: qr=0
    #         qr
    #           (λbytes.                      depth 4: g(2)=Var(6), g(0)=Var(4)
    #             g(2)(bytes)(g(0)))
    #           (λqerr.                       depth 4
    #             g(2)("QFAIL")(g(0)))
    #       )
    #     )
    #     (λerr.                              depth 2: g(2)=Var(4), g(0)=Var(2)
    #       g(2)("RFAIL")(g(0)))
    # )
    # ------------------------------------------------------------------
    # depth 4: write(bytes, g(0))
    q1_wbytes = Lam(App(App(Var(6), Var(0)), Var(4)))
    # depth 4: write("QFAIL\n", g(0))
    q1_wqfail = Lam(App(App(Var(6), shift(qfail_bytes, 4)), Var(4)))
    # depth 3: qr(left_h)(right_h)
    q1_uqr = Lam(App(App(Var(0), q1_wbytes), q1_wqfail))
    # depth 2: g(4)(pair)(uqr) — g(4)=Var(6), pair=Var(0)
    q1_left = Lam(App(App(Var(6), Var(0)), q1_uqr))
    # depth 2: write("RFAIL\n", g(0))
    q1_right = Lam(App(App(Var(4), shift(rfail_bytes, 2)), Var(2)))
    # depth 1: e(left)(right)
    q1_cont = Lam(App(App(Var(0), q1_left), q1_right))
    q1_term = App(App(Var(201), nil), q1_cont)

    r, t = run("Q1: g(201)->unwrap->quote(pair)->unwrap->write", q1_term)
    results.append(("Q1", r, t))

    # ------------------------------------------------------------------
    # Q2: Quote component A after Scott-destructuring pair
    #
    # g(201)(nil)(λe.                          depth 1
    #   e
    #     (λpair.                              depth 2: pair=0
    #       pair                               Scott: pair(consumer)(dummy)
    #         (λa.λb.                          depth 4: a=1, b=0, g(4)=Var(8)
    #           g(4)(a)(λqr.                   depth 5: qr=0
    #             qr
    #               (λbytes.                   depth 6: g(2)=Var(8), g(0)=Var(6)
    #                 g(2)(bytes)(g(0)))
    #               (λqerr.                    depth 6
    #                 g(2)("QFAIL")(g(0)))
    #           )
    #         )
    #         nil                              dummy (closed, no shift needed)
    #     )
    #     (λerr.                               depth 2
    #       g(2)("RFAIL")(g(0)))
    # )
    # ------------------------------------------------------------------
    # depth 6: write(bytes, g(0))
    q2_wbytes = Lam(App(App(Var(8), Var(0)), Var(6)))
    # depth 6: write("QFAIL\n", g(0))
    q2_wqfail = Lam(App(App(Var(8), shift(qfail_bytes, 6)), Var(6)))
    # depth 5: qr(left_h)(right_h)
    q2_uqr = Lam(App(App(Var(0), q2_wbytes), q2_wqfail))
    # depth 4: g(4)(a)(uqr) — g(4)=Var(8), a=Var(1)
    q2_consumer = Lam(Lam(App(App(Var(8), Var(1)), q2_uqr)))
    # depth 2: pair(consumer)(nil)
    q2_left = Lam(App(App(Var(0), q2_consumer), nil))
    # depth 2: write("RFAIL\n", g(0))
    q2_right = Lam(App(App(Var(4), shift(rfail_bytes, 2)), Var(2)))
    q2_cont = Lam(App(App(Var(0), q2_left), q2_right))
    q2_term = App(App(Var(201), nil), q2_cont)

    r, t = run("Q2: g(201)->destruct pair->quote(A)->unwrap->write", q2_term)
    results.append(("Q2", r, t))

    # ------------------------------------------------------------------
    # Q3: Quote component B
    # Same as Q2 but quote b=Var(0) instead of a=Var(1)
    # ------------------------------------------------------------------
    q3_consumer = Lam(Lam(App(App(Var(8), Var(0)), q2_uqr)))  # Var(0)=b
    q3_left = Lam(App(App(Var(0), q3_consumer), nil))
    q3_right = Lam(App(App(Var(4), shift(rfail_bytes, 2)), Var(2)))
    q3_cont = Lam(App(App(Var(0), q3_left), q3_right))
    q3_term = App(App(Var(201), nil), q3_cont)

    r, t = run("Q3: g(201)->destruct pair->quote(B)->unwrap->write", q3_term)
    results.append(("Q3", r, t))

    # ==================================================================
    # GROUP T: TIMING with g(0) as continuation
    # If g(0) terminates silently, timing might differ for success vs failure.
    # ==================================================================
    print("--- GROUP T: TIMING ---")

    # T1: g(8)(nil)(g(0))
    r, t = run("T1: g(8)(nil)(g(0))", App(App(Var(8), nil), Var(0)), timeout_s=8.0)
    results.append(("T1", r, t))

    # T2: g(7)(int(11))(g(0)) — known LEFT (success)
    r, t = run(
        "T2: g(7)(int(11))(g(0)) [success baseline]",
        App(App(Var(7), encode_byte_term(11)), Var(0)),
        timeout_s=8.0,
    )
    results.append(("T2", r, t))

    # T3: g(7)(int(99))(g(0)) — known RIGHT (failure)
    r, t = run(
        "T3: g(7)(int(99))(g(0)) [failure baseline]",
        App(App(Var(7), encode_byte_term(99)), Var(0)),
        timeout_s=8.0,
    )
    results.append(("T3", r, t))

    # T4: g(14)(nil)(g(0)) — echo returns LEFT
    r, t = run(
        "T4: g(14)(nil)(g(0)) [echo]", App(App(Var(14), nil), Var(0)), timeout_s=8.0
    )
    results.append(("T4", r, t))

    # ==================================================================
    # GROUP S: sys8 with untested globals as arguments
    # ==================================================================
    print("--- GROUP S: sys8 + untested globals ---")

    r, t = run("S1: g(8)(g(0))(TC)", App(App(Var(8), Var(0)), tc))
    results.append(("S1", r, t))

    r, t = run("S2: g(8)(g(4))(TC) [quote]", App(App(Var(8), Var(4)), tc))
    results.append(("S2", r, t))

    r, t = run("S3: g(8)(g(2))(TC) [write]", App(App(Var(8), Var(2)), tc))
    results.append(("S3", r, t))

    # ==================================================================
    # GROUP N: Non-CPS invocations (no continuation)
    # ==================================================================
    print("--- GROUP N: NON-CPS ---")

    # N1: App(g(8), nil) — kernel might not match CPS pattern
    r, t = run("N1: g(8)(nil) [no cont]", App(Var(8), nil))
    results.append(("N1", r, t))

    # N2: Just Var(8) alone
    r, t = run("N2: g(8) bare", Var(8))
    results.append(("N2", r, t))

    # ==================================================================
    # GROUP G: g(0) with backdoor-produced values
    # Test if g(0) does something special when given kernel-produced terms.
    # ==================================================================
    print("--- GROUP G: g(0) + backdoor ---")

    tc_s2 = shift(tc, 2)
    tc_s4 = shift(tc, 4)
    right_m_s2 = shift(encode_bytes_list(RIGHT_MARKER), 2)

    # G1: g(201)(nil)(λe. e(λpair. g(0)(pair)(TC_s2))(λerr. write(RIGHT,g(0))))
    # depth 2: g(0)=Var(2), pair=Var(0)
    g1_left = Lam(App(App(Var(2), Var(0)), tc_s2))
    g1_right = Lam(App(App(Var(4), right_m_s2), Var(2)))
    g1_cont = Lam(App(App(Var(0), g1_left), g1_right))
    g1_term = App(App(Var(201), nil), g1_cont)
    r, t = run("G1: g(201)->g(0)(pair)(TC)", g1_term)
    results.append(("G1", r, t))

    # G2: g(201)(nil)(λe. e(λpair. pair(λa.λb. g(0)(a)(TC_s4))(nil))(...)
    # depth 4: g(0)=Var(4), a=Var(1)
    g2_consumer = Lam(Lam(App(App(Var(4), Var(1)), tc_s4)))
    g2_left = Lam(App(App(Var(0), g2_consumer), nil))
    g2_right = Lam(App(App(Var(4), right_m_s2), Var(2)))
    g2_cont = Lam(App(App(Var(0), g2_left), g2_right))
    g2_term = App(App(Var(201), nil), g2_cont)
    r, t = run("G2: g(201)->destruct->g(0)(A)(TC)", g2_term)
    results.append(("G2", r, t))

    # G3: g(0)(B)
    # depth 4: g(0)=Var(4), b=Var(0)
    g3_consumer = Lam(Lam(App(App(Var(4), Var(0)), tc_s4)))
    g3_left = Lam(App(App(Var(0), g3_consumer), nil))
    g3_right = Lam(App(App(Var(4), right_m_s2), Var(2)))
    g3_cont = Lam(App(App(Var(0), g3_left), g3_right))
    g3_term = App(App(Var(201), nil), g3_cont)
    r, t = run("G3: g(201)->destruct->g(0)(B)(TC)", g3_term)
    results.append(("G3", r, t))

    # ==================================================================
    # GROUP I: g(0) as index dispatcher for hidden globals 253-255
    # If g(0)(int(N)) dispatches to global N, this could reach unreachable globals.
    # ==================================================================
    print("--- GROUP I: g(0) INDEX DISPATCH ---")

    for idx in (253, 254, 255):
        r, t = run(
            f"I{idx - 252}: g(0)(int({idx}))(TC)",
            App(App(Var(0), encode_byte_term(idx)), tc),
        )
        results.append((f"I{idx - 252}", r, t))

    # ==================================================================
    # SUMMARY
    # ==================================================================
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"{'LABEL':55s} {'BUCKET':>10s} {'TIME':>8s}")
    print("-" * 80)
    for label, bucket, elapsed in results:
        print(f"{label:55.55s} {bucket:>10s} {elapsed:8.3f}")


if __name__ == "__main__":
    main()
