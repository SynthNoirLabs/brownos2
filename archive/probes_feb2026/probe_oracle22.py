#!/usr/bin/env python3
"""
probe_oracle22.py - Use pair components as functions + chained syscalls.

Now that quote-from-continuation works, we can observe computed values.

Groups:
  F: Use pair components A=λab.(bb), B=λab.(ab) as functions, quote results
  C: Chained syscalls — use output of one syscall as input to sys8
  X: Exotic sys8 invocations — pass computed terms to sys8
  E: Error code probing — does sys8 return DIFFERENT error codes for
     specific arguments? (We've only checked Left vs Right, not the error code)
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
    left_h = Lam(App(App(Var(4), shift(left_m, 2)), Var(2)))
    right_h = Lam(App(App(Var(4), shift(right_m, 2)), Var(2)))
    return Lam(App(App(Var(0), left_h), right_h))


def build_write_result_cont() -> object:
    """
    λresult. result
        (λpayload. write(payload, g(0)))    -- Left: write the payload
        (λerrcode. write(error_string(errcode), g(0)))  -- Right: write error string

    But error_string is a syscall (CPS). Simpler: just write a marker + the error code.
    Actually, let's write the error code as a single byte for Right.

    For Left: write the payload directly (assumes it's a byte list).
    For Right: write a marker "R:" then use error_string to get the text.

    Actually simplest: use QD-like approach. Quote the whole result.

    λresult. g(4)(result)(λqr. qr(λbytes. g(2)(bytes)(g(0)))(λerr. g(2)("QFAIL")(g(0))))
    """
    qfail = encode_bytes_list(b"QFAIL\n")
    # depth 1: result=0
    # depth 2 (λqr): qr=0, g(K)=Var(K+2)
    # depth 3 (λbytes or λerr): g(2)=Var(5), g(0)=Var(3)
    write_bytes = Lam(App(App(Var(5), Var(0)), Var(3)))
    write_qfail = Lam(App(App(Var(5), shift(qfail, 3)), Var(3)))
    unwrap_qr = Lam(App(App(Var(0), write_bytes), write_qfail))
    # depth 1: g(4)(result)(unwrap_qr) — g(4)=Var(5), result=Var(0)
    return Lam(App(App(Var(5), Var(0)), unwrap_qr))


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
    print("probe_oracle22.py - Pair funcs + chained syscalls + error codes")
    print(f"Target: {HOST}:{PORT}")
    print("=" * 80)
    print()

    nil = Lam(Lam(Var(0)))
    tc = build_tag_cont()
    qc = build_write_result_cont()  # quote-and-write continuation
    results: list[tuple[str, str, float]] = []

    # ------------------------------------------------------------------
    # SANITY
    # ------------------------------------------------------------------
    print("--- SANITY ---")
    r, t = run("SANITY: g(7)(int(11))(TC)", App(App(Var(7), encode_byte_term(11)), tc))
    results.append(("SANITY-TC", r, t))

    # Test QC (quote continuation)
    r, t = run(
        "SANITY-QC: g(14)(nil)(QC) [echo nil, quote result]", App(App(Var(14), nil), qc)
    )
    results.append(("SANITY-QC", r, t))

    # ==================================================================
    # GROUP E: ERROR CODE PROBING
    # Does sys8 return DIFFERENT error codes for different args?
    # We always checked Left vs Right but never extracted the error code.
    #
    # Continuation: λresult. result(λ_. write("L",g(0)))(λerrcode.
    #   g(1)(errcode)(λestr. estr(λtext. write(text,g(0)))(λe2. write("?",g(0)))))
    #
    # This writes the error STRING for Right cases.
    # ==================================================================
    print("--- GROUP E: ERROR CODES ---")

    # Build error-extracting continuation
    # λresult.                                          depth 1
    #   result
    #     (λpayload. write("LEFT\n", g(0)))            depth 2: g(2)=4, g(0)=2
    #     (λerrcode.                                    depth 2: errcode=0
    #       g(1)(errcode)(λestr.                        depth 3: g(1)=4, errcode=1
    #         estr                                      estr is Either from error_string
    #           (λtext. write(text, g(0)))              depth 4: g(2)=6, g(0)=4
    #           (λerr2. write("?\n", g(0)))             depth 4
    #       )
    #     )
    left_m_s2 = shift(encode_bytes_list(LEFT_MARKER), 2)
    e_left_h = Lam(App(App(Var(4), left_m_s2), Var(2)))

    # depth 4: write text
    e_write_text = Lam(App(App(Var(6), Var(0)), Var(4)))
    # depth 4: write "?\n"
    q_bytes = encode_bytes_list(b"?\n")
    e_write_q = Lam(App(App(Var(6), shift(q_bytes, 4)), Var(4)))
    # depth 3: estr(write_text)(write_q)
    e_unwrap_estr = Lam(App(App(Var(0), e_write_text), e_write_q))
    # depth 2: g(1)(errcode)(e_unwrap_estr) — g(1)=Var(3), errcode=Var(0)
    e_right_h = Lam(App(App(Var(3), Var(0)), e_unwrap_estr))
    # depth 1: result(left)(right)
    e_cont = Lam(App(App(Var(0), e_left_h), e_right_h))

    # E1: sys8(nil) — baseline error code
    r, t = run("E1: g(8)(nil) error_string", App(App(Var(8), nil), e_cont))
    results.append(("E1-nil", r, t))

    # E2: sys8(g(0))
    r, t = run("E2: g(8)(g(0)) error_string", App(App(Var(8), Var(0)), e_cont))
    results.append(("E2-g0", r, t))

    # E3: sys8(int(0))
    r, t = run(
        "E3: g(8)(int(0)) error_string", App(App(Var(8), encode_byte_term(0)), e_cont)
    )
    results.append(("E3-int0", r, t))

    # E4: sys8(int(1))
    r, t = run(
        "E4: g(8)(int(1)) error_string", App(App(Var(8), encode_byte_term(1)), e_cont)
    )
    results.append(("E4-int1", r, t))

    # E5: sys8("ilikephp")
    pw = encode_bytes_list(b"ilikephp")
    r, t = run('E5: g(8)("ilikephp") error_string', App(App(Var(8), pw), e_cont))
    results.append(("E5-pw", r, t))

    # E6: sys8 with backdoor pair (need to chain g(201) first)
    # g(201)(nil)(λe. e(λpair. g(8)(pair)(e_cont_s2))(λerr. write("RFAIL")))
    e_cont_s2 = shift(e_cont, 2)
    rfail = encode_bytes_list(b"RFAIL\n")
    e6_left = Lam(App(App(Var(10), Var(0)), e_cont_s2))
    e6_right = Lam(App(App(Var(4), shift(rfail, 2)), Var(2)))
    e6_outer = Lam(App(App(Var(0), e6_left), e6_right))
    r, t = run("E6: g(201)->g(8)(pair) error_string", App(App(Var(201), nil), e6_outer))
    results.append(("E6-pair", r, t))

    # E7: sys8 with A component from pair
    # g(201)(nil)(λe. e(λpair. pair(λa.λb. g(8)(a)(e_cont_s4))(nil))(λerr. ...))
    e_cont_s4 = shift(e_cont, 4)
    e7_consumer = Lam(Lam(App(App(Var(12), Var(1)), e_cont_s4)))
    e7_left = Lam(App(App(Var(0), e7_consumer), nil))
    e7_right = Lam(App(App(Var(4), shift(rfail, 2)), Var(2)))
    e7_outer = Lam(App(App(Var(0), e7_left), e7_right))
    r, t = run(
        "E7: g(201)->destruct->g(8)(A) error_string", App(App(Var(201), nil), e7_outer)
    )
    results.append(("E7-A", r, t))

    # E8: sys8 with B component
    e8_consumer = Lam(Lam(App(App(Var(12), Var(0)), e_cont_s4)))
    e8_left = Lam(App(App(Var(0), e8_consumer), nil))
    e8_right = Lam(App(App(Var(4), shift(rfail, 2)), Var(2)))
    e8_outer = Lam(App(App(Var(0), e8_left), e8_right))
    r, t = run(
        "E8: g(201)->destruct->g(8)(B) error_string", App(App(Var(201), nil), e8_outer)
    )
    results.append(("E8-B", r, t))

    # ==================================================================
    # GROUP C: CHAINED SYSCALLS
    # Use output of other syscalls as sys8 argument
    # ==================================================================
    print("--- GROUP C: CHAINED SYSCALLS ---")

    # C1: echo(g(8)) → unwrap → use Left payload as arg to sys8
    # g(14)(g(8))(λecho_r. echo_r(λval. g(8)(val)(TC_s2))(λerr. write(RIGHT)))
    tc_s2 = shift(tc, 2)
    c1_left = Lam(App(App(Var(10), Var(0)), tc_s2))
    rm_s2 = shift(encode_bytes_list(RIGHT_MARKER), 2)
    c1_right = Lam(App(App(Var(4), rm_s2), Var(2)))
    c1_echo_cont = Lam(App(App(Var(0), c1_left), c1_right))
    r, t = run(
        "C1: echo(g(8))->unwrap->sys8(echoed_g8)(TC)",
        App(App(Var(14), Var(8)), c1_echo_cont),
    )
    results.append(("C1", r, t))

    # C2: name(8) → get the name of file ID 8, pass to sys8
    # g(6)(int(8))(λnr. nr(λname. g(8)(name)(TC_s2))(λerr. write(RIGHT)))
    c2_left = Lam(App(App(Var(10), Var(0)), tc_s2))
    c2_right = Lam(App(App(Var(4), rm_s2), Var(2)))
    c2_cont = Lam(App(App(Var(0), c2_left), c2_right))
    r, t = run(
        "C2: name(8)->sys8(filename)(TC)",
        App(App(Var(6), encode_byte_term(8)), c2_cont),
    )
    results.append(("C2", r, t))

    # C3: What's the name of file 8? Let's just read it.
    # g(6)(int(8))(QC) — QC quotes and writes the result
    r, t = run(
        "C3: name(int(8))(QC) [what IS file 8?]",
        App(App(Var(6), encode_byte_term(8)), qc),
    )
    results.append(("C3", r, t))

    # C4: Quote g(8) directly — what does quote say about the opaque global?
    # g(4)(g(8))(λqr. qr(λbytes. write(bytes,g(0)))(λerr. write("QFAIL",g(0))))
    qfail_s2 = shift(encode_bytes_list(b"QFAIL\n"), 2)
    c4_wbytes = Lam(App(App(Var(4), Var(0)), Var(2)))
    c4_wqfail = Lam(App(App(Var(4), qfail_s2), Var(2)))
    c4_uqr = Lam(App(App(Var(0), c4_wbytes), c4_wqfail))
    # depth 0: g(4)=Var(4), g(8)=Var(8)
    r, t = run(
        "C4: quote(g(8)) [raw encoding of g(8)]", App(App(Var(4), Var(8)), c4_uqr)
    )
    results.append(("C4", r, t))

    # C5: Quote g(201)
    r, t = run(
        "C5: quote(g(201)) [raw encoding of g(201)]", App(App(Var(4), Var(201)), c4_uqr)
    )
    results.append(("C5", r, t))

    # C6: Quote g(0)
    r, t = run(
        "C6: quote(g(0)) [raw encoding of g(0)]", App(App(Var(4), Var(0)), c4_uqr)
    )
    results.append(("C6", r, t))

    # ==================================================================
    # GROUP F: PAIR COMPONENTS AS FUNCTIONS
    # A=λab.(bb), B=λab.(ab)
    # Apply them to interesting inputs and quote the results
    # ==================================================================
    print("--- GROUP F: PAIR FUNCS ---")

    # F1: A(nil)(nil) = nil(nil) = (λc.λn.n)(nil) = λn.n = id
    # So A(nil)(nil) should be id. Quote it.
    # At depth 0: just App(App(A_literal, nil), nil), then quote+write
    # But A is inside the pair. We need to extract it first.
    #
    # g(201)(nil)(λe. e(λpair. pair(λa.λb.
    #   let result = a(nil)(nil)
    #   g(4)(result)(unwrap -> write)
    # )(nil))(λerr. write("RFAIL")))
    #
    # Under λe.λpair.λa.λb (depth 4):
    #   a=Var(1), b=Var(0), nil needs shift=0 (closed)
    #   result = App(App(Var(1), nil), nil)
    #   g(4) = Var(8)
    #   Then quote continuation at depth 5 (λqr):
    #     at depth 6: g(2)=Var(8), g(0)=Var(6)

    f_wbytes_d6 = Lam(App(App(Var(8), Var(0)), Var(6)))
    f_wqfail_d6 = Lam(App(App(Var(8), shift(encode_bytes_list(b"QFAIL\n"), 6)), Var(6)))
    f_uqr_d5 = Lam(App(App(Var(0), f_wbytes_d6), f_wqfail_d6))

    # F1: a(nil)(nil) then quote
    f1_result = App(App(Var(1), nil), nil)  # a(nil)(nil) at depth 4
    f1_consumer = Lam(Lam(App(App(Var(8), f1_result), f_uqr_d5)))
    f1_left = Lam(App(App(Var(0), f1_consumer), nil))
    f1_right = Lam(App(App(Var(4), shift(rfail, 2)), Var(2)))
    f1_outer = Lam(App(App(Var(0), f1_left), f1_right))
    r, t = run(
        "F1: pair->a(nil)(nil)->quote [should be id?]",
        App(App(Var(201), nil), f1_outer),
    )
    results.append(("F1", r, t))

    # F2: b(nil)(nil) = nil(nil) = (same as F1 but with b)
    # b=Var(0), so b(nil)(nil) = App(App(Var(0), nil), nil)
    f2_result = App(App(Var(0), nil), nil)  # b(nil)(nil) at depth 4
    f2_consumer = Lam(Lam(App(App(Var(8), f2_result), f_uqr_d5)))
    f2_left = Lam(App(App(Var(0), f2_consumer), nil))
    f2_right = Lam(App(App(Var(4), shift(rfail, 2)), Var(2)))
    f2_outer = Lam(App(App(Var(0), f2_left), f2_right))
    r, t = run("F2: pair->b(nil)(nil)->quote", App(App(Var(201), nil), f2_outer))
    results.append(("F2", r, t))

    # F3: a(g(8))(nil) — A applied to g(8) then nil
    # At depth 4: g(8) = Var(12)
    # a(g(8))(nil) = A(g(8))(nil) = nil(nil) (since A=λab.bb, so A(g(8))(nil) = nil(nil))
    # Actually: A = λab.(bb). A(g(8)) = λb.(bb). A(g(8))(nil) = nil(nil) = λn.n
    # Hmm same as F1. Let me try something more interesting.

    # F3: b(g(8))(nil) = B(g(8))(nil) = g(8)(nil)
    # B = λab.(ab). B(g(8)) = λb.(g(8) b). B(g(8))(nil) = g(8)(nil)
    # g(8)(nil) is a partial application — this is just g(8) applied to nil without cont
    # This should reduce to the kernel applying g(8), but without a continuation...
    # Actually in the lazy setting, g(8)(nil) is just App(Var(12), nil) at depth 4
    # The kernel won't match it as a syscall because there's no continuation pattern
    # But then we QUOTE it. Quote should give us the bytes of App(g(8), nil).
    f3_result = App(Var(12), nil)  # g(8)(nil) at depth 4 — partial app
    f3_consumer = Lam(Lam(App(App(Var(8), f3_result), f_uqr_d5)))
    f3_left = Lam(App(App(Var(0), f3_consumer), nil))
    f3_right = Lam(App(App(Var(4), shift(rfail, 2)), Var(2)))
    f3_outer = Lam(App(App(Var(0), f3_left), f3_right))
    r, t = run(
        "F3: pair->quote(b(g(8))(nil)) [= quote(g(8) nil)]",
        App(App(Var(201), nil), f3_outer),
    )
    results.append(("F3", r, t))

    # F4: Apply A to B → omega: A(B) = λb.(bb)
    # Then quote the result
    # At depth 4: a=Var(1), b_var=Var(0)
    f4_result = App(Var(1), Var(0))  # a(b) = A(B) at depth 4
    f4_consumer = Lam(Lam(App(App(Var(8), f4_result), f_uqr_d5)))
    f4_left = Lam(App(App(Var(0), f4_consumer), nil))
    f4_right = Lam(App(App(Var(4), shift(rfail, 2)), Var(2)))
    f4_outer = Lam(App(App(Var(0), f4_left), f4_right))
    r, t = run("F4: pair->quote(a(b)) [= quote(ω)]", App(App(Var(201), nil), f4_outer))
    results.append(("F4", r, t))

    # F5: Apply B to A → B(A) = λb.(A b)
    f5_result = App(Var(0), Var(1))  # b(a) = B(A) at depth 4
    f5_consumer = Lam(Lam(App(App(Var(8), f5_result), f_uqr_d5)))
    f5_left = Lam(App(App(Var(0), f5_consumer), nil))
    f5_right = Lam(App(App(Var(4), shift(rfail, 2)), Var(2)))
    f5_outer = Lam(App(App(Var(0), f5_left), f5_right))
    r, t = run(
        "F5: pair->quote(b(a)) [= quote(B(A))]", App(App(Var(201), nil), f5_outer)
    )
    results.append(("F5", r, t))

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
