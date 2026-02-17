#!/usr/bin/env python3
"""
probe_oracle19b.py - Fix A3-A5: properly unwrap Either from g(201) before
extracting pair components, then pass them to sys8.

Bug in probe_oracle19.py: g(201) is CPS and returns Either(Left(pair)).
We were treating p as pair directly, but it's Left(pair) = λl.λr.(l pair).
Must unwrap: either(λpair. ... )(λerr. ...)
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
    Depth context for each handler: under 2 lambdas from top level.
    """
    left_m = encode_bytes_list(LEFT_MARKER)
    right_m = encode_bytes_list(RIGHT_MARKER)
    # Under λresult.λpayload (depth 2): g(2)=Var(4), g(0)=Var(2)
    left_h = Lam(App(App(Var(4), shift(left_m, 2)), Var(2)))
    right_h = Lam(App(App(Var(4), shift(right_m, 2)), Var(2)))
    return Lam(App(App(Var(0), left_h), right_h))


def run(label: str, term: object) -> str:
    payload = encode_term(term) + bytes([FF])
    plen = len(payload)
    print(f"{label}")
    print(f"  payload_len: {plen}")
    if plen > MAX_PAYLOAD:
        print(f"  SKIPPED (too big)")
        print()
        return "SKIPPED"
    out, elapsed = query_raw(payload)
    text = out.decode("latin-1", errors="replace") if out else ""
    bucket = "OTHER"
    if LEFT_MARKER in out and RIGHT_MARKER not in out:
        bucket = "LEFT"
    elif RIGHT_MARKER in out and LEFT_MARKER not in out:
        bucket = "RIGHT"
    elif not out:
        bucket = f"EMPTY({elapsed:.1f}s)"
    print(f"  elapsed: {elapsed:.3f}s")
    print(f"  raw_hex: {out.hex() if out else '(empty)'}")
    print(f"  text: {text!r}")
    print(f"  bucket: {bucket}")
    print()
    time.sleep(REQUEST_DELAY_S)
    return bucket


def main() -> None:
    print("=" * 72)
    print("probe_oracle19b.py - Fixed backdoor + sys8 probes")
    print(f"Target: {HOST}:{PORT}")
    print("=" * 72)
    print()

    nil = Lam(Lam(Var(0)))
    tc = build_tag_cont()  # tag continuation at depth 0

    results: list[tuple[str, str]] = []

    # ------------------------------------------------------------------
    # SANITY: verify TAG_CONT still works
    # ------------------------------------------------------------------
    print("--- Sanity ---")
    # readfile(11) → should print LEFT
    r = run(
        "SANITY: g(7)(int(11))(TAG_CONT)", App(App(Var(7), encode_byte_term(11)), tc)
    )
    results.append(("SANITY", r))

    # ------------------------------------------------------------------
    # FIXED A3: g(201)(nil)(λeither. either(λpair. pair(λa.λb. g(8)(a·b)(TC)))(λerr. write(RIGHT,g(0))))
    #
    # Structure:
    #   g(201)(nil)( λeither.
    #     either
    #       (λpair. pair (λa. λb. g(8)(App(a,b))(TC_shifted)))
    #       (λerr. write(RIGHT_MARKER, g(0)))
    #   )
    #
    # Depth analysis for the inner part:
    #   λeither (depth 1): either=Var(0)
    #     Left handler: λpair (depth 2): pair=Var(0)
    #       pair applied to: λa (depth 3): a=Var(0)
    #         λb (depth 4): b=Var(0), a=Var(1)
    #           g(8) = Var(8+4) = Var(12)
    #           App(a,b) = App(Var(1), Var(0))
    #           TC needs shift by 4
    #     Right handler: λerr (depth 2):
    #       g(2) = Var(2+2) = Var(4), g(0) = Var(0+2) = Var(2)
    #       write(RIGHT_MARKER, g(0))
    # ------------------------------------------------------------------
    print("--- Fixed A3-A5: Unwrap Either from g(201) ---")

    tc_s4 = shift(tc, 4)
    tc_s3 = shift(tc, 3)
    right_m_s2 = shift(encode_bytes_list(RIGHT_MARKER), 2)

    # Right handler for Either unwrap (depth 2): write error marker
    err_handler = Lam(App(App(Var(4), right_m_s2), Var(2)))

    # A3_FIX: pass ω = App(a,b) to sys8
    # Under λeither.λpair.λa.λb (depth 4): g(8)=Var(12), a=Var(1), b=Var(0)
    a3_inner = Lam(Lam(App(App(Var(12), App(Var(1), Var(0))), tc_s4)))
    # Under λeither.λpair (depth 2): pair=Var(0)
    a3_left = Lam(App(Var(0), a3_inner))
    # Under λeither (depth 1): either=Var(0)
    a3_cont = Lam(App(App(Var(0), a3_left), shift(err_handler, 1)))

    r = run(
        "A3_FIX: g(201)(nil)(λe. e(λpair. pair(λa.λb. g(8)(a·b)(TC)))(λerr. write(R,g(0))))",
        App(App(Var(201), nil), a3_cont),
    )
    results.append(("A3_FIX", r))

    # A4_FIX: pass component A to sys8
    # Under λeither.λpair.λa.λb (depth 4): g(8)=Var(12), a=Var(1)
    a4_inner = Lam(Lam(App(App(Var(12), Var(1)), tc_s4)))
    a4_left = Lam(App(Var(0), a4_inner))
    a4_cont = Lam(App(App(Var(0), a4_left), shift(err_handler, 1)))

    r = run(
        "A4_FIX: g(201)(nil)(λe. e(λpair. pair(λa.λb. g(8)(a)(TC)))(λerr. ...))",
        App(App(Var(201), nil), a4_cont),
    )
    results.append(("A4_FIX", r))

    # A5_FIX: pass component B to sys8
    # Under λeither.λpair.λa.λb (depth 4): g(8)=Var(12), b=Var(0)
    a5_inner = Lam(Lam(App(App(Var(12), Var(0)), tc_s4)))
    a5_left = Lam(App(Var(0), a5_inner))
    a5_cont = Lam(App(App(Var(0), a5_left), shift(err_handler, 1)))

    r = run(
        "A5_FIX: g(201)(nil)(λe. e(λpair. pair(λa.λb. g(8)(b)(TC)))(λerr. ...))",
        App(App(Var(201), nil), a5_cont),
    )
    results.append(("A5_FIX", r))

    # A6: pass the whole pair (without destructuring) to sys8
    # Under λeither.λpair (depth 2): g(8)=Var(10), pair=Var(0)
    tc_s2 = shift(tc, 2)
    a6_left = Lam(App(App(Var(10), Var(0)), tc_s2))
    a6_cont = Lam(App(App(Var(0), a6_left), shift(err_handler, 1)))

    r = run(
        "A6: g(201)(nil)(λe. e(λpair. g(8)(pair)(TC))(λerr. ...))",
        App(App(Var(201), nil), a6_cont),
    )
    results.append(("A6", r))

    # ------------------------------------------------------------------
    # A7: Backdoor THEN sys8 with gizmore's password as bytes
    # ------------------------------------------------------------------
    print("--- A7-A8: Backdoor then sys8 with specific data ---")

    # g(201)(nil)(λe. e(λpair. g(8)("ilikephp")(TC))(λerr. ...))
    pw_bytes = encode_bytes_list(b"ilikephp")
    # Under λeither.λpair (depth 2): g(8)=Var(10)
    a7_left = Lam(App(App(Var(10), shift(pw_bytes, 2)), tc_s2))
    a7_cont = Lam(App(App(Var(0), a7_left), shift(err_handler, 1)))

    r = run(
        'A7: g(201)(nil)(λe. e(λp. g(8)("ilikephp")(TC))(λerr. ...))',
        App(App(Var(201), nil), a7_cont),
    )
    results.append(("A7", r))

    # A8: sys8 with "ilikephp" directly (no backdoor chain)
    r = run('A8: g(8)("ilikephp")(TC)', App(App(Var(8), pw_bytes), tc))
    results.append(("A8", r))

    # ------------------------------------------------------------------
    # A9: What if sys8 needs the BACKDOOR ITSELF (g(201)) as arg?
    # ------------------------------------------------------------------
    print("--- A9-A10: Pass globals as arg to sys8 ---")
    r = run("A9: g(8)(g(201))(TC)", App(App(Var(8), Var(201)), tc))
    results.append(("A9", r))

    # A10: What about g(8)(g(8))(TC) — self-referential?
    r = run("A10: g(8)(g(8))(TC)", App(App(Var(8), Var(8)), tc))
    results.append(("A10", r))

    # ------------------------------------------------------------------
    # A11: Chain: readfile(solution_binary) → sys8
    # File ID 14 = /bin/sh (0 bytes), 15 = /bin/sudo (0 bytes), 16 = /bin/false (0 bytes)
    # What if we need to "sudo" g(8)?
    # sudo=g(15) as a syscall? Try g(15)(g(8))(TC) or g(15)(nil)(TC)
    # ------------------------------------------------------------------
    print("--- A11-A13: sudo / sh / false as syscalls ---")
    r = run("A11: g(15)(nil)(TC) [sudo]", App(App(Var(15), nil), tc))
    results.append(("A11", r))

    r = run("A12: g(14)(nil)(TC) [sh]", App(App(Var(14), nil), tc))
    results.append(("A12", r))

    # A13: What if sys8 takes 3 args? sys8(credential)(arg)(continuation)
    # Try: g(8)(g(201))(nil)(TC) = ((g(8) g(201)) nil) TC
    # This tests 3-arg hypothesis
    r = run(
        "A13: g(8)(g(201))(nil)(TC) [3-arg hypothesis]",
        App(App(App(Var(8), Var(201)), nil), tc),
    )
    results.append(("A13", r))

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    for label, bucket in results:
        print(f"  {label:60s} -> {bucket}")


if __name__ == "__main__":
    main()
