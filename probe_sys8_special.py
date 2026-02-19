#!/usr/bin/env python3
"""Probe sys8 with echo-shifted reserved var indices (253-255).

Core insight: echo(Var(N)) returns Left(payload) where payload lives
under 2 lambdas, so free Var(N) becomes Var(N+2) in the raw term.
When N >= 251, the shifted index lands in the reserved byte range
(0xFD=App, 0xFE=Lam, 0xFF=End) which quote/QD can't serialize.

We pass the echo result to sys8 and observe what happens.

Key constraint: Var(253), Var(254), Var(255) CANNOT appear in source
bytecode (those bytes are reserved markers). We can only generate them
inside the VM via echo's +2 shift on Var(251), Var(252).

Payloads:
  P1-P2. sys8(echo(Var(N), I)) QD for N=252,251  [primary probes]
  P3-P4. nested echo for double shifting
  P5-P6. echo feeds raw Either result directly to sys8 (no unwrap)
  P7-P8. Var(252/251) inside App structure before echo
  P9-P10. write-based continuation (avoids quote entirely)
  P11-P12. echo(Var(N)) with sys8 continuation AND write-based observer
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


@dataclass(frozen=True)
class Var:
    i: int

@dataclass(frozen=True)
class Lam:
    body: object

@dataclass(frozen=True)
class App:
    f: object
    x: object


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        if term.i > 0xFC:
            raise ValueError(f"Var({term.i}) cannot be encoded: byte 0x{term.i:02x} is reserved")
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unknown: {type(term)}")


def make_payload(term: object) -> bytes:
    """Encode a term and append FF end-of-code marker."""
    return encode_term(term) + bytes([FF])


def recv_some(sock: socket.socket, timeout_s: float = 3.0) -> bytes:
    """Receive data, tolerating missing FF terminator."""
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
        if FF in chunk:
            break
    return out


def query(payload: bytes, timeout_s: float = 3.0) -> bytes:
    for attempt in range(5):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as s:
                s.sendall(payload)
                try:
                    s.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_some(s, timeout_s=timeout_s)
        except OSError as e:
            if attempt == 4:
                raise RuntimeError(f"connect failed: {e}")
            time.sleep(0.2 * (2 ** attempt))
    raise RuntimeError("unreachable")


# ── Term building helpers ──

I = Lam(Var(0))                # identity λx.x
NIL = Lam(Lam(Var(0)))         # Scott nil / Church false
g_sys8 = Var(0x08)
g_echo = Var(0x0E)
g_write = Var(0x02)
g_quote = Var(0x04)


def parse_term_from_bytes(data: bytes) -> object:
    stack = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    assert len(stack) == 1, f"parse error: stack={stack}"
    return stack[0]


def shift_term(term: object, delta: int, cutoff: int = 0) -> object:
    """Shift free variables in term by delta (standard de Bruijn shift)."""
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_term(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_term(term.f, delta, cutoff),
                   shift_term(term.x, delta, cutoff))
    raise TypeError(f"Unknown: {type(term)}")


def cps_call(syscall: object, arg: object, cont_bytes: bytes) -> bytes:
    """Build ((syscall arg) cont) + FF as raw payload bytes.
    cont_bytes is the raw bytecode of the continuation (without FF)."""
    inner = encode_term(App(syscall, arg))
    return inner + cont_bytes + bytes([FD, FF])


QD_TERM = parse_term_from_bytes(QD)


# ── Payload definitions ──

def build_payloads() -> dict[str, bytes]:
    payloads = {}

    # ── PRIMARY: echo-shifted reserved vars with QD ──

    # P1. N=252: inside Left payload, Var(252) becomes Var(254) = 0xFE (Lam marker)
    echo_252 = App(App(g_echo, Var(252)), I)
    payloads["P1: sys8(echo(Var(252),I)) QD [inside=Var(254)=0xFE]"] = \
        cps_call(g_sys8, echo_252, QD)

    # P2. N=251: inside Left payload, Var(251) becomes Var(253) = 0xFD (App marker)
    echo_251 = App(App(g_echo, Var(251)), I)
    payloads["P2: sys8(echo(Var(251),I)) QD [inside=Var(253)=0xFD]"] = \
        cps_call(g_sys8, echo_251, QD)

    # ── NESTED ECHO (double shift) ──

    # P3. echo(echo(Var(252),I), I) -- wraps the already-shifted Left in another Left
    nested_echo_252 = App(App(g_echo, echo_252), I)
    payloads["P3: sys8(echo(echo(Var(252),I),I)) QD [nested]"] = \
        cps_call(g_sys8, nested_echo_252, QD)

    # P4. Same for 251
    nested_echo_251 = App(App(g_echo, echo_251), I)
    payloads["P4: sys8(echo(echo(Var(251),I),I)) QD [nested]"] = \
        cps_call(g_sys8, nested_echo_251, QD)

    # ── RAW EITHER TO SYS8 (don't unwrap echo result) ──
    # Instead of echo(V,I) which unwraps via identity, use echo(V, λr.sys8(r,QD))
    # This passes the entire Either Left(...) to sys8, not the unwrapped payload.

    # P5. echo(Var(252), λresult. ((sys8_shifted result) QD_shifted))
    qd_shifted1 = shift_term(QD_TERM, 1)
    sys8_at_depth1 = Var(0x08 + 1)  # Var(9) under 1 lambda
    echo_then_sys8_252 = App(
        App(g_echo, Var(252)),
        Lam(App(App(sys8_at_depth1, Var(0)), qd_shifted1))
    )
    payloads["P5: echo(Var(252), λr.sys8(r,QD)) [raw Either→sys8]"] = \
        make_payload(echo_then_sys8_252)

    # P6. Same for 251
    echo_then_sys8_251 = App(
        App(g_echo, Var(251)),
        Lam(App(App(sys8_at_depth1, Var(0)), qd_shifted1))
    )
    payloads["P6: echo(Var(251), λr.sys8(r,QD)) [raw Either→sys8]"] = \
        make_payload(echo_then_sys8_251)

    # ── STRUCTURAL WRAPPING (App, not pair/lambda) ──
    # Can't use pairs (λf. f a b) because the lambda shifts Var(252)→Var(253)
    # which is unencodable. But we CAN use App(Var(252), X) -- no lambda needed.

    # P7. sys8(echo(App(Var(252), nil), I)) QD
    app_252_nil = App(Var(252), NIL)
    echo_app_252 = App(App(g_echo, app_252_nil), I)
    payloads["P7: sys8(echo(App(Var(252),nil),I)) QD [app struct]"] = \
        cps_call(g_sys8, echo_app_252, QD)

    # P8. sys8(echo(App(nil, Var(252)), I)) QD
    app_nil_252 = App(NIL, Var(252))
    echo_app_252b = App(App(g_echo, app_nil_252), I)
    payloads["P8: sys8(echo(App(nil,Var(252)),I)) QD [app struct v2]"] = \
        cps_call(g_sys8, echo_app_252b, QD)

    # ── WRITE-BASED CONTINUATION (avoids quote entirely) ──
    # λresult. ((Var(3) Var(0)) (λ_.λ_.Var(0)))
    # Under 1 lambda: Var(3)=write (was Var(2)+1), Var(0)=result
    # Continuation for write: nil (just stop)
    # This tries to treat the result as a byte-list and write it directly.
    # If result is Right(6), it won't be a valid byte-list, but the VM's
    # behavior on type mismatch may still reveal something.
    write_cont = Lam(App(App(Var(3), Var(0)), NIL))

    payloads["P9: sys8(echo(Var(252),I)) write_cont [no quote]"] = \
        make_payload(App(App(g_sys8, echo_252), write_cont))

    payloads["P10: sys8(echo(Var(251),I)) write_cont [no quote]"] = \
        make_payload(App(App(g_sys8, echo_251), write_cont))

    # ── ECHO → SYS8 WITH WRITE-BASED OBSERVER (fully avoids quote) ──
    # echo(Var(252), λecho_result. sys8(echo_result, λsys8_result. write(sys8_result, nil)))
    # Under depth 1 (echo cont): sys8=Var(9), write=Var(3)
    # Under depth 2 (sys8 cont): write=Var(4)
    write_cont_shifted = Lam(App(App(Var(4), Var(0)), NIL))
    echo_sys8_write_252 = App(
        App(g_echo, Var(252)),
        Lam(App(App(sys8_at_depth1, Var(0)), write_cont_shifted))
    )
    payloads["P11: echo(252,λr.sys8(r,write_cont)) [full no-quote]"] = \
        make_payload(echo_sys8_write_252)

    echo_sys8_write_251 = App(
        App(g_echo, Var(251)),
        Lam(App(App(sys8_at_depth1, Var(0)), write_cont_shifted))
    )
    payloads["P12: echo(251,λr.sys8(r,write_cont)) [full no-quote]"] = \
        make_payload(echo_sys8_write_251)

    # ── BASELINE: sys8(nil) QD for comparison ──
    payloads["BASELINE: sys8(nil) QD"] = cps_call(g_sys8, NIL, QD)

    return payloads


def format_response(out: bytes) -> str:
    """Pretty-format a response."""
    lines = []
    lines.append(f"  raw:         {out!r}")
    lines.append(f"  hex:         {out.hex()}")
    lines.append(f"  length:      {len(out)}")

    if out:
        ascii_repr = ''.join(
            chr(b) if 32 <= b < 127 else f'\\x{b:02x}'
            for b in out
        )
        lines.append(f"  ascii-ish:   {ascii_repr}")

    ff_present = b'\xff' in out
    lines.append(f"  FF-term:     {'yes' if ff_present else 'NO'}")

    if b"Encoding failed" in out:
        lines.append(f"  !! Contains 'Encoding failed' !!")
    if b"Permission" in out:
        lines.append(f"  !! Contains 'Permission' text !!")
    if b"Invalid" in out:
        lines.append(f"  !! Contains 'Invalid' text !!")

    return '\n'.join(lines)


def main():
    payloads = build_payloads()

    print("=" * 70)
    print("Probing sys8 with echo-shifted reserved var indices")
    print(f"Target: {HOST}:{PORT}")
    print(f"Total payloads: {len(payloads)}")
    print("=" * 70)

    results: dict[str, bytes | None] = {}
    baseline_hex: str | None = None

    for name, payload in payloads.items():
        print(f"\n--- {name} ---")
        print(f"  payload:     {payload.hex()} ({len(payload)}B)")

        try:
            out = query(payload, timeout_s=5.0)
            results[name] = out
            print(format_response(out))

            if name.startswith("BASELINE"):
                baseline_hex = out.hex()
                print(f"  (saved as baseline)")

        except Exception as e:
            results[name] = None
            print(f"  ERROR: {e}")

        time.sleep(0.3)

    # ── Summary ──
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    if baseline_hex:
        print(f"\n  Baseline (sys8(nil) QD): {baseline_hex}")

    response_groups: dict[str, list[str]] = {}
    for name, out in results.items():
        key = out.hex() if out else "ERROR/EMPTY"
        response_groups.setdefault(key, []).append(name)

    for resp_hex, names in sorted(response_groups.items()):
        marker = ""
        if baseline_hex and resp_hex != baseline_hex:
            marker = " *** DIFFERENT FROM BASELINE ***"
        print(f"\n  Response [{resp_hex}]{marker}")
        for n in names:
            print(f"    - {n}")

    unique = len(response_groups)
    print(f"\n  Unique responses: {unique}")
    if unique > 1:
        print("  *** MULTIPLE DISTINCT RESPONSES - investigate further! ***")
    else:
        print("  All identical (likely all Right(6)).")


if __name__ == "__main__":
    main()
