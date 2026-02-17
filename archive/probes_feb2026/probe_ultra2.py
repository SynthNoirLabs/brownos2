#!/usr/bin/env python3
"""
probe_ultra2.py — Deep investigation of the 3-arg sys8 empty responses.

The empty responses from g(8)(arg1)(arg2)(QD) need careful analysis:
- Is sys8 truly a 2-arg syscall (takes arg + continuation)?
- Or is it a 3-arg syscall (takes arg1 + arg2 + continuation)?

Strategy:
1. Use a "sentinel" continuation that ALWAYS writes something, to distinguish
   "sys8 consumed 2 args and called continuation" from "sys8 consumed 1 arg and
   the result got applied to random stuff"
2. If sys8 is 2-arg CPS: sys8(arg)(k) → k(result)
   Then sys8(arg1)(arg2)(QD) = (arg2(result))(QD) — likely garbage/empty
3. If sys8 is 3-arg CPS: sys8(arg1)(arg2)(k) → k(result)
   Then with proper k, we'd see the result

We test with:
- Sentinel continuation that writes "OK" + quotes the result
- 2-arg form with sentinel: sys8(arg)(sentinel) — should always work
- 3-arg form with sentinel: sys8(arg1)(arg2)(sentinel) — only works if 3-arg

Also: investigate the RateLimit response from sys201(A) and sys201(B).
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


def query(payload: bytes, retries: int = 3, timeout_s: float = 5.0) -> bytes:
    delay = 0.3
    last_err = None
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s=timeout_s)
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed: {last_err}")


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported: {type(term)}")


def encode_byte_term(n: int) -> object:
    expr: object = Var(0)
    for idx, weight in (
        (1, 1),
        (2, 2),
        (3, 4),
        (4, 8),
        (5, 16),
        (6, 32),
        (7, 64),
        (8, 128),
    ):
        if n & weight:
            expr = App(Var(idx), expr)
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_bytes_list(bs: bytes) -> object:
    nil: object = Lam(Lam(Var(0)))

    def cons(h: object, t: object) -> object:
        return Lam(Lam(App(App(Var(1), h), t)))

    cur: object = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


nil = Lam(Lam(Var(0)))


def test(label: str, payload_bytes: bytes):
    full = payload_bytes + bytes([FF])
    try:
        raw = query(full)
        if raw:
            hex_str = raw.hex()
            # Try to interpret as ASCII too
            try:
                text = raw.decode("latin-1")
                printable = "".join(
                    c if 32 <= ord(c) < 127 else f"\\x{ord(c):02x}" for c in text
                )
                print(f"  {label}: hex={hex_str[:80]} text='{printable[:60]}'")
            except:
                print(f"  {label}: hex={hex_str[:80]}")
        else:
            print(f"  {label}: EMPTY (no data received)")
    except Exception as e:
        print(f"  {label}: ERROR: {e}")
    time.sleep(0.4)


def main():
    print("=" * 70)
    print("PROBE ULTRA2 — Deep investigation of empty responses & rate limits")
    print("=" * 70)

    # ── Understanding the 3-arg empty responses ──
    # Hypothesis: sys8 is standard 2-arg CPS. sys8(arg)(cont) → cont(Right(6)).
    # When we do sys8(arg1)(arg2)(QD), the CPS continuation is arg2 (not QD).
    # So sys8(arg1)(arg2) = arg2(Right(6)), then (arg2(Right(6)))(QD) produces garbage.
    #
    # To CONFIRM this, let's compare:
    # (a) sys8(nil)(QD) — standard 2-arg, QD is the continuation → should show Right(6)
    # (b) sys8(nil)('ilikephp')(QD) — 3-arg, continuation is 'ilikephp' → empty garbage
    # (c) A known 2-arg syscall in 3-arg form: sys7(11)(extra)(QD) → should also be empty

    print("\n[A] Confirm sys8 is 2-arg CPS (not 3-arg):")
    print("    Compare sys8 2-arg vs 3-arg, and compare with known 2-arg syscall7:")

    # sys8(nil)(QD) — standard form
    p1 = bytes([0x08]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD])
    test("sys8(nil)(QD) [2-arg standard]", p1)

    # sys8(nil)(extra)(QD) — 3-arg form
    extra = encode_bytes_list(b"test")
    p2 = (
        bytes([0x08])
        + encode_term(nil)
        + bytes([FD])
        + encode_term(extra)
        + bytes([FD])
        + QD
        + bytes([FD])
    )
    test("sys8(nil)(extra)(QD) [3-arg]", p2)

    # sys7(11)(QD) — standard readfile
    p3 = (
        bytes([0x07])
        + encode_term(encode_byte_term(11))
        + bytes([FD])
        + QD
        + bytes([FD])
    )
    test("sys7(11)(QD) [2-arg standard, reads passwd]", p3)

    # sys7(11)(extra)(QD) — readfile in 3-arg form (should also be empty/garbage)
    p4 = (
        bytes([0x07])
        + encode_term(encode_byte_term(11))
        + bytes([FD])
        + encode_term(extra)
        + bytes([FD])
        + QD
        + bytes([FD])
    )
    test("sys7(11)(extra)(QD) [3-arg, should be garbage]", p4)

    # ── RateLimit investigation ──
    print("\n[B] sys201 RateLimit investigation:")
    print(
        "    sys201(A) and sys201(B) returned RateLimit(7). Is this real rate-limiting"
    )
    print("    or a meaningful different response? Re-test with delays.")

    time.sleep(2)  # Wait to clear any rate limit

    # Re-test A and B with proper delays
    A_term = Lam(Lam(App(Var(0), Var(0))))
    B_term = Lam(Lam(App(Var(1), Var(0))))

    # First re-test nil (control)
    p5 = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD])
    test("sys201(nil) [control - should be Left(pair)]", p5)
    time.sleep(1)

    # Now A
    p6 = bytes([0xC9]) + encode_term(A_term) + bytes([FD]) + QD + bytes([FD])
    test("sys201(A=λab.bb) [was RateLimit]", p6)
    time.sleep(1)

    # Now B
    p7 = bytes([0xC9]) + encode_term(B_term) + bytes([FD]) + QD + bytes([FD])
    test("sys201(B=λab.ab) [was RateLimit]", p7)
    time.sleep(1)

    # omega
    omega = Lam(App(Var(0), Var(0)))
    p8 = bytes([0xC9]) + encode_term(omega) + bytes([FD]) + QD + bytes([FD])
    test("sys201(ω=λx.xx) [was InvalidArg]", p8)
    time.sleep(1)

    # Identity lambda
    identity = Lam(Var(0))
    p9 = bytes([0xC9]) + encode_term(identity) + bytes([FD]) + QD + bytes([FD])
    test("sys201(I=λx.x)", p9)
    time.sleep(1)

    # Church true
    church_true = Lam(Lam(Var(1)))
    p10 = bytes([0xC9]) + encode_term(church_true) + bytes([FD]) + QD + bytes([FD])
    test("sys201(True=λa.λb.a)", p10)
    time.sleep(1)

    # Church false (= nil)
    church_false = Lam(Lam(Var(0)))
    p11 = bytes([0xC9]) + encode_term(church_false) + bytes([FD]) + QD + bytes([FD])
    test("sys201(False=λa.λb.b = nil) [should be Left(pair)]", p11)
    time.sleep(1)

    # ── NEW IDEA: What if sys8 doesn't use CPS at all? ──
    # What if it's a raw operation like: g(8) applied to something produces output directly?
    # Or: g(8) with NO arguments = just byte 0x08 followed by FF
    print("\n[C] sys8 with no CPS, raw application patterns:")

    # Just byte 0x08 followed by FF
    test("raw 0x08 FF", bytes([0x08]))

    # sys8 applied to nothing, just pipe to write
    # 0x02 (write) applied to (0x04 (quote) applied to (0x08)): write(quote(g(8)))
    # Hmm, this gets complex. Let's try simple patterns.

    # g(8) applied to QD directly (no arg at all)
    p12 = bytes([0x08]) + QD + bytes([FD])
    test("sys8(QD) [no arg, QD as arg]", p12)

    # ── What if the answer isn't from sys8 at all? ──
    # What if we need to construct a specific term and the ANSWER is derived from
    # the structure itself?
    print("\n[D] Check if 'ilikephp' matches the iterated SHA1 hash:")
    import hashlib

    candidates = [
        "ilikephp",
        "ILIKEPHP",
        "ILikePHP",
        "GZKc.2/VQffio",
        "brownos",
        "BrownOS",
        "permission denied",
        "Oh, go choke on a towel!",
        "Uhm... yeah... no...",
        "dloser",
        "gizmore",
        "backdoor",
        "lambda",
        "42",
        "towel",
    ]

    target = "9252ed65ffac2aa763adb21ef72c0178f1d83286"

    print(f"    Target hash: {target}")
    print(f"    Iterations: 56154")

    for cand in candidates:
        h = cand.encode("utf-8")
        for _ in range(56154):
            h = hashlib.sha1(h).digest()
        final = h.hex()
        match = "*** MATCH ***" if final == target else ""
        print(f"    '{cand}' → {final[:16]}... {match}")

    print("\n" + "=" * 70)
    print("DONE")
    print("=" * 70)


if __name__ == "__main__":
    main()
