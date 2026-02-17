#!/usr/bin/env python3
"""
probe_3leaf_full_sweep.py — Exhaustive sweep of 3-leaf programs.

dloser says "My record is 3 leafs" — the solution program has 3 Var nodes.
A 3-leaf program with no lambdas: App(App(Var(a), Var(b)), Var(c))
Bytecode: a b FD c FD FF (6 bytes)

In CPS: ((g(a) g(b)) g(c)) = syscall a with arg g(b) and continuation g(c)

CRITICAL INSIGHT: dloser confirmed EMPTY = success for programs without output.
So if g(8)(g(X))(g(Y)) returns EMPTY, it might mean sys8 SUCCEEDED!
But ALL 3-leaf programs return EMPTY because raw globals as continuations
don't have write paths. So we need to distinguish "success EMPTY" from
"no-output EMPTY".

APPROACH: Test g(8)(g(b))(g(c)) for ALL b=0..252 with a WRITE-CAPABLE
continuation instead of a raw global. Use QD as continuation (adds more
than 3 leaves, but lets us SEE the result).

If sys8(g(b))(QD) returns Left(something) for ANY b, that's the answer!

We already tested many b values but NOT all 253. Let's be exhaustive.
"""

import socket
import time
import sys

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

# Standard Right(6) response (Permission Denied)
RIGHT_6 = bytes.fromhex("00030200fdfdfefefefefefefefefefdfefeff")


def send_recv(payload, timeout_s=5.0):
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            sock.settimeout(timeout_s)
            out = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out += chunk
                except socket.timeout:
                    break
            return out
    except Exception as e:
        return f"ERR:{e}".encode()


def main():
    print("=" * 70)
    print("EXHAUSTIVE 3-LEAF SWEEP: sys8(g(b))(QD) for b=0..252")
    print("Looking for ANY response that is NOT Right(6)")
    print("=" * 70)
    print()

    anomalies = []
    right6_count = 0
    empty_count = 0
    error_count = 0

    for b in range(253):
        # Build: ((g(8) g(b)) QD) + FF
        payload = bytes([0x08, b, FD]) + QD + bytes([FD, FF])

        resp = send_recv(payload)

        if resp == RIGHT_6:
            right6_count += 1
            if b % 50 == 0:
                print(f"  b={b:3d}: Right(6) [standard]")
        elif not resp or resp.startswith(b"ERR:"):
            empty_count += 1
            status = "EMPTY" if not resp else resp.decode("utf-8", "replace")[:40]
            print(f"  b={b:3d}: {status}")
            if resp and not resp.startswith(b"ERR:"):
                anomalies.append((b, resp))
        elif resp.startswith(b"Invalid term!"):
            error_count += 1
            print(f"  b={b:3d}: Invalid term!")
        elif resp.startswith(b"Encoding failed!"):
            error_count += 1
            print(f"  b={b:3d}: Encoding failed!")
        elif resp.startswith(b"Term too big!"):
            error_count += 1
            print(f"  b={b:3d}: Term too big!")
        else:
            # ANYTHING ELSE IS POTENTIALLY INTERESTING
            hex_str = " ".join(f"{x:02x}" for x in resp[:30])
            print(f"  b={b:3d}: *** ANOMALY *** ({len(resp)}B): {hex_str}")
            anomalies.append((b, resp))

            # Check if it's a different Right(N)
            if resp != RIGHT_6 and len(resp) > 0:
                # Try to see if it's text
                try:
                    text = resp.decode("utf-8", "replace")
                    if text.isprintable() or all(
                        c in "\n\r\t" or c.isprintable() for c in text
                    ):
                        print(f"         TEXT: {text[:80]}")
                except:
                    pass

        time.sleep(0.35)

    print()
    print("=" * 70)
    print(
        f"RESULTS: {right6_count} Right(6), {empty_count} empty/error, {error_count} parse errors"
    )
    print(f"ANOMALIES: {len(anomalies)}")
    print("=" * 70)

    if anomalies:
        print("\n*** ANOMALIES FOUND ***")
        for b, resp in anomalies:
            hex_str = " ".join(f"{x:02x}" for x in resp[:50])
            print(f"  b={b:3d} ({len(resp)}B): {hex_str}")
    else:
        print("\nNo anomalies — ALL 253 values returned Right(6)")

    # PHASE 2: Also test a few other 3-leaf patterns
    print("\n" + "=" * 70)
    print("PHASE 2: Other 3-leaf patterns with QD observation")
    print("=" * 70)

    phase2_tests = [
        # backdoor(g(b))(QD) — we know backdoor only accepts nil, but let's verify a few
        ("bd(g(0))(QD)", bytes([0xC9, 0x00, FD]) + QD + bytes([FD, FF])),
        ("bd(g(8))(QD)", bytes([0xC9, 0x08, FD]) + QD + bytes([FD, FF])),
        # sys8 with 1 arg only (no continuation): g(8)(QD) — QD as argument
        ("g(8)(QD) [1-arg]", bytes([0x08]) + QD + bytes([FD, FF])),
        # sys8 with nil, then nil, then QD (3 args)
        (
            "g(8)(nil)(nil)(QD)",
            bytes([0x08, 0x00, FE, FE, FD, 0x00, FE, FE, FD]) + QD + bytes([FD, FF]),
        ),
        # sys8 with A as arg, QD as cont
        (
            "sys8(A)(QD)",
            bytes([0x08, 0x00, 0x00, FD, FE, FE, FD]) + QD + bytes([FD, FF]),
        ),
        # sys8 with B as arg, QD as cont
        (
            "sys8(B)(QD)",
            bytes([0x08, 0x01, 0x00, FD, FE, FE, FD]) + QD + bytes([FD, FF]),
        ),
        # sys8 with pair(A,B) as arg, QD as cont
        (
            "sys8(pair)(QD)",
            bytes(
                [
                    0x08,
                    0x00,
                    0x00,
                    0x00,
                    FD,
                    FE,
                    FE,
                    FD,
                    0x01,
                    0x00,
                    FD,
                    FE,
                    FE,
                    FD,
                    FD,
                    FE,
                    FD,
                ]
            )
            + QD
            + bytes([FD, FF]),
        ),
        # What if sys8 needs Left(nil) as argument?
        # Left(nil) = λl.λr.l(nil) = 01 00 FE FE FD FE FE
        (
            "sys8(Left(nil))(QD)",
            bytes([0x08, 0x01, 0x00, FE, FE, FD, FE, FE, FD]) + QD + bytes([FD, FF]),
        ),
        # What if sys8 needs Right(nil) as argument?
        # Right(nil) = λl.λr.r(nil) = 00 00 FE FE FD FE FE
        (
            "sys8(Right(nil))(QD)",
            bytes([0x08, 0x00, 0x00, FE, FE, FD, FE, FE, FD]) + QD + bytes([FD, FF]),
        ),
    ]

    for label, payload in phase2_tests:
        resp = send_recv(payload)
        if resp == RIGHT_6:
            print(f"  {label}: Right(6) [standard]")
        elif not resp:
            print(f"  {label}: EMPTY")
        else:
            hex_str = " ".join(f"{x:02x}" for x in resp[:40])
            is_text = all(32 <= x < 127 or x in (10, 13) for x in resp if x != 0xFF)
            if is_text and len(resp) < 100:
                text = resp.replace(bytes([0xFF]), b"").decode("utf-8", "replace")
                print(f"  {label}: TEXT '{text}'")
            else:
                print(f"  {label}: ({len(resp)}B) {hex_str}")
                if resp != RIGHT_6:
                    print(f"         *** DIFFERENT FROM RIGHT(6) ***")
        time.sleep(0.4)

    print("\n" + "=" * 70)
    print("SWEEP COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
