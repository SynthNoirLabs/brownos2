#!/usr/bin/env python3
"""
The author says "figuring out the meaning of the input codes" is most important.

Let's use echo() on EVERY global 0-252 and see what structures appear.
Echo wraps in Left and shifts by +2, so echo(Var(N)) = Left(Var(N+2)).

BUT: what if some globals are NOT bare Var references?
What if some of them reduce to lambda terms when evaluated?

We know arguments ARE evaluated before syscall receives them.
So echo(g(N)) evaluates g(N) first, then wraps in Left.

If g(N) is a regular syscall primitive, echo sees it as an opaque Var.
But what if g(N) is actually a LAMBDA TERM in the environment?

Also: let's check what quote(g(N)) returns for ALL globals.
If some globals are lambda terms (not primitives), quote would serialize
their full structure instead of just the Var byte.
"""

from __future__ import annotations

import socket
import time

from solve_brownos_answer import (
    HOST,
    PORT,
    FD,
    FE,
    FF,
    QD,
    encode_term,
    parse_term,
    decode_either,
    decode_byte_term,
    decode_bytes_list,
    Var,
    Lam,
    App,
    query,
)


def pretty(term: object, depth: int = 0) -> str:
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{pretty(term.body, depth + 1)}"
    if isinstance(term, App):
        return f"({pretty(term.f, depth)} {pretty(term.x, depth)})"
    return str(term)


def call_syscall_safe(
    syscall_num: int, arg_bytes: bytes, timeout_s: float = 5.0
) -> bytes:
    """Safe query that returns raw bytes."""
    payload = bytes([syscall_num]) + arg_bytes + bytes([FD]) + QD + bytes([FD, FF])
    delay = 0.15
    for _ in range(3):
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
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    out += chunk
                return out
        except Exception:
            time.sleep(delay)
            delay *= 2
    return b""


def main():
    print("=" * 60)
    print("COMPREHENSIVE GLOBAL SCAN VIA ECHO AND QUOTE")
    print("=" * 60)

    # First: echo every global 0-252 and look for anomalies
    print("\n--- echo(g(N)) for N=0..252 ---")
    print("Expected: Left(Var(N+2)) for all. Looking for deviations.\n")

    anomalies_echo = []

    for n in range(253):
        resp = call_syscall_safe(0x0E, bytes([n]), timeout_s=4.0)

        if not resp:
            if n in (0,):  # Var(0) is known to be stuck
                pass
            else:
                anomalies_echo.append((n, "EMPTY"))
                print(f"  echo(g({n:3d})): EMPTY  *** ANOMALY ***")
            continue

        try:
            term = parse_term(resp)
            tag, payload = decode_either(term)
            if tag == "Left":
                if isinstance(payload, Var) and payload.i == n + 2:
                    pass  # Expected behavior
                else:
                    anomalies_echo.append((n, f"Left({pretty(payload)[:60]})"))
                    print(
                        f"  echo(g({n:3d})): Left({pretty(payload)[:60]})  *** ANOMALY ***"
                    )
            elif tag == "Right":
                errcode = decode_byte_term(payload)
                anomalies_echo.append((n, f"Right({errcode})"))
                print(f"  echo(g({n:3d})): Right({errcode})  *** ANOMALY ***")
            else:
                anomalies_echo.append((n, f"other: {pretty(term)[:60]}"))
                print(f"  echo(g({n:3d})): {pretty(term)[:60]}  *** ANOMALY ***")
        except Exception as e:
            if resp.startswith(b"Encoding failed!"):
                anomalies_echo.append((n, "ENCODING_FAILED"))
                print(f"  echo(g({n:3d})): ENCODING FAILED  *** ANOMALY ***")
            else:
                anomalies_echo.append((n, f"PARSE_ERROR: {e}"))
                print(f"  echo(g({n:3d})): PARSE ERROR: {e}  *** ANOMALY ***")

        time.sleep(0.05)

    print(f"\n--- Echo anomalies summary ({len(anomalies_echo)} found) ---")
    for n, desc in anomalies_echo:
        print(f"  g({n:3d}): {desc}")

    # Now: quote every global that showed anomaly + a few extras
    # quote(g(N)) should return Left(bytes=Nhex FF) for opaque primitives
    # If any global is a lambda term, quote will return its full serialization
    print("\n\n--- quote(g(N)) for anomalous globals ---")

    test_globals = list(
        set([n for n, _ in anomalies_echo] + [0, 1, 2, 4, 8, 14, 42, 201])
    )
    test_globals.sort()

    for n in test_globals:
        resp = call_syscall_safe(0x04, bytes([n]), timeout_s=4.0)
        if not resp:
            print(f"  quote(g({n:3d})): EMPTY")
            continue

        try:
            term = parse_term(resp)
            tag, payload = decode_either(term)
            if tag == "Left":
                bs = decode_bytes_list(payload)
                # Expected for opaque: bytes = [n, 0xFF]
                if bs == bytes([n, 0xFF]):
                    print(f"  quote(g({n:3d})): opaque Var({n})")
                else:
                    print(
                        f"  quote(g({n:3d})): Left(bytes={bs.hex()}) [{len(bs)} bytes]  *** NON-OPAQUE ***"
                    )
                    # Try to parse as a term
                    try:
                        inner = parse_term(bs)
                        print(f"    -> parsed: {pretty(inner)[:100]}")
                    except Exception:
                        pass
            elif tag == "Right":
                errcode = decode_byte_term(payload)
                print(f"  quote(g({n:3d})): Right({errcode})")
            else:
                print(f"  quote(g({n:3d})): {pretty(term)[:80]}")
        except Exception as e:
            print(f"  quote(g({n:3d})): ERROR: {e}")

        time.sleep(0.05)

    print("\n" + "=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
