#!/usr/bin/env python3
"""
Test the 3 specific payloads an LLM suggested as "breakthroughs" for sys8.
"""

from __future__ import annotations

import socket
import time
import sys

sys.path.insert(0, ".")
from solve_brownos_answer import (
    App,
    Lam,
    Var,
    encode_term,
    encode_bytes_list,
    encode_byte_term,
)

HOST = "wc3.wechall.net"
PORT = 61221
FF = 0xFF
FD = 0xFD
FE = 0xFE
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def recv_all(sock, timeout_s=8.0):
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


def send_payload(label, payload):
    print(f"\n{'=' * 70}")
    print(f"TEST: {label}")
    print(f"Payload ({len(payload)} bytes): {payload.hex()}")
    print(f"{'=' * 70}")

    delay = 0.3
    for attempt in range(4):
        try:
            with socket.create_connection((HOST, PORT), timeout=8) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                out = recv_all(sock)
                if out:
                    print(f"  Raw hex ({len(out)} bytes): {out.hex()}")
                    try:
                        text = out.decode("utf-8", "replace")
                        print(f"  Text: {repr(text)}")
                    except Exception:
                        pass
                else:
                    print("  EMPTY RESPONSE")
                return out
        except Exception as e:
            print(f"  Attempt {attempt + 1} failed: {e}")
            time.sleep(delay)
            delay *= 2
    print("  ALL ATTEMPTS FAILED")
    return b""


def main():
    print("=" * 70)
    print("LLM PAYLOAD TEST - Testing 3 'breakthrough' suggestions")
    print("=" * 70)

    # PAYLOAD 1: "3-Leaf" CPS chain: (((sys201 nil) sys8) QD)
    # Claim: sys8 as CONTINUATION of sys201
    payload1 = (
        bytes([0xC9])
        + bytes([0x00, 0xFE, 0xFE])
        + bytes([0xFD])
        + bytes([0x08])
        + bytes([0xFD])
        + QD
        + bytes([0xFD, 0xFF])
    )
    send_payload("Payload 1: (((sys201 nil) sys8) QD) - '3-leaf' chain", payload1)
    time.sleep(0.5)

    # PAYLOAD 2: Echo variant: (((echo g251) sys8) QD)
    payload2 = bytes([0x0E, 0xFB, 0xFD, 0x08, 0xFD]) + QD + bytes([0xFD, 0xFF])
    send_payload("Payload 2: (((echo g251) sys8) QD) - echo variant", payload2)
    time.sleep(0.5)

    # PAYLOAD 3: Shifted QD variant with /bin/solution path
    SHIFTED_QD = bytes.fromhex("0600fd000600fd04fdfefd03fdfefdfe")
    path_bytes = encode_term(encode_bytes_list(b"/bin/solution"))
    payload3 = (
        bytes([0xC9, 0x00, 0xFE, 0xFE, 0xFD, 0x09])
        + path_bytes
        + bytes([0xFD])
        + SHIFTED_QD
        + bytes([0xFD, 0xFE, 0xFD, 0xFF])
    )
    send_payload(
        "Payload 3: backdoor -> sys8('/bin/solution') with shifted QD", payload3
    )
    time.sleep(0.5)

    # ADDITIONAL VARIANTS the LLM didn't suggest but are worth testing

    # Variant A: sys8 as continuation, but with OBS-style observer instead of QD
    # (((sys201 nil) sys8) (λres. ((0x02 "OK") nil)))
    ok_str = encode_term(encode_bytes_list(b"OK\n"))
    nil_term = bytes([0x00, 0xFE, 0xFE])
    obs_simple = bytes([0x02]) + ok_str + bytes([0xFD]) + nil_term + bytes([0xFD, 0xFE])
    payload_a = (
        bytes([0xC9])
        + nil_term
        + bytes([0xFD])
        + bytes([0x08])
        + bytes([0xFD])
        + obs_simple
        + bytes([0xFD, 0xFF])
    )
    send_payload("Variant A: (((sys201 nil) sys8) simple_obs)", payload_a)
    time.sleep(0.5)

    # Variant B: What if sys201 result feeds directly through sys8 to QD
    # but we also try: ((sys201 nil) (λpair. ((sys8 pair) QD)))
    # This is the "traditional" nesting WITH correct shifting
    # Under 1 lambda, QD indices need +1 shift
    shifted_qd_bytes = SHIFTED_QD
    payload_b = (
        bytes([0xC9])
        + nil_term
        + bytes([0xFD])
        + bytes([0x09])  # sys8 shifted by +1 under lambda
        + bytes([0x00])  # Var(0) = the lambda param (pair)
        + bytes([0xFD])
        + shifted_qd_bytes
        + bytes([0xFD, 0xFE])  # close the lambda
        + bytes([0xFD, 0xFF])
    )
    send_payload(
        "Variant B: ((sys201 nil) (λpair. ((sys8 pair) shifted_QD)))", payload_b
    )
    time.sleep(0.5)

    # Variant C: Standard CPS but arg is the Left(pair) from backdoor
    # i.e. ((sys201 nil) is called, returns Left(pair)
    # Then we do ((sys8 <that_result>) QD)
    # Using the named DSL approach for correctness
    term_c = App(
        App(
            Var(0xC9),
            Lam(Lam(Var(0))),  # nil
        ),
        Lam(  # λresult.
            App(
                App(Var(9), Var(0)),  # (sys8 result) - sys8 is g(8), shifted +1 = 9
                # shifted QD as a term
                App(
                    App(Var(6), Var(0)),  # shifted quote(result)
                    Lam(
                        App(
                            App(Var(4), Var(0)),  # shifted write(quoted)
                            Lam(Lam(Var(0))),  # nil continuation
                        )
                    ),
                ),
            )
        ),
    )
    try:
        payload_c = encode_term(term_c) + bytes([0xFF])
        send_payload(
            "Variant C: ((sys201 nil) (λres. ((sys8 res) manual_obs)))", payload_c
        )
    except Exception as e:
        print(f"  Variant C encoding failed: {e}")

    print("\n" + "=" * 70)
    print("ALL TESTS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
