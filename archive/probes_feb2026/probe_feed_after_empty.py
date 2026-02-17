#!/usr/bin/env python3
"""
KEY HYPOTHESIS: When sys8 returns EMPTY (no output), the connection might
still be alive and the VM might be WAITING FOR MORE INPUT.

Cases that produced EMPTY:
- sys8(nil) + identity/nil/K/write continuations
- sys8(nil) alone (no continuation)
- sys8 with pair as continuation
- ((sys8 nil) write/echo/quote) — bare globals as continuation

What if after the silence, we can send ANOTHER term (or more bytes)?
This would explain gizmore's "interrupt and transfer parameters to the kernel."

Also test: what if sys8's RESULT is a function waiting for input?
Right(6) = λl.λr.(r 6) — when applied to QD, QD prints it.
But with identity continuation, the result is Right(6) which is just sitting there.
What if we need to CONTINUE the computation by feeding more?
"""

from __future__ import annotations

import socket
import time
import select

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
NIL = bytes([0x00, FE, FE])  # λc.λn.n


def recv_timed(sock: socket.socket, timeout_s: float = 3.0) -> bytes:
    sock.settimeout(timeout_s)
    out = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
            if 0xFF in chunk:
                break
    except socket.timeout:
        pass
    return out


def is_socket_alive(sock: socket.socket) -> bool:
    """Check if socket is still connected."""
    try:
        ready = select.select([sock], [], [], 0.1)
        if ready[0]:
            data = sock.recv(1, socket.MSG_PEEK)
            return len(data) > 0
        return True  # no data but no error = still alive
    except Exception:
        return False


def classify(out: bytes) -> str:
    if not out:
        return "EMPTY"
    if out.startswith(b"Invalid term!"):
        return "INVALID"
    if out.startswith(b"Encoding failed!"):
        return "ENCFAIL"
    return f"DATA:{out.hex()[:40]}{'...' if len(out) > 20 else ''} len={len(out)}"


def test_feed_after(
    label: str,
    first_payload: bytes,
    followups: list[tuple[str, bytes]],
    first_timeout: float = 4.0,
    followup_timeout: float = 4.0,
):
    """Send first_payload, wait for response, then try each followup."""
    print(f"\n[{label}]")
    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        sock.sendall(first_payload)

        # Wait for initial response
        resp1 = recv_timed(sock, timeout_s=first_timeout)
        print(f"  Initial: {classify(resp1)}")

        if resp1:
            print(f"  Got data on first payload, connection may be done")
            # Still try followups
            for fname, fpayload in followups[:2]:
                time.sleep(0.1)
                try:
                    sock.sendall(fpayload)
                    resp = recv_timed(sock, timeout_s=followup_timeout)
                    print(f"  Follow-up '{fname}': {classify(resp)}")
                except Exception as e:
                    print(f"  Follow-up '{fname}': SEND FAILED: {e}")
                    break
        else:
            # EMPTY response — this is the interesting case
            print(f"  EMPTY response — trying follow-ups on live socket...")

            for fname, fpayload in followups:
                time.sleep(0.1)
                try:
                    sock.sendall(fpayload)
                    resp = recv_timed(sock, timeout_s=followup_timeout)
                    print(f"  Feed '{fname}': {classify(resp)}")
                    if resp:
                        print(f"    >>> GOT DATA AFTER FEEDING! raw={resp.hex()[:80]}")
                except BrokenPipeError:
                    print(f"  Feed '{fname}': BROKEN PIPE (connection closed)")
                    break
                except ConnectionResetError:
                    print(f"  Feed '{fname}': CONNECTION RESET")
                    break
                except Exception as e:
                    print(f"  Feed '{fname}': ERROR: {e}")
                    break

        sock.close()
    except Exception as e:
        print(f"  CONNECTION ERROR: {e}")


def main():
    print("=" * 60)
    print("FEED-AFTER-EMPTY PROBE")
    print("Does the server accept more input after EMPTY responses?")
    print("=" * 60)

    # Common followup payloads
    qd_nil = bytes([0x04, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])  # quote(nil) via QD
    just_ff = bytes([FF])
    just_qd_ff = QD + bytes([FF])
    towel_qd = bytes([0x2A, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])  # towel via QD
    echo_nil_qd = bytes([0x0E, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])
    sys8_nil_qd = bytes([0x08, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])

    followups = [
        ("FF only", just_ff),
        ("QD+FF", just_qd_ff),
        ("quote(nil)+QD", qd_nil),
        ("towel+QD", towel_qd),
        ("echo(nil)+QD", echo_nil_qd),
        ("sys8(nil)+QD", sys8_nil_qd),
    ]

    # ============================================================
    # Test 1: sys8(nil) with identity continuation → EMPTY
    # Then feed more data
    # ============================================================
    identity = bytes([0x00, FE])  # λx.x
    first = bytes([0x08]) + NIL + bytes([FD]) + identity + bytes([FD, FF])
    test_feed_after("1: sys8(nil)+identity, then feed", first, followups)
    time.sleep(0.3)

    # ============================================================
    # Test 2: sys8(nil) alone (08 00FEFE FD FF) → EMPTY
    # Then feed more
    # ============================================================
    first = bytes([0x08, 0x00, FE, FE, FD, FF])
    test_feed_after("2: (sys8 nil), then feed", first, followups)
    time.sleep(0.3)

    # ============================================================
    # Test 3: bare sys8 (08 FF) → EMPTY
    # Then feed argument bytes
    # ============================================================
    first = bytes([0x08, FF])
    test_feed_after("3: bare Var(8)+FF, then feed", first, followups)
    time.sleep(0.3)

    # ============================================================
    # Test 4: sys8 with nil continuation → EMPTY
    # ============================================================
    first = bytes([0x08]) + NIL + bytes([FD]) + NIL + bytes([FD, FF])
    test_feed_after("4: sys8(nil)+nil_cont, then feed", first, followups)
    time.sleep(0.3)

    # ============================================================
    # Test 5: sys8 WITHOUT FF — send bytes incrementally
    # Maybe the server is still parsing and we can extend the term
    # ============================================================
    print(f"\n[5: sys8 partial send — extend before FF]")
    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        # Send sys8 applied to nil, but NO continuation yet
        partial = bytes([0x08]) + NIL + bytes([FD])
        sock.sendall(partial)
        print(f"  Sent partial: {partial.hex()}")

        # Wait a moment
        time.sleep(0.5)
        resp = recv_timed(sock, timeout_s=1.0)
        print(f"  After partial (no FF): {classify(resp)}")

        # Now send QD + FD + FF to complete the CPS call
        rest = QD + bytes([FD, FF])
        sock.sendall(rest)
        print(f"  Sent rest: QD+FD+FF")
        resp = recv_timed(sock, timeout_s=5.0)
        print(f"  After completing: {classify(resp)}")

        sock.close()
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.3)

    # ============================================================
    # Test 6: Send sys8(nil) with write as continuation
    # write expects a byte list — sys8 returns Right(6) which is an Either
    # Does write try to interpret the Either? Could cause interesting behavior
    # ============================================================
    print(f"\n[6: ((sys8 nil) write) — write as continuation]")
    first = bytes([0x08]) + NIL + bytes([FD, 0x02, FD, FF])
    test_feed_after("6: sys8(nil)+write, then feed", first, followups[:3])
    time.sleep(0.3)

    # ============================================================
    # Test 7: CRITICAL — sys8 with K combinator as continuation
    # K(Right(6)) = λb.Right(6)
    # This is a FUNCTION waiting for one more argument!
    # What if we feed that argument?
    # ============================================================
    print(f"\n[7: sys8(nil)+K — result is λb.Right(6), feed more]")
    K = bytes([0x01, FE, FE])  # λa.λb.a = K combinator
    first = bytes([0x08]) + NIL + bytes([FD]) + K + bytes([FD, FF])
    # The result of eval is K(Right(6)) = λb.Right(6)
    # This is a closure. The VM should reduce to normal form and stop.
    # But the VALUE sitting in the VM is a function...
    test_feed_after("7: sys8(nil)+K, then feed", first, followups[:3])
    time.sleep(0.3)

    # ============================================================
    # Test 8: What about sending JUST the QD continuation AFTER
    # the empty response? QD is a function. If the result of sys8
    # is Right(6) and it's "sitting" somewhere, applying QD to it
    # might produce output.
    # ============================================================
    print(f"\n[8: sys8(nil)+identity → Right(6), then send QD applied to it]")
    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        # First: ((sys8 nil) (λx.x)) FF — result is Right(6) but no output
        first = bytes([0x08]) + NIL + bytes([FD]) + identity + bytes([FD, FF])
        sock.sendall(first)
        resp1 = recv_timed(sock, timeout_s=3.0)
        print(f"  Initial: {classify(resp1)}")

        # Now try to apply QD to the result by sending it as a new program
        # But... the first program already evaluated. If server processes one term,
        # it should be done. Let's see.
        time.sleep(0.2)

        # Send QD applied to Right(6) directly, as a fresh term
        # QD(Right(6)): QD [Right(6)] FD FF
        # Right(6) = λl.λr.(r int6)
        # int6 = λ^9.(V2 (V1 V0)) = 02 01 00 FD FD FE FE FE FE FE FE FE FE FE
        int6_bytes = bytes(
            [0x02, 0x01, 0x00, FD, FD, FE, FE, FE, FE, FE, FE, FE, FE, FE]
        )
        right6 = bytes([0x00]) + int6_bytes + bytes([FD, FE, FE])  # λl.λr.(r int6)
        prog2 = QD + right6 + bytes([FD, FF])
        sock.sendall(prog2)
        resp2 = recv_timed(sock, timeout_s=5.0)
        print(f"  After QD(Right(6)): {classify(resp2)}")

        sock.close()
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.3)

    # ============================================================
    # Test 9: What if we send bytes that are NOT a complete term?
    # Just raw bytes without FD/FE structure
    # ============================================================
    print(f"\n[9: Send raw bytes 'ilikephp' as ASCII then FF]")
    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        sock.sendall(b"ilikephp" + bytes([FF]))
        resp = recv_timed(sock, timeout_s=5.0)
        print(f"  Response: {classify(resp)}")
        if not resp:
            # Try feeding more
            sock.sendall(QD + bytes([FD, FF]))
            resp2 = recv_timed(sock, timeout_s=3.0)
            print(f"  After feeding QD: {classify(resp2)}")
        sock.close()
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.3)

    # ============================================================
    # Test 10: Multiple FFs in sequence — does second term get eval'd?
    # ============================================================
    print(f"\n[10: Send prog1+FF+prog2+FF in one shot, read carefully]")
    try:
        sock = socket.create_connection((HOST, PORT), timeout=15)
        prog1 = (
            bytes([0x08]) + NIL + bytes([FD]) + bytes([0x00, FE]) + bytes([FD, FF])
        )  # sys8(nil)+id
        prog2 = bytes([0x2A]) + NIL + bytes([FD]) + QD + bytes([FD, FF])  # towel+QD
        sock.sendall(prog1 + prog2)

        # Read everything over a longer period
        all_data = b""
        sock.settimeout(2.0)
        for _ in range(5):
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                all_data += chunk
                print(f"  Received chunk: {chunk.hex()[:60]} ({len(chunk)} bytes)")
            except socket.timeout:
                break

        print(f"  Total: {classify(all_data)}")

        # Connection still alive?
        try:
            sock.sendall(towel_qd)
            resp = recv_timed(sock, timeout_s=3.0)
            print(f"  After 3rd send: {classify(resp)}")
        except Exception as e:
            print(f"  3rd send failed: {e}")

        sock.close()
    except Exception as e:
        print(f"  ERROR: {e}")

    # ============================================================
    # Test 11: What if the FIRST program should produce no output
    # (like sys8) and the SECOND one collects the result?
    # Send sys8 with no output continuation, then send QD
    # ============================================================
    print(f"\n[11: sys8(nil)+nil → silence, then send QD as second program]")
    try:
        sock = socket.create_connection((HOST, PORT), timeout=15)
        # First program: sys8(nil) applied to nil (discards result)
        prog1 = bytes([0x08]) + NIL + bytes([FD]) + NIL + bytes([FD, FF])
        sock.sendall(prog1)

        time.sleep(1.0)  # Give server time to process
        resp1 = recv_timed(sock, timeout_s=1.0)
        print(f"  After sys8+nil: {classify(resp1)}")

        # Send second program
        prog2 = bytes([0x2A]) + NIL + bytes([FD]) + QD + bytes([FD, FF])
        try:
            sock.sendall(prog2)
            resp2 = recv_timed(sock, timeout_s=5.0)
            print(f"  After towel+QD: {classify(resp2)}")
        except Exception as e:
            print(f"  Send failed: {e}")

        sock.close()
    except Exception as e:
        print(f"  ERROR: {e}")

    print("\n" + "=" * 60)
    print("ALL FEED-AFTER-EMPTY TESTS COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
