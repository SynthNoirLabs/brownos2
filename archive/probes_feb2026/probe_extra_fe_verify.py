#!/usr/bin/env python3
"""
Verify the "extra FE" observation from probe_backdoor_password.py Test 3.

The claim: sys8(bd_output)(QD) returns 20 bytes instead of the standard 19-byte Right(6).
If true, this could indicate a DIFFERENT response from sys8.

We will:
1. Get the standard Right(6) from sys8(nil)(QD) — the baseline
2. Get backdoor(nil)(QD) output
3. Extract the raw term bytes from backdoor's response
4. Feed those exact bytes as an argument to sys8: sys8(bd_term_bytes)(QD)
5. Compare byte-by-byte with the baseline
"""

import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def send_and_recv(payload, timeout_s=5.0):
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


def hex_dump(data):
    return " ".join(f"{b:02x}" for b in data)


def count_fes(data):
    return sum(1 for b in data if b == FE)


def main():
    print("=" * 80)
    print("EXTRA FE VERIFICATION")
    print("=" * 80)

    # ================================================================
    # TEST 1: Baseline — sys8(nil)(QD)
    # ================================================================
    print("\n--- TEST 1: sys8(nil)(QD) = standard Right(6) baseline ---")
    nil_bytes = bytes([0x00, FE, FE])
    payload1 = bytes([0x08]) + nil_bytes + bytes([FD]) + QD + bytes([FD, FF])
    print(f"Payload ({len(payload1)}B): {hex_dump(payload1)}")

    resp1 = send_and_recv(payload1)
    print(f"Response ({len(resp1)}B): {hex_dump(resp1)}")
    print(f"FE count: {count_fes(resp1)}")

    time.sleep(0.5)

    # ================================================================
    # TEST 2: backdoor(nil)(QD) — get the pair
    # ================================================================
    print("\n--- TEST 2: backdoor(nil)(QD) = Left(pair(A,B)) ---")
    bd_payload = bytes([0xC9]) + nil_bytes + bytes([FD]) + QD + bytes([FD, FF])
    print(f"Payload ({len(bd_payload)}B): {hex_dump(bd_payload)}")

    resp2 = send_and_recv(bd_payload)
    print(f"Response ({len(resp2)}B): {hex_dump(resp2)}")
    print(f"FE count: {count_fes(resp2)}")

    time.sleep(0.5)

    # ================================================================
    # TEST 3: Extract term bytes from backdoor response, feed to sys8
    # This is the EXACT reproduction of the "extra FE" test
    # ================================================================
    print("\n--- TEST 3: sys8(bd_raw_term)(QD) — the critical test ---")

    # Extract term bytes (everything before FF)
    if FF in resp2:
        bd_term_bytes = resp2[: resp2.index(FF)]
        print(
            f"Extracted term bytes ({len(bd_term_bytes)}B): {hex_dump(bd_term_bytes)}"
        )
    else:
        print("ERROR: No FF in backdoor response!")
        bd_term_bytes = resp2
        print(f"Using full response ({len(bd_term_bytes)}B): {hex_dump(bd_term_bytes)}")

    # Build: sys8(bd_term_bytes)(QD) + FF
    payload3 = bytes([0x08]) + bd_term_bytes + bytes([FD]) + QD + bytes([FD, FF])
    print(f"Payload ({len(payload3)}B): {hex_dump(payload3)}")
    print(f"Payload size check: {'OK' if len(payload3) < 2000 else 'TOO BIG!'}")

    resp3 = send_and_recv(payload3)
    print(f"Response ({len(resp3)}B): {hex_dump(resp3)}")
    print(f"FE count: {count_fes(resp3)}")

    time.sleep(0.5)

    # ================================================================
    # COMPARISON
    # ================================================================
    print("\n" + "=" * 80)
    print("COMPARISON")
    print("=" * 80)

    print(f"\nBaseline sys8(nil)(QD):")
    print(f"  Length: {len(resp1)} bytes")
    print(f"  Hex: {hex_dump(resp1)}")
    print(f"  FE count: {count_fes(resp1)}")

    print(f"\nsys8(bd_raw_term)(QD):")
    print(f"  Length: {len(resp3)} bytes")
    print(f"  Hex: {hex_dump(resp3)}")
    print(f"  FE count: {count_fes(resp3)}")

    if resp1 == resp3:
        print("\n>>> IDENTICAL — same response. No extra FE.")
    else:
        print(f"\n>>> DIFFERENT!")
        print(f"  Length diff: {len(resp3) - len(resp1)} bytes")
        # Find where they differ
        for i in range(max(len(resp1), len(resp3))):
            b1 = resp1[i] if i < len(resp1) else None
            b3 = resp3[i] if i < len(resp3) else None
            if b1 != b3:
                print(
                    f"  First diff at byte {i}: baseline={b1:#04x if b1 is not None else 'N/A'} vs bd={b3:#04x if b3 is not None else 'N/A'}"
                )
                break

    # ================================================================
    # TEST 4: Also try passing the ENTIRE response (including FF) as argument
    # ================================================================
    print("\n--- TEST 4: sys8(bd_full_response_with_ff)(QD) ---")
    payload4 = bytes([0x08]) + resp2 + bytes([FD]) + QD + bytes([FD, FF])
    print(f"Payload ({len(payload4)}B): {hex_dump(payload4[:50])}...")

    resp4 = send_and_recv(payload4)
    print(f"Response ({len(resp4)}B): {hex_dump(resp4) if resp4 else 'EMPTY'}")
    if resp4:
        print(f"FE count: {count_fes(resp4)}")
        if resp4 != resp1:
            print(f"  >>> DIFFERENT from baseline!")
        else:
            print(f"  >>> Same as baseline")

    time.sleep(0.5)

    # ================================================================
    # TEST 5: Repeat baseline to confirm consistency
    # ================================================================
    print("\n--- TEST 5: sys8(nil)(QD) again — confirm baseline is stable ---")
    resp5 = send_and_recv(payload1)
    print(f"Response ({len(resp5)}B): {hex_dump(resp5)}")
    if resp5 == resp1:
        print("  >>> Baseline is stable (matches Test 1)")
    else:
        print("  >>> BASELINE CHANGED! Possible flakiness.")

    time.sleep(0.5)

    # ================================================================
    # TEST 6: sys8 with various other args to see if response ever changes
    # ================================================================
    print("\n--- TEST 6: sys8 with different args — response consistency ---")

    # 6a: sys8(I)(QD) where I = λx.x = 00 FE
    payload6a = bytes([0x08, 0x00, FE, FD]) + QD + bytes([FD, FF])
    resp6a = send_and_recv(payload6a)
    print(f"  sys8(I)(QD) ({len(resp6a)}B): {hex_dump(resp6a)}")

    time.sleep(0.45)

    # 6b: sys8(K)(QD) where K = λx.λy.x = 01 FE FE
    payload6b = bytes([0x08, 0x01, FE, FE, FD]) + QD + bytes([FD, FF])
    resp6b = send_and_recv(payload6b)
    print(f"  sys8(K)(QD) ({len(resp6b)}B): {hex_dump(resp6b)}")

    time.sleep(0.45)

    # 6c: sys8(Var(42))(QD) — the towel number
    payload6c = bytes([0x08, 0x2A, FD]) + QD + bytes([FD, FF])
    resp6c = send_and_recv(payload6c)
    print(f"  sys8(Var(42))(QD) ({len(resp6c)}B): {hex_dump(resp6c)}")

    time.sleep(0.45)

    # 6d: sys8(Var(201))(QD) — the backdoor global
    payload6d = bytes([0x08, 0xC9, FD]) + QD + bytes([FD, FF])
    resp6d = send_and_recv(payload6d)
    print(f"  sys8(Var(201))(QD) ({len(resp6d)}B): {hex_dump(resp6d)}")

    # Check if ALL are identical
    all_resp = [resp1, resp6a, resp6b, resp6c, resp6d]
    if all(r == resp1 for r in all_resp):
        print("\n  >>> ALL responses identical — sys8 is truly argument-independent")
    else:
        for i, r in enumerate(all_resp):
            if r != resp1:
                print(f"\n  >>> Response {i} DIFFERS! ({len(r)}B): {hex_dump(r)}")

    print("\n" + "=" * 80)
    print("VERIFICATION COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
