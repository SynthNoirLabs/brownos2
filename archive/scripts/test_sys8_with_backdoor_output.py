#!/usr/bin/env python3
"""
CRITICAL TEST: Use backdoor output as input to syscall 8.

The mail says "Backdoor is ready at syscall 201; start with 00 FE FE."
What if the backdoor RETURNS the key/token needed to unlock syscall 8?
"""

import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def send_raw(payload, timeout=8.0):
    """Send raw payload and return response."""
    with socket.create_connection((HOST, PORT), timeout=timeout) as s:
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)
        s.settimeout(timeout)
        out = b""
        while True:
            try:
                c = s.recv(4096)
                if not c:
                    break
                out += c
            except:
                break
        return out


def test_sys8_with_backdoor_keys():
    """Test syscall 8 with backdoor outputs as keys."""

    print("=" * 80)
    print("TESTING SYSCALL 8 WITH BACKDOOR OUTPUTS AS KEYS")
    print("=" * 80)

    # The backdoor outputs we discovered:
    backdoor_outputs = {
        "Common (most globals)": "000200fdfefefefefefefefefefdfefeff",
        "Special (00 FE FE)": "01010000fdfefefd0100fdfefefdfefefdfefeff",
        "A and B pair": "0003020100fdfdfdfefefefefefefefefefdfefeff",
    }

    for name, key_hex in backdoor_outputs.items():
        print(f"\n{'=' * 80}")
        print(f"TEST: sys8({name})")
        print(f"{'=' * 80}")

        # Remove the trailing FF (end marker) from the key
        key_bytes = bytes.fromhex(key_hex.replace("ff", ""))

        # Build payload: syscall 8, key as argument, QD continuation, end
        # Format: 0x08 <key_bytes> 0xFD <QD> 0xFD 0xFF
        payload = bytes([0x08]) + key_bytes + bytes([0xFD]) + QD + bytes([0xFD, 0xFF])

        print(f"Key hex: {key_hex}")
        print(f"Payload hex: {payload.hex()}")
        print(f"Payload length: {len(payload)} bytes")

        result = send_raw(payload)
        print(f"\nResponse ({len(result)} bytes): {result.hex()}")

        if result:
            # Check if it's still error 6 (permission denied)
            if result.startswith(bytes([0x01, 0x06])):
                print("❌ STILL ERROR 6 (Permission denied)")
            elif result.startswith(bytes([0x01])):
                print(f"❌ Still an error: Right({result[1]})")
            elif result.startswith(bytes([0x00])):
                print("✅ LEFT RESPONSE - NOT AN ERROR!")
                # Decode the Left payload
                print(f"Left payload: {result[1:].hex()}")
            else:
                print(f"⚠️  UNKNOWN RESPONSE FORMAT: {result[:20].hex()}")
        else:
            print("⚠️  EMPTY RESPONSE")

        time.sleep(0.4)

    # Also test: What if we need to CALL backdoor INSIDE the sys8 call?
    print(f"\n{'=' * 80}")
    print("TEST: sys8(backdoor(00 FE FE)) - nested call")
    print("=" * 80)

    # syscall 8 (syscall 201 (00 FE FE) continuation) continuation
    # This requires CPS: sys8 needs a continuation that calls backdoor

    # Actually, let's try simpler: pass backdoor AS THE CONTINUATION
    # sys8(anything)(backdoor)

    payload = bytes([0x08, 0x00, 0xFE, 0xFE, 0xFD])  # sys8(Church 0)
    payload += bytes([0xC9])  # backdoor syscall as continuation
    payload += bytes([0xFD, 0xFF])  # apply and end

    print(f"Payload: {payload.hex()}")
    result = send_raw(payload)
    print(f"Response ({len(result)} bytes): {result.hex()}")

    if result:
        if result.startswith(bytes([0x01, 0x06])):
            print("❌ STILL ERROR 6")
        else:
            print(f"⚠️  Different response: {result[:20].hex()}")

    time.sleep(0.4)

    print("\n" + "=" * 80)
    print("ANALYSIS")
    print("=" * 80)

    print("""
If sys8 still returns error 6 with backdoor outputs:
  - The backdoor outputs are NOT directly the unlock key
  - OR we need to combine them differently
  - OR the backdoor is telling us WHAT to do, not giving us a key
  
Next steps:
  1. Decode what the lambda terms MEAN semantically
  2. Look for patterns in the 9 nested lambdas (Church numerals?)
  3. Check if backdoor output encodes a FILE ID or other syscall argument
  4. Try using backdoor output as argument to OTHER syscalls
""")


if __name__ == "__main__":
    test_sys8_with_backdoor_keys()
