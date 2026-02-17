#!/usr/bin/env python3
"""
Final sweep: Looking for any clue we might have missed

1. Error codes 8+ - do they have hidden messages?
2. Special byte combinations that produce unique results
3. Any pattern in the empty responses
"""

from __future__ import annotations

import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def query_raw(payload: bytes, timeout_s: float = 5.0) -> bytes:
    delay = 0.2
    for attempt in range(3):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                sock.shutdown(socket.SHUT_WR)
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
            time.sleep(delay)
            delay *= 2
    return b""


def build_nil():
    return bytes([0x00, FE, FE])


def build_byte_term(n: int) -> bytes:
    parts = [0x00]
    weights = [(1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)]
    for idx, weight in weights:
        if n & weight:
            parts = [idx] + parts + [FD]
    return bytes(parts + [FE] * 9)


def decode_bytes_from_response(resp: bytes) -> str:
    """Try to decode a response as a byte list (string)"""
    # Response structure after Either unwrap would be a Scott list of byte terms
    # Each byte term is 9 lambdas around an additive expression
    # This is complex to decode without full parsing
    return resp.decode("latin-1", errors="replace")


def test_error_strings_extended():
    """Check error strings for codes beyond 7"""
    print("\n=== TEST: Extended Error Strings (codes 0-20) ===")

    nil = build_nil()

    # error syscall = 0x01
    # ((error code) λres.((res printer) ignore))
    # where printer = λstr.((write str) nil)

    # Let me build a simple chain:
    # ((error code) λres.((res (λstr.((write str) nil))) nil))

    # At depth 1: res = V0
    # At depth 2: str = V0, write = V2+2 = V4
    # printer = λstr.((write str) nil) = λ.((V4 V0) nil)
    printer = bytes([0x04, 0x00, FD]) + nil + bytes([FD, FE])
    ignore = nil + bytes([FE])  # λ_.nil

    # disc = λres.((V0 printer) ignore)
    disc = bytes([0x00]) + printer + bytes([FD]) + ignore + bytes([FD, FE])

    for code in range(21):
        code_term = build_byte_term(code)
        # ((error code_term) disc)
        payload = bytes([0x01]) + code_term + bytes([FD]) + disc + bytes([FD, FF])
        resp = query_raw(payload, timeout_s=5)
        if resp:
            # Try to extract text
            text = resp.decode("latin-1", errors="replace")
            print(f"   Error {code}: {text[:50]}")
        else:
            print(f"   Error {code}: EMPTY")


def test_syscall8_error_code():
    """What specific error code does syscall8 return?"""
    print("\n=== TEST: Syscall8 Error Code Extraction ===")

    nil = build_nil()

    # ((syscall8 nil) λres.((res on_left) on_right))
    # on_right = λcode.((error code) printer_chain)
    # This should print "Permission denied" for code 6

    # on_left: λpayload. write "SUCCESS"
    # on_right: λcode. ((error code) string_printer)

    # string_printer: λerror_res. ((error_res (λstr.((write str) nil))) nil)

    # Depths:
    # 1: λres (discriminator)
    # 2: λcode (on_right) or λpayload (on_left)
    # 3: λerror_res (string_printer)
    # 4: λstr (printer)

    # At depth 4: write = V2+4 = V6
    printer = bytes([0x06, 0x00, FD]) + nil + bytes([FD, FE])
    ignore = nil + bytes([FE])

    # At depth 3: error = V1+3 = V4
    string_printer = bytes([0x00]) + printer + bytes([FD]) + ignore + bytes([FD, FE])

    # At depth 2: error = V1+2 = V3
    on_right = bytes([0x03, 0x00, FD]) + string_printer + bytes([FD, FE])

    # on_left: just write "L" to indicate success (won't happen but let's be thorough)
    # For simplicity, just use ignore
    on_left = ignore

    # disc at depth 1: λres.((V0 on_left) on_right)
    disc = bytes([0x00]) + on_left + bytes([FD]) + on_right + bytes([FD, FE])

    print("\n1. syscall8(nil):")
    payload = bytes([0x08]) + nil + bytes([FD]) + disc + bytes([FD, FF])
    resp = query_raw(payload, timeout_s=10)
    print(
        f"   Response: {resp.decode('latin-1', errors='replace') if resp else 'EMPTY'}"
    )

    print("\n2. syscall8(identity):")
    identity = bytes([0x00, FE])
    payload2 = bytes([0x08]) + identity + bytes([FD]) + disc + bytes([FD, FF])
    resp2 = query_raw(payload2, timeout_s=10)
    print(
        f"   Response: {resp2.decode('latin-1', errors='replace') if resp2 else 'EMPTY'}"
    )


def test_syscall_sweep():
    """Quick sweep of syscalls 0-20 to see their behavior"""
    print("\n=== TEST: Syscall Sweep 0-20 ===")

    nil = build_nil()

    for syscall in range(21):
        payload = bytes([syscall]) + nil + bytes([FD]) + QD + bytes([FD, FF])
        resp = query_raw(payload, timeout_s=3)
        if resp:
            # Truncate for display
            hex_str = resp.hex()[:40]
            try:
                text = resp.decode("latin-1", errors="replace")[:30]
            except:
                text = "???"
            print(f"   {syscall:02d} (0x{syscall:02X}): {text}")
        else:
            print(f"   {syscall:02d} (0x{syscall:02X}): EMPTY")


def test_backdoor_variations():
    """Try backdoor with different arguments"""
    print("\n=== TEST: Backdoor Argument Variations ===")

    nil = build_nil()
    identity = bytes([0x00, FE])
    true_term = bytes([0x01, FE, FE])
    false_term = bytes([0x00, FE, FE])  # same as nil

    tests = [
        (nil, "nil"),
        (identity, "identity"),
        (true_term, "true"),
        (bytes([0x00]), "V0"),
        (bytes([0x01]), "V1"),
    ]

    for arg, name in tests:
        payload = bytes([0xC9]) + arg + bytes([FD]) + QD + bytes([FD, FF])
        resp = query_raw(payload, timeout_s=5)
        if resp:
            hex_str = resp.hex()[:40]
            print(f"   backdoor({name}): {hex_str}...")
        else:
            print(f"   backdoor({name}): EMPTY")


def test_towel_syscall():
    """The towel syscall (0x2A) - does it give any other hints?"""
    print("\n=== TEST: Towel Syscall (0x2A) ===")

    nil = build_nil()

    # Get the towel message
    payload = bytes([0x2A]) + nil + bytes([FD]) + QD + bytes([FD, FF])
    resp = query_raw(payload)

    print(f"   Raw response: {resp.hex() if resp else 'EMPTY'}")

    # The response should be Left(string) where string is the towel message
    # Let me try to extract it properly

    # Use error string chain to print it
    # Wait, towel already returns a string, just need to write it

    # ((towel nil) λres.((res (λstr.((write str) nil))) nil))
    printer = bytes([0x04, 0x00, FD]) + nil + bytes([FD, FE])  # write = V4 at depth 2
    ignore = nil + bytes([FE])
    disc = bytes([0x00]) + printer + bytes([FD]) + ignore + bytes([FD, FE])

    payload2 = bytes([0x2A]) + nil + bytes([FD]) + disc + bytes([FD, FF])
    resp2 = query_raw(payload2)
    print(f"   Text: {resp2.decode('latin-1', errors='replace') if resp2 else 'EMPTY'}")


def test_file_256_content():
    """Re-verify hidden file 256 content"""
    print("\n=== TEST: Hidden File 256 ===")

    nil = build_nil()

    # Build 256 as byte term: 256 = 128 + 128 = V8 + V8
    # body = (V8 (V8 V0)) = 08 08 00 FD FD
    byte_256_body = bytes([0x08, 0x08, 0x00, FD, FD])
    byte_256_term = byte_256_body + bytes([FE] * 9)

    # readfile(256)
    # Chain to print the result
    printer = bytes([0x04, 0x00, FD]) + nil + bytes([FD, FE])
    ignore = nil + bytes([FE])
    disc = bytes([0x00]) + printer + bytes([FD]) + ignore + bytes([FD, FE])

    # readfile = 0x07
    payload = bytes([0x07]) + byte_256_term + bytes([FD]) + disc + bytes([FD, FF])
    resp = query_raw(payload, timeout_s=10)
    print(
        f"   Content: {resp.decode('latin-1', errors='replace') if resp else 'EMPTY'}"
    )

    # Also get name
    # name = 0x06
    payload_name = bytes([0x06]) + byte_256_term + bytes([FD]) + disc + bytes([FD, FF])
    resp_name = query_raw(payload_name, timeout_s=10)
    print(
        f"   Name: {resp_name.decode('latin-1', errors='replace') if resp_name else 'EMPTY'}"
    )


def main():
    print("=" * 60)
    print("FINAL SWEEP: Looking for Missed Clues")
    print("=" * 60)

    test_error_strings_extended()
    test_syscall8_error_code()
    test_syscall_sweep()
    test_backdoor_variations()
    test_towel_syscall()
    test_file_256_content()

    print("\n" + "=" * 60)
    print("SWEEP COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
