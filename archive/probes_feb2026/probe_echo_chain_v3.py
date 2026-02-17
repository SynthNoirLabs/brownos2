#!/usr/bin/env python3
"""
Probe v3: Extract error codes and try Var(255)

From v2 we confirmed:
- syscall8(Var(253)) returns Right (some error)
- syscall8(Var(254)) returns Right (some error)

Now let's find out WHICH error code:
- Right(2) = "Invalid argument" (different code path!)
- Right(6) = "Permission denied" (normal rejection)

Also try reaching Var(255) via double echo chain.
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
            print(f"  [Attempt {attempt + 1} failed: {e}]")
            time.sleep(delay)
            delay *= 2
    return b""


def build_byte_term(n: int) -> bytes:
    """Build 9-lambda byte term for value n"""
    # body starts with V0 (base 0)
    parts = [0x00]
    weights = [(1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)]
    for idx, weight in weights:
        if n & weight:
            parts = [idx] + parts + [FD]
    return bytes(parts + [FE] * 9)


def build_nil() -> bytes:
    return bytes([0x00, FE, FE])


def build_cons(head: bytes, tail: bytes) -> bytes:
    """cons h t = λc.λn.((c h) t) = λλ.((1 h) t)"""
    # bytecode: 01 [head] FD [tail] FD FE FE
    return bytes([0x01]) + head + bytes([FD]) + tail + bytes([FD, FE, FE])


def build_single_byte_list(char_code: int) -> bytes:
    """Build Scott list containing single byte"""
    byte_term = build_byte_term(char_code)
    nil = build_nil()
    return build_cons(byte_term, nil)


def test_error_code_extraction():
    """
    Extract the actual error code from syscall8's Right response.

    Strategy:
    Right y = λl.λr.(r y)
    Apply Right to (λ_.dummy) and (λcode. use_code)

    use_code converts the integer code to a digit and writes it

    Codes we care about:
    - 2 = "Invalid argument"
    - 6 = "Permission denied"

    For simplicity: write the digit directly
    - Code 2 → write "2" (0x32)
    - Code 6 → write "6" (0x36)
    """
    print("\n=== TEST: Extract Error Codes ===")

    nil = build_nil()

    # We'll use a different approach:
    # Apply the error code to ((error code) QD) to print the error STRING
    # This way we can read "Invalid argument" vs "Permission denied"

    # on_left = λpayload. ((write ['L']) nil)  -- just writes 'L'
    # on_right = λcode. ((error code) QD)  -- prints error string

    # But QD inside the structure gets complicated with de Bruijn...
    # Let's try a simpler discrimination:
    # Use the error code as a Church numeral to select from options

    # Actually simplest: just run ((syscall8 arg) λres.((res on_L) on_R))
    # where on_R = λcode.((error code) custom_print)

    # custom_print that just prints what error returns, which is Left(string)
    # custom_print = λerror_result. ((error_result print_string) ignore)
    # print_string = λstr. ((write str) nil)

    # This is getting deep. Let me try a flatter approach:
    #
    # Full chain for syscall8(nil):
    # ((syscall8 nil) λres. ((res ignore) (λcode. ((error code) string_printer))))
    # string_printer = λerror_res. ((error_res (λstr.((write str) nil))) ignore)

    # Let's count depths:
    # Depth 0: top
    # Depth 1: λres
    # Depth 2: λcode (on_right)
    # Depth 3: λerror_res (string_printer)
    # Depth 4: λstr (actual printer)

    # At depth 2: error = V1+2 = V3
    # At depth 3: nothing new
    # At depth 4: write = V2+4 = V6

    # printer = λstr. ((write str) nil)
    # At depth 4: write=V6, str=V0
    # bytecode: 06 00 FD [nil] FD FE
    printer = bytes([0x06, 0x00, FD]) + nil + bytes([FD, FE])

    # ignore = λx.nil (just returns nil, ignores its arg)
    # bytecode: [nil] FE = 00FEFE FE
    ignore = nil + bytes([FE])

    # string_printer = λerror_res. ((error_res printer) ignore)
    # At depth 3: error_res=V0
    # bytecode: 00 [printer] FD [ignore] FD FE
    string_printer = bytes([0x00]) + printer + bytes([FD]) + ignore + bytes([FD, FE])

    # on_right = λcode. ((error code) string_printer)
    # At depth 2: code=V0, error=V3
    # bytecode: 03 00 FD [string_printer] FD FE
    on_right = bytes([0x03, 0x00, FD]) + string_printer + bytes([FD, FE])

    # on_left = λpayload. nil  -- ignore success payload, return nil
    # bytecode: [nil] FE = 00FEFE FE
    on_left = nil + bytes([FE])

    # discriminator = λres. ((res on_left) on_right)
    # At depth 1: res=V0
    # bytecode: 00 [on_left] FD [on_right] FD FE
    discriminator = bytes([0x00]) + on_left + bytes([FD]) + on_right + bytes([FD, FE])

    # === Test 1: syscall8(nil) - should print "Permission denied" ===
    print("\n1. syscall8(nil) error string:")
    payload1 = bytes([0x08]) + nil + bytes([FD]) + discriminator + bytes([FD, FF])
    print(f"   Payload: {payload1.hex()}")
    resp1 = query_raw(payload1, timeout_s=10)
    print(f"   Response: {resp1.hex() if resp1 else 'EMPTY'}")
    if resp1:
        # Response might be bytecode of the string, try to decode
        print(f"   As text: {resp1.decode('latin-1', errors='replace')}")

    # === Test 2: syscall8(Var(253)) via echo chain ===
    print("\n2. syscall8(Var(253)) via echo(251):")

    # handler = λx. ((syscall8 x) discriminator_shifted)
    # Under additional λ for echo's Left unwrapping:
    # Depth increases by 1 everywhere

    # Let me rebuild with correct depths:
    # Outer: ((echo 251) λleft. ((left handler) nil))
    # Depth 0: top
    # Depth 1: λleft
    # Depth 2: λx (handler)
    # Depth 3: λres (discriminator)
    # Depth 4: λcode (on_right)
    # Depth 5: λerror_res (string_printer)
    # Depth 6: λstr (printer)

    # At depth 2: syscall8 = V8+2 = V10 = 0x0A
    # At depth 4: error = V1+4 = V5
    # At depth 6: write = V2+6 = V8

    # Rebuild:
    # printer_v2 = λstr. ((V8 V0) nil)
    printer_v2 = bytes([0x08, 0x00, FD]) + nil + bytes([FD, FE])

    # ignore_v2 = λx.nil
    ignore_v2 = nil + bytes([FE])

    # string_printer_v2 = λerror_res. ((V0 printer_v2) ignore_v2)
    string_printer_v2 = (
        bytes([0x00]) + printer_v2 + bytes([FD]) + ignore_v2 + bytes([FD, FE])
    )

    # on_right_v2 = λcode. ((V5 V0) string_printer_v2)
    on_right_v2 = bytes([0x05, 0x00, FD]) + string_printer_v2 + bytes([FD, FE])

    # on_left_v2 = λpayload. nil
    on_left_v2 = nil + bytes([FE])

    # discriminator_v2 = λres. ((V0 on_left_v2) on_right_v2)
    discriminator_v2 = (
        bytes([0x00]) + on_left_v2 + bytes([FD]) + on_right_v2 + bytes([FD, FE])
    )

    # handler = λx. ((V10 V0) discriminator_v2)
    handler = bytes([0x0A, 0x00, FD]) + discriminator_v2 + bytes([FD, FE])

    # outer_cont = λleft. ((V0 handler) nil)
    outer_cont = bytes([0x00]) + handler + bytes([FD]) + nil + bytes([FD, FE])

    # full = ((echo 251) outer_cont)
    payload2 = bytes([0x0E, 0xFB, FD]) + outer_cont + bytes([FD, FF])
    print(f"   Payload: {payload2.hex()}")
    resp2 = query_raw(payload2, timeout_s=15)
    print(f"   Response: {resp2.hex() if resp2 else 'EMPTY'}")
    if resp2:
        print(f"   As text: {resp2.decode('latin-1', errors='replace')}")

    # === Test 3: syscall8(Var(254)) via echo chain ===
    print("\n3. syscall8(Var(254)) via echo(252):")
    payload3 = bytes([0x0E, 0xFC, FD]) + outer_cont + bytes([FD, FF])
    resp3 = query_raw(payload3, timeout_s=15)
    print(f"   Response: {resp3.hex() if resp3 else 'EMPTY'}")
    if resp3:
        print(f"   As text: {resp3.decode('latin-1', errors='replace')}")


def test_double_echo_for_255():
    """
    Chain: echo(251) → Left(253) → unwrap → echo(253) → Left(255)
    Then feed Var(255) to syscall8
    """
    print("\n=== TEST: Double Echo to Reach Var(255) ===")

    nil = build_nil()

    # Structure:
    # ((echo 251) λleft1. ((left1 handler1) nil))
    # handler1 = λvar253. ((echo var253) λleft2. ((left2 handler2) nil))
    # handler2 = λvar255. ((syscall8 var255) QD)
    #
    # But we can't use QD because Var(255) can't be serialized!
    # Use discrimination instead.

    # Let's simplify - just check if syscall8(Var(255)) is Left or Right
    # by writing 'L' or 'R'

    # Build byte list for 'L' (76) and 'R' (82)
    list_L = build_single_byte_list(76)  # 'L'
    list_R = build_single_byte_list(82)  # 'R'

    # Count depths for double echo chain:
    # Depth 0: top
    # Depth 1: λleft1
    # Depth 2: λvar253 (handler1)
    # Depth 3: λleft2 (echo's continuation)
    # Depth 4: λvar255 (handler2)
    # Depth 5: λres (discriminator)
    # Depth 6: λ_ (write_L / write_R)

    # At depth 4: syscall8 = V8+4 = V12 = 0x0C
    # At depth 2: echo = V14+2 = V16 = 0x10
    # At depth 6: write = V2+6 = V8

    # write_L at depth 6: λ_.((V8 list_L) nil)
    write_L = bytes([0x08]) + list_L + bytes([FD]) + nil + bytes([FD, FE])
    write_R = bytes([0x08]) + list_R + bytes([FD]) + nil + bytes([FD, FE])

    # discriminator at depth 5: λres.((V0 write_L) write_R)
    discriminator = bytes([0x00]) + write_L + bytes([FD]) + write_R + bytes([FD, FE])

    # handler2 at depth 4: λvar255.((V12 V0) discriminator)
    # V12 = 0x0C
    handler2 = bytes([0x0C, 0x00, FD]) + discriminator + bytes([FD, FE])

    # inner_cont at depth 3: λleft2.((V0 handler2) nil)
    inner_cont = bytes([0x00]) + handler2 + bytes([FD]) + nil + bytes([FD, FE])

    # handler1 at depth 2: λvar253.((V16 V0) inner_cont)
    # V16 = 0x10
    handler1 = bytes([0x10, 0x00, FD]) + inner_cont + bytes([FD, FE])

    # outer_cont at depth 1: λleft1.((V0 handler1) nil)
    outer_cont = bytes([0x00]) + handler1 + bytes([FD]) + nil + bytes([FD, FE])

    # full: ((echo 251) outer_cont)
    payload = bytes([0x0E, 0xFB, FD]) + outer_cont + bytes([FD, FF])

    print(f"  Payload length: {len(payload)}")
    print(f"  Payload: {payload.hex()}")

    resp = query_raw(payload, timeout_s=20)
    print(f"  Response length: {len(resp)}")
    print(f"  Response hex: {resp.hex() if resp else 'EMPTY'}")
    if resp:
        print(f"  Response text: {resp.decode('latin-1', errors='replace')}")
        if b"L" in resp:
            print("  *** SYSCALL8(Var(255)) = LEFT (SUCCESS?!) ***")
        elif b"R" in resp:
            print("  syscall8(Var(255)) = RIGHT (still error)")


def test_triple_echo():
    """
    What about Var(257)? echo(255) → Left(257)
    But we need to reach Var(255) first via double echo...
    """
    print("\n=== TEST: Can we go beyond Var(255)? ===")
    print("  To reach Var(257), we'd need triple echo chain")
    print("  echo(251) → 253 → echo(253) → 255 → echo(255) → 257")
    print("  This would be very deep nesting, skipping for now")


def test_syscall8_with_255_as_continuation():
    """
    What if Var(255) is used as the CONTINUATION instead of argument?
    ((syscall8 nil) Var(255))
    """
    print("\n=== TEST: Var(255) as Continuation ===")

    nil = build_nil()
    list_L = build_single_byte_list(76)
    list_R = build_single_byte_list(82)

    # We want: ((syscall8 nil) extracted_var255)
    # where extracted_var255 comes from echo chain

    # Structure:
    # ((echo 251) λl1.(l1 (λv253.
    #   ((echo v253) λl2.(l2 (λv255.
    #     ((syscall8 nil) v255)  -- use v255 as continuation!
    #   ) nil))
    # ) nil))

    # Depths:
    # 0: top
    # 1: λl1
    # 2: λv253
    # 3: λl2
    # 4: λv255

    # At depth 4:
    #   syscall8 = V8+4 = V12 = 0x0C
    #   nil needs to be constructed (closed term)
    #   v255 = V0

    # inner_body at depth 4: ((V12 nil) V0)
    # bytecode: 0C [nil] FD 00 FD
    inner_body = bytes([0x0C]) + nil + bytes([FD, 0x00, FD])

    # handler2 at depth 4: λv255. inner_body
    handler2 = inner_body + bytes([FE])

    # unwrap2 at depth 3: λl2.((V0 handler2) nil)
    unwrap2 = bytes([0x00]) + handler2 + bytes([FD]) + nil + bytes([FD, FE])

    # inner_echo at depth 2: ((V16 V0) unwrap2)  -- echo = V14+2 = V16
    inner_echo = bytes([0x10, 0x00, FD]) + unwrap2 + bytes([FD])

    # handler1 at depth 2: λv253. inner_echo
    handler1 = inner_echo + bytes([FE])

    # unwrap1 at depth 1: λl1.((V0 handler1) nil)
    unwrap1 = bytes([0x00]) + handler1 + bytes([FD]) + nil + bytes([FD, FE])

    # full: ((echo 251) unwrap1)
    payload = bytes([0x0E, 0xFB, FD]) + unwrap1 + bytes([FD, FF])

    print(f"  Payload length: {len(payload)}")
    print(f"  Payload: {payload.hex()}")

    resp = query_raw(payload, timeout_s=20)
    print(f"  Response length: {len(resp)}")
    print(f"  Response hex: {resp.hex() if resp else 'EMPTY'}")
    if resp:
        print(f"  Response text: {resp.decode('latin-1', errors='replace')}")


def test_special_var_combinations():
    """
    Try various combinations with special vars
    """
    print("\n=== TEST: Special Var Combinations ===")

    nil = build_nil()
    list_L = build_single_byte_list(76)
    list_R = build_single_byte_list(82)

    # Build write_L and write_R for quick discrimination
    # At various depths we need different var indices for write

    print("\n1. ((Var(253) Var(254)) nil) via echo chain")
    # This applies manufactured special vars to each other

    # Structure:
    # ((echo 251) λl1.(l1 (λv253.
    #   ((echo 252) λl2.(l2 (λv254.
    #     ((v253 v254) nil)  -- apply them!
    #   ) nil))
    # ) nil))

    # Depths: 0→1→2→3→4
    # At depth 4: v253 is at depth 2, so needs +2 = V2
    #            v254 is V0

    # Wait, de Bruijn: at depth 4, v253 was bound at depth 2
    # Distance = 4 - 2 = 2, so v253 is V2
    # v254 was bound at depth 4, so V0

    # inner_apply at depth 4: ((V2 V0) nil)
    inner_apply = bytes([0x02, 0x00, FD]) + nil + bytes([FD])

    # handler2 at depth 4: λv254. inner_apply
    handler2 = inner_apply + bytes([FE])

    # unwrap2 at depth 3: λl2.((V0 handler2) nil)
    unwrap2 = bytes([0x00]) + handler2 + bytes([FD]) + nil + bytes([FD, FE])

    # echo2 at depth 2: ((echo_shifted V252) unwrap2)
    # echo at depth 2 = V14+2 = V16 = 0x10
    # But we want echo(v253), not echo(252)!
    # Actually let's echo 252 to get v254, then combine with existing v253
    echo2 = bytes([0x10, 0xFC, FD]) + unwrap2 + bytes([FD])  # echo(252)

    # handler1 at depth 2: λv253. echo2
    handler1 = echo2 + bytes([FE])

    # unwrap1 at depth 1: λl1.((V0 handler1) nil)
    unwrap1 = bytes([0x00]) + handler1 + bytes([FD]) + nil + bytes([FD, FE])

    # full: ((echo 251) unwrap1)
    payload = bytes([0x0E, 0xFB, FD]) + unwrap1 + bytes([FD, FF])

    print(f"  Payload: {payload.hex()}")
    resp = query_raw(payload, timeout_s=20)
    print(f"  Response: {resp.hex() if resp else 'EMPTY'} ({len(resp)} bytes)")
    if resp:
        print(f"  Text: {resp.decode('latin-1', errors='replace')}")


def main():
    print("=" * 60)
    print("PROBE v3: Error Code Extraction and Var(255)")
    print("=" * 60)

    test_error_code_extraction()
    test_double_echo_for_255()
    test_syscall8_with_255_as_continuation()
    test_special_var_combinations()
    test_triple_echo()

    print("\n" + "=" * 60)
    print("PROBE v3 COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
