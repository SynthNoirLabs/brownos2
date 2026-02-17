#!/usr/bin/env python3
"""
Probe v4: Backdoor combinators + special vars

From v3: All special vars (253/254/255) give "Permission denied" to syscall8
Let's try combining backdoor combinators A/B with special vars.

Also test the "3 leafs" hint with manufactured special bytes.
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
            print(f"  [Attempt {attempt + 1} failed: {e}]")
            time.sleep(delay)
            delay *= 2
    return b""


def build_nil() -> bytes:
    return bytes([0x00, FE, FE])


def build_byte_term(n: int) -> bytes:
    parts = [0x00]
    weights = [(1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)]
    for idx, weight in weights:
        if n & weight:
            parts = [idx] + parts + [FD]
    return bytes(parts + [FE] * 9)


def build_single_byte_list(char_code: int) -> bytes:
    byte_term = build_byte_term(char_code)
    nil = build_nil()
    return bytes([0x01]) + byte_term + bytes([FD]) + nil + bytes([FD, FE, FE])


# Backdoor combinators (from BROWNOS_MASTER.md):
# A = λa.λb.(b b) = 00 00 FD FE FE
# B = λa.λb.(a b) = 01 00 FD FE FE
COMBINATOR_A = bytes([0x00, 0x00, FD, FE, FE])
COMBINATOR_B = bytes([0x01, 0x00, FD, FE, FE])


def test_backdoor_with_echo_chain():
    """
    Get A,B from backdoor, then combine with echo-manufactured special vars
    """
    print("\n=== TEST: Backdoor + Echo Chain ===")

    nil = build_nil()

    # Backdoor returns Left(pair) where pair = (λs. s A B)
    # To extract A: (pair true) where true = λx.λy.x
    # To extract B: (pair false) where false = λx.λy.y

    # true = λx.λy.x = λλ.1 = 01 FE FE
    true_term = bytes([0x01, FE, FE])
    # false = λx.λy.y = λλ.0 = 00 FE FE
    false_term = bytes([0x00, FE, FE])

    print("\n1. Test backdoor returns Left:")
    # ((backdoor nil) λres.((res write_L) write_R))

    list_L = build_single_byte_list(76)  # 'L'
    list_R = build_single_byte_list(82)  # 'R'

    # At depth 2 (inside discriminator lambdas): write = V2+2 = V4
    write_L = bytes([0x04]) + list_L + bytes([FD]) + nil + bytes([FD, FE])
    write_R = bytes([0x04]) + list_R + bytes([FD]) + nil + bytes([FD, FE])

    # discriminator at depth 1: λres.((V0 write_L) write_R)
    discriminator = bytes([0x00]) + write_L + bytes([FD]) + write_R + bytes([FD, FE])

    # backdoor = syscall 201 = 0xC9
    payload = bytes([0xC9]) + nil + bytes([FD]) + discriminator + bytes([FD, FF])
    resp = query_raw(payload, timeout_s=10)
    print(
        f"   Response: {resp.decode('latin-1', errors='replace') if resp else 'EMPTY'}"
    )

    print("\n2. Extract A from backdoor and apply to Var(253):")
    # Chain:
    # ((backdoor nil) λpair_left.
    #   ((pair_left (λpair.
    #     ((pair true) λA.
    #       ((echo 251) λecho_left.
    #         ((echo_left (λvar253.
    #           ((A var253) disc)
    #         )) nil)
    #       )
    #     )
    #   )) nil)
    # )

    # This is getting very deep. Let me try a simpler approach:
    # Just manually construct (A var253) and observe

    # Actually, let's test (A nil) first to verify A works
    print("\n3. Test (A nil):")
    # A = λa.λb.(b b), so (A nil) = λb.(b b)
    # Then (A nil nil) = (nil nil) = ...
    # ((A nil) nil) should evaluate

    # payload: ((A nil) QD)
    # = 00 00 FD FE FE (A) 00 FE FE (nil) FD QD FD FF
    payload_a_nil = COMBINATOR_A + nil + bytes([FD]) + QD + bytes([FD, FF])
    resp_a = query_raw(payload_a_nil, timeout_s=10)
    print(f"   Response: {resp_a.hex() if resp_a else 'EMPTY'}")
    if resp_a and b"Encoding" not in resp_a:
        print(f"   Text: {resp_a.decode('latin-1', errors='replace')}")

    print("\n4. Test (B nil):")
    # B = λa.λb.(a b), so (B nil) = λb.(nil b)
    payload_b_nil = COMBINATOR_B + nil + bytes([FD]) + QD + bytes([FD, FF])
    resp_b = query_raw(payload_b_nil, timeout_s=10)
    print(f"   Response: {resp_b.hex() if resp_b else 'EMPTY'}")
    if resp_b and b"Encoding" not in resp_b:
        print(f"   Text: {resp_b.decode('latin-1', errors='replace')}")


def test_syscall8_with_a_b():
    """
    Try syscall8 with backdoor combinators as argument
    """
    print("\n=== TEST: Syscall8 with A/B Combinators ===")

    nil = build_nil()

    print("\n1. syscall8(A):")
    payload_a = bytes([0x08]) + COMBINATOR_A + bytes([FD]) + QD + bytes([FD, FF])
    resp_a = query_raw(payload_a, timeout_s=10)
    print(f"   Response hex: {resp_a.hex() if resp_a else 'EMPTY'}")

    print("\n2. syscall8(B):")
    payload_b = bytes([0x08]) + COMBINATOR_B + bytes([FD]) + QD + bytes([FD, FF])
    resp_b = query_raw(payload_b, timeout_s=10)
    print(f"   Response hex: {resp_b.hex() if resp_b else 'EMPTY'}")

    print("\n3. syscall8((A B)):")
    # (A B) = omega = λx.(x x)
    # omega bytecode: 00 00 FD FE
    omega = bytes([0x00, 0x00, FD, FE])
    payload_omega = bytes([0x08]) + omega + bytes([FD]) + QD + bytes([FD, FF])
    resp_omega = query_raw(payload_omega, timeout_s=10)
    print(f"   Response hex: {resp_omega.hex() if resp_omega else 'EMPTY'}")


def test_3_leafs_with_special():
    """
    The "3 leafs" hint - try various 3-var terms including manufactured special vals
    """
    print("\n=== TEST: 3 Leafs Patterns ===")

    nil = build_nil()
    list_L = build_single_byte_list(76)
    list_R = build_single_byte_list(82)

    # 3 leafs = term with exactly 3 Var nodes
    # Patterns: App(App(Va, Vb), Vc) or App(Va, App(Vb, Vc)) etc.

    # What if the 3 leafs involves syscall8 + special manufactured vars?
    # Term: ((syscall8 var253) var254)
    # But var253/var254 must be manufactured via echo...

    print("\n1. Direct 3-leaf patterns (without echo manufacturing):")

    # ((8 251) 252) - 3 vars: 8, 251, 252
    pattern1 = bytes([0x08, 0xFB, FD, 0xFC, FD, FF])
    resp1 = query_raw(pattern1)
    print(f"   ((8 251) 252): {resp1.hex() if resp1 else 'EMPTY'}")

    # ((8 0) 8) - 3 vars: 8, 0, 8
    pattern2 = bytes([0x08, 0x00, FD, 0x08, FD, FF])
    resp2 = query_raw(pattern2)
    print(f"   ((8 0) 8): {resp2.hex() if resp2 else 'EMPTY'}")

    # ((0 8) 0) - 3 vars
    pattern3 = bytes([0x00, 0x08, FD, 0x00, FD, FF])
    resp3 = query_raw(pattern3)
    print(f"   ((0 8) 0): {resp3.hex() if resp3 else 'EMPTY'}")

    print("\n2. 3-leaf patterns with echo-manufactured vars:")

    # Chain: echo(251) → extract v253 → apply in 3-leaf pattern
    # ((v253 syscall8) v253)  -- using same v253 twice

    # Structure:
    # ((echo 251) λleft.((left (λv253.
    #   ((v253 V9) v253)  -- syscall8 at depth 2 = V8+2=V10=0x0A? No wait...
    # )) nil))

    # At depth 2: syscall8 = V8+2 = V10 = 0x0A
    #            v253 = V0

    # inner 3-leaf: ((V0 V10) V0) = ((v253 syscall8) v253)
    inner = bytes([0x00, 0x0A, FD, 0x00, FD])

    # handler = λv253. inner
    handler = inner + bytes([FE])

    # outer_cont = λleft. ((V0 handler) nil)
    outer_cont = bytes([0x00]) + handler + bytes([FD]) + nil + bytes([FD, FE])

    # full = ((echo 251) outer_cont)
    payload = bytes([0x0E, 0xFB, FD]) + outer_cont + bytes([FD, FF])

    print(f"   Payload: {payload.hex()}")
    resp = query_raw(payload, timeout_s=15)
    print(f"   Response: {resp.hex() if resp else 'EMPTY'} ({len(resp)} bytes)")
    if resp:
        print(f"   Text: {resp.decode('latin-1', errors='replace')}")


def test_apply_special_to_syscall8():
    """
    What if we apply Var(253) TO syscall8 instead of as argument?
    (Var(253) syscall8) instead of (syscall8 Var(253))
    """
    print("\n=== TEST: Apply Special Vars TO Syscall8 ===")

    nil = build_nil()
    list_L = build_single_byte_list(76)
    list_R = build_single_byte_list(82)

    # Build discrimination that writes L or R
    # depth 4: write = V2+4 = V6
    write_L = bytes([0x06]) + list_L + bytes([FD]) + nil + bytes([FD, FE])
    write_R = bytes([0x06]) + list_R + bytes([FD]) + nil + bytes([FD, FE])
    disc = bytes([0x00]) + write_L + bytes([FD]) + write_R + bytes([FD, FE])

    print("\n1. (Var(253) syscall8) continuation=disc:")
    # Chain: echo(251) → λleft.((left (λv253.
    #   ((v253 V10) disc)  -- apply v253 to syscall8!
    # )) nil))

    # At depth 2: v253=V0, syscall8=V10=0x0A
    inner1 = bytes([0x00, 0x0A, FD]) + disc + bytes([FD, FE])
    outer1 = bytes([0x00]) + inner1 + bytes([FD]) + nil + bytes([FD, FE])
    payload1 = bytes([0x0E, 0xFB, FD]) + outer1 + bytes([FD, FF])

    resp1 = query_raw(payload1, timeout_s=15)
    print(f"   Response: {resp1.hex() if resp1 else 'EMPTY'}")
    if resp1:
        print(f"   Text: {resp1.decode('latin-1', errors='replace')}")
        if b"L" in resp1:
            print("   *** LEFT - SUCCESS? ***")

    print("\n2. ((Var(253) Var(253)) syscall8):")
    # self-application of v253
    # At depth 2: ((V0 V0) V10)
    inner2 = bytes([0x00, 0x00, FD, 0x0A, FD]) + disc + bytes([FD, FE])
    outer2 = bytes([0x00]) + inner2 + bytes([FD]) + nil + bytes([FD, FE])
    payload2 = bytes([0x0E, 0xFB, FD]) + outer2 + bytes([FD, FF])

    resp2 = query_raw(payload2, timeout_s=15)
    print(f"   Response: {resp2.hex() if resp2 else 'EMPTY'}")
    if resp2:
        print(f"   Text: {resp2.decode('latin-1', errors='replace')}")


def test_echo_result_direct():
    """
    What does echo actually return? Let's examine the Left wrapper
    """
    print("\n=== TEST: Examine Echo Result Structure ===")

    nil = build_nil()

    print("\n1. Echo(0) with QD - should show Left(Var(2)):")
    payload = bytes([0x0E, 0x00, FD]) + QD + bytes([FD, FF])
    resp = query_raw(payload)
    print(f"   Response hex: {resp.hex() if resp else 'EMPTY'}")
    # Should be: λλ.(1 02) = Left(Var(2)) = 01 02 FD FE FE
    # Actually with QD it serializes: 01 02 FD FE FE FF

    print("\n2. Echo(250) with QD - should show Left(Var(252)):")
    payload = bytes([0x0E, 0xFA, FD]) + QD + bytes([FD, FF])
    resp = query_raw(payload)
    print(f"   Response hex: {resp.hex() if resp else 'EMPTY'}")
    # Should be: 01 FC FD FE FE FF = Left(Var(252))


def test_raw_var_253_in_bytecode():
    """
    What happens if we try to put 0xFD where a Var should be?
    (This should fail parsing)
    """
    print("\n=== TEST: Raw 0xFD in Var Position ===")

    # This is malformed: using FD as a variable
    # (syscall8 <FD>) - but FD is parsed as App marker!
    malformed = bytes([0x08, FD, FD, 0x00, FD, FF])
    print(f"   Payload: {malformed.hex()}")
    resp = query_raw(malformed)
    print(f"   Response: {resp.hex() if resp else 'EMPTY'}")
    if resp:
        print(f"   Text: {resp.decode('latin-1', errors='replace')}")


def main():
    print("=" * 60)
    print("PROBE v4: Backdoor + Special Vars + 3 Leafs")
    print("=" * 60)

    test_backdoor_with_echo_chain()
    test_syscall8_with_a_b()
    test_3_leafs_with_special()
    test_apply_special_to_syscall8()
    test_echo_result_direct()
    test_raw_var_253_in_bytecode()

    print("\n" + "=" * 60)
    print("PROBE v4 COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
