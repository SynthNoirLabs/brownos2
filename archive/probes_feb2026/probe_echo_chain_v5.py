#!/usr/bin/env python3
"""
Probe v5: Focus on callback/projection hypothesis

What if syscall8's argument receives a callback with internal data?
We need to project out the right piece.

Also: what if the backdoor combinators NEED the special vars to work?
(A Var(253)) or (B Var(253)) might do something interesting.
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

COMBINATOR_A = bytes([0x00, 0x00, FD, FE, FE])  # λa.λb.(b b)
COMBINATOR_B = bytes([0x01, 0x00, FD, FE, FE])  # λa.λb.(a b)


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


def test_backdoor_combinators_with_special():
    """
    Apply backdoor combinators to echo-manufactured special vars
    """
    print("\n=== TEST: Backdoor Combinators + Echo-Manufactured Vars ===")

    nil = build_nil()
    list_L = build_single_byte_list(76)
    list_R = build_single_byte_list(82)

    # Get A and B from backdoor, then apply to Var(253)
    #
    # ((backdoor nil) λbdoor_result.
    #   ((bdoor_result (λpair.
    #     ((pair true) λA.
    #       ((echo 251) λecho_left.
    #         ((echo_left (λvar253.
    #           ((A var253) observer)
    #         )) nil)
    #       )
    #     )
    #   )) nil)
    # ))

    # This is VERY deep. Let me try a simpler test:
    # Manually use combinator A with echo chain

    print("\n1. (A Var(253)) with echo chain:")
    # Chain: echo(251) → λleft.((left (λv253.((A v253) disc))) nil)
    # At depth 2: A needs to be shifted... but A is a closed term!
    # A = λa.λb.(b b) has no free variables, so no shifting needed

    # disc at depth 3: λres.((res write_L) write_R)
    # At depth 4: write = V2+4 = V6
    write_L = bytes([0x06]) + list_L + bytes([FD]) + nil + bytes([FD, FE])
    write_R = bytes([0x06]) + list_R + bytes([FD]) + nil + bytes([FD, FE])
    disc = bytes([0x00]) + write_L + bytes([FD]) + write_R + bytes([FD, FE])

    # inner at depth 2: ((A V0) disc)
    # A is closed term, V0 = var253
    inner = COMBINATOR_A + bytes([0x00, FD]) + disc + bytes([FD, FE])

    # outer at depth 1: λleft.((V0 inner) nil)
    outer = bytes([0x00]) + inner + bytes([FD]) + nil + bytes([FD, FE])

    # full: ((echo 251) outer)
    payload = bytes([0x0E, 0xFB, FD]) + outer + bytes([FD, FF])

    print(f"   Payload len: {len(payload)}")
    resp = query_raw(payload, timeout_s=15)
    print(f"   Response: {resp.hex() if resp else 'EMPTY'}")
    if resp:
        print(f"   Text: {resp.decode('latin-1', errors='replace')}")
        if b"L" in resp:
            print("   *** (A Var(253)) = LEFT ***")

    print("\n2. (B Var(253)) with echo chain:")
    inner_b = COMBINATOR_B + bytes([0x00, FD]) + disc + bytes([FD, FE])
    outer_b = bytes([0x00]) + inner_b + bytes([FD]) + nil + bytes([FD, FE])
    payload_b = bytes([0x0E, 0xFB, FD]) + outer_b + bytes([FD, FF])

    resp_b = query_raw(payload_b, timeout_s=15)
    print(f"   Response: {resp_b.hex() if resp_b else 'EMPTY'}")
    if resp_b:
        print(f"   Text: {resp_b.decode('latin-1', errors='replace')}")

    print("\n3. ((A Var(253)) Var(253)) - self-application pattern:")
    # inner: ((A V0) V0) disc
    # = (λb.(b b) applied to V0) then to disc
    # = ((V0 V0) disc)
    inner_self = COMBINATOR_A + bytes([0x00, FD, 0x00, FD]) + disc + bytes([FD, FE])
    outer_self = bytes([0x00]) + inner_self + bytes([FD]) + nil + bytes([FD, FE])
    payload_self = bytes([0x0E, 0xFB, FD]) + outer_self + bytes([FD, FF])

    resp_self = query_raw(payload_self, timeout_s=15)
    print(f"   Response: {resp_self.hex() if resp_self else 'EMPTY'}")
    if resp_self:
        print(f"   Text: {resp_self.decode('latin-1', errors='replace')}")


def test_syscall8_callback_hypothesis():
    """
    What if syscall8 applies its argument to hidden internals?
    Try: syscall8(λx.write(x))
    This would print whatever syscall8 passes to its argument!
    """
    print("\n=== TEST: Syscall8 Callback Hypothesis ===")

    nil = build_nil()

    # Build a callback that writes its argument
    # λx. ((write (quote x)) nil)
    # But x might not be serializable...

    # Simpler: λx. ((quote x) λbytes. ((write bytes) nil))
    # This quotes x then writes the bytecode

    # Actually, let's build:
    # syscall8 argument = λcallback_arg. ((quote callback_arg) write_cont)
    # where write_cont = λbytes. ((write bytes) done)

    # If syscall8 calls (argument internal_data), we'd get:
    # ((quote internal_data) write_cont) which writes the serialized internal_data

    print("\n1. syscall8(λx.((quote x) write_then_done)):")

    # write_then_done at depth 2: λbytes.((V4 V0) nil)
    # write=V2+2=V4, bytes=V0
    write_then_done = bytes([0x04, 0x00, FD]) + nil + bytes([FD, FE])

    # quoter at depth 1: λx.((V5 V0) write_then_done)
    # quote=V4+1=V5, x=V0
    quoter = bytes([0x05, 0x00, FD]) + write_then_done + bytes([FD, FE])

    # full: ((syscall8 quoter) QD)
    payload = bytes([0x08]) + quoter + bytes([FD]) + QD + bytes([FD, FF])

    print(f"   Payload: {payload.hex()}")
    resp = query_raw(payload, timeout_s=15)
    print(f"   Response: {resp.hex() if resp else 'EMPTY'}")
    if resp:
        print(f"   Text: {resp.decode('latin-1', errors='replace')}")

    print("\n2. syscall8(λf.λx.(f x)) - identity combinator:")
    # This is B combinator! Already tested

    print("\n3. syscall8(λf.(f f)) - omega-like:")
    # This is similar to A's body
    omega_like = bytes([0x00, 0x00, FD, FE])  # λf.(f f)
    payload_omega = bytes([0x08]) + omega_like + bytes([FD]) + QD + bytes([FD, FF])
    resp_omega = query_raw(payload_omega, timeout_s=15)
    print(f"   Response: {resp_omega.hex() if resp_omega else 'EMPTY'}")


def test_projection_arguments():
    """
    Try different projection lambdas as syscall8 argument
    """
    print("\n=== TEST: Projection Arguments to Syscall8 ===")

    nil = build_nil()
    list_L = build_single_byte_list(76)
    list_R = build_single_byte_list(82)

    # Projections:
    # true = λx.λy.x = first
    # false = λx.λy.y = second
    # K = λx.λy.x (same as true)
    # KI = λx.λy.y (same as false)

    true_term = bytes([0x01, FE, FE])  # λλ.V1
    false_term = bytes([0x00, FE, FE])  # λλ.V0

    print("\n1. syscall8(true) - project first:")
    payload1 = bytes([0x08]) + true_term + bytes([FD]) + QD + bytes([FD, FF])
    resp1 = query_raw(payload1)
    print(f"   Response: {resp1.hex() if resp1 else 'EMPTY'}")

    print("\n2. syscall8(false) - project second:")
    payload2 = bytes([0x08]) + false_term + bytes([FD]) + QD + bytes([FD, FF])
    resp2 = query_raw(payload2)
    print(f"   Response: {resp2.hex() if resp2 else 'EMPTY'}")

    print("\n3. syscall8(λx.x) - identity:")
    id_term = bytes([0x00, FE])  # λ.V0
    payload3 = bytes([0x08]) + id_term + bytes([FD]) + QD + bytes([FD, FF])
    resp3 = query_raw(payload3)
    print(f"   Response: {resp3.hex() if resp3 else 'EMPTY'}")

    print("\n4. syscall8(λx.λy.λz.x) - project first of three:")
    first3 = bytes([0x02, FE, FE, FE])  # λλλ.V2
    payload4 = bytes([0x08]) + first3 + bytes([FD]) + QD + bytes([FD, FF])
    resp4 = query_raw(payload4)
    print(f"   Response: {resp4.hex() if resp4 else 'EMPTY'}")


def test_syscall8_with_backdoor_result():
    """
    Feed the entire backdoor result to syscall8
    """
    print("\n=== TEST: Syscall8 with Backdoor Result ===")

    nil = build_nil()

    # Chain: backdoor → extract payload from Left → feed to syscall8
    # ((backdoor nil) λbdoor_res.((bdoor_res (λpair.((syscall8 pair) QD))) nil))

    print("\n1. syscall8(backdoor_pair):")
    # At depth 2: syscall8 = V8+2 = V10 = 0x0A
    # QD at depth 2 needs shifting... let's try unshifted first

    inner = bytes([0x0A, 0x00, FD]) + QD + bytes([FD, FE])  # λpair.((syscall8 pair) QD)
    outer = bytes([0x00]) + inner + bytes([FD]) + nil + bytes([FD, FE])  # λbdoor_res...
    payload = bytes([0xC9]) + nil + bytes([FD]) + outer + bytes([FD, FF])

    print(f"   Payload: {payload.hex()}")
    resp = query_raw(payload, timeout_s=15)
    print(f"   Response: {resp.hex() if resp else 'EMPTY'}")
    if resp:
        print(f"   Text: {resp.decode('latin-1', errors='replace')}")


def test_direct_var_indices():
    """
    What if certain global indices have special meaning?
    Try calling various indices as syscalls with nil
    """
    print("\n=== TEST: Sweep Global Indices 200-210 ===")

    nil = build_nil()

    for idx in range(200, 211):
        if idx == 0xFD or idx == 0xFE or idx == 0xFF:
            continue
        payload = bytes([idx]) + nil + bytes([FD]) + QD + bytes([FD, FF])
        resp = query_raw(payload, timeout_s=3)
        if resp:
            text = resp.decode("latin-1", errors="replace")[:30]
            print(f"   syscall {idx} (0x{idx:02X}): {text}")
        else:
            print(f"   syscall {idx} (0x{idx:02X}): EMPTY")


def main():
    print("=" * 60)
    print("PROBE v5: Callback/Projection Hypothesis")
    print("=" * 60)

    test_backdoor_combinators_with_special()
    test_syscall8_callback_hypothesis()
    test_projection_arguments()
    test_syscall8_with_backdoor_result()
    test_direct_var_indices()

    print("\n" + "=" * 60)
    print("PROBE v5 COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
