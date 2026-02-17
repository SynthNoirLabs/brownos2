#!/usr/bin/env python3
"""
Probe v6: Deep dive into (A Var(253)) behavior

From v5: (A Var(253)) produces "LR" output - something computed!
Let's understand what's happening.

A = λa.λb.(b b)
(A Var(253)) = λb.(b b)  [with Var(253) substituted but unused!]

So (A x) for ANY x gives λb.(b b) which is the self-application combinator ω.
When we apply ω to our discriminator, we get (disc disc) which is confusing.

Let me try cleaner tests to see what (A Var(253)) and similar constructs actually produce.
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


def test_a_behavior():
    """
    A = λa.λb.(b b)
    A discards its first arg and returns ω = λb.(b b)
    """
    print("\n=== TEST: Combinator A Behavior ===")

    nil = build_nil()

    # (A nil) should give ω = λb.(b b)
    print("\n1. (A nil) with QD:")
    payload1 = COMBINATOR_A + nil + bytes([FD]) + QD + bytes([FD, FF])
    resp1 = query_raw(payload1)
    print(f"   Response: {resp1.hex() if resp1 else 'EMPTY'}")
    # Expected: λb.(b b) = 00 00 FD FE = ω

    # What if we then apply ω to QD?
    print("\n2. ((A nil) QD) - this is (ω QD) = (QD QD):")
    # (A nil QD) = (ω QD) = (QD QD)
    # This applies QD to itself!
    payload2 = COMBINATOR_A + nil + bytes([FD]) + QD + bytes([FD, FF])
    # Wait, that's the same as payload1... Let me restructure

    # payload: ((A nil) QD) + FF
    # = A nil FD QD FD FF
    payload2b = COMBINATOR_A + nil + bytes([FD]) + QD + bytes([FD, FF])
    # This IS (A nil) applied to QD as continuation. So it computes (A nil)
    # and then applies QD to the result. The result is ω.
    # QD(ω) should print ω's bytecode.

    print("\n3. Direct ω = λb.(b b):")
    omega = bytes([0x00, 0x00, FD, FE])
    payload3 = omega + QD + bytes([FD, FF])  # (ω QD) wait no...
    # This is ω applied to QD, not QD applied to ω
    # (ω QD) = (QD QD) which might be weird

    # Let's just quote ω directly:
    # ((quote ω) write_chain)
    print("\n4. Quote ω directly:")
    # quote = syscall 4
    # ((quote ω) λbytes.((write bytes) nil))
    write_chain = (
        bytes([0x02, 0x00, FD]) + nil + bytes([FD, FE])
    )  # λbytes.((write bytes) nil), write=V2
    payload4 = bytes([0x04]) + omega + bytes([FD]) + write_chain + bytes([FD, FF])
    resp4 = query_raw(payload4)
    print(f"   Response: {resp4.hex() if resp4 else 'EMPTY'}")
    # Expected: bytecode of ω = 00 00 FD FE FF


def test_b_with_special():
    """
    B = λa.λb.(a b)
    (B x) = λb.(x b)  - applies x to its second argument
    """
    print("\n=== TEST: Combinator B with Special Var ===")

    nil = build_nil()

    # (B Var(253)) = λb.(Var(253) b)
    # If we then apply this to something, it applies Var(253) to that thing

    # Chain: echo(251) → extract v253 → (B v253) → apply to nil → observe
    print("\n1. ((B Var(253)) nil) - applies Var(253) to nil:")

    # At depth 2: B is closed, v253=V0
    # ((B V0) nil) = (λb.(V0 b) nil) = (V0 nil) = (Var(253) nil)
    # But wait, v253 was manufactured, what does it DO when applied?

    # Let's build: echo(251) → λleft.((left handler) nil)
    # handler = λv253. (((B v253) nil) QD)
    # This computes (B v253) applied to nil, then prints with QD

    # Actually (B v253) = λb.(v253 b), applied to nil gives (v253 nil)
    # If v253 is Var(253), what is (Var(253) nil)?
    # Var(253) at runtime is just a variable - if not bound, it's stuck

    # Let me try QD on the whole thing
    inner = COMBINATOR_B + bytes([0x00, FD]) + nil + bytes([FD]) + QD + bytes([FD, FE])
    outer = bytes([0x00]) + inner + bytes([FD]) + nil + bytes([FD, FE])
    payload = bytes([0x0E, 0xFB, FD]) + outer + bytes([FD, FF])

    print(f"   Payload: {payload.hex()}")
    resp = query_raw(payload, timeout_s=10)
    print(f"   Response: {resp.hex() if resp else 'EMPTY'}")
    if resp:
        print(f"   Text: {resp.decode('latin-1', errors='replace')}")


def test_syscall8_via_b():
    """
    What if we use B to "inject" Var(253) into syscall8?
    ((B syscall8) Var(253)) = (syscall8 Var(253))

    But we can construct this differently via B!
    """
    print("\n=== TEST: Syscall8 via B Combinator ===")

    nil = build_nil()
    list_L = build_single_byte_list(76)
    list_R = build_single_byte_list(82)

    # B = λa.λb.(a b)
    # (B syscall8) = λb.(syscall8 b)
    # ((B syscall8) arg) = (syscall8 arg)

    # Chain: echo(251) → v253 → ((B syscall8) v253) → disc

    print("\n1. ((B syscall8) Var(253)) with discrimination:")

    # At depth 2: syscall8 = V10 = 0x0A
    # (B V10) = λb.(V10 b) -- but B is closed, V10 needs to be captured somehow

    # Actually, let me think about this more carefully
    # B = λa.λb.(a b) where a and b are de Bruijn V1 and V0 inside
    # When I write COMBINATOR_B, it's the bytecode 01 00 FD FE FE
    # which is λ.λ.(V1 V0) = λa.λb.(a b)

    # At depth 2 in our chain, to apply B to syscall8:
    # B syscall8 FD = (B syscall8)
    # But B is a closed term - its V1 and V0 refer to its OWN lambdas, not outer scope
    # So (B X) = λb.(X b) works correctly

    # To get syscall8 at depth 2, it's V8+2 = V10 = 0x0A

    # Build: λv253. (((B V10) v253) disc)
    # = λ. ((B V10 FD V0 FD) disc FD)
    # = λ. ((COMBINATOR_B 0A FD 00 FD) disc FD)

    # Disc at depth 3
    write_L = bytes([0x06]) + list_L + bytes([FD]) + nil + bytes([FD, FE])
    write_R = bytes([0x06]) + list_R + bytes([FD]) + nil + bytes([FD, FE])
    disc = bytes([0x00]) + write_L + bytes([FD]) + write_R + bytes([FD, FE])

    # inner at depth 2: λv253.((B syscall8 v253) disc)
    # ((B syscall8) v253) = B syscall8 FD v253 FD
    inner = COMBINATOR_B + bytes([0x0A, FD, 0x00, FD]) + disc + bytes([FD, FE])

    # outer at depth 1
    outer = bytes([0x00]) + inner + bytes([FD]) + nil + bytes([FD, FE])

    # full
    payload = bytes([0x0E, 0xFB, FD]) + outer + bytes([FD, FF])

    print(f"   Payload: {payload.hex()}")
    resp = query_raw(payload, timeout_s=15)
    print(f"   Response: {resp.hex() if resp else 'EMPTY'}")
    if resp:
        print(f"   Text: {resp.decode('latin-1', errors='replace')}")
        if b"L" in resp and b"R" not in resp:
            print("   *** PURE LEFT - SUCCESS? ***")


def test_apply_253_directly():
    """
    What happens when Var(253) is used as a FUNCTION?
    (Var(253) arg) = ???

    253 as an index refers to some global. In the VM, what IS global 253?
    It's past the normal syscall range (0-252 are regular vars/syscalls)
    """
    print("\n=== TEST: Var(253) as Function ===")

    nil = build_nil()

    # Chain: echo(251) → v253 → (v253 nil) → observe
    print("\n1. (Var(253) nil):")

    # inner at depth 2: λv253.((v253 nil) QD)
    # v253 = V0, nil is closed
    inner = bytes([0x00]) + nil + bytes([FD]) + QD + bytes([FD, FE])
    outer = bytes([0x00]) + inner + bytes([FD]) + nil + bytes([FD, FE])
    payload = bytes([0x0E, 0xFB, FD]) + outer + bytes([FD, FF])

    resp = query_raw(payload, timeout_s=10)
    print(f"   Response: {resp.hex() if resp else 'EMPTY'}")
    if resp:
        print(f"   Text: {resp.decode('latin-1', errors='replace')}")

    # Also try Var(254) and Var(255) as functions
    print("\n2. (Var(254) nil):")
    outer254 = bytes([0x00]) + inner + bytes([FD]) + nil + bytes([FD, FE])
    payload254 = bytes([0x0E, 0xFC, FD]) + outer254 + bytes([FD, FF])
    resp254 = query_raw(payload254, timeout_s=10)
    print(f"   Response: {resp254.hex() if resp254 else 'EMPTY'}")


def test_what_is_var253():
    """
    Investigate: what IS Var(253) when used at runtime?
    Is it a function? A value? An error?
    """
    print("\n=== TEST: Identity of Var(253) ===")

    nil = build_nil()

    # echo(251) gives us Left(Var(253))
    # Var(253) should be some global at index 253
    # In BrownOS, indices 0-252 are regular, 253/254/255 are special wire bytes

    # At RUNTIME, Var(253) is just a variable reference
    # If there's no binder for it, it stays stuck
    # But maybe it refers to something in the global environment?

    # Let's try using it as various things:

    print("\n1. Just return Var(253) wrapped in lambda for safety:")
    # λ_.v253 = λ.V1 where v253 is the outer
    # No wait, we need to capture v253...

    # Chain: echo(251) → λleft.((left (λv253. λ_.v253)) nil)
    # At depth 2: λv253. gives us v253 = V0
    # λ_. adds depth 3: v253 = V1
    # So λ_.v253 = 01 FE at depth 3

    # But then how do we observe it? We can't print Var(253) directly...

    print("\n2. Apply Var(253) to the K combinator:")
    # K = λx.λy.x
    # (K Var(253)) = λy.Var(253) -- captures Var(253)
    # ((K Var(253)) nil) = Var(253)

    # So: echo(251) → v253 → ((K v253) nil) → try to use result

    K = bytes([0x01, FE, FE])  # λλ.V1 = K

    # inner: λv253. ((K v253 nil) something)
    # At depth 2: K applied to v253 (V0) then to nil
    # = K V0 FD nil FD
    # Then what do we do with the result? It's Var(253), can't print it

    # Let's see if we can apply it to syscall8:
    # ((syscall8 ((K v253) nil)) disc)
    # = ((syscall8 v253) disc)
    # This is what we already tested

    print("   (Same as syscall8 tests - Var(253) as value)")

    print("\n3. Use Var(253) as identity - apply it to echo chain result:")
    # echo(251) → v253 → echo(250) → v252 → (v253 v252) → observe
    # If v253 acts as identity, we get v252
    # If v253 acts as some function, we get something else

    # This gets complicated with nested chains...


def test_simple_observations():
    """
    Simple tests to understand the system better
    """
    print("\n=== TEST: Simple Observations ===")

    nil = build_nil()

    print("\n1. What does echo(14) return? (14 = 0x0E = echo syscall)")
    payload1 = bytes([0x0E, 0x0E, FD]) + QD + bytes([FD, FF])
    resp1 = query_raw(payload1)
    print(f"   Response: {resp1.hex() if resp1 else 'EMPTY'}")
    # Expected: Left(Var(16)) = 01 10 FD FE FE FF

    print("\n2. What does echo(8) return? (8 = syscall8)")
    payload2 = bytes([0x0E, 0x08, FD]) + QD + bytes([FD, FF])
    resp2 = query_raw(payload2)
    print(f"   Response: {resp2.hex() if resp2 else 'EMPTY'}")
    # Expected: Left(Var(10)) = 01 0A FD FE FE FF

    print("\n3. Can we call the ECHOED syscall8 reference?")
    # echo(8) → Left(Var(10))
    # Extract Var(10), which should be syscall8 shifted...
    # Wait no, Var(10) inside Left is shifted by the Left wrapper
    # At runtime after unwrapping, what do we get?

    # Actually, echo returns the INPUT shifted by +2
    # So echo(8) → Left(Var(10))
    # When we unwrap Left, we get Var(10)
    # Inside the unwrap lambda (depth 1), Var(10) refers to...
    # Wait, de Bruijn indices are about BINDERS, not globals

    # Let me think again. At top level:
    # Var(8) refers to global at index 8 (syscall8)
    # Inside a lambda, Var(9) refers to global 8 (shifted by 1)
    # Inside two lambdas, Var(10) refers to global 8

    # So echo(8) returns Left(Var(10))
    # When unwrapped, at depth 1, Var(10) is... global 9? No wait...

    # De Bruijn: Var(n) in body at depth d refers to:
    #   if n < d: the (n)th enclosing binder (0 = innermost)
    #   if n >= d: global at index (n - d)

    # At depth 0: Var(8) → global 8
    # At depth 1 (inside lambda): Var(10) → 10-1=9? No...

    # Actually echo adds +2 because the RESULT is wrapped in Left = λλ.(1 payload)
    # The payload is under 2 lambdas, so free vars in payload need +2
    # So if input was Var(8) (referring to global 8 at depth 0),
    # inside Left's body (depth 2), it becomes Var(10) to still refer to global 8

    # When we unwrap Left and extract Var(10), we're at depth 1 in our handler
    # Var(10) at depth 1 refers to global 10-1=9? That seems wrong...

    # I think the key is: the extracted value is Var(10) as a TERM
    # It's not re-interpreted; it's just data
    # If we then use it in application, it acts as Var(10) at whatever depth we're at

    # This is confusing. Let me just try it:

    print("\n4. Chain: echo(8) → extract Var(10) → apply to nil → QD")
    # ((echo 8) λleft.((left (λv10. ((v10 nil) QD))) nil))

    inner = (
        bytes([0x00]) + nil + bytes([FD]) + QD + bytes([FD, FE])
    )  # λv10.((v10 nil) QD)
    outer = bytes([0x00]) + inner + bytes([FD]) + nil + bytes([FD, FE])
    payload = bytes([0x0E, 0x08, FD]) + outer + bytes([FD, FF])

    print(f"   Payload: {payload.hex()}")
    resp = query_raw(payload, timeout_s=10)
    print(f"   Response: {resp.hex() if resp else 'EMPTY'}")
    if resp:
        print(f"   Text: {resp.decode('latin-1', errors='replace')}")


def main():
    print("=" * 60)
    print("PROBE v6: Deep Dive into (A Var(253))")
    print("=" * 60)

    test_a_behavior()
    test_b_with_special()
    test_syscall8_via_b()
    test_apply_253_directly()
    test_what_is_var253()
    test_simple_observations()

    print("\n" + "=" * 60)
    print("PROBE v6 COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
