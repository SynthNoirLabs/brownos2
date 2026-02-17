#!/usr/bin/env python3
"""
Probe v2: Echo chaining with proper observation

Key insight from v1:
- echo(251) produces Left(Var(253)) but QD can't serialize Var(253)!
- We get "Encoding failed!" when trying to print these values
- The EMPTY responses might mean the computation succeeds but we can't see it

Strategy:
1. Feed echo-manufactured Var(253/254/255) to syscall8
2. DON'T try to print the raw result
3. Instead, check if the Either is Left or Right by applying projections
4. If it's Left (success!), try to extract/observe the payload

The trick: We can TEST whether something is Left or Right without serializing it!
Left x = λl.λr.(l x)  → (Left proj_left proj_right) = (proj_left x)
Right y = λl.λr.(r y) → (Right proj_left proj_right) = (proj_right y)

If we use proj_left = λx."SUCCESS" and proj_right = λy."FAILURE",
we can distinguish without serializing x or y directly!
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


@dataclass(frozen=True)
class Var:
    i: int


@dataclass(frozen=True)
class Lam:
    body: object


@dataclass(frozen=True)
class App:
    f: object
    x: object


def query_raw(payload: bytes, timeout_s: float = 5.0) -> bytes:
    """Query and return raw response"""
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


def encode_string_term(s: str) -> bytes:
    """Encode a string as a Scott list of byte-terms"""
    # nil = λc.λn.n = 00 FE FE
    # cons h t = λc.λn.(c h t) = ... complex

    # For simplicity, let's encode each char as 9-lambda byte term
    # This gets big fast, so use short strings

    result = bytes([0x00, FE, FE])  # nil

    for ch in reversed(s):
        byte_val = ord(ch)
        # Encode byte as 9-lambda term
        byte_term = encode_byte_as_term(byte_val)
        # cons = λc.λn.(c head tail)
        # = λ.λ.((1 head) tail)
        # Under 2 lambdas, head is shifted, tail is current result
        # Actually this is getting complex, let me use a simpler approach

    # Actually, for testing, let's just use fixed marker terms
    return result


def encode_byte_as_term(n: int) -> bytes:
    """Encode a byte value as 9-lambda additive term"""
    # Start with base (Var 0)
    # Add weights by applying Var(1) for +1, Var(2) for +2, etc.

    parts = []
    parts.append(0x00)  # base V0

    weights = [(1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)]
    for idx, weight in weights:
        if n & weight:
            # Prepend: current becomes App(Var(idx), current)
            parts = [idx] + parts + [FD]

    # Wrap in 9 lambdas
    parts = parts + [FE] * 9
    return bytes(parts)


def test_either_discrimination():
    """
    Test if we can tell Left from Right without serializing the payload.

    Approach:
    1. Apply Either to two different continuations
    2. One writes "L" for Left, one writes "R" for Right
    3. Observe which one fires

    Left x = λl.λr.(l x) → (Left write_L write_R) = write_L(x)
    Right y = λl.λr.(r y) → (Right write_L write_R) = write_R(y)

    If write_L = λ_.write("L") and write_R = λ_.write("R"), we can tell!
    """
    print("\n=== TEST: Either Discrimination ===")

    # Build write_marker that writes a single byte and ignores its argument
    # write_marker(byte) = λ_. ((write [byte]) nil)
    # = λ. ((Var(3) [byte_list]) nil)  -- write is syscall 2, +1 for lambda = Var(3)

    # Actually simpler: use write directly to output a marker
    # We need: λx. ((write marker_bytes) continuation)
    #
    # marker_bytes = Scott list containing single byte
    # single_byte_list = cons(byte_term, nil)

    # This is getting complex. Let's try a simpler approach:
    # Just observe the RAW output length or pattern differences

    # First, verify discrimination works with a known Either
    # Call error syscall with code 0 → returns Left("Unexpected exception")
    # Apply it to projections

    print("\n1. Testing known Left (error string for code 0)")

    # ((error 0) either_test) where either_test = λe. ((e proj_L) proj_R)
    # proj_L = λpayload. write "L"
    # proj_R = λpayload. write "R"

    # Simpler: just use write directly
    # ((error 0) λresult. ((result (λ_.((write L_list) nil)) (λ_.((write R_list) nil)))))

    # For now, let's just test the raw approach:
    # Can we get syscall8's result and test if it's Left?

    # Method: Chain echo → syscall8 → discrimination
    # ((echo 251) λleft. ((left (λx. ((syscall8 x) discriminator))) nil))
    # discriminator = λresult. ((result on_left) on_right)
    # on_left = λ_. write("L")
    # on_right = λ_. write("R")

    # Let me build this step by step...

    # Actually, let me first test if basic discrimination works
    # with a syscall that returns a known Either

    # Test: ((syscall8 nil) discriminator)
    # We know this returns Right(6)
    # discriminator should fire on_right

    # on_right = λerr. ((write R_marker) nil)
    # R_marker = single byte 0x52 ('R') as Scott list

    # This requires building byte lists which is tedious
    # Let me try an even simpler approach:

    # Use the error code directly: Right contains error code as integer
    # If we can extract and print JUST the error code, that's observable

    # ((syscall8 nil) λresult. ((result (λx.((write [76]) done)) (λcode.((code handler) done)))))
    # where handler tries to write the code value somehow

    # Actually, the cleanest test: use the result's error code to index into error strings
    # ((syscall8 nil) λresult. ((result left_handler) (λcode. ((error code) print_string))))
    # This should print "Permission denied" if Right(6)

    print("\n2. Testing syscall8 with error-string follow-up")

    # Chain: ((syscall8 nil) λres. ((res on_left) on_right))
    # on_left = λpayload. ((write [0x4C]) done)  -- write 'L'
    # on_right = λcode. ((error code) QD)  -- print the error string

    # Under outer λ: syscall8=V9, write=V3, error=V2
    # on_left under 2 λs: write=V4
    # on_right under 2 λs: error=V3

    # on_left = λ. ((V4 L_list) nil)
    # L_list = cons(byte_76, nil) -- 'L' = 76 = 0x4C
    # This is getting tedious to construct...

    # Let me try a simpler marker approach
    # on_left = λ. V99  -- just return some identifiable term
    # on_right = λcode. ((V3 code) QD_shifted)  -- call error(code) then QD

    # Actually simplest:
    # on_left = λ.((V3 zero) QD)  -- call error(0) to print "Unexpected exception"
    # on_right = λcode.((V3 code) QD)  -- call error(code) to print actual error

    # If result is Left, we see "Unexpected exception"
    # If result is Right(6), we see "Permission denied"

    # Let's build this:
    # Full term: ((syscall8 nil) λres.((res on_left) on_right))

    # on_left = λ_.((error 0) QD)
    # Under 2 lambdas (outer + on_left): error = V1+2 = V3
    # zero = 9-lambda term for 0
    # QD needs +2 shift

    # on_right = λcode.((error code) QD)
    # Under 2 lambdas: error = V3, code = V0
    # QD needs +2 shift

    # These are the same! on_left just ignores its arg and uses 0
    # on_right uses its arg as the code

    # zero term = 9 lambdas around V0 = 00 FE FE FE FE FE FE FE FE FE
    zero_term = bytes([0x00] + [FE] * 9)

    # on_left = λ.((V3 zero_term) QD_shifted)
    # = λ.((03 [zero_term] FD) [QD_shifted] FD)
    # bytecode: 03 [zero_term] FD [QD_shifted] FD FE

    # For QD shifted by 2... let me think about this more carefully
    # QD uses globals: we identified 2 (write), 4 (quote), possibly 5
    # Under 2 extra lambdas, all free var refs need +2

    # QD bytecode: 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
    # Free var refs at top level of QD (depth 0 in QD): 05 at pos 0,4 → should become 07
    # Refs inside QD's first lambda (depth 1): none that are free
    # Refs inside QD's deeper lambdas: 03, 02 → need to trace depth

    # Actually, let me just test with QD unshifted and see what happens
    # If it fails, I'll adjust

    # on_left_naive = λ.((V3 zero) QD)
    on_left_naive = bytes([0x03]) + zero_term + bytes([FD]) + QD + bytes([FD, FE])

    # on_right_naive = λ.((V3 V0) QD) -- use incoming arg as error code
    on_right_naive = bytes([0x03, 0x00, FD]) + QD + bytes([FD, FE])

    # discriminator = λres.((V0 on_left) on_right)
    # = λ.((00 [on_left]) [on_right])
    # but wait, on_left and on_right are terms that need to be inserted...
    # and they have their own lambdas...

    # Let me trace the structure more carefully:
    # discriminator = λres. ((res on_left) on_right)
    #   res is V0 in this lambda's scope
    #   on_left is a closed term (has its own lambda)
    #   on_right is a closed term
    #
    # bytecode: [on_left] [on_right] V0 FD FD FE
    # Wait no, in postfix:
    #   push V0
    #   push on_left  (on_left_naive)
    #   FD → App(V0, on_left)
    #   push on_right
    #   FD → App(App(V0,on_left), on_right)
    #   FE → Lam(App(App(V0,on_left), on_right))

    # So: 00 [on_left] FD [on_right] FD FE
    discriminator = (
        bytes([0x00]) + on_left_naive + bytes([FD]) + on_right_naive + bytes([FD, FE])
    )

    # nil for syscall8 argument
    nil = bytes([0x00, FE, FE])

    # full: ((syscall8 nil) discriminator)
    # = 08 [nil] FD [discriminator] FD FF
    payload = bytes([0x08]) + nil + bytes([FD]) + discriminator + bytes([FD, FF])

    print(f"  Payload length: {len(payload)} bytes")
    print(f"  Payload: {payload.hex()}")

    resp = query_raw(payload, timeout_s=10)
    print(f"  Response: {resp.hex() if resp else 'EMPTY'} ({len(resp)} bytes)")
    if resp and b"Encoding" not in resp:
        print(f"  As text: {resp.decode('latin-1', errors='replace')}")


def test_direct_echo_chain_to_syscall8():
    """
    Build the full chain: echo(251) → extract Var(253) → syscall8(Var(253)) → observe
    """
    print("\n=== TEST: Full Echo Chain to Syscall8 ===")

    # We want:
    # ((echo 251) λleft. ((left (λx. ((syscall8 x) discriminator))) dummy))
    #
    # where discriminator tests Left vs Right and outputs appropriately

    # This is complex because:
    # 1. echo(251) produces Left(Var(253))
    # 2. Left(Var(253)) = λl.λr.(l Var(253))
    # 3. When we apply (left handler dummy), we get (handler Var(253))
    # 4. handler should be λx.((syscall8 x) k)
    # 5. So we get ((syscall8 Var(253)) k)

    # The key: Var(253) exists INSIDE the evaluation, never needs serialization!
    # We just need k to discriminate Left vs Right

    # Let me build this step by step with explicit de Bruijn tracking

    # Depth 0 (top level): syscall8=V8, echo=V14 (0x0E), write=V2, error=V1

    # outer_cont = λleft. ((left handler) dummy)
    # Depth 1: left=V0, syscall8=V9, echo=V15, etc.

    # handler = λx. ((syscall8 x) disc)
    # Depth 2: x=V0, syscall8=V10

    # disc = λres. ((res on_left) on_right)
    # Depth 3: res=V0

    # on_left = λ_. ((error 0) QD)  -- prints "Unexpected exception"
    # Depth 4: error=V13? (1+4=5... no wait, error is global 1)
    # Under 4 lambdas: error = V1+4 = V5

    # on_right = λcode. ((error code) QD)  -- prints actual error
    # Depth 4: code=V0, error=V5

    # Let's build the bytecode bottom-up:

    # zero term (9 lambdas around V0)
    zero = bytes([0x00] + [FE] * 9)

    # === on_left (depth 4) ===
    # λ_.((V5 zero) QD_shifted_by_4)
    # For now, use unshifted QD and see what happens
    on_left = bytes([0x05]) + zero + bytes([FD]) + QD + bytes([FD, FE])

    # === on_right (depth 4) ===
    # λcode.((V5 V0) QD_shifted)
    on_right = bytes([0x05, 0x00, FD]) + QD + bytes([FD, FE])

    # === disc (depth 3) ===
    # λres.((V0 on_left) on_right)
    # postfix: V0 on_left FD on_right FD FE
    disc = bytes([0x00]) + on_left + bytes([FD]) + on_right + bytes([FD, FE])

    # === handler (depth 2) ===
    # λx.((V10 V0) disc)
    # V10 = 0x0A
    # postfix: 0A 00 FD disc FD FE
    handler = bytes([0x0A, 0x00, FD]) + disc + bytes([FD, FE])

    # === outer_cont (depth 1) ===
    # λleft.((V0 handler) dummy)
    # dummy = nil = 00 FE FE
    # postfix: 00 handler FD dummy FD FE
    nil = bytes([0x00, FE, FE])
    outer_cont = bytes([0x00]) + handler + bytes([FD]) + nil + bytes([FD, FE])

    # === full payload (depth 0) ===
    # ((echo V251) outer_cont)
    # postfix: 0E FB FD outer_cont FD FF
    payload = bytes([0x0E, 0xFB, FD]) + outer_cont + bytes([FD, FF])

    print(f"  Payload length: {len(payload)} bytes")
    print(f"  Payload hex: {payload.hex()}")

    resp = query_raw(payload, timeout_s=15)
    print(f"  Response length: {len(resp)} bytes")
    print(f"  Response hex: {resp.hex() if resp else 'EMPTY'}")
    if resp:
        if b"Encoding" in resp:
            print("  ERROR: Encoding failed (expected if chain didn't work)")
        else:
            print(f"  As text: {resp.decode('latin-1', errors='replace')}")


def test_echo_chain_for_255():
    """
    Try to reach Var(255) via double echo:
    echo(251) → Left(253) → unwrap → echo(253) → Left(255)
    """
    print("\n=== TEST: Double Echo to Reach Var(255) ===")

    # Chain:
    # ((echo 251) λleft1.
    #   ((left1 (λx.
    #     ((echo x) λleft2.
    #       ((left2 (λy. ((syscall8 y) disc))) dummy2)
    #     )
    #   )) dummy1)
    # )

    # This is getting VERY deep. Let me trace the depths:
    # Depth 0: top level
    # Depth 1: λleft1
    # Depth 2: λx (handler1)
    # Depth 3: λleft2 (continuation to second echo)
    # Depth 4: λy (handler2)
    # Depth 5: disc
    # Depth 6: on_left, on_right

    # At depth 4, syscall8 = V8+4 = V12 = 0x0C
    # At depth 6, error = V1+6 = V7 = 0x07

    # This is too complex to build manually. Let me try a simpler structure:
    # Use recursion/fixed point? Or just flatten the continuation...

    # Actually, here's a key insight:
    # We don't NEED to chain echo twice to test!
    # echo(251) already gives us Var(253) inside the evaluation
    # Let's first confirm syscall8(Var(253)) gives a DIFFERENT result

    # If syscall8(Var(253)) returns InvalidArg (code 2) instead of PermDenied (code 6),
    # our discriminator test would show "Invalid argument" text!

    print("  (Skipping complex double-chain for now)")
    print("  Let's first verify single chain discrimination works")


def test_simpler_discrimination():
    """
    Simpler test: just check if syscall8's result is Left or Right
    by applying it to marker lambdas that write different bytes
    """
    print("\n=== TEST: Simple Discrimination via Write ===")

    # The simplest observable difference:
    # ((syscall8 nil) λres. ((res λ_.write_L) λ_.write_R))
    #
    # write_L writes byte 0x4C ('L')
    # write_R writes byte 0x52 ('R')

    # To write a single byte: ((write [byte_list]) continuation)
    # byte_list = cons(byte_term, nil)
    # cons h t = λc.λn.(c h t) = complex encoding

    # Actually simpler: write a single-element list
    # [76] as Scott list = cons(encode(76), nil)
    # = λc.λn.(c encode(76) nil)
    # = λλ.((1 [76_term]) [nil])

    # 76 decimal = 0x4C = 01001100 binary
    # bits: 64+8+4 = 76
    # 76_term body = (V7 (V4 (V3 V0))) -- under 9 lambdas
    # bytecode: 07 04 03 00 FD FD FD + FE*9
    byte_76_body = bytes([0x07, 0x04, 0x03, 0x00, FD, FD, FD])
    byte_76_term = byte_76_body + bytes([FE] * 9)

    # 82 decimal = 0x52 = 01010010 binary
    # bits: 64+16+2 = 82
    # 82_term body = (V7 (V5 (V2 V0)))
    byte_82_body = bytes([0x07, 0x05, 0x02, 0x00, FD, FD, FD])
    byte_82_term = byte_82_body + bytes([FE] * 9)

    # nil = λλ.0 = 00 FE FE
    nil = bytes([0x00, FE, FE])

    # cons(h, t) = λc.λn.((c h) t)
    # = λλ.((1 h) t)
    # bytecode: 01 [h] FD [t] FD FE FE
    # But h and t need to be "shifted" when placed inside the lambdas?
    # Actually no - we're BUILDING the term, so we encode h and t at current depth

    # list_L = cons(byte_76_term, nil)
    # Under 2 lambdas (cons's), byte_76_term's free vars would need shifting,
    # but byte_76_term is CLOSED (9 lambdas binding everything)
    # So: λλ.((V1 byte_76) nil)
    # bytecode: 01 [byte_76_term] FD [nil] FD FE FE
    list_L = bytes([0x01]) + byte_76_term + bytes([FD]) + nil + bytes([FD, FE, FE])

    # list_R = cons(byte_82_term, nil)
    list_R = bytes([0x01]) + byte_82_term + bytes([FD]) + nil + bytes([FD, FE, FE])

    print(f"  list_L length: {len(list_L)}")
    print(f"  list_R length: {len(list_R)}")

    # write_L = λ_.((write list_L) nil)
    # Under 1 lambda: write=V3, but list_L is closed
    # = λ.((V3 list_L) nil)
    # bytecode: 03 list_L FD nil FD FE

    # Wait, under the discriminator structure:
    # ((syscall8 nil) λres.((res write_L) write_R))
    # res = V0
    # write_L and write_R are under 1 lambda
    # write_L = λ_.((V3 list_L) nil) -- write is at +2 from outer, so V2+1=V3?
    # No wait: at depth 1, write (global 2) = V3

    # write_L = λ.((V4 list_L) nil) -- under 2 lambdas (outer + this), write=V2+2=V4
    write_L = bytes([0x04]) + list_L + bytes([FD]) + nil + bytes([FD, FE])
    write_R = bytes([0x04]) + list_R + bytes([FD]) + nil + bytes([FD, FE])

    # discriminator = λres.((V0 write_L) write_R)
    # bytecode: 00 write_L FD write_R FD FE
    discriminator = bytes([0x00]) + write_L + bytes([FD]) + write_R + bytes([FD, FE])

    # full = ((syscall8 nil) discriminator)
    # bytecode: 08 nil FD discriminator FD FF
    payload = bytes([0x08]) + nil + bytes([FD]) + discriminator + bytes([FD, FF])

    print(f"  Total payload length: {len(payload)}")
    print(f"  Payload: {payload.hex()}")

    resp = query_raw(payload, timeout_s=10)
    print(f"  Response length: {len(resp)}")
    print(f"  Response hex: {resp.hex() if resp else 'EMPTY'}")
    if resp:
        print(f"  Response text: {resp.decode('latin-1', errors='replace')}")
        if resp == bytes([0x4C, FF]) or b"L" in resp:
            print("  RESULT: LEFT (SUCCESS?!)")
        elif resp == bytes([0x52, FF]) or b"R" in resp:
            print("  RESULT: RIGHT (error as expected)")


def test_echo_to_syscall8_with_discrimination():
    """
    The big test: feed Var(253) to syscall8 and observe via discrimination
    """
    print("\n=== TEST: Echo(251) → Syscall8(Var(253)) with Discrimination ===")

    # Structure:
    # ((echo 251) λleft. ((left handler) nil))
    # handler = λx. ((syscall8 x) discriminator)
    # discriminator = λres.((res write_L) write_R)

    # Depths:
    # 0: top
    # 1: λleft
    # 2: λx (handler)
    # 3: λres (discriminator)
    # 4: λ_ (write_L/write_R)

    nil = bytes([0x00, FE, FE])

    # Build byte terms
    # 76 = 'L' = 64+8+4
    byte_76_body = bytes([0x07, 0x04, 0x03, 0x00, FD, FD, FD])
    byte_76_term = byte_76_body + bytes([FE] * 9)
    # 82 = 'R' = 64+16+2
    byte_82_body = bytes([0x07, 0x05, 0x02, 0x00, FD, FD, FD])
    byte_82_term = byte_82_body + bytes([FE] * 9)

    # Build lists
    list_L = bytes([0x01]) + byte_76_term + bytes([FD]) + nil + bytes([FD, FE, FE])
    list_R = bytes([0x01]) + byte_82_term + bytes([FD]) + nil + bytes([FD, FE, FE])

    # write_L at depth 4: write (global 2) = V2+4 = V6 = 0x06
    write_L = bytes([0x06]) + list_L + bytes([FD]) + nil + bytes([FD, FE])
    write_R = bytes([0x06]) + list_R + bytes([FD]) + nil + bytes([FD, FE])

    # discriminator at depth 3: λres.((V0 write_L) write_R)
    discriminator = bytes([0x00]) + write_L + bytes([FD]) + write_R + bytes([FD, FE])

    # handler at depth 2: λx.((syscall8 x) discriminator)
    # syscall8 (global 8) at depth 2 = V8+2 = V10 = 0x0A
    handler = bytes([0x0A, 0x00, FD]) + discriminator + bytes([FD, FE])

    # outer_cont at depth 1: λleft.((V0 handler) nil)
    outer_cont = bytes([0x00]) + handler + bytes([FD]) + nil + bytes([FD, FE])

    # full: ((echo 251) outer_cont)
    # echo = 0x0E, 251 = 0xFB
    payload = bytes([0x0E, 0xFB, FD]) + outer_cont + bytes([FD, FF])

    print(f"  Payload length: {len(payload)}")
    print(f"  Payload: {payload.hex()}")

    resp = query_raw(payload, timeout_s=15)
    print(f"  Response length: {len(resp)}")
    print(f"  Response hex: {resp.hex() if resp else 'EMPTY'}")
    if resp:
        print(f"  Response text: {resp.decode('latin-1', errors='replace')}")
        if b"L" in resp:
            print("  *** RESULT: LEFT (SUCCESS?!) ***")
        elif b"R" in resp:
            print("  RESULT: RIGHT (still error)")


def test_syscall8_with_252():
    """Same but with Var(254)"""
    print("\n=== TEST: Echo(252) → Syscall8(Var(254)) with Discrimination ===")

    nil = bytes([0x00, FE, FE])

    byte_76_body = bytes([0x07, 0x04, 0x03, 0x00, FD, FD, FD])
    byte_76_term = byte_76_body + bytes([FE] * 9)
    byte_82_body = bytes([0x07, 0x05, 0x02, 0x00, FD, FD, FD])
    byte_82_term = byte_82_body + bytes([FE] * 9)

    list_L = bytes([0x01]) + byte_76_term + bytes([FD]) + nil + bytes([FD, FE, FE])
    list_R = bytes([0x01]) + byte_82_term + bytes([FD]) + nil + bytes([FD, FE, FE])

    write_L = bytes([0x06]) + list_L + bytes([FD]) + nil + bytes([FD, FE])
    write_R = bytes([0x06]) + list_R + bytes([FD]) + nil + bytes([FD, FE])

    discriminator = bytes([0x00]) + write_L + bytes([FD]) + write_R + bytes([FD, FE])
    handler = bytes([0x0A, 0x00, FD]) + discriminator + bytes([FD, FE])
    outer_cont = bytes([0x00]) + handler + bytes([FD]) + nil + bytes([FD, FE])

    # Use 252 instead of 251
    payload = bytes([0x0E, 0xFC, FD]) + outer_cont + bytes([FD, FF])

    print(f"  Payload length: {len(payload)}")

    resp = query_raw(payload, timeout_s=15)
    print(f"  Response length: {len(resp)}")
    print(f"  Response hex: {resp.hex() if resp else 'EMPTY'}")
    if resp:
        print(f"  Response text: {resp.decode('latin-1', errors='replace')}")


def main():
    print("=" * 60)
    print("PROBE v2: Echo Chain with Discrimination")
    print("=" * 60)

    # First, verify our discrimination approach works
    test_either_discrimination()

    # Test simpler discrimination
    test_simpler_discrimination()

    # The real tests: echo chain to syscall8
    test_direct_echo_chain_to_syscall8()
    test_echo_to_syscall8_with_discrimination()
    test_syscall8_with_252()

    # Try reaching Var(255)
    test_echo_chain_for_255()

    print("\n" + "=" * 60)
    print("PROBE v2 COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
