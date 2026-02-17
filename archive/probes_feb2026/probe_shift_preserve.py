#!/usr/bin/env python3
"""
CRITICAL PROBE: Preserve echo's +2 shift instead of unwrapping Left.

Key insight from Oracle:
- Echo wraps output in Left = λl.λr.(l payload)
- Inside Left, free vars are shifted +2
- When we EXTRACT via beta-reduction, +2 cancels
- If we DON'T extract, internal Var(253+) survive!
- These Var(253+) might be the key to unlocking syscall 8

Strategy: Use write-based probes (NOT QD/quote which choke on Var(253+))
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


def query_raw(payload: bytes, timeout_s: float = 10.0) -> bytes:
    delay = 0.2
    for attempt in range(3):
        try:
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
        except Exception:
            time.sleep(delay)
            delay *= 2
    return b""


def classify(out: bytes) -> str:
    if not out:
        return "SILENT"
    if out.startswith(b"Invalid term!"):
        return "INVALID"
    if out.startswith(b"Encoding failed!"):
        return "ENCFAIL"
    if out.startswith(b"Term too big!"):
        return "TOOBIG"
    # Check for ASCII text (potential answer!)
    try:
        text = out.decode("ascii")
        if text.isprintable() or text.replace("\n", "").replace("\r", "").isprintable():
            return f"TEXT:{text!r}"
    except:
        pass
    return f"HEX:{out[:30].hex()}"


def run(name: str, payload: bytes) -> str:
    out = query_raw(payload)
    cls = classify(out)
    print(f"  {name:55s} -> {cls}")
    if (
        "TEXT:" in cls
        and cls != "TEXT:'R'"
        and cls != "TEXT:'E'"
        and cls != "TEXT:'Z'"
        and cls != "TEXT:'B'"
    ):
        print(f"    *** INTERESTING OUTPUT: {cls} ***")
    return cls


# ============================================================
# Helper: build a write-based success probe (not QD)
# write(bytes) writes to socket. We write "OK" on success.
# ============================================================
# encode "OK" as byte list: cons(79, cons(75, nil))
# byte_term(79) = O, byte_term(75) = K
# Using compact encoding for single chars


def byte_term_compact(n: int) -> bytes:
    """Encode byte term for value n (9 lambdas + additive bitset)"""
    parts = [0x00]  # Var(0) base
    weights = [(1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)]
    for idx, weight in weights:
        if n & weight:
            parts = [idx] + parts + [FD]
    return bytes(parts + [FE] * 9)


def build_nil() -> bytes:
    return bytes([0x00, FE, FE])


def build_single_byte_list(ch: int) -> bytes:
    """Scott list with single byte: cons(ch, nil) = λc.λn.(c byte_ch nil)"""
    bt = byte_term_compact(ch)
    nil = build_nil()
    return bytes([0x01]) + bt + bytes([FD]) + nil + bytes([FD, FE, FE])


def build_byte_list(chars: list[int]) -> bytes:
    """Scott list of bytes"""
    nil = build_nil()
    result = nil
    for ch in reversed(chars):
        bt = byte_term_compact(ch)
        result = bytes([0x01]) + bt + bytes([FD]) + result + bytes([FD, FE, FE])
    return result


# "L" marker list (single char 76='L')
MARKER_L = build_byte_list([76])
# "R" marker list
MARKER_R = build_byte_list([82])
# "OK" marker list
MARKER_OK = build_byte_list([79, 75])
# "!" marker list
MARKER_BANG = build_byte_list([33])


def write_marker(marker_bytes: bytes) -> bytes:
    """Build: ((write marker) nil) where write=syscall 2 at current depth"""
    # This needs to be at the right depth. For top-level: write=Var(2)
    # We'll use a generic version that takes the depth offset
    nil = build_nil()
    return bytes([0x02]) + marker_bytes + bytes([FD]) + nil + bytes([FD])


def main():
    print("=" * 70)
    print("SHIFT-PRESERVE PROBE: Keep echo's +2 shift alive")
    print("=" * 70)

    nil = build_nil()

    # ============================================================
    # APPROACH A: Pass the ENTIRE echo Left term to sys8
    # echo(x) returns Left(x_shifted) = λl.λr.(l x_shifted)
    # Don't unwrap! Pass the WHOLE thing to sys8.
    # ((sys8 echo(nil)) write_probe)
    # But we can't call echo first and then pass... we need CPS.
    #
    # The trick: echo returns Left(y). Instead of applying Left to handlers,
    # pass Left ITSELF as the argument to sys8.
    #
    # Program: ((echo nil) (λleft_result. ((sys8 left_result) write_disc)))
    # Here left_result IS the Left wrapper = λl.λr.(l y_shifted)
    # We pass it directly to sys8 as argument!
    # ============================================================
    print("\n[A] Echo result (Left wrapper) directly as sys8 argument")

    # write_disc at depth 2 (under echo handler + left_result handler):
    # sys8 = Var(8+2) = Var(10), write = Var(2+2) = Var(4)
    # disc = λres.(res (λ_.((write "L") nil)) (λ_.((write "R") nil)))
    # At depth 3 (under disc lambda): write = Var(5)
    # At depth 4 (under left/right handler): write = Var(6)

    # Let me use the simplest possible approach:
    # echo(seed) returns either. We take EITHER (not unwrapped) and feed to sys8.
    # ((echo seed) (λeither. ((sys8 either) QD)))
    # depth 0: echo=Var(14)
    # depth 1 (λeither): sys8=Var(9), either=Var(0)
    # QD at depth 1 needs shifting... let's use raw QD_shifted

    # Actually, let me just try it with QD first and see what happens
    # If QD chokes on Var(253+), we'll get "Encoding failed!" which is INFORMATIVE

    for seed_idx in [0, 251, 252]:
        # ((echo Var(seed)) (λeither. ((sys8 either) QD_shifted)))
        # At depth 0: echo = Var(14), seed = Var(seed_idx)
        # Under λeither (depth 1): sys8 = Var(9), either = Var(0)
        # QD needs to reference globals, at depth 1 they shift by 1
        # QD originally: quote=Var(4) -> Var(5), write=Var(2) -> Var(3), name=Var(5) -> Var(6)
        # But QD is complex... let me just embed it as opaque

        # Simple version: just pass either to sys8 with identity continuation
        # ((echo seed) (λe. ((sys8 e) (λr. r))))
        # λe.((sys8 e) id) at depth 1: sys8=Var(9), e=Var(0), id=Lam(Var(0))
        inner = bytes([0x09, 0x00, FD]) + bytes([0x00, FE]) + bytes([FD, FE])
        # = λe. ((Var(9) Var(0)) (λ.Var(0)))
        # This won't produce output... let me use write-based disc

        # λe. ((sys8 e) disc) where disc = λres.(res (λ_.write_L) (λ_.write_R))
        # At depth 1: sys8=Var(9), write=Var(3)
        # At depth 2 (disc lambda): write=Var(4)
        # At depth 3 (left/right handlers): write=Var(5)
        write_L_d5 = bytes([0x05]) + MARKER_L + bytes([FD]) + nil + bytes([FD])
        write_R_d5 = bytes([0x05]) + MARKER_R + bytes([FD]) + nil + bytes([FD])
        disc = (
            bytes([0x00])
            + write_L_d5
            + bytes([FE])
            + bytes([FD])
            + write_R_d5
            + bytes([FE])
            + bytes([FD, FE])
        )
        # disc = λres.((res (λ_. write_L)) (λ_. write_R))

        inner_body = bytes([0x09, 0x00, FD]) + disc + bytes([FD, FE])
        # = λe. ((Var(9) Var(0)) disc)

        payload = (
            bytes([0x0E])
            + bytes([seed_idx])
            + bytes([FD])
            + inner_body
            + bytes([FD, FF])
        )
        run(f"echo({seed_idx})->(λe.((sys8 e) disc))  [Left NOT unwrapped]", payload)
        time.sleep(0.1)

    # ============================================================
    # APPROACH B: Apply echo's Left to sys8 directly
    # Left = λl.λr.(l payload)
    # (Left sys8) = λr.(sys8 payload_shifted)
    # = λr.(sys8 Var(253+shifted))
    # This creates a CLOSURE containing sys8 applied to the shifted var!
    # Then apply this to a write probe: ((Left sys8) write_disc)
    # ============================================================
    print("\n[B] Apply echo Left to sys8: (Left sys8) = λr.(sys8 payload_shifted)")

    for seed_idx in [0, 251, 252]:
        # ((echo seed) (λleft. ((left sys8_shifted) disc)))
        # depth 0: echo=14
        # depth 1 (λleft): left=Var(0), sys8=Var(9)
        # (left sys8) = Var(0) applied to Var(9)
        # This reduces: Left = λl.λr.(l x), so (Left Var(9)) = λr.(Var(9) x_shifted)
        # = λr.(Var(9+1) x_shifted) wait, no. After beta-reduction:
        # Left = λl.λr.(l x) applied to Var(9): substitute l=Var(9)
        # Result: λr.(Var(9) x_shifted) -- but Var(9) in the body refers to...
        # Actually under the remaining λr, Var(9) at depth 1 refers to global 8 (9-1=8? no)
        # De Bruijn: at depth 1 (λleft), Var(9) refers to global index 9-1=8 = sys8

        # Then we apply this to disc:
        # ((λr.(sys8 x_shifted)) disc) = (sys8 x_shifted)[with disc stuff]
        # = the disc applied to... wait, this is getting confused.

        # Let me try the SIMPLEST version:
        # ((echo seed) (λleft. ((left Var(9)) Var(9))))
        # = ((echo seed) (λleft. ((left sys8) sys8)))
        # (Left sys8) = λr.(sys8 payload)
        # ((λr.(sys8 payload)) sys8) = (sys8 payload) -- sys8 applied to the shifted payload!
        # Then we need a continuation for sys8...

        # Better: ((echo seed) (λleft. (left (λpayload. ((sys8 payload) disc)) ignore_right)))
        # Wait, this IS the normal unwrap which cancels the shift!

        # The key insight: DON'T apply Left to TWO handlers.
        # Apply Left to ONE handler, getting back a function.
        # Then use THAT function somehow.

        # (Left handler) = λr.(handler payload_with_shift)
        # If handler = sys8, then (Left sys8) = λr.(sys8 payload_with_253)
        # This is a FUNCTION. Apply it to anything: ((Left sys8) anything) = (sys8 payload_with_253)
        # But sys8 is CPS: (sys8 arg) needs a continuation.
        # So (sys8 payload_with_253) is PARTIALLY applied. It needs one more arg.
        # ((sys8 payload_with_253) disc) = sys8 invoked with the shifted payload!

        # So: ((echo seed) (λleft. (((left sys8_ref) disc_or_dummy) maybe_more)))
        # At depth 1 (λleft): sys8 = Var(9), left = Var(0)
        # (Var(0) Var(9)) FD = (left sys8) -- this gives λr.(sys8 payload_253)
        # Then apply disc to it: ((left sys8) disc) = (sys8 payload_253) applied to disc
        # Wait: ((left sys8) disc) = ((λr.(sys8 payload)) disc) = (sys8 payload)
        # And sys8 needs a continuation, so (sys8 payload) still needs one more application!
        # (sys8 payload disc) = ((sys8 payload) disc) -- YES this is the CPS call!

        # But wait, (left sys8) = λr.(sys8 payload). Applying disc: ((λr.(sys8 payload)) disc)
        # = (sys8[r:=disc] payload[r:=disc])? No! Beta reduction substitutes r=Var(0):
        # In λr.(sys8 payload), sys8 and payload don't contain Var(0) (they're shifted).
        # So ((λr.(sys8 payload)) disc) = (sys8 payload) -- disc is just DISCARDED.
        # We lost our continuation!

        # We need: (((left sys8) dummy) disc) where the second app provides the continuation.
        # ((λr.(sys8 payload)) dummy) = (sys8 payload)
        # ((sys8 payload) disc) = CPS call with payload_253 and disc continuation!
        # YES! Three applications: (((left sys8) dummy) disc)

        # At depth 1: left=V0, sys8=V9
        # disc at depth 2 (after dummy lambda): write=V4
        # At depth 3 (disc): write=V5
        # At depth 4 (handlers): write=V6

        # Actually, disc here is at depth 1 (no extra lambda), so write=V3
        # Let me be more careful. The full term:
        # ((echo seed) (λleft. (((left V9) V0_dummy) disc)))
        # Hmm, V0 at depth 1 IS left, not dummy. I need a different dummy.

        # Let me use nil as dummy:
        # ((echo seed) (λleft. (((Var(0) Var(9)) nil_shifted) disc_shifted)))
        # At depth 1: Var(0)=left, Var(9)=sys8
        # nil at depth 1: nil is closed, no shift needed
        # disc at depth 1: needs globals shifted by 1

        # Disc at depth 1: λres.(res (λ_.write_L) (λ_.write_R))
        # At depth 2 (λres): write=Var(4) [was Var(2) at depth 0, +2 for outer lambdas]
        # Hmm wait, at depth 1 we have one λleft. Then disc adds λres = depth 2.
        # Then handlers add depth 3. write at depth 3 = Var(2+3) = Var(5).

        disc_d1 = bytes([0x00])  # res = Var(0) at its own depth
        # λres.(res (λ_.((V5 L) nil)) (λ_.((V5 R) nil)))
        write_L_at_d3 = bytes([0x05]) + MARKER_L + bytes([FD]) + nil + bytes([FD])
        write_R_at_d3 = bytes([0x05]) + MARKER_R + bytes([FD]) + nil + bytes([FD])
        disc_body = (
            bytes([0x00])
            + write_L_at_d3
            + bytes([FE])
            + bytes([FD])
            + write_R_at_d3
            + bytes([FE])
            + bytes([FD])
        )
        disc_at_d1 = disc_body + bytes([FE])

        # Inner: λleft. (((left Var(9)) nil) disc)
        # = λ. (((V0 V9) nil) disc_at_d1)
        # Bytecode: V0 V9 FD nil FD disc_at_d1 FD FE
        inner = (
            bytes([0x00, 0x09, FD]) + nil + bytes([FD]) + disc_at_d1 + bytes([FD, FE])
        )

        payload = (
            bytes([0x0E]) + bytes([seed_idx]) + bytes([FD]) + inner + bytes([FD, FF])
        )
        run(f"echo({seed_idx})->(λleft.(((left sys8) nil) disc))", payload)
        time.sleep(0.1)

    # ============================================================
    # APPROACH C: Direct "3 leaves" raw payloads
    # The author says "3 leafs" - try the minimal possible programs
    # ============================================================
    print("\n[C] Raw 3-leaf payloads: ((X Y) Z) = X Y FD Z FD FF")

    # Interesting combinations for ((X Y) Z):
    # X=sys8(8), Y=echo(14), Z=write(2) -> ((sys8 echo) write)
    # X=echo(14), Y=sys8(8), Z=write(2) -> ((echo sys8) write)
    # X=backdoor(201=0xC9), Y=sys8(8), Z=write(2)
    # etc.

    three_leaf_tests = [
        ("((sys8 echo) write)", 0x08, 0x0E, 0x02),
        ("((sys8 echo) nil)", 0x08, 0x0E, 0x00),
        ("((echo sys8) write)", 0x0E, 0x08, 0x02),
        ("((echo sys8) sys8)", 0x0E, 0x08, 0x08),
        ("((backdoor sys8) write)", 0xC9, 0x08, 0x02),
        ("((sys8 backdoor) write)", 0x08, 0xC9, 0x02),
        ("((backdoor echo) sys8)", 0xC9, 0x0E, 0x08),
        ("((echo backdoor) sys8)", 0x0E, 0xC9, 0x08),
        ("((sys8 sys8) sys8)", 0x08, 0x08, 0x08),
        ("((echo echo) sys8)", 0x0E, 0x0E, 0x08),
        ("((sys8 echo) echo)", 0x08, 0x0E, 0x0E),
        ("((sys8 write) echo)", 0x08, 0x02, 0x0E),
        ("((sys8 quote) write)", 0x08, 0x04, 0x02),
        ("((echo nil) sys8)", 0x0E, 0x00, 0x08),
        ("((towel sys8) write)", 0x2A, 0x08, 0x02),
        # Right-associative: (X (Y Z)) = X Y Z FD FD FF
    ]

    for name, x, y, z in three_leaf_tests:
        # Left-assoc: ((X Y) Z) = X Y FD Z FD FF
        payload_left = bytes([x, y, FD, z, FD, FF])
        cls = run(f"L-assoc {name}", payload_left)
        time.sleep(0.05)

        # Right-assoc: (X (Y Z)) = X Y Z FD FD FF
        payload_right = bytes([x, y, z, FD, FD, FF])
        run(f"R-assoc ({x:#04x} ({y:#04x} {z:#04x}))", payload_right)
        time.sleep(0.05)

    # ============================================================
    # APPROACH D: Nested echo WITHOUT unwrapping
    # echo(echo(x)) - outer echo wraps inner's Left in another Left
    # Inner Left has +2, outer adds another +2 = +4 total!
    # Feed this double-shifted value to sys8
    # ============================================================
    print("\n[D] Double echo (nested Left) fed to sys8")

    # ((echo ((echo nil) id)) disc)
    # Inner: ((echo nil) id) - echo nil returns Left(nil_shifted), apply to identity
    # This unwraps... we DON'T want that.

    # Instead: echo APPLIED TO echo's raw Left output
    # Can we compose? echo(echo(nil)):
    # ((echo Var(0)) ...) but we need echo(echo_result)
    # CPS chain: ((echo nil) (λleft1. ((echo left1) (λleft2. ((sys8 left2) disc)))))
    # Here left1 = Left(nil_shifted), left2 = Left(left1_shifted) = double-wrapped!
    # Then sys8 gets the double-Left which internally has Var(255+)

    # At depth 0: echo=V14
    # λleft1 (depth 1): echo=V15, left1=V0
    # ((echo left1) handler2)
    # λleft2 (depth 2): sys8=V10, left2=V0
    # ((sys8 left2) disc)

    # disc at depth 2: write=V4
    # disc λres (depth 3): write=V5
    # handlers (depth 4): write=V6
    write_L_d4 = bytes([0x06]) + MARKER_L + bytes([FD]) + nil + bytes([FD])
    write_R_d4 = bytes([0x06]) + MARKER_R + bytes([FD]) + nil + bytes([FD])
    disc_d2 = (
        bytes([0x00])
        + write_L_d4
        + bytes([FE])
        + bytes([FD])
        + write_R_d4
        + bytes([FE])
        + bytes([FD, FE])
    )

    # Inner handler 2: λleft2. ((sys8 left2) disc)
    handler2 = bytes([0x0A, 0x00, FD]) + disc_d2 + bytes([FD, FE])

    # Inner handler 1: λleft1. ((echo left1) handler2)
    # At depth 1: echo=V15, left1=V0
    handler1 = bytes([0x0F, 0x00, FD]) + handler2 + bytes([FD, FE])

    # Full: ((echo nil) handler1)
    payload = bytes([0x0E]) + nil + bytes([FD]) + handler1 + bytes([FD, FF])
    run("echo(nil)->L1, echo(L1)->L2, sys8(L2) disc", payload)
    time.sleep(0.1)

    # Same but with seed = ((nil nil) nil) which echo normalizes interestingly
    seed3 = nil + nil + bytes([FD]) + nil + bytes([FD])  # ((nil nil) nil)
    payload2 = bytes([0x0E]) + seed3 + bytes([FD]) + handler1 + bytes([FD, FF])
    run("echo(((nil nil)nil))->L1, echo(L1)->L2, sys8(L2)", payload2)
    time.sleep(0.1)

    # ============================================================
    # APPROACH E: Backdoor + echo without unwrapping
    # backdoor(nil) -> Left(pair)
    # echo(Left(pair)) -> Left(Left(pair)_shifted) -- double wrap!
    # Pass to sys8
    # ============================================================
    print("\n[E] Backdoor result through echo without unwrapping, to sys8")

    # ((backdoor nil) (λbd_result. ((echo bd_result) (λecho_result. ((sys8 echo_result) disc)))))
    # depth 0: backdoor=V201, echo=V14
    # depth 1 (λbd): echo=V15, bd_result=V0
    # depth 2 (λecho): sys8=V10, echo_result=V0

    # Reuse disc_d2 from above
    handler_echo = bytes([0x0A, 0x00, FD]) + disc_d2 + bytes([FD, FE])
    handler_bd = bytes([0x0F, 0x00, FD]) + handler_echo + bytes([FD, FE])
    payload3 = bytes([0xC9]) + nil + bytes([FD]) + handler_bd + bytes([FD, FF])
    run("bd(nil)->L, echo(L)->L2, sys8(L2) disc", payload3)
    time.sleep(0.1)

    # ============================================================
    # APPROACH F: Use the Left wrapper in function position with sys8
    # echo(nil) -> Left(stuff)
    # (Left sys8) = λr.(sys8 stuff_253)
    # ((Left sys8) dummy) = (sys8 stuff_253)
    # (((Left sys8) dummy) disc) = ((sys8 stuff_253) disc)
    # ============================================================
    print("\n[F] (Left sys8) to invoke sys8 with shifted payload")

    # ((echo seed) (λleft. (((left Var(9)) nil) disc)))
    for seed_idx in [0, 251, 252]:
        # Same as approach B but let me double-check the encoding
        # depth 0: echo=V14
        # λleft (depth 1): left=V0, sys8=V9

        # disc at depth 1:
        # λres (depth 2): write = V4
        # λ_ (depth 3): write = V5
        disc_for_d1 = (
            bytes([0x00])
            + (bytes([0x05]) + MARKER_L + bytes([FD]) + nil + bytes([FD, FE]))
            + bytes([FD])
            + (bytes([0x05]) + MARKER_R + bytes([FD]) + nil + bytes([FD, FE]))
            + bytes([FD, FE])
        )

        # λleft. (((V0 V9) nil) disc)
        # In bytecode: 00 09 FD nil FD disc FD FE
        body = (
            bytes([0x00, 0x09, FD]) + nil + bytes([FD]) + disc_for_d1 + bytes([FD, FE])
        )

        payload = (
            bytes([0x0E]) + bytes([seed_idx]) + bytes([FD]) + body + bytes([FD, FF])
        )
        run(f"echo({seed_idx})->L, (((L sys8) nil) disc)", payload)
        time.sleep(0.1)

    # ============================================================
    # APPROACH G: Backdoor then (Left sys8) pattern
    # Get pair from backdoor, echo the pair, use Left wrapper with sys8
    # ============================================================
    print("\n[G] Backdoor->pair, echo(pair)->L, (((L sys8) nil) disc)")

    # ((backdoor nil) (λbd_res.
    #   ((bd_res                        -- unwrap backdoor's Left to get pair
    #     (λpair.                        -- left handler: got the pair
    #       ((echo pair)                 -- echo the pair
    #         (λecho_left.               -- echo returns Left(pair_shifted)
    #           (((echo_left sys8_ref) nil) disc)  -- use Left in function position
    #     )))
    #     (λerr. write_E)               -- right handler
    #   ))
    # ))

    # depth 0: backdoor=V201=0xC9, echo=V14=0x0E
    # depth 1 (λbd_res): bd_res=V0
    # depth 2 (left handler λpair): pair=V0, echo=V16=0x10
    # depth 3 (λecho_left): echo_left=V0, sys8=V11=0x0B

    # disc at depth 3:
    # λres (d4): write=V6
    # λ_ (d5): write=V7
    disc_d3 = (
        bytes([0x00])
        + (bytes([0x07]) + MARKER_L + bytes([FD]) + nil + bytes([FD, FE]))
        + bytes([FD])
        + (bytes([0x07]) + MARKER_R + bytes([FD]) + nil + bytes([FD, FE]))
        + bytes([FD, FE])
    )

    # λecho_left. (((V0 V11) nil) disc_d3)
    echo_handler = (
        bytes([0x00, 0x0B, FD]) + nil + bytes([FD]) + disc_d3 + bytes([FD, FE])
    )

    # λpair. ((echo pair) echo_handler) -- at depth 2: echo=V16=0x10, pair=V0
    pair_handler = bytes([0x10, 0x00, FD]) + echo_handler + bytes([FD, FE])

    # error handler at depth 2: write "B"
    # write at depth 3 = V5
    err_handler = bytes([0x05]) + MARKER_R + bytes([FD]) + nil + bytes([FD, FE])

    # λbd_res. ((bd_res pair_handler) err_handler)
    bd_handler = (
        bytes([0x00]) + pair_handler + bytes([FD]) + err_handler + bytes([FD, FE])
    )

    payload = bytes([0xC9]) + nil + bytes([FD]) + bd_handler + bytes([FD, FF])
    run("bd->pair, echo(pair)->L, (((L sys8) nil) disc)", payload)
    time.sleep(0.1)

    # ============================================================
    # APPROACH H: Multiple echo + backdoor chain with shift preservation
    # The echo-ladder but keeping Left wrappers at the final step
    # ============================================================
    print("\n[H] Echo-ladder depth 1-3, keep Left at final step for sys8")

    # Depth 1: backdoor(nil)->L_pair, echo(L_pair)->L2, (((L2 sys8) nil) disc)
    # This is approach E already. Let me try explicitly passing the ladder's
    # echo output through sys8 WITHOUT unwrapping at the final step.

    # Depth 1 with selector:
    # backdoor(nil) -> unwrap Left -> pair
    # echo(pair selector) -> DON'T unwrap, pass to sys8

    # ((backdoor nil) (λbd. ((bd
    #   (λpair. ((echo ((pair selector))) (λeleft. (((eleft sys8) nil) disc))))
    #   (λerr. write_E)))))

    sel = bytes([0x00, 0x00, FD, FE, FE])  # λa.λb.((a a) a) wait no
    # selector ((a a) a) = λa.λb.((a a) a)
    # = λ.λ.((V1 V1) V1)
    # = 01 01 FD 01 FD FE FE
    sel = bytes([0x01, 0x01, FD, 0x01, FD, FE, FE])

    # depth 0: backdoor=0xC9
    # depth 1 (λbd): bd=V0
    # depth 2 (λpair): pair=V0, echo=V16=0x10
    # pair applied to selector: ((V0 sel))
    # depth 3 (λeleft): eleft=V0, sys8=V11=0x0B

    # Reuse disc_d3 from approach G
    echo_handler2 = (
        bytes([0x00, 0x0B, FD]) + nil + bytes([FD]) + disc_d3 + bytes([FD, FE])
    )

    # λpair. ((echo (pair sel)) echo_handler2)
    pair_sel = (
        bytes([0x00]) + sel + bytes([FD])
    )  # (pair sel) at depth 2: V0 applied to sel
    pair_handler2 = (
        bytes([0x10]) + pair_sel + bytes([FD]) + echo_handler2 + bytes([FD, FE])
    )

    # Same err handler
    bd_handler2 = (
        bytes([0x00]) + pair_handler2 + bytes([FD]) + err_handler + bytes([FD, FE])
    )

    payload = bytes([0xC9]) + nil + bytes([FD]) + bd_handler2 + bytes([FD, FF])
    run("bd->pair, echo(pair sel)->L, (((L sys8) nil) disc)", payload)

    print("\n" + "=" * 70)
    print("SHIFT-PRESERVE PROBE COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
