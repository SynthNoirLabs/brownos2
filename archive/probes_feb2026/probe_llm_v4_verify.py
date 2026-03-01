#!/usr/bin/env python3
"""
Comprehensive verification probe:
1. Re-confirm LLM v4 payloads all return Right(6)
2. Test genuinely unexplored angles:
   - Var(253/254) in CONTINUATION position
   - Var(253/254) applied to each other (tag confusion)
   - Hidden global CPS calls ((Var(253) arg) cont)
   - Double-echo for Var(255)
"""

from __future__ import annotations
import socket, time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221
FD, FE, FF = 0xFD, 0xFE, 0xFF
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


nil = Lam(Lam(Var(0)))
identity = Lam(Var(0))


def encode_term(t):
    if isinstance(t, Var):
        assert t.i <= 0xFC, f"Var({t.i}) cannot be encoded in bytecode"
        return bytes([t.i])
    if isinstance(t, Lam):
        return encode_term(t.body) + bytes([FE])
    if isinstance(t, App):
        return encode_term(t.f) + encode_term(t.x) + bytes([FD])
    raise TypeError


def shift(t, n, c=0):
    if isinstance(t, Var):
        return Var(t.i + n) if t.i >= c else t
    if isinstance(t, Lam):
        return Lam(shift(t.body, n, c + 1))
    if isinstance(t, App):
        return App(shift(t.f, n, c), shift(t.x, n, c))
    return t


def cons(h, t):
    return Lam(Lam(App(App(Var(1), shift(h, 2)), shift(t, 2))))


def encode_byte_term(n):
    expr = Var(0)
    for idx, w in ((1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)):
        if n & w:
            expr = App(Var(idx), expr)
    for _ in range(9):
        expr = Lam(expr)
    return expr


def encode_bytes_list(bs):
    cur = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


def query(payload, timeout_s=5.0):
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
                        if FF in chunk:
                            break
                    except socket.timeout:
                        break
                return out
        except Exception as e:
            if attempt < 2:
                time.sleep(0.3 * (attempt + 1))
            else:
                return b"CONN_ERR:" + str(e).encode()
    return b""


def classify(data):
    if isinstance(data, bytes) and data.startswith(b"CONN_ERR:"):
        return f"CONN_ERR"
    if len(data) == 0:
        return "EMPTY"
    try:
        text = data.decode("ascii")
        if "Invalid term" in text:
            return "INVALID_TERM"
        if "Term too big" in text:
            return "TERM_TOO_BIG"
        if "Encoding failed" in text:
            return "ENCODING_FAILED"
        if "Not so fast" in text:
            return "RATE_LIMITED"
        return f"TEXT:{text!r}"
    except:
        pass
    h = data.hex()
    if "00030200fdfd" in h:
        return "RIGHT(6)"
    if "00020100fdfd" in h:
        return "RIGHT(3)"
    if "000200fdfd" in h and "00030200" not in h:
        return "RIGHT(2)"
    if "00010000fdfd" in h:
        return "RIGHT(1)"
    if "0100fdfefefefefefefefefefd" in h:
        return "RIGHT(0)"
    # Check for any Left response
    if h.endswith("fefeff") and h[0:2] == "01":
        return f"*** LEFT *** hex={h} [{len(data)}b]"
    return f"OTHER:{h[:80]} [{len(data)}b]"


def cps(sc, arg):
    return bytes([sc]) + encode_term(arg) + bytes([FD]) + QD + bytes([FD, FF])


def test(name, payload):
    time.sleep(0.4)
    r = query(payload)
    c = classify(r)
    mark = " *** BREAKTHROUGH ***" if "LEFT" in c else ""
    print(f"  {name}: {c}{mark}")
    if "OTHER" in c or "LEFT" in c or "TEXT" in c:
        print(f"    raw hex: {r.hex()[:100]}")
        try:
            print(f"    text: {r[:60]!r}")
        except:
            pass
    return c


def main():
    print("=" * 70)
    print("SECTION 1: Re-confirm LLM v4 payloads (Right(3) theory probes)")
    print("  Expected: ALL Right(6), proving Right(3) theory is wrong")
    print("=" * 70)

    test(
        "sys8(b'\\x00\\xFE\\xFE') [LLM Probe 1: nil bytecode]",
        cps(0x08, encode_bytes_list(b"\x00\xfe\xfe")),
    )

    test(
        "sys8('00 FE FE') [LLM Probe 2: ASCII repr]",
        cps(0x08, encode_bytes_list(b"00 FE FE")),
    )

    test(
        "sys8(b'\\x00\\x00\\xFD\\xFE\\xFE') [LLM Probe 3a: A bytecode]",
        cps(0x08, encode_bytes_list(b"\x00\x00\xfd\xfe\xfe")),
    )

    # Also the strings from previous rounds that were claimed Right(3)
    test(
        "sys8('ilikephp') [was claimed Right(3)]",
        cps(0x08, encode_bytes_list(b"ilikephp")),
    )

    test(
        "sys8('/bin/sh') [was claimed Right(3)]",
        cps(0x08, encode_bytes_list(b"/bin/sh")),
    )

    test(
        "sys8('gizmore') [was claimed Right(3)]",
        cps(0x08, encode_bytes_list(b"gizmore")),
    )

    print()
    print("=" * 70)
    print("SECTION 2: CONTINUATION experiments")
    print("  Hypothesis: sys8 might check the continuation, not the argument")
    print("  We inject Var(253/254) into continuation via echo extraction")
    print("=" * 70)

    # echo(Var(251)) returns Left(Var(253))
    # We can extract Var(253) by applying Left to a selector: Left(λx.x)(λe.e)
    # Then use extracted Var(253) as continuation for sys8
    #
    # Plan: echo(251)(λv253. sys8(nil)(v253))(dummy)
    # Under 1 lambda (v253=Var(0)): echo=Var(15), sys8=Var(9), nil shifts
    # The Left result: Left(V253) = λl.λr.(l V253)
    # Apply to (λv. sys8(nil)(v)): extracts V253, calls sys8(nil)(V253)

    # echo(251)( λpayload. sys8(nil)(payload) )( λerr. nil )
    # Under 1 lam: echo=g14=Var(15), sys8=g8=Var(9), nil=Lam(Lam(Var(0)))
    shifted_nil = Lam(Lam(Var(0)))  # nil has no free vars, no shift needed
    left_handler = Lam(App(App(Var(9), shifted_nil), Var(0)))  # λv. sys8(nil)(v)
    right_handler = Lam(shifted_nil)  # λe. nil

    # echo(Var(251))( left_handler )( right_handler )
    echo_251 = App(Var(14), Var(251))
    full_term = App(App(echo_251, left_handler), right_handler)
    test(
        "echo(251)→extract V253→sys8(nil)(V253) [V253 as continuation]",
        encode_term(full_term) + bytes([FF]),
    )

    # Same but V254
    echo_252 = App(Var(14), Var(252))
    full_term2 = App(App(echo_252, left_handler), right_handler)
    test(
        "echo(252)→extract V254→sys8(nil)(V254) [V254 as continuation]",
        encode_term(full_term2) + bytes([FF]),
    )

    # sys8(nil) with V253-containing lambda as continuation
    # λx. write(quote(x)) but with V253 embedded
    # echo(251)(λv253. sys8(nil)(λresult. write(quote(v253))))(λe.nil)
    # This puts V253 in the continuation body even though it's not used as the result
    shifted_qd = Lam(App(App(Var(6), App(Var(5), Var(0))), Lam(Lam(Var(0)))))
    # Under 2 lambdas (echo handler + result):
    # write=g2=Var(4), quote=g4=Var(6), sys8=g8=Var(10)
    # λv253. sys8(nil)( λresult. write(quote(v253)) )
    inner_cont = Lam(App(App(Var(5), App(Var(7), Var(1))), Lam(Lam(Var(0)))))
    # v253=Var(0) inside this λ. write=Var(4), quote=Var(6)... wait indices are tricky
    # Let me just do simpler: sys8(nil)(QD) but from inside echo handler
    # echo(251)(λv253. ((sys8 nil) QD_shifted))(λe. nil)
    shifted_qd_1 = bytes(
        [0x06, 0x00, FD, 0x00, 0x06, 0x00, FD, 0x04, FD, FE, FD, 0x03, FD, FE, FD, FE]
    )
    inner_sys8 = (
        bytes([0x09])
        + encode_term(shifted_nil)
        + bytes([FD])
        + shifted_qd_1
        + bytes([FD])
    )
    inner_body = inner_sys8 + bytes([FE])  # λv253. sys8(nil)(QD)
    right_h = encode_term(Lam(shifted_nil))
    payload_echo_then_sys8 = (
        bytes([0x0E, 0xFB, FD]) + inner_body + bytes([FD]) + right_h + bytes([FD, FF])
    )
    test(
        "echo(251)(λv253. sys8(nil)(QD↑1))(λe.nil) [V253 in scope during sys8]",
        payload_echo_then_sys8,
    )

    print()
    print("=" * 70)
    print("SECTION 3: Var(253/254) applied to EACH OTHER (tag confusion)")
    print("  'combining the special bytes' = App(V253, V254)?")
    print("=" * 70)

    # We need both V253 and V254 in scope simultaneously
    # echo(251)(λe1. e1(λv253. echo(252)(λe2. e2(λv254. BODY)(drop))(drop))
    # This is getting deep. Simpler approach:
    # Build term where V253 and V254 interact during reduction
    # echo(251) → Left(V253). echo(252) → Left(V254).
    # Chain: echo(251)(λleft1. echo(252)(λleft2. left1(λv253. left2(λv254. COMBINE)(drop))(drop))

    # Actually the simplest test: just see if applying V253 to V254 does something
    # echo(251)(λleft. left(λv253. v253)(λerr.nil))
    # This extracts V253 and returns it as a raw value — but then what?
    # We need to use it in an App.

    # Minimal: echo(251)(λl. l (λv. ((v nil) QD)) (λe. nil))(dummy)
    # This extracts V253, then calls ((V253 nil) QD) — V253 as a CPS syscall
    # Under 3 lambdas: v=Var(0), nil shifts, QD shifts...
    # echo=g14. Under echo handler (1 lam): g14=Var(15)
    # Left handler: λv. ((v nil) QD_shifted)
    # Under 2 lams total: sys8 would be Var(10), nil no shift needed
    # But v=Var(0), so: ((Var(0) nil) QD_shifted_by_2)
    qd_shift2 = bytes(
        [0x07, 0x00, FD, 0x00, 0x07, 0x00, FD, 0x05, FD, FE, FD, 0x04, FD, FE, FD, FE]
    )
    # λv. ((v nil) QD↑2)
    v253_as_syscall = (
        bytes([0x00])
        + encode_term(shifted_nil)
        + bytes([FD])
        + qd_shift2
        + bytes([FD, FE])
    )
    # Left handler extracts and calls
    # Right handler: λe. nil
    right_h_bytes = encode_term(Lam(shifted_nil))

    # echo(251)( left_extract )( right_handler )
    payload_v253_syscall = (
        bytes([0x0E, 0xFB, FD])
        + v253_as_syscall
        + bytes([FD])
        + right_h_bytes
        + bytes([FD, FF])
    )
    test(
        "echo(251)→extract V253→((V253 nil) QD) [V253 as hidden syscall]",
        payload_v253_syscall,
    )

    # Same for V254
    payload_v254_syscall = (
        bytes([0x0E, 0xFC, FD])
        + v253_as_syscall
        + bytes([FD])
        + right_h_bytes
        + bytes([FD, FF])
    )
    test(
        "echo(252)→extract V254→((V254 nil) QD) [V254 as hidden syscall]",
        payload_v254_syscall,
    )

    print()
    print("=" * 70)
    print("SECTION 4: Double-echo for Var(255) = 0xFF")
    print("  Can we create Var(255) via nested echo?")
    print("  echo(Var(253)) would need byte FD in source = impossible")
    print("  But: echo(251)→V253, then echo(V253)→Left(V255)?")
    print("=" * 70)

    # echo(251)(λleft. left(λv253. echo(v253))(λe.nil))
    # This extracts V253, then calls echo(V253)
    # echo(V253) → Left(V255) because Left adds +2 shift: 253+2=255
    # Under 2 lams: echo=g14=Var(16)
    # λv253. echo(v253) = λv. Var(16)(v) = λ. App(Var(16), Var(0))
    inner_echo = Lam(App(Var(16), Var(0)))  # λv253. echo(v253)
    # But then we need to handle the result... let's chain with QD
    # echo(251)(λleft. left(λv253. ((echo v253) QD↑3))(λe. nil))
    # Under 3 lams: echo=g14=Var(17), QD shifts by 3
    qd_shift3 = bytes(
        [0x08, 0x00, FD, 0x00, 0x08, 0x00, FD, 0x06, FD, FE, FD, 0x05, FD, FE, FD, FE]
    )
    double_echo_inner = (
        bytes([0x11, 0x00, FD]) + qd_shift3 + bytes([FD, FE])
    )  # λv. ((echo v) QD↑3)
    # This is the Left handler for the first echo's result
    # Full: echo(251)( λleft. left( double_echo_inner )( λe. nil ) )
    # Wait, I need to handle the Either properly
    # Left(V253) applied to left_handler gives: left_handler(V253) = ((echo V253) QD)
    # So the left_handler for the outer Either is: λv253. ((echo v253) QD↑2)
    # Under 2 lambdas total: echo=g14=Var(16)
    qd_shift2_bytes = bytes(
        [0x07, 0x00, FD, 0x00, 0x07, 0x00, FD, 0x05, FD, FE, FD, 0x04, FD, FE, FD, FE]
    )
    # λv253. ((g14 v253) QD↑2)
    # = λ. ((Var(16) Var(0)) QD↑2)
    double_echo_left = bytes([0x10, 0x00, FD]) + qd_shift2_bytes + bytes([FD, FE])
    payload_double = (
        bytes([0x0E, 0xFB, FD])
        + double_echo_left
        + bytes([FD])
        + right_h_bytes
        + bytes([FD, FF])
    )
    test("echo(251)→V253→echo(V253)→Left(V255)? [double echo for V255]", payload_double)

    print()
    print("=" * 70)
    print("SECTION 5: Backdoor pair components in continuation position")
    print("=" * 70)

    # backdoor(nil)(λpair. pair(λa.λb. sys8(nil)(a))(nil))
    # Extract A from pair, use A as continuation for sys8
    # Under 3 lambdas: sys8=g8=Var(11)
    shifted_qd_3 = bytes(
        [0x08, 0x00, FD, 0x00, 0x08, 0x00, FD, 0x06, FD, FE, FD, 0x05, FD, FE, FD, FE]
    )
    # λa.λb. ((sys8 nil) a)  — use A itself as continuation
    use_a_as_cont = Lam(Lam(App(App(Var(12), Lam(Lam(Var(0)))), Var(1))))
    # λpair. pair(use_a)(nil)
    left_pair_handler = Lam(App(App(Var(0), shift(use_a_as_cont, 1)), Lam(Lam(Var(0)))))
    right_pair_handler = Lam(Lam(Lam(Var(0))))

    # backdoor(nil)(λeither. either(left_pair)(right_pair))
    either_handler = Lam(
        App(App(Var(0), shift(left_pair_handler, 1)), shift(right_pair_handler, 1))
    )

    payload_bd_a_cont = (
        bytes([0xC9])
        + encode_term(nil)
        + bytes([FD])
        + encode_term(either_handler)
        + bytes([FD, FF])
    )
    test("backdoor→pair→sys8(nil)(A) [backdoor A as continuation]", payload_bd_a_cont)

    # Same but use B as continuation
    use_b_as_cont = Lam(Lam(App(App(Var(12), Lam(Lam(Var(0)))), Var(0))))
    left_pair_handler_b = Lam(
        App(App(Var(0), shift(use_b_as_cont, 1)), Lam(Lam(Var(0))))
    )
    either_handler_b = Lam(
        App(App(Var(0), shift(left_pair_handler_b, 1)), shift(right_pair_handler, 1))
    )
    payload_bd_b_cont = (
        bytes([0xC9])
        + encode_term(nil)
        + bytes([FD])
        + encode_term(either_handler_b)
        + bytes([FD, FF])
    )
    test("backdoor→pair→sys8(nil)(B) [backdoor B as continuation]", payload_bd_b_cont)

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("Done. Any '*** BREAKTHROUGH ***' or '*** LEFT ***' is a hit.")
    print("Any 'ENCODING_FAILED' or unusual behavior is also notable.")


if __name__ == "__main__":
    main()
