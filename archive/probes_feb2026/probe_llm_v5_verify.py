#!/usr/bin/env python3
"""
Test LLM v5 proposals with SAFE OBSERVER (no QD/quote).
Also: thunk injection into sys201, tag confusion V253×V254.
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


def encode_term(t):
    if isinstance(t, Var):
        assert t.i <= 0xFC
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


def query(payload, timeout_s=8.0):
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
        return b"ERR:" + str(e).encode()


def test(name, payload):
    time.sleep(0.4)
    r = query(payload)
    if len(r) == 0:
        print(f"  {name}: EMPTY")
    elif r.startswith(b"ERR:"):
        print(f"  {name}: {r.decode()}")
    else:
        h = r.hex()
        try:
            text = r.decode("ascii")
            if "Encoding failed" in text:
                print(f"  {name}: ENCODING_FAILED (no 0xFF!)")
                return "ENCODING_FAILED"
            if "Invalid term" in text:
                print(f"  {name}: INVALID_TERM")
                return "INVALID_TERM"
            if "Permission denied" in text:
                print(f"  {name}: TEXT 'Permission denied'")
                return "TEXT_PERM"
            print(f"  {name}: TEXT={text!r}")
            return "TEXT"
        except:
            pass
        if "00030200fdfd" in h:
            print(f"  {name}: RIGHT(6)")
            return "RIGHT6"
        # Check for safe observer markers
        if b"B" in r[:5] or b"\x42" in r[:5]:
            print(f"  {name}: *** GOT MARKER 'B' *** hex={h[:40]}")
            return "MARKER"
        if b"L:" in r[:10]:
            print(f"  {name}: *** LEFT DETECTED via safe obs *** hex={h[:60]}")
            return "LEFT"
        if b"Permission denied" in r:
            print(f"  {name}: SAFE_OBS 'Permission denied' [{len(r)}b]")
            return "SAFE_RIGHT6"
        print(f"  {name}: OTHER hex={h[:80]} [{len(r)}b]")
        try:
            print(f"    text attempt: {r[:40]!r}")
        except:
            pass
        return "OTHER"
    return "EMPTY"


def main():
    # ==========================================
    # SAFE OBSERVER: λresult. write([0x42])(nil)
    # Writes byte 'B' (0x42) regardless of result
    # Under 1 lambda: write = g(2) = Var(3)
    # ==========================================
    marker_byte = encode_bytes_list(b"\x42")
    SAFE_OBS = Lam(App(App(Var(3), shift(marker_byte, 1)), nil))

    # Also: observer that writes "Permission denied" error string for Right
    # λresult. result(λp. write("L")(nil))(λe. write("R")(nil))
    L_bytes = encode_bytes_list(b"L")
    R_bytes = encode_bytes_list(b"R")
    EITHER_OBS = Lam(
        App(
            App(Var(0), Lam(App(App(Var(4), shift(L_bytes, 2)), nil))),
            Lam(App(App(Var(4), shift(R_bytes, 2)), nil)),
        )
    )

    print("=" * 70)
    print("SECTION 1: Safe Observer baseline — confirm sys8 returns Right")
    print("=" * 70)

    # sys8(nil)(SAFE_OBS) — should write "B" because sys8 calls continuation
    test(
        "sys8(nil)(SAFE_OBS) [should print 'B']",
        bytes([0x08])
        + encode_term(nil)
        + bytes([FD])
        + encode_term(SAFE_OBS)
        + bytes([FD, FF]),
    )

    # sys8(nil)(EITHER_OBS) — should write "R" for Right
    test(
        "sys8(nil)(EITHER_OBS) [should print 'R']",
        bytes([0x08])
        + encode_term(nil)
        + bytes([FD])
        + encode_term(EITHER_OBS)
        + bytes([FD, FF]),
    )

    # Control: towel(nil)(EITHER_OBS) — should write "L"
    test(
        "towel(nil)(EITHER_OBS) [should print 'L']",
        bytes([0x2A])
        + encode_term(nil)
        + bytes([FD])
        + encode_term(EITHER_OBS)
        + bytes([FD, FF]),
    )

    print()
    print("=" * 70)
    print("SECTION 2: V253/V254 as hidden syscalls — SAFE OBSERVER")
    print("  Previously EMPTY with QD. Does safe obs reveal anything?")
    print("=" * 70)

    # echo(251)(λleft. left(λv253. ((v253 nil) SAFE_OBS))(λe.nil))
    # Extract V253, call as CPS syscall with safe observer
    # Under 3 lambdas: write=g2=Var(5)
    safe_obs_s3 = Lam(App(App(Var(6), shift(marker_byte, 4)), nil))
    inner_call = Lam(
        App(App(Var(0), shift(nil, 3)), safe_obs_s3)
    )  # λv253. ((v253 nil) safe_obs)
    right_h = Lam(nil)

    for var_idx, label in [(251, "V253"), (252, "V254")]:
        term = App(App(App(Var(14), Var(var_idx)), inner_call), right_h)
        test(
            f"echo({var_idx})→extract {label}→(({label} nil) SAFE_OBS)",
            encode_term(term) + bytes([FF]),
        )

    print()
    print("=" * 70)
    print("SECTION 3: Thunk injection — sys201(sys8(nil)(QD))")
    print("  Theory: sys201 elevates privileges, evaluates arg, sys8 runs elevated")
    print("=" * 70)

    # sys201( sys8(nil)(QD) )( QD )
    thunk = App(App(Var(8), nil), Lam(App(App(Var(4), App(Var(6), Var(0))), nil)))
    test(
        "sys201( sys8(nil)(write∘quote) )( QD ) [thunk injection]",
        bytes([0xC9]) + encode_term(thunk) + bytes([FD]) + QD + bytes([FD, FF]),
    )

    # Also try with safe observer
    test(
        "sys201( sys8(nil)(SAFE_OBS) )( QD ) [thunk + safe obs]",
        bytes([0xC9])
        + encode_term(App(App(Var(8), nil), SAFE_OBS))
        + bytes([FD])
        + QD
        + bytes([FD, FF]),
    )

    # And: sys8(nil)(QD) embedded deeper
    # sys201( App(sys8, nil) )( QD ) — partial application, not full CPS
    test(
        "sys201( App(sys8,nil) )( QD ) [partial thunk]",
        bytes([0xC9, 0x08]) + encode_term(nil) + bytes([FD, FD]) + QD + bytes([FD, FF]),
    )

    print()
    print("=" * 70)
    print("SECTION 4: Tag confusion — V253 applied to V254")
    print("  'combining special bytes' — with SAFE observer")
    print("=" * 70)

    # echo(251)(λl1. l1(λv253. echo(252)(λl2. l2(λv254. ((v253 v254) SAFE_OBS↑deep))(λe.nil)))(λe.nil))
    # This is complex. Let me build it step by step.
    # Under 5 lambdas: write=g2=Var(7)
    safe_obs_s5 = Lam(App(App(Var(8), shift(marker_byte, 6)), nil))

    # Innermost: λv254. ((v253 v254) safe_obs)
    # v253=Var(1) (from outer lambda), v254=Var(0)
    v253v254_body = Lam(App(App(Var(1), Var(0)), safe_obs_s5))

    # λl2. l2(v253v254_body)(λe.nil)
    l2_handler = Lam(App(App(Var(0), shift(v253v254_body, 1)), Lam(nil)))

    # echo(252) under 2 lambdas: echo=g14=Var(16)
    echo252_call = App(App(Var(16), Var(252)), l2_handler)

    # λv253. echo(252)...
    v253_handler = Lam(echo252_call)

    # λl1. l1(v253_handler)(λe.nil)
    l1_handler = Lam(App(App(Var(0), shift(v253_handler, 1)), Lam(nil)))

    # echo(251)(l1_handler)
    full_tag_confusion = App(App(Var(14), Var(251)), l1_handler)
    test(
        "V253(V254)(SAFE_OBS) [tag confusion: combining special bytes]",
        encode_term(full_tag_confusion) + bytes([FF]),
    )

    # Simpler: just V253(V254) without observer, check if it hangs
    # echo(251)(λl1. l1(λv253. echo(252)(λl2. l2(λv254. v253(v254))(λe.nil)))(λe.nil))
    v254_apply = Lam(App(Var(1), Var(0)))  # λv254. v253(v254)
    l2_handler2 = Lam(App(App(Var(0), shift(v254_apply, 1)), Lam(nil)))
    echo252_call2 = App(App(Var(16), Var(252)), l2_handler2)
    v253_handler2 = Lam(echo252_call2)
    l1_handler2 = Lam(App(App(Var(0), shift(v253_handler2, 1)), Lam(nil)))
    full_bare = App(App(Var(14), Var(251)), l1_handler2)
    test("V253(V254) bare [does it hang/crash?]", encode_term(full_bare) + bytes([FF]))

    print()
    print("=" * 70)
    print("SECTION 5: Manual echo (pre-2018 path)")
    print("  λx.λl.λr.(l x) applied to Var(251) = Left(Var(253))")
    print("  Then chain to sys8 via safe observer")
    print("=" * 70)

    # Manual Left constructor: λx. λl.λr. (l x)
    # In de Bruijn: Lam(Lam(Lam(App(Var(1), Var(2)))))
    manual_left = Lam(Lam(Lam(App(Var(1), Var(2)))))

    # Apply to Var(251): beta reduces to Lam(Lam(App(Var(1), Var(253))))
    # = Left(Var(253)) — identical to echo(251)!
    manual_echo_result = App(manual_left, Var(251))

    # Chain: manual_echo(251)(λv253. sys8(nil)(SAFE_OBS))(λe.nil)
    # Under 2 lambdas: sys8=g8=Var(10), write=g2=Var(4)
    safe_obs_s2 = Lam(App(App(Var(4), shift(marker_byte, 2)), nil))
    left_h = Lam(App(App(Var(10), nil), safe_obs_s2))
    right_h2 = Lam(nil)

    term = App(App(manual_echo_result, left_h), right_h2)
    test(
        "manual_Left(V251)→extract V253→sys8(nil)(SAFE_OBS) [pre-2018 path]",
        encode_term(term) + bytes([FF]),
    )

    print()
    print("Done.")


if __name__ == "__main__":
    main()
