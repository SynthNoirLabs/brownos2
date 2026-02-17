#!/usr/bin/env python3
"""
probe_ultra1.py — Comprehensive experiment batch from ultrabrain consultation.

Tests:
1. sys201 (backdoor) with non-nil inputs (A, B, int(1), int(201), pair, omega)
2. sys8 with crypt hash string "GZKc.2/VQffio"
3. sys8 with credential pairs
4. sys8 with 3-arg form: g(8)(username)(password)(QD)
5. sys8 as continuation to readfile
6. sys8 with file IDs 0-20 (quick sweep)
"""

from __future__ import annotations

import socket
import sys
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


def recv_until_ff(sock: socket.socket, timeout_s: float = 5.0) -> bytes:
    sock.settimeout(timeout_s)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
        if FF in chunk:
            break
    return out


def query(payload: bytes, retries: int = 3, timeout_s: float = 5.0) -> bytes:
    delay = 0.3
    last_err = None
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_until_ff(sock, timeout_s=timeout_s)
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed: {last_err}")


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported: {type(term)}")


def parse_term(data: bytes) -> object:
    stack: list[object] = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    if len(stack) != 1:
        raise ValueError(f"Stack size {len(stack)}")
    return stack[0]


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def encode_byte_term(n: int) -> object:
    expr: object = Var(0)
    for idx, weight in (
        (1, 1),
        (2, 2),
        (3, 4),
        (4, 8),
        (5, 16),
        (6, 32),
        (7, 64),
        (8, 128),
    ):
        if n & weight:
            expr = App(Var(idx), expr)
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_bytes_list(bs: bytes) -> object:
    nil: object = Lam(Lam(Var(0)))

    def cons(h: object, t: object) -> object:
        return Lam(Lam(App(App(Var(1), h), t)))

    cur: object = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


def scott_pair(a: object, b: object) -> object:
    """Scott pair: λsel. sel a b"""
    return Lam(App(App(Var(0), a), b))


def decode_either_tag(term: object) -> str:
    if isinstance(term, Lam) and isinstance(term.body, Lam):
        body = term.body.body
        if isinstance(body, App) and isinstance(body.f, Var):
            if body.f.i == 1:
                return "Left"
            elif body.f.i == 0:
                return "Right"
    return "Unknown"


def strip_lams(term: object, n: int) -> object:
    cur = term
    for _ in range(n):
        if not isinstance(cur, Lam):
            return cur
        cur = cur.body
    return cur


def eval_bitset_expr(expr: object) -> int:
    if isinstance(expr, Var):
        return WEIGHTS.get(expr.i, -1)
    if isinstance(expr, App) and isinstance(expr.f, Var):
        w = WEIGHTS.get(expr.f.i, -1)
        if w < 0:
            return -1
        rest = eval_bitset_expr(expr.x)
        if rest < 0:
            return -1
        return w + rest
    return -1


def decode_result_summary(raw: bytes) -> str:
    """Best-effort decode of a QD response."""
    if not raw or FF not in raw:
        return f"empty/no-FF (raw={raw.hex() if raw else 'empty'})"
    try:
        term = parse_term(raw)
    except Exception as e:
        return f"parse_error({e}) raw={raw[:40].hex()}"

    tag = decode_either_tag(term)
    if tag == "Right":
        body = term.body.body
        if isinstance(body, App):
            inner = body.x
            inner_body = strip_lams(inner, 9)
            code = eval_bitset_expr(inner_body)
            err_map = {
                0: "Exception",
                1: "NotImpl",
                2: "InvalidArg",
                3: "NoSuchFile",
                4: "NotDir",
                5: "NotFile",
                6: "PermDenied",
                7: "RateLimit",
            }
            return f"Right({code})={err_map.get(code, '???')}"
        return f"Right(?)"
    elif tag == "Left":
        return f"Left(...) raw_len={len(raw)}"
    return f"Unknown tag, raw={raw[:40].hex()}"


def call_with_qd(payload_bytes: bytes) -> str:
    """Send payload, decode QD result."""
    full = payload_bytes + bytes([FF])
    try:
        raw = query(full)
        return decode_result_summary(raw)
    except Exception as e:
        return f"ERROR: {e}"


def test(label: str, payload_bytes: bytes):
    """Test a payload and print result."""
    result = call_with_qd(payload_bytes)
    print(f"  {label}: {result}")
    time.sleep(0.3)


# ── Build terms ──────────────────────────────────────────────────

# Backdoor combinators (as lambda terms for embedding in payloads)
A_term = Lam(Lam(App(Var(0), Var(0))))  # λa.λb.(b b)
B_term = Lam(Lam(App(Var(1), Var(0))))  # λa.λb.(a b)
omega = Lam(App(Var(0), Var(0)))  # λx.(x x)
pair_AB = Lam(App(App(Var(0), A_term), B_term))  # λsel. sel A B

nil = Lam(Lam(Var(0)))  # Scott nil = λc.λn. n
int0 = encode_byte_term(0)
int1 = encode_byte_term(1)
int8 = encode_byte_term(8)
int201 = encode_byte_term(201)

password_bytes = encode_bytes_list(b"ilikephp")
crypt_hash_bytes = encode_bytes_list(b"GZKc.2/VQffio")
username_bytes = encode_bytes_list(b"gizmore")

# uid 1000 as integer term
uid_1000 = encode_byte_term(1000)


def make_syscall_qd(syscall_num: int, arg: object) -> bytes:
    """Build: syscall(arg)(QD) → bytes (without FF)"""
    return bytes([syscall_num]) + encode_term(arg) + bytes([FD]) + QD + bytes([FD])


def make_syscall_3arg_qd(syscall_num: int, arg1: object, arg2: object) -> bytes:
    """Build: syscall(arg1)(arg2)(QD) → bytes (without FF)"""
    return (
        bytes([syscall_num])
        + encode_term(arg1)
        + bytes([FD])
        + encode_term(arg2)
        + bytes([FD])
        + QD
        + bytes([FD])
    )


def make_chained(syscall1: int, arg1: object, syscall2: int, arg2_template) -> bytes:
    """Build: syscall1(arg1)(λresult. syscall2(arg2_template(result))(QD))
    For simplicity, arg2_template is just identity — pass result directly to syscall2."""
    # continuation = λresult. syscall2(result)(QD)
    # In de Bruijn: under 1 lambda, result = Var(0), syscall2 = Var(syscall2+1)
    # But globals shift! Under 1 lambda: g(n) = Var(n+1) if n is a free var
    # Actually... globals ARE free vars. Under 1 lambda, Var(0) = bound param,
    # Var(n+1) = what was Var(n) at top level
    # So syscall2 = Var(syscall2 + 1) inside the lambda
    # QD also needs shifting... this is complex.
    # Let's just build it with explicit bytes.
    # λ. (g(syscall2+1) Var(0) FD QD_shifted FD)
    # Actually QD uses globals 2,3,4,5 at top level. Under 1 extra lambda they become 3,4,5,6.
    # This is error-prone. Let's use a simpler approach:
    # Build the full CPS chain at top level using the continuation trick.
    #
    # syscall1(arg1)(λr. syscall2(r)(QD))
    # = App(App(Var(syscall1), arg1), Lam(App(App(Var(syscall2+1), Var(0)), QD_shifted)))
    #
    # QD shifted by 1: every free var in QD increments by 1
    # QD = 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
    # Parse QD: λ. ((write (quote Var(0)) (λeither. either (λbytes. ...) exception)))
    # Hmm, shifting QD is non-trivial. Let's do a different approach.
    #
    # Actually, we can avoid shifting by using a TWO-STEP approach:
    # Send two separate connections. That's easier. Skip this for now.
    pass


def main():
    print("=" * 60)
    print("PROBE ULTRA1 — Comprehensive experiment batch")
    print("=" * 60)

    # ── SECTION 1: Backdoor (sys201) with non-nil inputs ──
    print("\n[1] sys201 (backdoor) with non-nil inputs:")
    print("    Expected: Right(2)=InvalidArg for non-nil, but looking for surprises")

    test("sys201(int0)", make_syscall_qd(201, int0))
    test("sys201(int1)", make_syscall_qd(201, int1))
    test("sys201(int8)", make_syscall_qd(201, int8))
    test("sys201(int201)", make_syscall_qd(201, int201))
    test("sys201(A_term)", make_syscall_qd(201, A_term))
    test("sys201(B_term)", make_syscall_qd(201, B_term))
    test("sys201(omega)", make_syscall_qd(201, omega))
    test("sys201(pair_AB)", make_syscall_qd(201, pair_AB))
    test("sys201(password 'ilikephp')", make_syscall_qd(201, password_bytes))
    test("sys201(crypt hash)", make_syscall_qd(201, crypt_hash_bytes))

    # ── SECTION 2: sys8 with crypt hash ──
    print("\n[2] sys8 with crypt hash and password variants:")

    test("sys8(crypt_hash 'GZKc.2/VQffio')", make_syscall_qd(8, crypt_hash_bytes))
    test("sys8(password 'ilikephp')", make_syscall_qd(8, password_bytes))
    test("sys8(username 'gizmore')", make_syscall_qd(8, username_bytes))

    # ── SECTION 3: sys8 with credential pairs ──
    print("\n[3] sys8 with credential pairs:")

    # pair(uid, password)
    pair_uid_pw = scott_pair(uid_1000, password_bytes)
    test("sys8(pair(uid1000, 'ilikephp'))", make_syscall_qd(8, pair_uid_pw))

    # pair(username, password)
    pair_user_pw = scott_pair(username_bytes, password_bytes)
    test("sys8(pair('gizmore', 'ilikephp'))", make_syscall_qd(8, pair_user_pw))

    # pair(username, crypt_hash)
    pair_user_hash = scott_pair(username_bytes, crypt_hash_bytes)
    test("sys8(pair('gizmore', crypt_hash))", make_syscall_qd(8, pair_user_hash))

    # Just the password as int (each char)
    # Try with uid as a simple int
    test("sys8(int(1000)=uid)", make_syscall_qd(8, uid_1000))

    # ── SECTION 4: sys8 with 3-arg form ──
    print("\n[4] sys8 with 3-arg form: g(8)(arg1)(arg2)(QD):")

    test(
        "sys8('gizmore')('ilikephp')(QD)",
        make_syscall_3arg_qd(8, username_bytes, password_bytes),
    )
    test(
        "sys8(uid1000)('ilikephp')(QD)",
        make_syscall_3arg_qd(8, uid_1000, password_bytes),
    )
    test("sys8('ilikephp')(nil)(QD)", make_syscall_3arg_qd(8, password_bytes, nil))
    test("sys8(nil)('ilikephp')(QD)", make_syscall_3arg_qd(8, nil, password_bytes))

    # ── SECTION 5: sys8 with file IDs (quick sweep) ──
    print("\n[5] sys8 with file IDs 0-20:")

    for fid in range(21):
        test(f"sys8(int({fid}))", make_syscall_qd(8, encode_byte_term(fid)))

    # Also test some interesting IDs
    for fid in [42, 46, 65, 88, 201, 256]:
        test(f"sys8(int({fid}))", make_syscall_qd(8, encode_byte_term(fid)))

    # ── SECTION 6: sys8 with backdoor result components ──
    print("\n[6] sys8 with backdoor-derived terms:")

    test("sys8(A=λab.bb)", make_syscall_qd(8, A_term))
    test("sys8(B=λab.ab)", make_syscall_qd(8, B_term))
    test("sys8(pair(A,B))", make_syscall_qd(8, pair_AB))
    test("sys8(ω=λx.xx)", make_syscall_qd(8, omega))

    # A(B) = λb.(b b)[b:=B] = ... hmm let's just use App
    # Actually A(B) as a term: App(A_term, B_term)
    # But the evaluator is CBN so it won't reduce unless forced
    # Let's try both the unevaluated and manually-reduced forms
    AB_app = App(A_term, B_term)  # unevaluated A(B)
    test("sys8(A(B) unevaluated)", make_syscall_qd(8, AB_app))

    # A(B) reduces to: λb.(b b) applied to B = (B B)
    # B(B) = (λa.λb.(a b))(λa.λb.(a b)) = λb.((λa.λb.(a b)) b) = λb.λb'.(b b')
    # which is just λx.λy.(x y) = the I combinator on 2 args, or the apply combinator
    # Actually: A = λa.λb.(b b), so A(B) = λb.(b b) with a→B, so = λb.(b b) still? No:
    # A = λa.λb.(b b) means the body doesn't USE a at all! So A(B) = λb.(b b) = A_without_first_arg
    # Wait: A = λa.λb.(b b). Body under 2 lambdas = App(Var(0), Var(0)).
    # A(B) beta-reduces: substitute B for Var(1) in λb.(Var(0) Var(0)). But Var(1)=a doesn't appear in body!
    # So A(B) = λb.(b b) = ω = λx.(x x). Confirmed: A applied to anything = ω.

    # B(A) = (λa.λb.(a b))(λa.λb.(b b)) = λb.((λa.λb.(b b)) b) = λb.λb'.(b' b')
    # = λb.ω essentially (renaming: λy.λz.(z z))
    BA_reduced = Lam(Lam(App(Var(0), Var(0))))  # same as A_term actually, λa.λb.(b b)
    # Hmm, B(A) = λb.(A b) = λb.(λa.λb.(b b) applied to b) = λb.λb'.(b' b')
    # Under de Bruijn: λ.λ.(Var(0) Var(0)) — same structure as A_term!
    # So B(A) has same structure as A. Interesting but probably not useful.

    test("sys8(B(A)≈A)", make_syscall_qd(8, App(B_term, A_term)))

    # ── SECTION 7: sys8 with readfile result as continuation trick ──
    print("\n[7] Pass sys8 as continuation (sys8 receives readfile result):")
    # readfile(65)(λresult. sys8(result)(QD))
    # Under 1 lambda: result=Var(0), sys8=Var(8+1)=Var(9), QD needs shifting
    # This is tricky. Let's try a simpler version:
    # Just feed the ACTUAL file content to sys8.
    # We know .history(65) = "sodu deluser dloser\nilikephp\nsudo deluser dloser\n"
    history_bytes = encode_bytes_list(
        b"sodu deluser dloser\nilikephp\nsudo deluser dloser\n"
    )
    test("sys8(.history content)", make_syscall_qd(8, history_bytes))

    # dloser mail content
    mail_bytes = encode_bytes_list(
        b"From: mailer@brownos\nTo: dloser@brownos\nSubject: Delivery failure\n\nFailed to deliver following message to boss@evil.com:\n\nBackdoor is ready at syscall 201; start with 00 FE FE.\n"
    )
    # This is probably too big. Let's try a shorter version.
    test("sys8(dloser mail content)", make_syscall_qd(8, mail_bytes))

    print("\n" + "=" * 60)
    print("DONE — All experiments complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
