#!/usr/bin/env python3
"""
Final angles probe: Test patterns we genuinely haven't tried.

ANGLE 1: Non-CPS sys8 invocations
- What if sys8 takes 3 arguments? sys8(arg1)(arg2)(continuation)
- What if sys8 needs to be the CONTINUATION of another syscall?

ANGLE 2: Echo with constructed terms (not just globals)
- echo(A), echo(B), echo(pair(A,B))
- echo(λx.x), echo(λx.xx)

ANGLE 3: Using the backdoor pair as a COMPUTATIONAL tool
- A(B)(sys8) = sys8(sys8) — self-apply sys8?
- B(B)(A) = B(A) = λb. A(b) = λb.λc. c(c)

ANGLE 4: What if sys8's argument must be a LAMBDA (not a global)?
- sys8(λx.x)(QD) — identity as argument
- sys8(λx.xx)(QD) — self-application as argument
- sys8(λa.λb.bb)(QD) — A as argument (manually constructed)
- sys8(λa.λb.ab)(QD) — B as argument

ANGLE 5: What if the program needs EXACTLY 3 nodes total (not 3 Vars)?
"""

import socket
import time
import sys
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE
FF = 0xFF


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


def encode_term(term):
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError


def shift(term, d, c=0):
    if isinstance(term, Var):
        return Var(term.i + d) if term.i >= c else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, d, c + 1))
    if isinstance(term, App):
        return App(shift(term.f, d, c), shift(term.x, d, c))
    raise TypeError


QD_HEX = "0500fd000500fd03fdfefd02fdfefdfe"


def parse_qd():
    stack = []
    for b in bytes.fromhex(QD_HEX):
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
    return stack[0]


QD = parse_qd()

nil = Lam(Lam(Var(0)))
I = Lam(Var(0))  # identity
A = Lam(Lam(App(Var(0), Var(0))))  # λa.λb. bb (Mockingbird)
B = Lam(Lam(App(Var(1), Var(0))))  # λa.λb. ab


def g(n):
    return Var(n)


def send_raw(payload_bytes, timeout_s=8.0):
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload_bytes)
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
    except Exception as e:
        return f"ERROR: {e}".encode()


novel_list = []


def test(label, term):
    payload = encode_term(term) + bytes([FF])
    if len(payload) > 2000:
        print(f"[TOOBIG     ] {label} ({len(payload)} bytes)")
        return "TOOBIG"
    time.sleep(0.42)
    resp = send_raw(payload)
    resp_hex = resp.hex() if resp else "EMPTY"
    resp_text = resp.decode("utf-8", "replace") if resp else ""

    is_perm = "Permission denied" in resp_text
    is_right6 = "00030200fdfd" in resp_hex
    is_empty = len(resp) == 0
    is_invalid = "Invalid term" in resp_text
    is_enc = "Encoding failed" in resp_text
    is_toobig = "Term too big" in resp_text
    is_right2 = "000200fd" in resp_hex and not is_right6  # Right(2) = InvalidArg
    is_right1 = (
        "000100fd" in resp_hex and not is_right6 and not is_right2
    )  # Right(1) = NotImpl
    is_error = resp_text.startswith("ERROR:")

    status = (
        "PERM_DENIED"
        if is_perm
        else "RIGHT6_RAW"
        if is_right6
        else "RIGHT2_RAW"
        if is_right2
        else "RIGHT1_RAW"
        if is_right1
        else "EMPTY"
        if is_empty
        else "INVALID"
        if is_invalid
        else "ENC_FAIL"
        if is_enc
        else "TOO_BIG"
        if is_toobig
        else "CONN_ERR"
        if is_error
        else "*** NOVEL ***"
    )

    print(f"[{status:12s}] {label}")
    if status == "*** NOVEL ***":
        print(f"  !!! BREAKTHROUGH !!!")
        print(f"  Payload: {payload.hex()[:80]}")
        print(f"  Full hex: {resp_hex}")
        print(f"  Full text: {repr(resp_text)}")
        novel_list.append((label, resp_hex, resp_text))
    sys.stdout.flush()
    return status


def test_raw(label, hex_str):
    payload = bytes.fromhex(hex_str)
    time.sleep(0.42)
    resp = send_raw(payload)
    resp_hex = resp.hex() if resp else "EMPTY"
    resp_text = resp.decode("utf-8", "replace") if resp else ""

    is_perm = "Permission denied" in resp_text
    is_right6 = "00030200fdfd" in resp_hex
    is_empty = len(resp) == 0
    is_invalid = "Invalid term" in resp_text

    status = (
        "PERM_DENIED"
        if is_perm
        else "RIGHT6_RAW"
        if is_right6
        else "EMPTY"
        if is_empty
        else "INVALID"
        if is_invalid
        else "*** NOVEL ***"
    )

    print(f"[{status:12s}] {label}")
    if status == "*** NOVEL ***":
        print(f"  !!! BREAKTHROUGH !!!")
        print(f"  Full hex: {resp_hex}")
        print(f"  Full text: {repr(resp_text)}")
        novel_list.append((label, resp_hex, resp_text))
    sys.stdout.flush()
    return status


# ============================================================
print("=" * 70)
print("ANGLE 1: Non-CPS sys8 — what if sys8 takes 3 args?")
print("=" * 70)

# sys8(arg1)(arg2)(QD) — 3-arg CPS
# Maybe sys8 needs BOTH the password AND the backdoor?
test("sys8(nil)(nil)(QD)", App(App(App(g(8), nil), nil), QD))
test("sys8(nil)(g(201))(QD)", App(App(App(g(8), nil), g(201)), QD))
test("sys8(g(201))(nil)(QD)", App(App(App(g(8), g(201)), nil), QD))
test("sys8(g(201))(g(14))(QD)", App(App(App(g(8), g(201)), g(14)), QD))
test("sys8(g(14))(g(201))(QD)", App(App(App(g(8), g(14)), g(201)), QD))

# What if sys8 needs the password as a SECOND argument?
# sys8(nil)("ilikephp")(QD)
# Skip password tests - encode_bytes_list type incompatible
# Already tested sys8 with password in probe_backdoor_auth.py

# ============================================================
print("\n" + "=" * 70)
print("ANGLE 2: sys8 as CONTINUATION of another syscall")
print("What if another syscall must 'unlock' sys8 first?")
print("=" * 70)

# backdoor(nil)(λbd. bd(λpair. sys8(nil)(QD))(λerr. QD(err)))
# The idea: calling backdoor first might set VM state that unlocks sys8
# Even though the backdoor result isn't passed to sys8
QD_s3 = shift(QD, 3)
QD_s2 = shift(QD, 2)
# Under 1 lam (bd): Var(0)=bd
# Under 2 lams (bd, pair): sys8=Var(10), nil needs shift
nil_s2 = shift(nil, 2)
left_h = Lam(App(App(Var(10), nil_s2), QD_s2))  # λpair. sys8(nil)(QD)
right_h = Lam(App(QD_s2, Var(0)))  # λerr. QD(err)
bd_cont = Lam(App(App(Var(0), left_h), right_h))
test("bd(nil) → [ignore pair] → sys8(nil)(QD)", App(App(g(201), nil), bd_cont))

# echo(nil)(λ_. sys8(nil)(QD)) — echo first, then sys8
QD_s1 = shift(QD, 1)
nil_s1 = shift(nil, 1)
echo_then_sys8 = Lam(App(App(Var(9), nil_s1), QD_s1))
test("echo(nil)(λ_. sys8(nil)(QD))", App(App(g(14), nil), echo_then_sys8))

# towel(nil)(λ_. sys8(nil)(QD)) — towel first, then sys8
test("towel(nil)(λ_. sys8(nil)(QD))", App(App(g(42), nil), echo_then_sys8))

# ============================================================
print("\n" + "=" * 70)
print("ANGLE 3: sys8 with LAMBDA arguments (not globals)")
print("=" * 70)

# sys8(I)(QD) where I = λx.x
test("sys8(I)(QD)", App(App(g(8), I), QD))

# sys8(A)(QD) where A = λa.λb.bb
test("sys8(A)(QD)", App(App(g(8), A), QD))

# sys8(B)(QD) where B = λa.λb.ab
test("sys8(B)(QD)", App(App(g(8), B), QD))

# sys8(ω)(QD) where ω = λx.xx (same as A actually)
omega = Lam(App(Var(0), Var(0)))
test("sys8(ω=λx.xx)(QD)", App(App(g(8), omega), QD))

# sys8(K)(QD) where K = λa.λb.a
K = Lam(Lam(Var(1)))
test("sys8(K)(QD)", App(App(g(8), K), QD))

# sys8(S)(QD) where S = λa.λb.λc.ac(bc)
S = Lam(Lam(Lam(App(App(Var(2), Var(0)), App(Var(1), Var(0))))))
test("sys8(S)(QD)", App(App(g(8), S), QD))

# sys8(Church True)(QD) = sys8(K)(QD) — already tested
# sys8(Church False)(QD) = sys8(nil)(QD) — already tested

# sys8(pair(A,B))(QD) — Scott pair of backdoor components
pair_AB = Lam(Lam(App(App(Var(1), A), B)))
test("sys8(pair(A,B))(QD)", App(App(g(8), pair_AB), QD))

# ============================================================
print("\n" + "=" * 70)
print("ANGLE 4: Echo with constructed terms → sys8")
print("=" * 70)

# echo(A)(λleft. sys8(left)(QD))
echo_to_sys8 = Lam(App(App(Var(9), Var(0)), shift(QD, 1)))
test("echo(A)(λl. sys8(l)(QD))", App(App(g(14), A), echo_to_sys8))
test("echo(B)(λl. sys8(l)(QD))", App(App(g(14), B), echo_to_sys8))
test("echo(I)(λl. sys8(l)(QD))", App(App(g(14), I), echo_to_sys8))
test("echo(ω)(λl. sys8(l)(QD))", App(App(g(14), omega), echo_to_sys8))
test("echo(pair(A,B))(λl. sys8(l)(QD))", App(App(g(14), pair_AB), echo_to_sys8))

# ============================================================
print("\n" + "=" * 70)
print("ANGLE 5: What if sys8 needs to be called with NO argument?")
print("sys8(QD) — just one arg, QD as continuation")
print("=" * 70)

# sys8(QD) — partial application, QD is the "argument" not continuation
test("sys8(QD) [1-arg]", App(g(8), QD))

# What about: (λx. x(nil)(QD))(sys8) = sys8(nil)(QD) — same thing
# But what about: QD(sys8) — apply QD to sys8?
test("QD(sys8)", App(QD, g(8)))

# ============================================================
print("\n" + "=" * 70)
print("ANGLE 6: What if the PROGRAM ITSELF is the answer?")
print("What if sys8 reads the bytecode of the program that called it?")
print("=" * 70)

# If sys8 inspects the calling program's bytecode, then the specific
# bytecode pattern matters, not just the semantic meaning.
# What if sys8 needs to see specific bytes in the program?

# Try: a program that contains the bytes "00 FE FE" (from the mail hint)
# as part of its structure, AND calls sys8
# 00 FE FE = nil. So: sys8(nil)(QD) already contains 00 FE FE.
# But what about: 00 FE FE 08 FD QD FD FF
# = App(App(nil, g(8)), QD) = nil(sys8)(QD) = QD
# This reduces to QD, not a sys8 call.

# What if the bytecode must START with 00 FE FE?
# 00 FE FE 08 00 FE FE FD FD QD FD FF
# Parse: 00 → Var(0), FE → Lam(Var(0)), FE → Lam(Lam(Var(0))) = nil
# 08 → Var(8), 00 → Var(0), FE → Lam(Var(0)), FE → Lam(Lam(Var(0))) = nil
# FD → App(nil, Var(8)) ... this gets messy
# Let me just try it:
test_raw(
    "00FEFE prefix: nil 08 nil FD FD QD FD FF", "00fefe0800fefefdfd" + QD_HEX + "fdff"
)

# ============================================================
print("\n" + "=" * 70)
print("ANGLE 7: What if we need to use readfile(8) instead of sys8?")
print("File ID 8 might not be in the directory tree but might exist")
print("=" * 70)

# We know the filesystem has specific IDs. What's at ID 8?
# From the tree: id 1=bin, 2=etc, 3=brownos, 4=var, 5=log, 6=brownos(log),
# 9=sbin, 11=passwd, 14=sh, 15=sudo, 16=false, 22=home, 25=spool, etc.
# ID 8 is NOT listed! Could it be /bin/solution?

from solve_brownos_answer import encode_byte_term as ebt

test("name(8)", App(App(g(6), ebt(8)), QD))
test("readfile(8)", App(App(g(7), ebt(8)), QD))
test("readdir(8)", App(App(g(5), ebt(8)), QD))

# Also check IDs 7, 10, 12, 13 which are gaps in the tree
for fid in [7, 8, 10, 12, 13, 17, 18, 19, 20, 21]:
    test(f"name({fid})", App(App(g(6), ebt(fid)), QD))

# ============================================================
print("\n" + "=" * 70)
print("ANGLE 8: What if sys8 is readfile for a specific path?")
print("sys8 might be 'read /bin/solution' which needs a file ID, not nil")
print("=" * 70)

# What if sys8 expects a FILE ID as argument (like readfile)?
# sys8(int(8))(QD) — file ID 8
for fid in [
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    14,
    15,
    16,
    22,
    25,
    39,
    43,
    46,
    50,
    65,
    88,
    256,
]:
    test(f"sys8(int({fid}))(QD)", App(App(g(8), ebt(fid)), QD))

# ============================================================
print("\n" + "=" * 70)
print(f"SUMMARY: {len(novel_list)} novel responses")
print("=" * 70)
if novel_list:
    for label, hex_resp, text_resp in novel_list:
        print(f"  {label}: {hex_resp[:60]}")
else:
    print("  No novel responses.")
