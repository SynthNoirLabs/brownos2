#!/usr/bin/env python3
"""
What if the backdoor has a second mode?
- backdoor(nil) returns pair(A,B) — we know this
- What if backdoor(password_string) does something different?
- What if backdoor(pair(password, nil)) works?
- What if we need to call backdoor with the password "ilikephp" encoded as a byte list?

Also: what if we need to call sys8 with the password?
We tested sys8("ilikephp") before but maybe the encoding was wrong.

And: what if we need to use the backdoor pair (A,B) to BUILD a specific term
that acts as a key for sys8?
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


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def encode_byte_term(n):
    expr = Var(0)
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
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_bytes_list(bs):
    nil = Lam(Lam(Var(0)))

    def cons(h, t):
        return Lam(Lam(App(App(Var(1), h), t)))

    cur = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


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


def test(label, term):
    payload = encode_term(term) + bytes([FF])
    if len(payload) > 2000:
        print(f"[TOOBIG     ] {label} ({len(payload)} bytes)")
        return "TOOBIG", "", ""
    time.sleep(0.45)
    resp = send_raw(payload)
    resp_hex = resp.hex() if resp else "EMPTY"
    resp_text = resp.decode("utf-8", "replace") if resp else ""

    is_perm_denied = "Permission denied" in resp_text
    is_right6 = "00030200fdfd" in resp_hex
    is_empty = len(resp) == 0
    is_invalid = "Invalid term" in resp_text
    is_enc_fail = "Encoding failed" in resp_text
    is_toobig = "Term too big" in resp_text
    is_error = resp_text.startswith("ERROR:")

    status = (
        "PERM_DENIED"
        if is_perm_denied
        else "RIGHT6_RAW"
        if is_right6
        else "EMPTY"
        if is_empty
        else "INVALID"
        if is_invalid
        else "ENC_FAIL"
        if is_enc_fail
        else "TOO_BIG"
        if is_toobig
        else "CONN_ERR"
        if is_error
        else "*** NOVEL ***"
    )

    print(f"[{status:12s}] {label}")
    if not is_empty:
        print(f"  hex: {resp_hex[:80]}")
    if resp_text and not is_empty:
        safe = resp_text.replace("\n", "\\n")[:80]
        print(f"  txt: {safe}")
    if status == "*** NOVEL ***":
        print(f"  !!! BREAKTHROUGH !!!")
        print(f"  Full: {resp_hex}")
        print(f"  Text: {repr(resp_text)}")
    print()
    sys.stdout.flush()
    return status, resp_hex, resp_text


def g(n):
    return Var(n)


# ============================================================
print("=" * 70)
print("PHASE 1: Backdoor with password string")
print("=" * 70)

password = encode_bytes_list(b"ilikephp")
test("backdoor('ilikephp')(QD)", App(App(g(201), password), QD))

# What about just the password without encoding as byte list?
# Try passing the raw string bytes as a Scott list
test("backdoor(nil)(QD) [baseline]", App(App(g(201), nil), QD))

# ============================================================
print("=" * 70)
print("PHASE 2: sys8 with password string")
print("=" * 70)

test("sys8('ilikephp')(QD)", App(App(g(8), password), QD))

# ============================================================
print("=" * 70)
print("PHASE 3: Backdoor → use pair to call sys8")
print("The pair (A,B) where A=λa.λb.bb, B=λa.λb.ab")
print("What if we need to apply A or B to sys8 or the password?")
print("=" * 70)

# A = λa.λb. b b (Mockingbird / self-application)
# B = λa.λb. a b (regular application)
A = Lam(Lam(App(Var(0), Var(0))))
B = Lam(Lam(App(Var(1), Var(0))))

# A(sys8)(password) = password(password) — self-applies password (diverges?)
# B(sys8)(password) = sys8(password) — just applies sys8 to password!
# B(sys8)(password)(QD) = sys8(password)(QD) — standard CPS!

# But we already tested sys8(password)(QD)... unless B does something special
# because it's the KERNEL-MINTED B, not our manually constructed one?

# Let's test with the ACTUAL backdoor-extracted B:
# backdoor(nil)(λresult. result(λpair. pair(λhead.λtail.
#   B_from_pair(sys8)(password)(QD)
# ))(λerr. QD(err)))

# Actually, let's test: does B(g(8))(password)(QD) work?
# B = λa.λb. a b, so B(g(8)) = λb. g(8)(b) = λb. sys8(b)
# B(g(8))(password) = sys8(password)
# B(g(8))(password)(QD) = sys8(password)(QD)
# This is IDENTICAL to sys8(password)(QD). No difference.

# But what if we use the RUNTIME-EXTRACTED B from the backdoor?
# backdoor(nil)(λbd_result. bd_result(λpair. pair(λa.λb. b(g(8))(password)(QD)))(λerr. QD(err)))

# Under 1 lambda (bd_result): Var(0)=bd_result
# bd_result is Left(pair(A,B))
# Left(x)(handler)(err_handler) = handler(x)
# So: bd_result(left_handler)(right_handler)

# left_handler = λpair. pair(λa.λb. b(g(8))(password)(QD))
# Under 2 lambdas: pair=Var(0)
# pair is Scott cons: λc.λn. c(head)(tail)
# pair(selector) = selector(A)(B)
# selector = λa.λb. b(g(8))(password)(QD)
# Under 4 lambdas (bd_result, pair, a, b):
#   b=Var(0), a=Var(1), g(8)=Var(12), password needs shifting by 4


def shift(term, d, c=0):
    if isinstance(term, Var):
        return Var(term.i + d) if term.i >= c else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, d, c + 1))
    if isinstance(term, App):
        return App(shift(term.f, d, c), shift(term.x, d, c))
    raise TypeError


# This is getting complex. Let me try a simpler approach:
# Just manually construct the chain.

# backdoor(nil)(λbd. bd(λpair. pair(λa.λb. BODY)(nil))(λerr. QD(err)))
# where BODY uses a and b (the backdoor components)

# Test 1: Use B to call sys8
# B(sys8)(nil)(QD) = sys8(nil)(QD)
# Under 4 lambdas: b=Var(0), a=Var(1), sys8=Var(12)
# b(sys8)(nil)(QD) = Var(0)(Var(12))(nil_shifted)(QD_shifted)
QD_s4 = shift(QD, 4)
nil_s4 = shift(nil, 4)
body1 = App(App(App(Var(0), Var(12)), nil_s4), QD_s4)
selector1 = Lam(Lam(body1))  # λa.λb. b(sys8)(nil)(QD)
left_handler1 = Lam(App(App(Var(0), selector1), shift(nil, 2)))
QD_s2 = shift(QD, 2)
right_handler1 = Lam(App(QD_s2, Var(0)))
bd_cont1 = Lam(App(App(Var(0), left_handler1), right_handler1))
program1 = App(App(g(201), nil), bd_cont1)
test("bd(nil) → extract B → B(sys8)(nil)(QD)", program1)

# Test 2: Use A to self-apply sys8
# A(sys8)(nil)(QD) = nil(nil)(QD) = QD (nil selects 2nd arg)
# Under 4 lambdas: a=Var(1), sys8=Var(12)
body2 = App(App(App(Var(1), Var(12)), nil_s4), QD_s4)
selector2 = Lam(Lam(body2))
left_handler2 = Lam(App(App(Var(0), selector2), shift(nil, 2)))
bd_cont2 = Lam(App(App(Var(0), left_handler2), right_handler1))
program2 = App(App(g(201), nil), bd_cont2)
test("bd(nil) → extract A → A(sys8)(nil)(QD)", program2)

# Test 3: Use B to call sys8 with password
# B(sys8)(password)(QD)
password_s4 = shift(password, 4)
body3 = App(App(App(Var(0), Var(12)), password_s4), QD_s4)
selector3 = Lam(Lam(body3))
left_handler3 = Lam(App(App(Var(0), selector3), shift(nil, 2)))
bd_cont3 = Lam(App(App(Var(0), left_handler3), right_handler1))
program3 = App(App(g(201), nil), bd_cont3)
test("bd(nil) → extract B → B(sys8)(password)(QD)", program3)

# ============================================================
print("=" * 70)
print("PHASE 4: What if backdoor needs the password as argument?")
print("backdoor(password)(QD) instead of backdoor(nil)(QD)")
print("=" * 70)

# We know backdoor(non-nil) returns Right(2) = InvalidArg
# But what if there's a SPECIFIC non-nil argument that works?
# The mail says "start with 00 FE FE" = nil. But what if that's a red herring?

# Test backdoor with password
test("backdoor('ilikephp')(QD)", App(App(g(201), password), QD))

# Test backdoor with Church numerals
for n in [1, 2, 8, 42, 201]:
    church_n = encode_byte_term(n)
    test(f"backdoor(int({n}))(QD)", App(App(g(201), church_n), QD))

# ============================================================
print("=" * 70)
print("PHASE 5: What if we need to call sys8 with the CRYPT HASH?")
print("=" * 70)

crypt_hash = encode_bytes_list(b"GZKc.2/VQffio")
test("sys8('GZKc.2/VQffio')(QD)", App(App(g(8), crypt_hash), QD))

# What about the full passwd line?
passwd_line = encode_bytes_list(
    b"gizmore:GZKc.2/VQffio:1000:1000:Gizmore:/home/gizmore:/bin/sh"
)
test("sys8(passwd_line)(QD)", App(App(g(8), passwd_line), QD))

# ============================================================
print("=" * 70)
print("PHASE 6: What if sys8 needs a PAIR of (password, something)?")
print("=" * 70)


# Scott pair: λc.λn. c(fst)(snd)
def scott_pair(fst, snd):
    return Lam(Lam(App(App(Var(1), fst), snd)))


# sys8(pair(password, nil))(QD)
test("sys8(pair(password, nil))(QD)", App(App(g(8), scott_pair(password, nil)), QD))

# sys8(pair(nil, password))(QD)
test("sys8(pair(nil, password))(QD)", App(App(g(8), scott_pair(nil, password)), QD))

# sys8(pair(password, password))(QD)
test(
    "sys8(pair(password, password))(QD)",
    App(App(g(8), scott_pair(password, password)), QD),
)

# ============================================================
print("=" * 70)
print("PHASE 7: What if we need to use the password WITH the backdoor pair?")
print("sys8(pair(A, password))(QD) or sys8(pair(password, B))(QD)")
print("=" * 70)

test("sys8(pair(A, password))(QD)", App(App(g(8), scott_pair(A, password)), QD))

test("sys8(pair(password, B))(QD)", App(App(g(8), scott_pair(password, B)), QD))

test("sys8(pair(A, B))(QD) [baseline]", App(App(g(8), scott_pair(A, B)), QD))

# ============================================================
print("=" * 70)
print("PHASE 8: What if the answer is in the ACCESS LOG?")
print("The access log changes per connection - maybe it contains a clue")
print("=" * 70)

# Read access log multiple times to see if it changes
for i in range(3):
    time.sleep(0.5)
    program = App(App(g(7), encode_byte_term(46)), QD)
    payload = encode_term(program) + bytes([FF])
    resp = send_raw(payload)
    if resp:
        from solve_brownos_answer import (
            parse_term as pt,
            decode_either as de,
            decode_bytes_list as dbl,
        )

        term = pt(resp)
        tag, payload_term = de(term)
        if tag == "Left":
            content = dbl(payload_term)
            print(
                f"  Access log read {i + 1}: {content.decode('utf-8', 'replace').strip()}"
            )

print()
print("=" * 70)
print("DONE")
print("=" * 70)
