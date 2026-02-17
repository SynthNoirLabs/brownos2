#!/usr/bin/env python3
"""
KEY INSIGHT from probe results + Oracle analysis:

echo(g(N)) returns Left(g(N)). Left is λl.λr. l(payload).
Under 2 lambdas, g(N) becomes Var(N+2).
So echo(g(251)) creates a term containing Var(253) = 0xFD internally.
echo(g(252)) creates Var(254) = 0xFE internally.
echo(g(253)) would create Var(255) = 0xFF internally.

These terms CANNOT be serialized by quote (hence "Encoding failed!").
But they CAN be passed to other syscalls via CPS chaining!

The Oracle says: sys8 might check for these "impossible" variables.
dloser says: "interesting results when combining the special bytes" with echo.

PLAN: Use echo to create terms with Var(253/254/255) inside,
then pass those terms to sys8 via CPS chaining (NOT via QD observation).

The "3 leafs" program structure:
  echo(g(251))(λleft. sys8(left)(write))
  - 3 key leaves: g(251), sys8, write
  - But the full program has more nodes due to CPS plumbing

OR: The 3-leaf program IS the raw bytecode:
  sys8(echo_result)(write)
  where echo_result is computed at runtime

Let's try ALL combinations of echo → sys8 chaining.
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
    raise TypeError(f"Unknown: {type(term)}")


def send_raw(payload_bytes: bytes, timeout_s: float = 8.0) -> bytes:
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


def send_term(term, label=""):
    payload = encode_term(term) + bytes([FF])
    time.sleep(0.45)
    resp = send_raw(payload)
    resp_hex = resp.hex() if resp else "EMPTY"
    resp_text = ""
    try:
        resp_text = resp.decode("utf-8", "replace")
    except:
        pass

    is_perm_denied = "Permission denied" in resp_text
    is_right6 = "00030200fdfd" in resp_hex
    is_empty = len(resp) == 0
    is_invalid = "Invalid term" in resp_text
    is_encoding_fail = "Encoding failed" in resp_text
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
        if is_encoding_fail
        else "CONN_ERR"
        if is_error
        else "*** NOVEL ***"
    )

    print(f"[{status:12s}] {label}")
    print(f"  Payload hex: {payload.hex()[:100]}")
    if not is_empty:
        print(f"  Resp hex: {resp_hex[:100]}")
    if resp_text and not is_empty:
        safe = resp_text.replace("\n", "\\n")[:80]
        print(f"  Resp txt: {safe}")
    if status == "*** NOVEL ***":
        print(f"  !!! BREAKTHROUGH !!!")
        print(f"  Full hex: {resp_hex}")
        print(f"  Full text: {repr(resp_text)}")
    print()
    sys.stdout.flush()
    return status, resp_hex, resp_text


# Helper terms
nil = Lam(Lam(Var(0)))

# QD as a term (parsed from hex)
QD_HEX = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def parse_term_bytes(data):
    stack = []
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
    return stack[0]


QD = parse_term_bytes(QD_HEX)

# Observer that decodes Either and writes the result
# OBS = λresult. result (λleft. write(quote(left))) (λright. write(quote(right)))
# Simplified: just use QD which does quote→write


def g(n):
    """Global variable reference."""
    return Var(n)


# ============================================================
print("=" * 70)
print("PHASE 1: Echo → CPS chain → sys8")
print("Echo(g(N)) returns Left(g(N)). Pass the Left to sys8 via CPS.")
print("=" * 70)

# Pattern: echo(g(N))(λleft. sys8(left)(QD))
# Under 1 lambda: Var(0)=left (the echo result), Var(9)=g(8)=sys8
# sys8(left)(QD_shifted) = App(App(Var(9), Var(0)), QD_shifted)
# But QD needs to be shifted by 1 under the lambda...
# This is getting complex. Let's build it properly.


def shift(term, d, c=0):
    """Shift free variables in term by d, with cutoff c."""
    if isinstance(term, Var):
        return Var(term.i + d) if term.i >= c else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, d, c + 1))
    if isinstance(term, App):
        return App(shift(term.f, d, c), shift(term.x, d, c))
    raise TypeError


# echo(g(N))(λleft. sys8(left)(QD))
for N in [251, 252, 250, 249, 248, 201, 14, 8, 0]:
    # Build: echo(g(N))(λleft. sys8(left)(QD))
    # Under 1 lambda: sys8 = Var(8+1) = Var(9), left = Var(0)
    QD_shifted = shift(QD, 1)
    cont = Lam(App(App(Var(9), Var(0)), QD_shifted))
    program = App(App(g(14), g(N)), cont)
    label = f"echo(g({N}))(λleft. sys8(left)(QD))"
    send_term(program, label)

print("=" * 70)
print("PHASE 2: Echo → unwrap Left → sys8")
print("Echo returns Left(x). Left = λl.λr. l(x).")
print("Unwrap: echo_result(λpayload. sys8(payload)(QD))(λerr. QD(err))")
print("=" * 70)

for N in [251, 252, 250, 249, 248]:
    # echo(g(N))(λleft. left(λpayload. sys8(payload)(QD))(λerr. QD(err)))
    # Under 1 lambda (left): Var(0)=left
    # Under 2 lambdas (left, payload): Var(0)=payload, Var(10)=g(8)=sys8
    QD_shifted2 = shift(QD, 2)
    left_handler = Lam(App(App(Var(10), Var(0)), QD_shifted2))
    # Under 2 lambdas (left, err): Var(0)=err
    right_handler = Lam(App(shift(QD, 2), Var(0)))
    # Under 1 lambda: Var(0)=left
    unwrap = Lam(App(App(Var(0), left_handler), right_handler))
    program = App(App(g(14), g(N)), unwrap)
    label = f"echo(g({N})) → unwrap Left → sys8(payload)(QD)"
    send_term(program, label)

print("=" * 70)
print("PHASE 3: Echo → pass raw Left to sys8 (no unwrap)")
print("sys8 receives the entire Left(g(N)) closure")
print("=" * 70)

for N in [251, 252, 250, 249, 248]:
    # echo(g(N))(λleft. sys8(left)(QD))
    # Same as Phase 1 but emphasizing: left IS the Left closure, not unwrapped
    QD_shifted = shift(QD, 1)
    cont = Lam(App(App(Var(9), Var(0)), QD_shifted))
    program = App(App(g(14), g(N)), cont)
    label = f"echo(g({N})) → sys8(Left(g({N})))(QD) [raw Left]"
    send_term(program, label)

print("=" * 70)
print("PHASE 4: Backdoor → echo → sys8 chain")
print("backdoor(nil) → echo(pair) → sys8(Left(pair))")
print("=" * 70)

# backdoor(nil)(λbd_result. bd_result(λpair. echo(pair)(λecho_result. sys8(echo_result)(QD)))(λerr. QD(err)))
# This is complex. Let's build step by step.

# Under 1 lambda (bd_result=Var(0)):
#   bd_result is Left(pair(A,B))
#   Unwrap: bd_result(left_handler)(right_handler)
#   left_handler = λpair. echo(pair)(λecho_result. sys8(echo_result)(QD))
#   Under 2 lambdas (bd_result, pair): echo=Var(16)=g(14), pair=Var(0)
#     echo(pair)(λecho_result. sys8(echo_result)(QD))
#     Under 3 lambdas: sys8=Var(11)=g(8), echo_result=Var(0)
QD_s3 = shift(QD, 3)
echo_cont = Lam(App(App(Var(11), Var(0)), QD_s3))  # λecho_result. sys8(echo_result)(QD)
left_handler = Lam(App(App(Var(16), Var(0)), echo_cont))  # λpair. echo(pair)(...)
QD_s2 = shift(QD, 2)
right_handler = Lam(App(QD_s2, Var(0)))  # λerr. QD(err)
unwrap_bd = Lam(App(App(Var(0), left_handler), right_handler))
program = App(App(g(201), nil), unwrap_bd)
label = "backdoor(nil) → unwrap → echo(pair) → sys8(Left(pair))(QD)"
send_term(program, label)

# Simpler: backdoor(nil)(λbd. echo(bd)(λecho. sys8(echo)(QD)))
# Don't unwrap backdoor result - pass entire Either to echo
QD_s2 = shift(QD, 2)
echo_cont2 = Lam(App(App(Var(10), Var(0)), QD_s2))  # λecho. sys8(echo)(QD)
bd_cont = Lam(App(App(Var(15), Var(0)), echo_cont2))  # λbd. echo(bd)(...)
program2 = App(App(g(201), nil), bd_cont)
label2 = "backdoor(nil)(λbd. echo(bd)(λecho. sys8(echo)(QD)))"
send_term(program2, label2)

print("=" * 70)
print("PHASE 5: Direct sys8 with echo-produced terms (no CPS)")
print("Build the term in lambda calculus, pass to sys8")
print("=" * 70)

# What if we need to pass echo's Left result DIRECTLY to sys8?
# echo(g(251)) produces Left(g(251)) which internally has Var(253)
# Can we construct: sys8(Left(g(251)))(QD)?
# Left(g(251)) = Lam(Lam(App(Var(1), Var(253))))
# But Var(253) can't be encoded in bytecode! (253 = 0xFD = App marker)
# So we MUST use echo at runtime to create this term.

# Alternative: use echo INSIDE the argument position
# sys8(echo(g(251)))(QD) — but echo returns Left, and sys8 gets a partially-applied echo
# Actually: echo is a syscall, so echo(g(251)) in CPS = ((echo g(251)) continuation)
# We can't just nest it as an argument...

# Unless we use a thunk: sys8(λk. echo(g(251))(k))(QD)
# Under 1 lambda (k=Var(0)): echo=Var(15), g(251)=Var(252)
thunk = Lam(App(App(Var(15), Var(252)), Var(0)))
program = App(App(g(8), thunk), QD)
label = "sys8(λk. echo(g(251))(k))(QD) [thunk]"
send_term(program, label)

# sys8(λk. echo(g(252))(k))(QD)
thunk2 = Lam(App(App(Var(15), Var(253)), Var(0)))
# Wait - Var(253) = 0xFD = App marker! Can't encode this!
# So we can't even BUILD this thunk in bytecode.
# This is the fundamental problem: we can't reference g(252) under a lambda
# because Var(253) = FD.

# But we CAN reference g(251) under 1 lambda: Var(252) = 0xFC (last valid byte)
# And g(250) under 1 lambda: Var(251) = 0xFB
# And g(249) under 1 lambda: Var(250) = 0xFA

# What about g(251) under 0 lambdas? Var(251) = 0xFB — valid!
# echo(g(251)) at top level: echo = Var(14), g(251) = Var(251)
# This works! And produces Left(g(251)) with internal Var(253)

print("=" * 70)
print("PHASE 6: The KEY insight - echo creates unserializable terms")
print("echo(g(251)) → Left containing Var(253)=FD")
print("echo(g(252)) → Left containing Var(254)=FE")
print("Pass these to sys8 via CPS WITHOUT serialization")
print("=" * 70)

# The critical test: echo(g(N)) → pass Left to sys8 → observe with WRITE not QD
# Because QD uses quote which FAILS on these terms!
# We need a continuation that doesn't use quote.

# Simple write continuation: λresult. write(result)
# But write expects a byte list, not a term...
# We need: λresult. result(λleft. write("LEFT"))(λright. write("RIGHT:" + error_code))

# Actually, the simplest test: does sys8 return something OTHER than Right(6)?
# We can check by having the continuation apply the result to two handlers:
# result(λl. write("L"))(λr. write("R" + r))

# Even simpler: echo(g(N))(λleft. sys8(left)(λresult. result(λl. write_string("SUCCESS"))(λr. write_string("DENIED"))))

# Let's use a simpler approach: write a single byte based on the result
# If Left: write "L", if Right: write "R"

# Scott byte for 'L' = 76 = 0x4C
# encode_byte_term(76) is complex... let's use a simpler marker

# Actually, let's just use the OBS pattern from solve_brownos_answer.py
# which decodes Either and writes the result as text

# Simplest possible: echo(g(N))(λleft. sys8(left)(λresult. write(quote(result))))
# Under 2 lambdas: write=Var(4), quote=Var(6), result=Var(0)
# write(quote(result)) = App(Var(4), App(Var(6), Var(0)))
write_quote_result = Lam(App(Var(4), App(Var(6), Var(0))))
# Under 1 lambda: sys8=Var(9), left=Var(0)
sys8_with_wq = Lam(App(App(Var(9), Var(0)), write_quote_result))
# Top level: echo=g(14), g(N)
for N in [251, 252, 250, 249, 248]:
    program = App(App(g(14), g(N)), sys8_with_wq)
    label = f"echo(g({N}))(λleft. sys8(left)(λr. write(quote(r))))"
    send_term(program, label)

print("=" * 70)
print("PHASE 7: Echo chain - echo(echo(g(N))) double wrapping")
print("=" * 70)

# echo(g(249))(λleft1. echo(left1)(λleft2. sys8(left2)(QD)))
# Under 1 lambda: echo=Var(15), left1=Var(0)
# Under 2 lambdas: sys8=Var(10), left2=Var(0)
QD_s2 = shift(QD, 2)
inner_cont = Lam(App(App(Var(10), Var(0)), QD_s2))
outer_cont = Lam(App(App(Var(15), Var(0)), inner_cont))
for N in [249, 250, 251, 248]:
    program = App(App(g(14), g(N)), outer_cont)
    label = f"echo(g({N}))(λl1. echo(l1)(λl2. sys8(l2)(QD)))"
    send_term(program, label)

print("=" * 70)
print("PHASE 8: Backdoor pair components via echo → sys8")
print("backdoor(nil) → extract A → echo(A) → sys8")
print("=" * 70)

# backdoor(nil)(λbd. bd(λpair. pair(λa.λb. echo(a)(λea. sys8(ea)(QD)))(...))(λerr. ...))
# This is getting very complex. Let's try a simpler approach:
# backdoor(nil)(λbd. bd(λpair. echo(pair)(λep. sys8(ep)(QD)))(λerr. QD(err)))

# Under 1 lambda (bd=Var(0)):
# bd is Left(pair(A,B))
# bd(left_handler)(right_handler)
# left_handler = λpair. echo(pair)(λep. sys8(ep)(QD))
# Under 2 lambdas: echo=Var(16), pair=Var(0)
# Under 3 lambdas: sys8=Var(11), ep=Var(0)
QD_s3 = shift(QD, 3)
ep_cont = Lam(App(App(Var(11), Var(0)), QD_s3))
left_h = Lam(App(App(Var(16), Var(0)), ep_cont))
QD_s2 = shift(QD, 2)
right_h = Lam(App(QD_s2, Var(0)))
bd_unwrap = Lam(App(App(Var(0), left_h), right_h))
program = App(App(g(201), nil), bd_unwrap)
label = "bd(nil) → unwrap Left → echo(pair) → sys8(echo_result)(QD)"
send_term(program, label)

# Also try: extract A from pair, echo(A), sys8
# pair(A,B) = cons(A,B) = λc.λn. c(A)(B)
# pair(λa.λb.a)(anything) = A
# So: bd(nil)(λbd. bd(λpair. pair(λa.λb.a)(nil)... → gets A
# Then echo(A)(λea. sys8(ea)(QD))

# Under 1 lambda (bd): bd=Var(0)
# Under 2 lambdas (bd, pair): pair=Var(0)
# pair is Scott cons: λc.λn. c(head)(tail)
# pair(fst)(snd) where fst=λa.λb.a, snd=anything
# Under 3 lambdas (bd, pair, extracted_a):
# Actually this is getting too nested. Let's try the direct approach.

# Direct: backdoor(nil)(λbd. bd(λpair. pair(λh.λt. echo(h)(λeh. sys8(eh)(QD)))(_))(λerr._))
# Too complex. Let's try something simpler.

print("=" * 70)
print("PHASE 9: The SIMPLEST possible echo→sys8 chain")
print("Just 3 leaves in the core: echo, g(N), sys8")
print("=" * 70)

# What if the "3 leafs" program is literally:
# echo(g(N))(sys8)
# = sys8(Left(g(N)))
# This has 3 leaves: g(14)=echo, g(N), g(8)=sys8
# Bytecode: 0E XX FD 08 FD FF (6 bytes, 3 var bytes)

for N in [251, 252, 250, 249, 248, 201, 0, 1, 2, 4, 5, 7, 8, 14, 42]:
    payload = bytes([0x0E, N, FD, 0x08, FD, FF])
    time.sleep(0.4)
    resp = send_raw(payload)
    resp_hex = resp.hex() if resp else "EMPTY"
    resp_text = ""
    try:
        resp_text = resp.decode("utf-8", "replace")
    except:
        pass
    is_empty = len(resp) == 0
    status = (
        "EMPTY"
        if is_empty
        else "PERM_DENIED"
        if "Permission denied" in resp_text
        else "ENC_FAIL"
        if "Encoding failed" in resp_text
        else "*** NOVEL ***"
    )
    print(f"[{status:12s}] echo(g({N}))(sys8) raw | hex: {resp_hex[:60]}")
    if status == "*** NOVEL ***":
        print(f"  !!! Full: {resp_hex} | {repr(resp_text)}")
    sys.stdout.flush()

print()

# What about: backdoor(g(N))(sys8)?
# 3 leaves: g(201), g(N), g(8)
for N in [0, 14, 251, 252]:
    payload = bytes([0xC9, N, FD, 0x08, FD, FF])
    time.sleep(0.4)
    resp = send_raw(payload)
    resp_hex = resp.hex() if resp else "EMPTY"
    is_empty = len(resp) == 0
    resp_text = resp.decode("utf-8", "replace") if resp else ""
    status = (
        "EMPTY"
        if is_empty
        else "PERM_DENIED"
        if "Permission denied" in resp_text
        else "*** NOVEL ***"
    )
    print(f"[{status:12s}] backdoor(g({N}))(sys8) raw | hex: {resp_hex[:60]}")
    if status == "*** NOVEL ***":
        print(f"  !!! Full: {resp_hex} | {repr(resp_text)}")
    sys.stdout.flush()

print()
print("=" * 70)
print("PHASE 10: sys8(echo)(continuation) - echo AS the argument")
print("=" * 70)

# What if sys8 needs the echo FUNCTION itself as the argument?
# sys8(g(14))(QD) — already tested, returns Right(6)
# But what about sys8(g(14))(write)?
# 3 leaves: g(8), g(14), g(2)
payload = bytes([0x08, 0x0E, FD, 0x02, FD, FF])
time.sleep(0.4)
resp = send_raw(payload)
print(f"sys8(echo)(write) raw: {resp.hex() if resp else 'EMPTY'}")

# sys8(g(14))(backdoor)?
payload = bytes([0x08, 0x0E, FD, 0xC9, FD, FF])
time.sleep(0.4)
resp = send_raw(payload)
print(f"sys8(echo)(backdoor) raw: {resp.hex() if resp else 'EMPTY'}")

# sys8(g(14))(echo)?
payload = bytes([0x08, 0x0E, FD, 0x0E, FD, FF])
time.sleep(0.4)
resp = send_raw(payload)
print(f"sys8(echo)(echo) raw: {resp.hex() if resp else 'EMPTY'}")

print()
print("=" * 70)
print("DONE")
print("=" * 70)
