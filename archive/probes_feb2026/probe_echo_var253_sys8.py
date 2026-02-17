#!/usr/bin/env python3
"""
CRITICAL INSIGHT: What if sys8 checks whether its argument IS a specific
internal VM value that can only be created via echo?

echo(g(251)) creates Left(g(251)). Inside the Left closure, g(251) becomes
Var(253) = the App structural byte. This term CANNOT be serialized.

But what if sys8 doesn't check the argument VALUE — it checks the argument
IDENTITY? Like, sys8 checks if the argument is literally the echo syscall's
internal Left wrapper?

Or: what if sys8 needs to receive a term that, when reduced, produces
a specific pattern involving Var(253/254/255)?

Let's try EVERY possible way to get echo-produced terms into sys8:

1. echo(g(N)) → pass Left directly to sys8 (already tried, Right(6))
2. echo(g(N)) → unwrap Left → pass payload to sys8 (already tried, Right(6))
3. echo(g(N)) → pass to sys8 as CONTINUATION (not argument!)
4. echo(g(N)) → apply Left to sys8 (Left(g(N))(sys8) = sys8(g(N+2)))
5. Multiple echo chains creating deeper nesting
6. echo(backdoor_result) → sys8
7. Use echo to create a FUNCTION that sys8 recognizes

KEY REALIZATION: Left(x)(f)(g) = f(x). So:
- echo(g(251))(sys8) = sys8(g(251)) — but under echo's CPS, this is
  actually sys8 receiving the Left closure, not the unwrapped payload!

Wait, no. In CPS: echo(g(251))(continuation) means the continuation
receives Left(g(251)). So:
- echo(g(251))(sys8) means sys8 receives Left(g(251)) as its argument.
  Then sys8(Left(g(251)))(???) — but there's no continuation for sys8!

Actually in the raw 3-leaf form: 0E FB FD 08 FD FF
This is App(App(Var(14), Var(251)), Var(8))
= echo(g(251))(g(8))
In CPS: echo gets g(251) as argument, g(8) as continuation.
echo returns Left(g(251)), then calls g(8)(Left(g(251))).
g(8) = sys8, so this becomes sys8(Left(g(251))).
But sys8 needs TWO arguments in CPS: sys8(arg)(continuation).
So sys8(Left(g(251))) is a PARTIAL APPLICATION — sys8 waiting for its continuation.
This partial application is then... returned? To nobody? → EMPTY.

So the 3-leaf program echo(g(251))(sys8) creates sys8(Left(g(251))) but
never provides sys8's continuation. That's why it's EMPTY.

What if we provide sys8's continuation as a 4th element?
echo(g(251))(λleft. sys8(left)(QD))
This has more than 3 leaves but the CORE is 3 leaves.

OR: What if the "3 leafs" refers to a program where echo's continuation
IS sys8, and sys8's continuation IS write?

echo(g(251))(λleft. left(sys8)(write))
= Left(g(251))(sys8)(write)
= sys8(g(253))(write)
= sys8(Var(253))(write)

Under the Left's 2 lambdas, g(251) becomes Var(253).
So Left(g(251))(f)(g) = f(g(251+2)) = f(Var(253)).
Then sys8(Var(253)) is sys8 with Var(253) as argument!
And write is the continuation!

But Var(253) at this point... what IS it? Under the Left's lambdas,
Var(253) refers to a free variable. When Left is applied to sys8 and write,
the lambdas are consumed, and Var(253) becomes... Var(253-2) = Var(251) = g(251)?
No wait, that's not how De Bruijn works.

Let me think again:
Left(x) = λl.λr. l(x)
Left(g(251)) = λl.λr. l(g(251))

But g(251) at top level is Var(251). Under 2 lambdas (l and r),
free variables shift by +2. So inside the Left closure:
Var(251) at top level → Var(253) inside the closure.

When we apply Left(g(251)) to f:
(λl.λr. l(Var(253)))(f) = λr. f(Var(252))
Wait, substituting l=f means Var(253) shifts... no.

Actually in De Bruijn:
Left(g(251)) = Lam(Lam(App(Var(1), Var(253))))

Apply to f: substitute Var(1) → f (shifted), and Var(253) → Var(252)
(because we remove one lambda, all free vars decrease by 1)
Result: Lam(App(f', Var(252)))
where f' is f shifted appropriately.

Apply to g: substitute, Var(252) → Var(251)
Result: App(f'', Var(251))
= f(g(251))

So Left(g(251))(f)(g) = f(g(251)). The +2 shift cancels out!
The payload is just g(251) again. No magic Var(253).

THIS IS WHY echo→sys8 doesn't work differently from direct sys8(g(251)).
The De Bruijn shifting is an ENCODING artifact, not a semantic difference.

So the "special bytes" insight must be about something ELSE.

Let me reconsider: what if "combining the special bytes" means using
FD, FE, FF as LITERAL BYTES in the bytecode stream in unusual positions?

What if there's a parser bug? What if certain byte sequences are
parsed differently than expected?

Let's try some unusual bytecode patterns:
"""

import socket
import time
import sys

HOST = "wc3.wechall.net"
PORT = 61221
FF = 0xFF


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


def test_raw(label, payload_hex):
    payload = bytes.fromhex(payload_hex)
    time.sleep(0.45)
    resp = send_raw(payload)
    resp_hex = resp.hex() if resp else "EMPTY"
    resp_text = resp.decode("utf-8", "replace") if resp else ""

    is_empty = len(resp) == 0
    is_perm = "Permission denied" in resp_text
    is_right6 = "00030200fdfd" in resp_hex
    is_invalid = "Invalid term" in resp_text
    is_enc = "Encoding failed" in resp_text
    is_toobig = "Term too big" in resp_text

    status = (
        "PERM_DENIED"
        if is_perm
        else "RIGHT6_RAW"
        if is_right6
        else "EMPTY"
        if is_empty
        else "INVALID"
        if is_invalid
        else "ENC_FAIL"
        if is_enc
        else "TOO_BIG"
        if is_toobig
        else "*** NOVEL ***"
    )

    print(f"[{status:12s}] {label}")
    if not is_empty:
        print(f"  hex: {resp_hex[:80]}")
    if status == "*** NOVEL ***":
        print(f"  !!! BREAKTHROUGH !!!")
        print(f"  Full hex: {resp_hex}")
        print(f"  Full text: {repr(resp_text)}")
    sys.stdout.flush()
    return status


# QD hex
QD = "0500fd000500fd03fdfefd02fdfefdfe"

print("=" * 70)
print("PHASE 1: Parser edge cases - unusual FD/FE/FF combinations")
print("=" * 70)

# What if we put FE FE (double lambda) in unusual positions?
# FE FE at the start: Lam(Lam(...)) — needs something on stack first
# 00 FE FE = Lam(Lam(Var(0))) = nil — normal

# What about FD FD (double application)?
# Needs 3+ items on stack
# 00 01 02 FD FD = App(App(Var(0), Var(1)), Var(2)) — wait, that's wrong
# Stack: [0, 1, 2] → FD → [0, App(1,2)] → FD → [App(0, App(1,2))]
# = App(Var(0), App(Var(1), Var(2)))
# Actually: 00 01 FD 02 FD = App(App(Var(0), Var(1)), Var(2))
# And: 00 01 02 FD FD = App(Var(0), App(Var(1), Var(2)))

# What about FE FD? Lambda then application?
# Stack: [..., body] → FE → [..., Lam(body)] → needs another item for FD
# 00 FE 01 FD = App(Lam(Var(0)), Var(1)) — beta redex!

# What about multiple FFs?
test_raw("Double FF: 08 00 FE FE FD FF FF", "0800fefefdffff")
test_raw("Triple FF: 08 FF FF FF", "08ffffff")

# What about no FF?
# Can't test — client would hang waiting for response

# What about FE FD FE patterns?
test_raw("FE FD FE: 00 01 FD FE 02 FD FE FF", "0001fdfe02fdfeff")

# What about using byte 0xFC (252) which is the LAST valid variable byte?
# Var(252) = g(252) — what syscall is this?
test_raw("g(252)(nil)(QD)", "fc00fefefd" + QD + "fdff")
test_raw("g(253 via FD?)", "fd" + QD + "fdff")  # FD is App, not Var!

print()
print("=" * 70)
print("PHASE 2: What if there are HIDDEN SYSCALLS beyond 252?")
print("g(252) is the highest addressable global. What does it do?")
print("=" * 70)

# Test g(N)(nil)(QD) for N near the boundary
for n in range(240, 253):
    test_raw(f"g({n})(nil)(QD)", f"{n:02x}00fefefd" + QD + "fdff")

print()
print("=" * 70)
print("PHASE 3: What if we need to use MULTIPLE syscalls in sequence?")
print("backdoor(nil)(λpair. sys8(pair)(QD))")
print("This passes the ENTIRE Left(pair(A,B)) to sys8")
print("=" * 70)

# We've tested this but let me verify the exact bytecode
# backdoor(nil)(λresult. sys8(result)(QD))
# Under 1 lambda: result=Var(0), sys8=Var(9)
# QD shifted by 1: each Var in QD increases by 1
# QD = 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
# QD shifted: 06 01 FD 01 06 01 FD 04 FD FE FD 03 FD FE FD FE
QD_s1 = "0601fd010601fd04fdfefd03fdfefdfe"
# Body: App(App(Var(9), Var(0)), QD_shifted)
# = 09 00 FD QD_s1 FD
# Full: λ(body) = 09 00 FD QD_s1 FD FE
# Program: C9 00 FE FE FD (09 00 FD QD_s1 FD FE) FD FF
program_hex = "c900fefefd" + "0900fd" + QD_s1 + "fdfe" + "fdff"
test_raw("bd(nil)(λr. sys8(r)(QD)) [pass entire Left to sys8]", program_hex)

# What about: backdoor(nil)(λresult. result(λpayload. sys8(payload)(QD))(λerr. QD(err)))
# This UNWRAPS the Left, extracting pair(A,B), then passes pair to sys8
# Under 1 lambda: result=Var(0)
# Under 2 lambdas (result, payload): sys8=Var(10), payload=Var(0)
# QD shifted by 2
QD_s2 = "0702fd020702fd05fdfefd04fdfefdfe"
# left_handler = λpayload. sys8(payload)(QD_s2)
# = 0a 00 FD QD_s2 FD FE
left_handler = "0a00fd" + QD_s2 + "fdfe"
# right_handler = λerr. QD_s2(err)
right_handler = QD_s2 + "00fdfe"
# Body: result(left_handler)(right_handler)
# = 00 left_handler FD right_handler FD
body = "00" + left_handler + "fd" + right_handler + "fd"
# Full continuation: λresult. body = body FE
cont = body + "fe"
# Program: C9 00 FE FE FD cont FD FF
program_hex2 = "c900fefefd" + cont + "fdff"
test_raw("bd(nil) → unwrap Left → sys8(pair(A,B))(QD)", program_hex2)

print()
print("=" * 70)
print("PHASE 4: What if the 3-leaf program uses WRITE directly?")
print("Instead of QD, use write as continuation")
print("sys8(arg)(write) — write receives sys8's result")
print("=" * 70)

# sys8(nil)(write) = write(Right(6)) — but Right(6) is not a byte list!
# So write would return InvalidArg
# But what if sys8 succeeds and returns Left(solution_bytes)?
# Then write(Left(solution_bytes)) — still not a byte list...
# Unless the solution IS a byte list wrapped in Left

# Let's try anyway
for arg_byte in [0x00, 0xC9, 0x0E, 0x2A, 0xFB, 0xFC]:
    # sys8(g(arg))(write) = 08 XX FD 02 FD FF
    test_raw(f"sys8(g({arg_byte}))(write)", f"08{arg_byte:02x}fd02fdff")

print()
print("=" * 70)
print("PHASE 5: What if we need to call sys8 with g(0) (exception handler)?")
print("g(0) might set up an exception context that changes sys8's behavior")
print("=" * 70)

# g(0)(handler)(body) — if body throws, handler is called
# What if: g(0)(λex. write(ex))(sys8(nil))
# = try { sys8(nil) } catch(ex) { write(ex) }
# Under 1 lambda (handler context): sys8=Var(9), nil needs shifting
# Actually g(0) is the exception syscall, not try/catch
# g(0)(handler)(thunk)(QD) — unclear semantics

# Let's try: g(0)(sys8)(nil)(QD)
test_raw("g(0)(sys8)(nil)(QD)", "0008fd00fefefd" + QD + "fdff")

# g(0)(nil)(sys8)(QD) — different order
test_raw("g(0)(nil)(sys8)(QD)", "0000fefefd08fd" + QD + "fdff")

# What about: sys8(g(0))(QD)
test_raw("sys8(g(0))(QD)", "0800fd" + QD + "fdff")

print()
print("=" * 70)
print("PHASE 6: Brute force ALL 3-leaf 6-byte programs with QD")
print("Shape: a b FD QD FD FF (sys8-like CPS with QD)")
print("Only test a=8 with ALL possible b values 0-252")
print("=" * 70)

# We've tested key values but not ALL 253 possible b values
# Let's be systematic: sys8(g(b))(QD) for b = 0..252
novel_count = 0
for b in range(253):
    status = test_raw(f"sys8(g({b}))(QD)", f"08{b:02x}fd" + QD + "fdff")
    if status == "*** NOVEL ***":
        novel_count += 1

print(f"\nNovel responses from sys8 sweep: {novel_count}")

print()
print("=" * 70)
print("DONE")
print("=" * 70)
