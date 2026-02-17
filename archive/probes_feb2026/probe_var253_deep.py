#!/usr/bin/env python3
"""
probe_var253_deep.py — Deep investigation of Var(253)/Var(254)/Var(255)

KEY INSIGHT: echo(g(251)) creates Left(Var(253)) internally.
Var(253) = 0xFD = App marker. Var(254) = 0xFE = Lam marker. Var(255) = 0xFF = End marker.

These terms CANNOT be quoted (Encoding failed!) because the encoder can't
distinguish Var(253) from the App structural byte.

HYPOTHESIS: What if the VM treats Var(253)/254/255 specially at runtime?
What if Var(253) IS the App operation as a first-class value?
What if applying Var(253) to something does something special?

Also: What if sys8 returns EMPTY (not Right(6)) with Var(253) because
the VM crashes/diverges when trying to process it?
"""

import socket
import time
import sys

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FF,
    FD,
    FE,
    encode_term,
    encode_byte_term,
    encode_bytes_list,
    parse_term,
    decode_either,
    decode_bytes_list,
    decode_byte_term,
)

HOST = "wc3.wechall.net"
PORT = 61221

QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
QD = parse_term(QD_BYTES + bytes([FF]))

nil = Lam(Lam(Var(0)))
I = Lam(Var(0))
A = Lam(Lam(App(Var(0), Var(0))))
B = Lam(Lam(App(Var(1), Var(0))))


def g(n):
    return Var(n)


def shift(term, d, c=0):
    if isinstance(term, Var):
        return Var(term.i + d) if term.i >= c else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, d, c + 1))
    if isinstance(term, App):
        return App(shift(term.f, d, c), shift(term.x, d, c))
    raise TypeError


novel_list = []


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
        return "TOOBIG"
    time.sleep(0.42)
    resp = send_raw(payload)
    return classify(label, resp)


def test_raw(label, hex_str):
    payload = bytes.fromhex(hex_str)
    time.sleep(0.42)
    resp = send_raw(payload)
    return classify(label, resp)


def classify(label, resp):
    resp_hex = resp.hex() if resp else "EMPTY"
    resp_text = resp.decode("utf-8", "replace") if resp else ""

    parsed_info = ""
    if resp and len(resp) > 0:
        try:
            term = parse_term(resp)
            tag, val = decode_either(term)
            if tag == "Left":
                try:
                    bs = decode_bytes_list(val)
                    parsed_info = f" -> Left({bs!r})"
                except Exception:
                    parsed_info = f" -> Left(<complex>)"
            else:
                try:
                    code = decode_byte_term(val)
                    parsed_info = f" -> Right({code})"
                except Exception:
                    parsed_info = f" -> Right(<complex>)"
        except Exception:
            if resp_text:
                parsed_info = f" [{resp_text[:60]}]"

    is_perm = "Permission denied" in resp_text
    is_right6 = "00030200fdfd" in resp_hex or is_perm
    is_empty = len(resp) == 0
    is_invalid = "Invalid term" in resp_text
    is_enc = "Encoding failed" in resp_text

    if is_right6:
        status = "RIGHT(6)"
    elif "-> Right(2)" in parsed_info:
        status = "RIGHT(2)"
    elif "-> Right(1)" in parsed_info:
        status = "RIGHT(1)"
    elif "-> Right(3)" in parsed_info:
        status = "RIGHT(3)"
    elif "-> Right(" in parsed_info:
        status = "RIGHT(?)"
    elif "-> Left(" in parsed_info:
        status = "LEFT"
    elif is_empty:
        status = "EMPTY"
    elif is_invalid:
        status = "INVALID"
    elif is_enc:
        status = "ENC_FAIL"
    else:
        status = "OTHER"

    print(f"[{status:10s}] {label}{parsed_info}")
    if status == "LEFT":
        print(f"  >>> hex={resp_hex[:80]}")
    if status == "OTHER":
        print(f"  >>> hex={resp_hex[:80]}")
        print(f"  >>> text={repr(resp_text[:80])}")
        novel_list.append((label, resp_hex, resp_text))
    sys.stdout.flush()
    return status


# ============================================================
print("=" * 70)
print("PART 1: Characterize echo(g(N)) for N near boundaries")
print("What does echo return for various N values?")
print("=" * 70)

# We know echo(g(N)) returns Left(Var(N+2)) because Left adds 2 lambdas
# Under QD's observation, this gets quoted. For N+2 >= 253, quote fails.

# First, let's see what echo(g(N)) returns when observed with a WRITE observer
# instead of QD. The write observer just writes the raw bytes.
# OBS = λeither. either(λx. write("L:")(λ_. nil))(λx. write("R:")(λ_. nil))
# Actually let's use a simpler observer that writes "L" or "R" then the raw term

# Use QD for now — it will fail for high N but succeed for low N
for n in [0, 1, 100, 200, 248, 249, 250, 251, 252]:
    test(f"echo(g({n}))(QD)", App(App(g(14), g(n)), QD))


# ============================================================
print("\n" + "=" * 70)
print("PART 2: What happens when we APPLY echo's Left result?")
print("Left(Var(N+2)) applied to f and g gives f(Var(N+2))")
print("=" * 70)

# echo(g(251))(λleft. left(λval. write_val)(λval. write_val))
# Left(Var(253))(f)(g) = f(Var(253))
# If f = write, then write(Var(253)) — but Var(253) isn't a byte list
# If f = quote, then quote(Var(253)) — this should fail (Encoding failed)
# If f = echo, then echo(Var(253)) — creates Left(Var(255))!

# echo(g(251)) → unwrap → echo(Var(253)) → observe
# echo(g(251))(λleft. left(λval. echo(val)(QD))(λerr. QD(err)))
# Under λleft (1 lam): echo=Var(15)
# Under λleft.left.λval (3 lams): echo=Var(17), QD needs shift by 3
QD_s3 = shift(QD, 3)
QD_s2 = shift(QD, 2)
inner_echo = Lam(App(App(Var(17), Var(0)), QD_s3))  # λval. echo(val)(QD)
err_handler = Lam(App(QD_s3, Var(0)))  # λerr. QD(err)
unwrap_echo = Lam(
    App(App(Var(0), inner_echo), err_handler)
)  # λleft. left(echo_handler)(err_handler)
test("echo(g(251)) → unwrap → echo(Var253)(QD)", App(App(g(14), g(251)), unwrap_echo))

# echo(g(252)) → unwrap → echo(Var(254))(QD)
test("echo(g(252)) → unwrap → echo(Var254)(QD)", App(App(g(14), g(252)), unwrap_echo))

# echo(g(250)) → unwrap → echo(Var(252))(QD) — this should work (252 < 253)
test("echo(g(250)) → unwrap → echo(Var252)(QD)", App(App(g(14), g(250)), unwrap_echo))


# ============================================================
print("\n" + "=" * 70)
print("PART 3: Apply Var(253) to things")
print("What if Var(253) is a special runtime primitive?")
print("=" * 70)

# echo(g(251)) → unwrap Left → get Var(253) → apply it to nil → observe
# echo(g(251))(λleft. left(λval. val(nil)(QD))(λerr. QD(err)))
# Under λleft.left.λval (3 lams): nil needs shift
nil_s3 = shift(nil, 3)
QD_s3b = shift(QD, 3)
apply_to_nil = Lam(App(App(Var(0), nil_s3), QD_s3b))  # λval. val(nil)(QD)
err_h = Lam(App(QD_s3b, Var(0)))
unwrap_apply_nil = Lam(App(App(Var(0), apply_to_nil), err_h))
test("echo(g(251)) → Var253(nil)(QD)", App(App(g(14), g(251)), unwrap_apply_nil))

# echo(g(252)) → Var254(nil)(QD)
test("echo(g(252)) → Var254(nil)(QD)", App(App(g(14), g(252)), unwrap_apply_nil))

# What about Var(253) applied to Var(253)?
# echo(g(251)) → unwrap → val(val) — self-application of Var(253)
# This might diverge ("froze my whole system!")
apply_self = Lam(App(Var(0), Var(0)))  # λval. val(val)
unwrap_self = Lam(App(App(Var(0), apply_self), err_h))
test(
    "echo(g(251)) → Var253(Var253) [self-app, may freeze]",
    App(App(g(14), g(251)), unwrap_self),
)


# ============================================================
print("\n" + "=" * 70)
print("PART 4: Var(253) as a syscall?")
print("What if Var(253) is a hidden syscall not in the global table?")
print("=" * 70)

# echo(g(251)) → unwrap → val(nil)(QD) — treat Var(253) as CPS syscall
# Already tested above as "Var253(nil)(QD)"

# echo(g(251)) → unwrap → val("ilikephp")(QD) — Var(253) with password
QD_s3c = shift(QD, 3)
pw = encode_bytes_list(b"ilikephp")
pw_s3 = shift(pw, 3)
apply_pw = Lam(App(App(Var(0), pw_s3), QD_s3c))  # λval. val(pw)(QD)
unwrap_apply_pw = Lam(App(App(Var(0), apply_pw), err_h))
test("echo(g(251)) → Var253('ilikephp')(QD)", App(App(g(14), g(251)), unwrap_apply_pw))

# echo(g(252)) → Var254('ilikephp')(QD)
test("echo(g(252)) → Var254('ilikephp')(QD)", App(App(g(14), g(252)), unwrap_apply_pw))

# What about using Var(253) as the CONTINUATION for sys8?
# sys8(nil)(Var253) — but we can't encode Var(253) directly
# We need to extract it from echo first
# echo(g(251)) → unwrap → sys8(nil)(val)(QD)
# Under λleft.left.λval (3 lams): sys8=Var(11)
nil_s3b = shift(nil, 3)
QD_s3d = shift(QD, 3)
sys8_with_var253_cont = Lam(
    App(App(App(Var(11), nil_s3b), Var(0)), QD_s3d)
)  # λval. sys8(nil)(val)(QD)
unwrap_sys8_cont = Lam(App(App(Var(0), sys8_with_var253_cont), err_h))
test("echo(g(251)) → sys8(nil)(Var253)(QD)", App(App(g(14), g(251)), unwrap_sys8_cont))

# sys8(Var253)(QD) — Var253 as argument (already tested as EMPTY, but let's confirm)
sys8_with_var253_arg = Lam(App(App(Var(11), Var(0)), QD_s3d))  # λval. sys8(val)(QD)
unwrap_sys8_arg = Lam(App(App(Var(0), sys8_with_var253_arg), err_h))
test(
    "echo(g(251)) → sys8(Var253)(QD) [confirm]",
    App(App(g(14), g(251)), unwrap_sys8_arg),
)


# ============================================================
print("\n" + "=" * 70)
print("PART 5: Double echo — create Var(255) = 0xFF = End marker")
print("echo(g(251)) → Left(Var(253)). echo that → Left(Var(255))!")
print("Var(255) = 0xFF = the END marker. What happens at runtime?")
print("=" * 70)

# echo(echo(g(251))) — but echo returns Left, not the raw value
# We need: echo(g(251))(λleft. echo(left)(QD))
# Under λleft (1 lam): echo=Var(15)
QD_s1 = shift(QD, 1)
echo_left = Lam(App(App(Var(15), Var(0)), QD_s1))  # λleft. echo(left)(QD)
test("echo(g(251)) → echo(Left(Var253))(QD)", App(App(g(14), g(251)), echo_left))

# Now unwrap the double-echo result to get the inner value
# echo(g(253-2=251)) → Left(Var(253))
# echo(Left(Var(253))) → Left(Left(Var(255)))
# Left(Left(Var(255))) is: λl.λr. l(λl2.λr2. l2(Var(255)))
# Unwrapping twice: Left(Left(Var(255)))(f)(g) = f(Left(Var(255)))
# Left(Var(255))(f2)(g2) = f2(Var(255))
# So double-unwrap gives us Var(255)!

# echo(g(251))(λleft1. echo(left1)(λleft2. left2(λinner. inner(λval. val(nil)(QD))(λerr. QD(err)))(λerr. QD(err))))
# This is getting very nested. Let me build it step by step.

# Innermost: λval. val(nil)(QD) — apply Var(255) as syscall
# Under 5 lams: nil and QD need shift by 5
nil_s5 = shift(nil, 5)
QD_s5 = shift(QD, 5)
apply_val = Lam(App(App(Var(0), nil_s5), QD_s5))  # λval. val(nil)(QD)
QD_s5b = shift(QD, 5)
err_h5 = Lam(App(QD_s5b, Var(0)))  # λerr. QD(err)

# λinner. inner(apply_val)(err_h5) — unwrap inner Left
unwrap_inner = Lam(App(App(Var(0), apply_val), err_h5))

# λleft2. left2(unwrap_inner)(err_h4) — unwrap outer Left
QD_s4 = shift(QD, 4)
err_h4 = Lam(App(QD_s4, Var(0)))
unwrap_outer = Lam(App(App(Var(0), unwrap_inner), err_h4))

# λleft1. echo(left1)(unwrap_outer) — echo the first Left
echo_and_unwrap = Lam(App(App(Var(15), Var(0)), unwrap_outer))

test(
    "echo(g(251)) → echo(Left) → unwrap² → Var255(nil)(QD)",
    App(App(g(14), g(251)), echo_and_unwrap),
)

# Simpler: just try to observe what double-echo produces
# echo(g(251))(λl1. echo(l1)(λl2. write_hex(l2)))
# But we can't easily write hex. Let's use QD on the double-echo result.
# echo(g(251))(λl1. echo(l1)(QD))
# This should try to quote Left(Var(255)) — which will ALSO fail with Encoding failed!
# Already tested above. Let's try with a write observer instead.

# echo(g(251))(λl1. echo(l1)(λl2. write("GOT:")(λ_. nil)))
# Under 2 lams: write=Var(4)
got_str = encode_bytes_list(b"GOT:")
got_s2 = shift(got_str, 2)
nil_s3c = shift(nil, 3)
write_got = Lam(App(App(Var(4), got_s2), Lam(nil_s3c)))  # λl2. write("GOT:")(λ_. nil)
echo_echo_write = Lam(App(App(Var(15), Var(0)), write_got))
test(
    "echo(g(251)) → echo(Left) → write('GOT:')",
    App(App(g(14), g(251)), echo_echo_write),
)


# ============================================================
print("\n" + "=" * 70)
print("PART 6: What if we need to use Var(253) as App at runtime?")
print("The VM might interpret Var(253) as the application operation itself")
print("=" * 70)

# If Var(253) = App operation, then Var(253)(f)(x) = f(x)
# This would make it equivalent to the B combinator!
# And Var(254) = Lam operation = some kind of abstraction?
# And Var(255) = End/halt?

# Test: echo(g(251)) → unwrap → val(g(8))(nil)(QD)
# If Var(253) = App, then Var(253)(g(8))(nil) = g(8)(nil) = sys8(nil)
# Then sys8(nil)(QD) = Right(6)
# Under λleft.left.λval (3 lams): g(8)=Var(11)
nil_s3d = shift(nil, 3)
QD_s3e = shift(QD, 3)
apply_sys8 = Lam(
    App(App(App(Var(0), Var(11)), nil_s3d), QD_s3e)
)  # λval. val(g(8))(nil)(QD)
QD_s3f = shift(QD, 3)
err_h3 = Lam(App(QD_s3f, Var(0)))
unwrap_apply_sys8 = Lam(App(App(Var(0), apply_sys8), err_h3))
test(
    "echo(g(251)) → Var253(sys8)(nil)(QD) [App as value?]",
    App(App(g(14), g(251)), unwrap_apply_sys8),
)

# What if Var(253)(sys8)(password) = sys8(password) with elevated privileges?
pw_s3b = shift(encode_bytes_list(b"ilikephp"), 3)
apply_sys8_pw = Lam(
    App(App(App(Var(0), Var(11)), pw_s3b), QD_s3e)
)  # λval. val(g(8))(pw)(QD)
unwrap_apply_sys8_pw = Lam(App(App(Var(0), apply_sys8_pw), err_h3))
test(
    "echo(g(251)) → Var253(sys8)(pw)(QD) [elevated?]",
    App(App(g(14), g(251)), unwrap_apply_sys8_pw),
)


# ============================================================
print("\n" + "=" * 70)
print("PART 7: Raw bytecode injection — what if FD/FE in data position?")
print("Can we craft bytecode where FD appears as a Var, not as App?")
print("=" * 70)

# The parser reads bytes sequentially:
# 0x00-0xFC → push Var(byte)
# 0xFD → pop 2, push App
# 0xFE → pop 1, push Lam
# 0xFF → end
# There's NO way to push Var(253) because 0xFD is always App.
# UNLESS there's a parser bug or alternative encoding.

# What about: a Lam whose body is Var(253)?
# Normally: body FE = Lam(body). If body = FD, that's App not Var(253).
# But what if we have an empty stack when FD is encountered?
# FD with <2 items on stack → parser error? Or special behavior?

# Test: just FD FF — App with empty stack
test_raw("FD FF [App with empty stack]", "fdff")

# Test: 00 FD FF — App with 1 item (needs 2)
test_raw("00 FD FF [App with 1 item]", "00fdff")

# Test: FE FD FF — Lam then App (Lam needs 1 item, but stack is empty before FE)
# Wait: FE pops 1 and pushes Lam. If stack has 0 items before FE, that's an error.
# Actually: 00 FE = Lam(Var(0)) = identity. Then FD needs 2 items but only 1.
test_raw("00 FE FD FF [identity then App with 1 item]", "00fefdff")

# What about: 00 FE FE FD FF — nil then App with 1 item
test_raw("00 FE FE FD FF [nil then App with 1 item]", "00fefefdff")

# What about sending raw bytes that include 0xFD as data?
# If we could somehow get the parser to treat FD as Var(253)...
# What about: a very long sequence that overflows some buffer?
# Probably not — the parser is likely simple and correct.


# ============================================================
print("\n" + "=" * 70)
print("PART 8: What if sys8 needs a SPECIFIC 3-leaf program structure?")
print("Not sys8(arg)(QD), but a program where sys8 is embedded differently")
print("=" * 70)

# "3 leafs" might mean the ENTIRE program (including observation) has 3 leaves
# A leaf = Var node. QD has many Var nodes. So "3 leafs" can't include QD.
# Unless QD is NOT part of the program — what if we don't use QD at all?

# What if the program IS: g(8)(g(X))(g(Y)) — exactly 3 leaves, no QD?
# We tested these and got EMPTY. But what if the OUTPUT is not via write
# but via some other mechanism?

# What if sys8 WRITES to the socket directly (not via CPS)?
# Then g(8)(arg)(cont) where cont is irrelevant — sys8 writes and then
# passes result to cont. If cont is g(2) (write), it would try to write
# the result too.

# Let's try: g(8)(nil)(g(2)) — sys8 with write as continuation
# If sys8 succeeds, it passes Left(answer) to write.
# write(Left(answer)) would fail (not a byte list) but we'd see something.
test_raw("g(8)(nil)(g(2)) [sys8→write]", "0800fefe fd 02 fd ff")

# g(8)(nil)(g(14)) — sys8 with echo as continuation
test_raw("g(8)(nil)(g(14)) [sys8→echo]", "0800fefe fd 0e fd ff")

# g(8)(nil)(g(4)) — sys8 with quote as continuation
test_raw("g(8)(nil)(g(4)) [sys8→quote]", "0800fefe fd 04 fd ff")

# g(8)(nil)(g(201)) — sys8 with backdoor as continuation
test_raw("g(8)(nil)(g(201)) [sys8→backdoor]", "0800fefe fd c9 fd ff")

# g(8)(g(201))(g(2)) — sys8(backdoor) with write as continuation
test_raw("g(8)(g(201))(g(2)) [sys8(bd)→write]", "08 c9 fd 02 fd ff")


# ============================================================
print("\n" + "=" * 70)
print(f"SUMMARY: {len(novel_list)} novel/other responses")
print("=" * 70)
if novel_list:
    for label, hex_resp, text_resp in novel_list:
        print(f"  {label}: hex={hex_resp[:60]} text={repr(text_resp[:80])}")
else:
    print("  No novel responses found.")
