#!/usr/bin/env python3
"""
probe_stateful_and_escalation.py — Test Oracle's remaining hypotheses:
1. Stateful write priming (write something, then sys8)
2. Backdoor escalation (feed A/B back into backdoor)
3. Multi-connection state (connect twice)
4. Echo + special bytes → sys8 (the dloser hint)
5. sys8 with Var(253)/Var(254) directly in bytecode
6. Partial send / timing tricks
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


def send_two_terms(payload1, payload2, timeout_s=8.0):
    """Send two terms on the same connection, reading between them."""
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            # Send first term
            sock.sendall(payload1)
            sock.settimeout(2.0)
            out1 = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out1 += chunk
                    if b"\xff" in chunk:
                        break
            except socket.timeout:
                pass

            # Send second term
            time.sleep(0.1)
            sock.sendall(payload2)
            sock.settimeout(timeout_s)
            out2 = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out2 += chunk
            except socket.timeout:
                pass

            return out1, out2
    except Exception as e:
        return f"ERROR: {e}".encode(), b""


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
            pass

    is_perm = "Permission denied" in resp_text
    is_right6 = "00030200fdfd" in resp_hex or is_perm
    is_empty = len(resp) == 0
    is_invalid = "Invalid term" in resp_text
    is_enc = "Encoding failed" in resp_text
    is_error = resp_text.startswith("ERROR:")

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
    elif is_error:
        status = "CONN_ERR"
    else:
        status = "NOVEL"

    print(f"[{status:10s}] {label}{parsed_info}")
    if status == "LEFT":
        print(f"  >>> hex={resp_hex[:80]}")
    if status == "NOVEL":
        print(f"  !!! NOVEL !!!")
        print(f"  hex: {resp_hex}")
        print(f"  text: {repr(resp_text)}")
        novel_list.append((label, resp_hex, resp_text))
    sys.stdout.flush()
    return status


# ============================================================
print("=" * 70)
print("PART 1: Stateful Write Priming")
print("Write something, then call sys8 in same CPS chain")
print("=" * 70)

# write("sudo /bin/solution\n") → sys8(nil)(QD)
# CPS: write(str)(λ_. sys8(nil)(QD))
sudo_str = encode_bytes_list(b"sudo /bin/solution\n")
QD_s1 = shift(QD, 1)
nil_s1 = shift(nil, 1)
write_then_sys8 = App(App(g(2), sudo_str), Lam(App(App(Var(9), nil_s1), QD_s1)))
test("write('sudo /bin/solution') → sys8(nil)(QD)", write_then_sys8)

# write("ilikephp") → sys8(nil)(QD)
pw_str = encode_bytes_list(b"ilikephp")
write_pw_then_sys8 = App(App(g(2), pw_str), Lam(App(App(Var(9), nil_s1), QD_s1)))
test("write('ilikephp') → sys8(nil)(QD)", write_pw_then_sys8)

# write(nil) → sys8(nil)(QD) — empty write
write_nil_then_sys8 = App(App(g(2), nil), Lam(App(App(Var(9), nil_s1), QD_s1)))
test("write(nil) → sys8(nil)(QD)", write_nil_then_sys8)


# ============================================================
print("\n" + "=" * 70)
print("PART 2: Backdoor Escalation")
print("Feed A/B back into backdoor, then sys8")
print("=" * 70)

# backdoor(nil) → extract A → backdoor(A) → sys8
# bd(nil)(λpair. pair(λa.λb. bd(a)(λres. sys8(nil)(QD))))
# Under 1 lam (pair): bd=Var(202), sys8=Var(9)
# Under 2 lams (pair, a): bd=Var(203), sys8=Var(10)
# Under 3 lams (pair, a, b): bd=Var(204), sys8=Var(11)
# Under 4 lams (pair, a, b, res): sys8=Var(12)
QD_s4 = shift(QD, 4)
nil_s4 = shift(nil, 4)
inner_cont = Lam(App(App(Var(12), nil_s4), QD_s4))  # λres. sys8(nil)(QD)
bd_A = Lam(
    Lam(App(App(Var(204), Var(1)), inner_cont))
)  # λa.λb. bd(a)(λres. sys8(nil)(QD))
pair_handler = Lam(
    App(App(Var(0), bd_A), Lam(Lam(Var(0))))
)  # λpair. pair(handler)(nil)
# Actually simpler: pair is λc. c(A)(B), so pair(handler) = handler(A)(B)
# Let me redo: bd(nil)(λeither. either(λpair. pair(λa.λb. bd(a)(λ_. sys8(nil)(QD))))(λerr. QD(err)))
# This is getting complex. Let me use a simpler approach.

# Simpler: backdoor(nil) returns Left(pair(A,B))
# Left(pair)(left_handler)(right_handler) = left_handler(pair)
# pair(λa.λb. body) = body[a:=A, b:=B]
# So: bd(nil)(λpair. pair(λa.λb. sys8(a)(QD)))(λerr. QD(err))

# Under 0 lams: bd=g(201), sys8=g(8)
# bd(nil)(cont)
# cont = λeither. either(left_h)(right_h)
# left_h = λpair. pair(λa.λb. sys8(a)(QD_shifted))
# right_h = λerr. QD_shifted(err)

# Let me build this step by step
# Under left_h's λpair (1 lam from cont): sys8=g(8)+1=Var(9)
# Under pair's λa.λb (3 lams from cont): sys8=Var(11)
QD_s3 = shift(QD, 3)
ab_body = App(App(Var(11), Var(1)), QD_s3)  # sys8(a)(QD) — a=Var(1) under 3 lams
pair_destructor = Lam(Lam(ab_body))  # λa.λb. sys8(a)(QD)
left_h = Lam(App(Var(0), pair_destructor))  # λpair. pair(λa.λb. ...)

QD_s2 = shift(QD, 2)
right_h = Lam(App(QD_s2, Var(0)))  # λerr. QD(err)

cont = Lam(App(App(Var(0), left_h), right_h))  # λeither. either(left_h)(right_h)

test("bd(nil) → pair → sys8(A)(QD)", App(App(g(201), nil), cont))

# Same but sys8(B) instead of sys8(A)
QD_s3b = shift(QD, 3)
ab_body_b = App(App(Var(11), Var(0)), QD_s3b)  # sys8(b)(QD) — b=Var(0) under 3 lams
pair_destructor_b = Lam(Lam(ab_body_b))
left_h_b = Lam(App(Var(0), pair_destructor_b))
cont_b = Lam(App(App(Var(0), left_h_b), right_h))
test("bd(nil) → pair → sys8(B)(QD)", App(App(g(201), nil), cont_b))

# Feed A into backdoor: bd(nil) → extract A → bd(A) → observe
# bd(nil)(λeither. either(λpair. pair(λa.λb. bd(a)(λres. res(λl.write(l))(λr.QD(r)))))(λerr.QD(err)))
# This is getting very complex. Let me try a simpler version:
# bd(nil)(λeither. either(λpair. pair(λa.λb. bd(a)(QD)))(λerr. QD(err)))
# Under pair's λa.λb (3 lams): bd=Var(204)
QD_s3c = shift(QD, 3)
ab_body_c = App(App(Var(204), Var(1)), QD_s3c)  # bd(a)(QD)
pair_destructor_c = Lam(Lam(ab_body_c))
left_h_c = Lam(App(Var(0), pair_destructor_c))
cont_c = Lam(App(App(Var(0), left_h_c), right_h))
test("bd(nil) → pair → bd(A)(QD) [escalation]", App(App(g(201), nil), cont_c))

# Feed B into backdoor
ab_body_d = App(App(Var(204), Var(0)), QD_s3c)  # bd(b)(QD)
pair_destructor_d = Lam(Lam(ab_body_d))
left_h_d = Lam(App(Var(0), pair_destructor_d))
cont_d = Lam(App(App(Var(0), left_h_d), right_h))
test("bd(nil) → pair → bd(B)(QD) [escalation]", App(App(g(201), nil), cont_d))

# Feed pair(A,B) itself into backdoor
# bd(nil)(λeither. either(λpair. bd(pair)(QD))(λerr. QD(err)))
QD_s2b = shift(QD, 2)
left_h_e = Lam(App(App(Var(203), Var(0)), QD_s2b))  # λpair. bd(pair)(QD)
cont_e = Lam(App(App(Var(0), left_h_e), right_h))
test("bd(nil) → bd(pair)(QD) [escalation]", App(App(g(201), nil), cont_e))


# ============================================================
print("\n" + "=" * 70)
print("PART 3: Echo + Special Bytes Gadgets")
print("What if echo with FD/FE/FF-adjacent vars creates magic terms?")
print("=" * 70)

# The key insight from dloser: "combining special bytes" with echo
# What if we need to echo a term that CONTAINS Var(253), Var(254), Var(255)?
# These can't be encoded directly (they collide with FD/FE/FF)
# But echo(g(251)) creates Left(Var(253)) internally!
# What if we need to pass this Left to something OTHER than sys8?

# echo(g(251)) → Left(Var(253)) → pass to backdoor?
# echo(g(251))(λleft. bd(left)(QD))
QD_s1b = shift(QD, 1)
echo_to_bd = Lam(App(App(Var(202), Var(0)), QD_s1b))  # λleft. bd(left)(QD)
test("echo(g(251)) → bd(Left(Var253))(QD)", App(App(g(14), g(251)), echo_to_bd))

# echo(g(252)) → Left(Var(254)) → pass to backdoor?
test("echo(g(252)) → bd(Left(Var254))(QD)", App(App(g(14), g(252)), echo_to_bd))

# echo(g(251)) → Left(Var(253)) → pass to echo again?
echo_to_echo = Lam(
    App(App(Var(15), Var(0)), Lam(App(App(Var(10), shift(nil, 2)), shift(QD, 2))))
)
test("echo(g(251)) → echo(Left) → sys8(nil)(QD)", App(App(g(14), g(251)), echo_to_echo))

# What if we need to APPLY the Left to something?
# Left(Var(253)) = λl.λr. l(Var(253))
# If we apply it: Left(Var(253))(f)(g) = f(Var(253))
# So: echo(g(251))(λleft. left(λx. sys8(x)(QD))(λx. QD(x)))
# Under λleft (1 lam): sys8=Var(9)
# Under λleft.left.λx (3 lams): sys8=Var(11)
QD_s3e = shift(QD, 3)
left_branch = Lam(App(App(Var(11), Var(0)), QD_s3e))  # λx. sys8(x)(QD)
QD_s3f = shift(QD, 3)
right_branch = Lam(App(QD_s3f, Var(0)))  # λx. QD(x)
unwrap_left = Lam(
    App(App(Var(0), left_branch), right_branch)
)  # λleft. left(sys8_handler)(err_handler)
test(
    "echo(g(251)) → unwrap Left → sys8(Var253)(QD)",
    App(App(g(14), g(251)), unwrap_left),
)

# Same for g(252) → Var(254)
test(
    "echo(g(252)) → unwrap Left → sys8(Var254)(QD)",
    App(App(g(14), g(252)), unwrap_left),
)

# What about echo(g(253))? Can we even encode Var(253)?
# Var(253) = byte 0xFD which is the App marker! Can't encode directly.
# But what if we send raw bytes that the parser interprets differently?
# 0E FD FD ... — g(14) applied to... FD is App, not Var(253)
# There's NO way to encode Var(253) in the bytecode. That's the point!
# But echo(g(251)) creates it INTERNALLY.

# What if the "combining special bytes" means sending FD FE FF as PART of the bytecode?
# Like: a program whose bytecode contains the sequence FD FE FF in a specific pattern?
# FD FE FF = App, then Lam, then End
# So: ... X FD FE FF means App(prev, Lam(X)) then End
# This is just normal bytecode structure.

# What about: echo applied to a term that, when quoted, produces FD FE FF?
# echo(g(251))(λleft. quote(left)(λbytes. sys8(bytes)(QD)))
# Under λleft (1 lam): quote=Var(5), sys8=Var(9)
# Under λleft.quote_cont.λbytes (3 lams): sys8=Var(11)
QD_s3g = shift(QD, 3)
quote_cont = Lam(App(App(Var(11), Var(0)), QD_s3g))  # λbytes. sys8(bytes)(QD)
left_to_quote = Lam(
    App(App(Var(5), Var(0)), quote_cont)
)  # λleft. quote(left)(λbytes. sys8(bytes)(QD))
test(
    "echo(g(251)) → quote(Left) → sys8(quoted)(QD)",
    App(App(g(14), g(251)), left_to_quote),
)

# What about quoting the UNWRAPPED value (Var(253))?
# echo(g(251))(λleft. left(λval. quote(val)(λbytes. write(bytes)(QD)))(λerr. QD(err)))
# Under λleft.left.λval (3 lams): quote=Var(7), write=Var(5)
QD_s5 = shift(QD, 5)
write_cont = Lam(
    App(App(Var(7), Var(0)), QD_s5)
)  # λbytes. write(bytes)(QD)  -- write=g(2)+5=Var(7)
# Wait, under 5 lams: g(2)=Var(7), g(4)=Var(9)
# Let me recalculate. Under λleft.left_handler.λval.quote_handler.λbytes (5 lams):
# g(2)=Var(7)
# Actually this is getting too complex. Let me just try quoting the Left directly.

# Simpler: echo(g(251))(λleft. quote(left)(λbytes. write(bytes)(λ_. nil)))
# Under λleft (1 lam): quote=g(4)+1=Var(5), write=g(2)+1=Var(3)
# Under λleft.λbytes (2 lams): write=g(2)+2=Var(4)
nil_s2 = shift(nil, 2)
write_bytes = Lam(
    App(App(Var(4), Var(0)), Lam(nil_s2))
)  # λbytes. write(bytes)(λ_. nil)
# Hmm, this won't show us the result via QD. Let me use a different approach.
# Just: echo(g(251))(λleft. quote(left)(QD))
QD_s1c = shift(QD, 1)
echo_quote = Lam(App(App(Var(5), Var(0)), QD_s1c))  # λleft. quote(left)(QD)
test("echo(g(251)) → quote(Left(Var253))(QD)", App(App(g(14), g(251)), echo_quote))

# echo(g(252)) → quote(Left(Var254))(QD)
test("echo(g(252)) → quote(Left(Var254))(QD)", App(App(g(14), g(252)), echo_quote))


# ============================================================
print("\n" + "=" * 70)
print("PART 4: Two-term same connection")
print("Send backdoor first, then sys8 on same TCP connection")
print("=" * 70)

# Term 1: backdoor(nil)(QD) — get the pair
term1 = encode_term(App(App(g(201), nil), QD)) + bytes([FF])
# Term 2: sys8(nil)(QD) — try sys8
term2 = encode_term(App(App(g(8), nil), QD)) + bytes([FF])

time.sleep(0.42)
out1, out2 = send_two_terms(term1, term2)
print(f"[2-TERM    ] backdoor then sys8:")
print(f"  Term1 resp: {out1.hex()[:60] if out1 else 'EMPTY'}")
print(f"  Term2 resp: {out2.hex()[:60] if out2 else 'EMPTY'}")

# Term 1: write("ilikephp") — authenticate?
time.sleep(0.42)
pw_payload = encode_term(
    App(App(g(2), encode_bytes_list(b"ilikephp")), Lam(nil))
) + bytes([FF])
out1b, out2b = send_two_terms(pw_payload, term2)
print(f"[2-TERM    ] write(ilikephp) then sys8:")
print(f"  Term1 resp: {out1b.hex()[:60] if out1b else 'EMPTY'}")
print(f"  Term2 resp: {out2b.hex()[:60] if out2b else 'EMPTY'}")


# ============================================================
print("\n" + "=" * 70)
print("PART 5: Partial send / delayed send")
print("Send sys8 bytecode in two parts with delay")
print("=" * 70)

# Send "08" (sys8), wait, then send rest
sys8_full = encode_term(App(App(g(8), nil), QD)) + bytes([FF])
time.sleep(0.42)
try:
    with socket.create_connection((HOST, PORT), timeout=8.0) as sock:
        # Send first byte
        sock.sendall(sys8_full[:1])
        time.sleep(1.0)
        # Send rest
        sock.sendall(sys8_full[1:])
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        sock.settimeout(8.0)
        out = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                out += chunk
            except socket.timeout:
                break
        resp_text = out.decode("utf-8", "replace") if out else ""
        print(
            f"[PARTIAL   ] Split send sys8: {out.hex()[:60] if out else 'EMPTY'} | {resp_text[:60]}"
        )
except Exception as e:
    print(f"[ERROR     ] Split send: {e}")


# ============================================================
print("\n" + "=" * 70)
print("PART 6: What if the answer is a server output string?")
print("Test known output strings against the hash")
print("=" * 70)

import hashlib

TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ROUNDS = 56154


def check_hash(candidate):
    cur = candidate.encode("utf-8") if isinstance(candidate, str) else candidate
    for _ in range(ROUNDS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET


# Test key strings
candidates = [
    "Permission denied",
    "Don't Panic!",
    "Invalid term!",
    "Encoding failed!",
    "Term too big!",
    "Not implemented",
    "Invalid argument",
    "No such file",
    "Not a directory",
    "Not a file",
    "Rate limited",
    "ilikephp",
    "GZKc.2/VQffio",
    "sudo /bin/solution",
    "cat /etc/passwd\nsu dloser\nsudo /bin/solution",
    "Uhm... yeah... no...",
    "From: admin@brownos\nSubject: Welcome!\n\nHi dloser,\nwelcome to BrownOS!\nYour password is: ilikephp\n\nCheers,\nThe Admin",
    "root:x:0:0::/root:/bin/sh\ngizmore:GZKc.2/VQffio:1000:1000::/home/gizmore:/bin/sh\ndloser:x:1001:1001::/home/dloser:/bin/false",
    # Bytecode strings
    "08ff",
    "00fefe",
    "00fefefd",
    # Lambda terms
    "\\a.\\b.b b",
    "\\a.\\b.a b",
    # The QD hex
    "0500fd000500fd03fdfefd02fdfefdfe",
    # Numbers
    "6",
    "8",
    "201",
    "42",
    # Combinations
    "dloser:ilikephp",
    "gizmore:ilikephp",
    "admin:ilikephp",
    "brownos",
    "BrownOS",
    "the answer is 42",
    "Don't Panic",
    "dont panic",
    "towel",
]

for c in candidates:
    if check_hash(c):
        print(f"  !!! HASH MATCH: {repr(c)} !!!")
    # Also check with trailing newline
    if check_hash(c + "\n"):
        print(f"  !!! HASH MATCH: {repr(c + chr(10))} !!!")

print("  Hash check complete — no matches (if no output above)")


# ============================================================
print("\n" + "=" * 70)
print(f"SUMMARY: {len(novel_list)} novel responses")
print("=" * 70)
if novel_list:
    for label, hex_resp, text_resp in novel_list:
        print(f"  {label}: hex={hex_resp[:60]} text={repr(text_resp[:80])}")
else:
    print("  No novel responses found.")
