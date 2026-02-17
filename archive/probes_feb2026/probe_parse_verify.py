#!/usr/bin/env python3
"""
probe_parse_verify.py — Carefully verify the backdoor output structure
and test minimal extraction approaches.
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
    parse_term,
    decode_either,
    encode_bytes_list,
)

HOST = "wc3.wechall.net"
PORT = 61221
QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
nil = Lam(Lam(Var(0)))
I = Lam(Var(0))


def send_raw(payload, timeout_s=5.0):
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
    except Exception as e:
        return f"ERROR: {e}".encode()


def term_to_str(t, depth=0):
    """Pretty-print a term with de Bruijn indices."""
    if isinstance(t, Var):
        return f"Var({t.i})"
    if isinstance(t, Lam):
        return f"\u03bb.{term_to_str(t.body, depth + 1)}"
    if isinstance(t, App):
        return f"({term_to_str(t.f, depth)}  {term_to_str(t.x, depth)})"
    return str(t)


def count_lams(t):
    """Count leading lambdas."""
    n = 0
    while isinstance(t, Lam):
        n += 1
        t = t.body
    return n, t


def count_vars(t):
    """Count total Var nodes in a term."""
    if isinstance(t, Var):
        return 1
    if isinstance(t, Lam):
        return count_vars(t.body)
    if isinstance(t, App):
        return count_vars(t.f) + count_vars(t.x)
    return 0


# ================================================================
# STEP 1: Parse the known hex output byte by byte
# ================================================================
print("=" * 70)
print("STEP 1: Parse backdoor QD output byte by byte")
print("=" * 70)

raw_hex = "01010000fdfefefd0100fdfefefdfefefdfefeff"
raw_bytes = bytes.fromhex(raw_hex)
print(f"Raw hex: {raw_hex}")
print(f"Raw bytes: {list(raw_bytes)}")
print()

# Manual stack-machine parse with trace
stack = []
for i, b in enumerate(raw_bytes):
    if b == FF:
        print(f"  [{i:2d}] FF -> END")
        break
    elif b == FD:
        x = stack.pop()
        f = stack.pop()
        result = App(f, x)
        print(f"  [{i:2d}] FD -> App(pop, pop) = ({term_to_str(f)}  {term_to_str(x)})")
        stack.append(result)
    elif b == FE:
        body = stack.pop()
        result = Lam(body)
        print(f"  [{i:2d}] FE -> Lam(pop) = \u03bb.{term_to_str(body)}")
        stack.append(result)
    else:
        stack.append(Var(b))
        print(f"  [{i:2d}] {b:02x} -> Var({b})")
    print(f"       Stack depth: {len(stack)}")

print(f"\nFinal stack: {len(stack)} item(s)")
if len(stack) == 1:
    result_term = stack[0]
    print(f"Result: {term_to_str(result_term)}")
    n_lams, inner = count_lams(result_term)
    print(f"Leading lambdas: {n_lams}")
    print(f"Inner body: {term_to_str(inner)}")
    n_vars = count_vars(result_term)
    print(f"Total Var nodes: {n_vars}")
else:
    print("ERROR: Stack has != 1 item!")
    for i, item in enumerate(stack):
        print(f"  [{i}] {term_to_str(item)}")

# Also parse with the library function
print("\n--- Library parse ---")
lib_term = parse_term(raw_bytes)
print(f"Library result: {term_to_str(lib_term)}")

# Try decode_either
print("\n--- decode_either ---")
try:
    tag, payload = decode_either(lib_term)
    print(f"Tag: {tag}")
    print(f"Payload: {term_to_str(payload)}")
    n_lams2, inner2 = count_lams(payload)
    print(f"Payload leading lambdas: {n_lams2}")
    print(f"Payload inner: {term_to_str(inner2)}")
    print(f"Payload Var count: {count_vars(payload)}")
except Exception as e:
    print(f"decode_either failed: {e}")

# ================================================================
# STEP 2: Verify by re-encoding
# ================================================================
print("\n" + "=" * 70)
print("STEP 2: Re-encode and compare")
print("=" * 70)

re_encoded = encode_term(lib_term)
print(f"Re-encoded hex: {re_encoded.hex()}")
print(f"Original hex:   {raw_hex[:-2]}")  # strip FF
print(f"Match: {re_encoded.hex() == raw_hex[:-2]}")

# ================================================================
# STEP 3: Live test -- get fresh backdoor output
# ================================================================
print("\n" + "=" * 70)
print("STEP 3: Fresh backdoor(nil)(QD) from server")
print("=" * 70)

# bd(nil)(QD) as raw bytes
bd_payload = bytes([201]) + encode_term(nil) + bytes([FD]) + QD_BYTES + bytes([FD, FF])
print(f"Sending: {bd_payload.hex()}")
time.sleep(0.45)
resp = send_raw(bd_payload)
print(f"Response hex: {resp.hex() if resp else 'EMPTY'}")
print(f"Response len: {len(resp)}")
if resp:
    print(f"Matches known: {resp.hex() == raw_hex}")
    fresh_term = parse_term(resp)
    print(f"Fresh parse: {term_to_str(fresh_term)}")
    try:
        tag, payload = decode_either(fresh_term)
        print(f"Fresh Either: {tag}({term_to_str(payload)})")
    except Exception as e:
        print(f"Fresh decode_either: {e}")

# ================================================================
# STEP 4: Test MINIMAL extraction -- avoid complex CPS
# ================================================================
print("\n" + "=" * 70)
print("STEP 4: Minimal extraction tests")
print("=" * 70)

# The simplest possible test: just apply the backdoor result to I and see what happens
# bd(nil)(I) -- apply Left(pair) to identity
# Left(pair) = \u03bbl.\u03bbr. l(pair)
# Left(pair)(I) = \u03bbr. I(pair) = \u03bbr. pair
# Left(pair)(I)(I) = pair
# Then pair is a free-standing term... but nobody writes it.
# We need: Left(pair)(I)(I)(sys8)(nil) -- but this is 5 applications

# Actually, let's think about this differently.
# Left(pair)(left_handler)(right_handler) = left_handler(pair)
# So: bd(nil)(\u03bbresult. result(\u03bbpair. pair(QD)(nil))(\u03bberr. nil))
# If Church: pair(QD)(nil) = QD(A)(B) -- QD receives A, then B
# QD = \u03bbresult. write(quote(result))
# QD(A) = write(quote(A)) -- this should print A's bytecode!
# Then QD(A)(B) = ... QD only takes 1 arg, so QD(A) runs and produces output,
# then the result of QD(A) is applied to B (which may be ignored)

# Let's try this with raw bytes to avoid shifting errors.
# bd(nil)(\u03bbe. e(\u03bbp. p(QD)(nil))(\u03bberr. nil))
#
# Encoding plan:
# The whole term: App(App(Var(201), nil), continuation)
# continuation = Lam(App(App(Var(0), left_handler), right_handler))
#   where Var(0) = e (the Either)
#   left_handler at depth 1 = Lam(App(App(Var(0), QD_shifted_2), nil_shifted_2))
#     where Var(0) = p (the pair), QD needs shift +2, nil needs shift +2
#   right_handler at depth 1 = Lam(nil_shifted_2)
#     where Var(0) = err

# But wait -- the left_handler is at depth 1 in the continuation lambda.
# When we write left_handler = Lam(...), the Lam adds depth 2.
# Inside left_handler body (depth 2): Var(0) = p, globals need +2
# QD at depth 2: shift all vars in QD by +2
# nil at depth 2: shift nil by +2

# Let me just build this carefully with raw bytes.
# Actually, let me use the term builder but be VERY careful.


def shift(term, d, c=0):
    if isinstance(term, Var):
        return Var(term.i + d) if term.i >= c else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, d, c + 1))
    if isinstance(term, App):
        return App(shift(term.f, d, c), shift(term.x, d, c))


QD_term = parse_term(QD_BYTES + bytes([FF]))

# Test A: bd(nil)(\u03bbe. e(\u03bbp. p(QD)(nil))(\u03bberr. nil))
# Church: pair(QD)(nil) = QD(A)(B) -> should print A's bytecode
qd_at_2 = shift(QD_term, 2)  # QD shifted for depth 2
nil_at_2 = shift(nil, 2)  # nil shifted for depth 2
nil_at_1 = shift(nil, 1)  # nil shifted for depth 1

# left_handler body (depth 2): p(QD)(nil) = App(App(Var(0), qd_at_2), nil_at_2)
lh_body = App(App(Var(0), qd_at_2), nil_at_2)
left_handler = Lam(lh_body)  # \u03bbp. p(QD)(nil)

# right_handler body (depth 2): nil
right_handler = Lam(shift(nil, 2))  # \u03bberr. nil

# continuation body (depth 1): e(left_handler)(right_handler)
# left_handler needs shift +1 (from depth 1 to depth 1+0... wait)
# Actually: at depth 1, Var(0) = e. left_handler and right_handler are
# terms that will be ARGUMENTS to e. They don't need shifting because
# they're already constructed with the right depth.
# Wait no -- left_handler was built assuming depth 2 (inside \u03bbp).
# When we place it as an argument at depth 1, the Lam in left_handler
# will add the depth. So left_handler = Lam(body_at_depth_2) is correct
# as-is when placed at depth 1.

# Hmm, but the QD inside left_handler was shifted by +2 assuming it's at depth 2.
# At depth 1, the left_handler is Lam(body). The Lam adds 1 more depth.
# So inside the Lam, we're at depth 2. QD shifted by +2 is correct!

# BUT WAIT: left_handler is placed as an argument to Var(0) at depth 1.
# The left_handler term itself has free variables (the shifted QD vars).
# These free variables were computed assuming the left_handler is at depth 2
# (inside its own lambda). But when left_handler is placed at depth 1 as
# an argument, its own lambda provides the +1, so total depth for its body
# is 1+1 = 2. This is correct!

# Similarly for right_handler.

cont_body = App(App(Var(0), left_handler), right_handler)
continuation = Lam(cont_body)  # \u03bbe. e(left_handler)(right_handler)

# But wait -- left_handler and right_handler contain free variables that
# reference globals. At depth 1 (inside the \u03bbe), globals are at +1.
# left_handler = Lam(App(App(Var(0), qd_at_2), nil_at_2))
# Inside this Lam (depth 2), qd_at_2 has globals shifted by +2. Correct!
# But left_handler itself is at depth 1. Its Var(0) refers to the \u03bbp binding.
# The free variables in qd_at_2 are shifted by +2 from top level.
# At depth 1 (inside \u03bbe), they should be shifted by +1 from top level...
# NO WAIT. The left_handler's Lam provides depth 2. The \u03bbe provides depth 1.
# So inside left_handler's body, we're at depth 2 total. Globals need +2. Correct!

# Actually I realize the issue. left_handler is a CLOSED term (a lambda).
# When placed inside the \u03bbe continuation, the left_handler's body is under
# its own \u03bbp AND the outer \u03bbe. So depth = 2. QD shifted by +2 is correct.

# BUT: left_handler is an argument to Var(0) (which is e). So:
# e(left_handler)(right_handler) at depth 1
# left_handler is Lam(App(App(Var(0), qd_at_2), nil_at_2))
# This is fine -- left_handler is a value, not evaluated until e applies it.

# Let me just encode and send it.
test_a = App(App(Var(201), nil), continuation)
payload_a = encode_term(test_a) + bytes([FF])
print(f"\nTest A: bd(nil)(le. e(lp. p(QD)(nil))(lerr. nil))")
print(f"  Church interpretation: pair(QD)(nil) = QD(A)(B)")
print(f"  Payload hex ({len(payload_a)}B): {payload_a.hex()[:160]}")
time.sleep(0.45)
resp_a = send_raw(payload_a)
print(f"  Response: {resp_a.hex() if resp_a else 'EMPTY'} ({len(resp_a)}B)")
if resp_a:
    try:
        txt = resp_a.decode("utf-8", "replace")
        print(f"  Text: {repr(txt[:100])}")
    except:
        pass
    if FF in resp_a:
        try:
            t = parse_term(resp_a)
            print(f"  Parsed: {term_to_str(t)}")
        except Exception as e:
            print(f"  Parse error: {e}")

# Test B: Same but Scott-style: pair(nil)(QD)
# Scott: pair(nil)(QD) = nil(A)(B) = B (since nil = \u03bbl.\u03bbr.r)
# Wait, nil = \u03bbl.\u03bbr. Var(0) = \u03bbl.\u03bbr. r. So nil(A)(B) = B.
# Then B is just sitting there, nobody writes it.
# Hmm, that's not useful. Let me try pair(nil)(QD) anyway.
lh_body_b = App(App(Var(0), nil_at_2), qd_at_2)  # p(nil)(QD)
left_handler_b = Lam(lh_body_b)
cont_body_b = App(App(Var(0), left_handler_b), right_handler)
continuation_b = Lam(cont_body_b)
test_b = App(App(Var(201), nil), continuation_b)
payload_b = encode_term(test_b) + bytes([FF])
print(f"\nTest B: bd(nil)(le. e(lp. p(nil)(QD))(lerr. nil))")
print(f"  Scott interpretation: pair(nil)(QD) = nil(A)(B) = B (no write)")
print(f"  Payload hex ({len(payload_b)}B): {payload_b.hex()[:160]}")
time.sleep(0.45)
resp_b = send_raw(payload_b)
print(f"  Response: {resp_b.hex() if resp_b else 'EMPTY'} ({len(resp_b)}B)")
if resp_b:
    try:
        txt = resp_b.decode("utf-8", "replace")
        print(f"  Text: {repr(txt[:100])}")
    except:
        pass

# Test C: What if the Either is NOT standard? Let's apply it to just ONE arg.
# bd(nil)(le. e(QD))
# If Left(pair) = \u03bbl.\u03bbr. l(pair), then Left(pair)(QD) = \u03bbr. QD(pair)
# This is partially applied -- returns a lambda, nobody writes.
# But what if Left is \u03bbl. l(pair) (only 1 lambda)?
# Then Left(pair)(QD) = QD(pair) -- should print pair's bytecode!
qd_at_1 = shift(QD_term, 1)
cont_c = Lam(App(Var(0), qd_at_1))  # \u03bbe. e(QD)
test_c = App(App(Var(201), nil), cont_c)
payload_c = encode_term(test_c) + bytes([FF])
print(f"\nTest C: bd(nil)(le. e(QD))")
print(f"  If Either has 1 lambda: e(QD) = QD(pair) -> prints pair bytecode")
print(f"  If Either has 2 lambdas: e(QD) = lr. QD(pair) -> EMPTY (partial)")
print(f"  Payload hex ({len(payload_c)}B): {payload_c.hex()[:160]}")
time.sleep(0.45)
resp_c = send_raw(payload_c)
print(f"  Response: {resp_c.hex() if resp_c else 'EMPTY'} ({len(resp_c)}B)")
if resp_c:
    try:
        txt = resp_c.decode("utf-8", "replace")
        print(f"  Text: {repr(txt[:100])}")
    except:
        pass
    if FF in resp_c:
        try:
            t = parse_term(resp_c)
            print(f"  Parsed: {term_to_str(t)}")
        except Exception as e:
            print(f"  Parse error: {e}")

# Test D: Apply to TWO args but simpler -- just I and I
# bd(nil)(le. e(I)(I))
# If Left(pair) = \u03bbl.\u03bbr. l(pair), then Left(pair)(I)(I) = I(pair) = pair
# pair is just sitting there, nobody writes. EMPTY expected.
# But let's confirm the Either works at all.

# Test E: Apply to write directly
# bd(nil)(le. e(\u03bbx. write(quote(x)))(\u03bbx. write(quote(x))))
# This should print the Left payload's bytecode regardless of Either shape
# At depth 2 (inside \u03bbx inside \u03bbe): write = g(2) = Var(4), quote = g(4) = Var(6)
# body: write(quote(x)) where x = Var(0)
# = App(App(Var(4), App(App(Var(6), Var(0)), ???)))
# Hmm, write and quote are CPS too. This gets complicated.

# Let me try the SIMPLEST possible thing:
# Test F: bd(nil)(QD) -- we know this works, returns Left(pair) hex
# Already done in Step 3. Let's try something else.

# Test G: What if we DON'T use CPS for the Either?
# What if the server's Either is NOT a Scott/Church encoding but something else?
# Let's try: bd(nil)(le. write("X")(l_. nil))
# This ignores the Either entirely and just writes "X"
# If this prints "X", we know the continuation runs.
x_str = encode_bytes_list(b"X")
# At depth 1: write = g(2) = Var(3)
write_x = App(App(Var(3), shift(x_str, 1)), Lam(shift(nil, 2)))
cont_g = Lam(write_x)  # \u03bbe. write("X")(l_.nil)
test_g = App(App(Var(201), nil), cont_g)
payload_g = encode_term(test_g) + bytes([FF])
print(f"\nTest G: bd(nil)(le. write('X')(l_.nil)) [ignore Either, just write]")
print(f"  Payload hex ({len(payload_g)}B): {payload_g.hex()[:160]}")
time.sleep(0.45)
resp_g = send_raw(payload_g)
print(f"  Response: {resp_g.hex() if resp_g else 'EMPTY'} ({len(resp_g)}B)")
if resp_g:
    try:
        txt = resp_g.decode("utf-8", "replace")
        print(f"  Text: {repr(txt[:100])}")
    except:
        pass

# Test H: Simpler write test -- just write("Y") without backdoor
# write("Y")(l_.nil)
y_str = encode_bytes_list(b"Y")
write_y = App(App(Var(2), y_str), Lam(shift(nil, 1)))
payload_h = encode_term(write_y) + bytes([FF])
print(f"\nTest H: write('Y')(l_.nil) [baseline write test]")
print(f"  Payload hex ({len(payload_h)}B): {payload_h.hex()[:160]}")
time.sleep(0.45)
resp_h = send_raw(payload_h)
print(f"  Response: {resp_h.hex() if resp_h else 'EMPTY'} ({len(resp_h)}B)")
if resp_h:
    try:
        txt = resp_h.decode("utf-8", "replace")
        print(f"  Text: {repr(txt[:100])}")
    except:
        pass

# Test I: bd(nil) with write in continuation, using KNOWN WORKING pattern
# from solve_brownos_answer.py: call_syscall builds App(App(Var(N), arg), QD)
# So bd(nil)(QD) works. Let's try bd(nil)(lr. QD(r))
# This should be equivalent to bd(nil)(QD) if QD is a function
qd_at_1_v2 = shift(QD_term, 1)
cont_i = Lam(App(qd_at_1_v2, Var(0)))  # \u03bbresult. QD(result)
test_i = App(App(Var(201), nil), cont_i)
payload_i = encode_term(test_i) + bytes([FF])
print(f"\nTest I: bd(nil)(lr. QD(r)) [should equal bd(nil)(QD)]")
print(f"  Payload hex ({len(payload_i)}B): {payload_i.hex()[:160]}")
time.sleep(0.45)
resp_i = send_raw(payload_i)
print(f"  Response: {resp_i.hex() if resp_i else 'EMPTY'} ({len(resp_i)}B)")
if resp_i:
    try:
        txt = resp_i.decode("utf-8", "replace")
        print(f"  Text: {repr(txt[:100])}")
    except:
        pass
    if FF in resp_i:
        try:
            t = parse_term(resp_i)
            print(f"  Parsed: {term_to_str(t)}")
        except Exception as e:
            print(f"  Parse error: {e}")

print("\n" + "=" * 70)
print("ALL TESTS COMPLETE")
print("=" * 70)
