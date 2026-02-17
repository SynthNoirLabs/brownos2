#!/usr/bin/env python3
"""
probe_fileid_and_oracle.py — Critical tests:
1. File ID gap tests (7, 8, 10, 12, 13, 17-21) with name/readfile/readdir
2. Oracle's A/B combinator payloads
3. g(15) "sudo" syscall tests
4. Additional creative angles
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

# Parse QD as a term
QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
QD = parse_term(QD_BYTES + bytes([FF]))

# Key terms
nil = Lam(Lam(Var(0)))
I = Lam(Var(0))
A = Lam(Lam(App(Var(0), Var(0))))  # Mockingbird
B = Lam(Lam(App(Var(1), Var(0))))  # regular application
K = Lam(Lam(Var(1)))


def g(n):
    return Var(n)


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


def test_term(label, term):
    """Send a term, print result."""
    payload = encode_term(term) + bytes([FF])
    if len(payload) > 2000:
        print(f"[TOOBIG     ] {label} ({len(payload)} bytes)")
        return "TOOBIG"
    time.sleep(0.42)
    resp = send_raw(payload)
    return classify(label, resp, payload)


def test_raw_hex(label, hex_str):
    """Send raw hex bytes."""
    payload = bytes.fromhex(hex_str)
    time.sleep(0.42)
    resp = send_raw(payload)
    return classify(label, resp, payload)


def classify(label, resp, payload):
    resp_hex = resp.hex() if resp else "EMPTY"
    resp_text = resp.decode("utf-8", "replace") if resp else ""

    # Try to parse and decode
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
    is_right6 = "00030200fdfd" in resp_hex
    is_empty = len(resp) == 0
    is_invalid = "Invalid term" in resp_text
    is_enc = "Encoding failed" in resp_text
    is_toobig = "Term too big" in resp_text
    is_error = resp_text.startswith("ERROR:")

    # Check for Right(N) patterns
    is_right2 = False
    is_right1 = False
    is_right3 = False
    is_right_other = False
    if not is_perm and not is_right6 and not is_empty and not is_invalid:
        # Try to detect Right(N) from parsed
        if "-> Right(" in parsed_info:
            code_str = parsed_info.split("Right(")[1].split(")")[0]
            try:
                code = int(code_str)
                if code == 2:
                    is_right2 = True
                elif code == 1:
                    is_right1 = True
                elif code == 3:
                    is_right3 = True
                else:
                    is_right_other = True
            except ValueError:
                pass

    is_left = "-> Left(" in parsed_info

    if is_perm or is_right6:
        status = "RIGHT(6)"
    elif is_right2:
        status = "RIGHT(2)"
    elif is_right1:
        status = "RIGHT(1)"
    elif is_right3:
        status = "RIGHT(3)"
    elif is_right_other:
        status = "RIGHT(?)"
    elif is_left:
        status = "LEFT"
    elif is_empty:
        status = "EMPTY"
    elif is_invalid:
        status = "INVALID"
    elif is_enc:
        status = "ENC_FAIL"
    elif is_toobig:
        status = "TOO_BIG"
    elif is_error:
        status = "CONN_ERR"
    else:
        status = "NOVEL"

    short_hex = resp_hex[:60] if resp_hex != "EMPTY" else "EMPTY"
    short_text = resp_text[:80] if resp_text else ""

    print(f"[{status:10s}] {label}{parsed_info}")
    if status == "LEFT":
        print(f"  >>> LEFT RESPONSE: hex={short_hex}")
        if parsed_info:
            print(f"  >>> {parsed_info}")
    if status == "NOVEL":
        print(f"  !!! NOVEL RESPONSE !!!")
        print(f"  hex: {resp_hex}")
        print(f"  text: {repr(resp_text)}")
        novel_list.append((label, resp_hex, resp_text))

    sys.stdout.flush()
    return status


# ============================================================
print("=" * 70)
print("PART 1: File ID Gap Tests")
print("Testing name(), readfile(), readdir() for gap IDs")
print("=" * 70)

gap_ids = [7, 8, 10, 12, 13, 17, 18, 19, 20, 21]

for fid in gap_ids:
    # name(fid) = g(6)(encode_byte_term(fid))(QD)
    test_term(f"name({fid})", App(App(g(6), encode_byte_term(fid)), QD))

print()
for fid in gap_ids:
    # readfile(fid) = g(7)(encode_byte_term(fid))(QD)
    test_term(f"readfile({fid})", App(App(g(7), encode_byte_term(fid)), QD))

print()
for fid in gap_ids:
    # readdir(fid) = g(5)(encode_byte_term(fid))(QD)
    test_term(f"readdir({fid})", App(App(g(5), encode_byte_term(fid)), QD))


# ============================================================
print("\n" + "=" * 70)
print("PART 2: Oracle's A/B Combinator Payloads")
print("=" * 70)

# 1-A: sys8(A(B)(B))(QD)
test_term("sys8(A(B)(B))(QD)", App(App(g(8), App(App(A, B), B)), QD))

# 1-B: sys8(B(A)(A))(QD)
test_term("sys8(B(A)(A))(QD)", App(App(g(8), App(App(B, A), A)), QD))

# 1-C: sys8(A(B)(A))(QD)
test_term("sys8(A(B)(A))(QD)", App(App(g(8), App(App(A, B), A)), QD))

# Additional A/B combos
test_term("sys8(B(B)(A))(QD)", App(App(g(8), App(App(B, B), A)), QD))
test_term("sys8(A(A)(B))(QD)", App(App(g(8), App(App(A, A), B)), QD))
test_term("sys8(B(A)(B))(QD)", App(App(g(8), App(App(B, A), B)), QD))

# 2-A: sys8(nil)(nil)(QD) — 3-arg
test_term("sys8(nil)(nil)(QD) [3-arg]", App(App(App(g(8), nil), nil), QD))

# 2-B: sys8(nil)(A)(QD) — 3-arg
test_term("sys8(nil)(A)(QD) [3-arg]", App(App(App(g(8), nil), A), QD))

# 2-C: sys8(nil)(B)(QD) — 3-arg
test_term("sys8(nil)(B)(QD) [3-arg]", App(App(App(g(8), nil), B), QD))


# ============================================================
print("\n" + "=" * 70)
print("PART 2b: Oracle's 3-leaf minimalist (raw hex)")
print("=" * 70)

# 3-A: g(8)(g(0))(g(5)) = 08 00 FD 05 FD FF
test_raw_hex("g(8)(g(0))(g(5)) [3-leaf raw]", "080005fdfdff")

# 3-B: g(8)(g(0))(g(0)) = 08 00 FD 00 FD FF
test_raw_hex("g(8)(g(0))(g(0)) [3-leaf raw]", "080000fdfdff")

# 3-C: g(8)(g(5))(g(5)) = 08 05 FD 05 FD FF
test_raw_hex("g(8)(g(5))(g(5)) [3-leaf raw]", "080505fdfdff")

# Additional 3-leaf with key syscall indices
test_raw_hex("g(8)(g(201))(g(14)) [3-leaf]", "08c9fd0efdff")
test_raw_hex("g(8)(g(14))(g(201)) [3-leaf]", "080efdc9fdff")
test_raw_hex("g(8)(g(201))(g(201)) [3-leaf]", "08c9fdc9fdff")
test_raw_hex("g(8)(g(42))(g(201)) [3-leaf]", "082afdc9fdff")
test_raw_hex("g(8)(g(15))(g(201)) [3-leaf]", "080ffdc9fdff")


# ============================================================
print("\n" + "=" * 70)
print("PART 3: g(15) 'sudo' syscall tests")
print("=" * 70)

# g(15)(g(8))(QD) — "sudo sys8"
test_term("g(15)(g(8))(QD) [sudo sys8]", App(App(g(15), g(8)), QD))

# g(15)(g(8))(nil)(QD) — "sudo sys8 nil"
test_term("g(15)(g(8))(nil)(QD) [sudo sys8 nil]", App(App(App(g(15), g(8)), nil), QD))

# g(15)(nil)(QD) — "sudo nil"
test_term("g(15)(nil)(QD) [sudo nil]", App(App(g(15), nil), QD))

# g(15)(encode_byte_term(8))(QD) — "sudo 8"
test_term("g(15)(int(8))(QD) [sudo file8]", App(App(g(15), encode_byte_term(8)), QD))

# g(15)(password)(QD) — "sudo ilikephp"
test_term(
    "g(15)('ilikephp')(QD) [sudo pw]",
    App(App(g(15), encode_bytes_list(b"ilikephp")), QD),
)

# g(15)(g(8))(password)(QD) — "sudo sys8 password"
test_term(
    "g(15)(g(8))('ilikephp')(QD)",
    App(App(App(g(15), g(8)), encode_bytes_list(b"ilikephp")), QD),
)

# What if sudo takes password THEN command?
test_term(
    "g(15)('ilikephp')(g(8))(QD)",
    App(App(App(g(15), encode_bytes_list(b"ilikephp")), g(8)), QD),
)


# ============================================================
print("\n" + "=" * 70)
print("PART 4: Additional creative angles")
print("=" * 70)

# What if we need to call backdoor with the password?
test_term(
    "backdoor('ilikephp')(QD)", App(App(g(201), encode_bytes_list(b"ilikephp")), QD)
)

# What if backdoor needs the crypt hash?
test_term(
    "backdoor('GZKc.2/VQffio')(QD)",
    App(App(g(201), encode_bytes_list(b"GZKc.2/VQffio")), QD),
)

# What if we need to authenticate with g(1) (error syscall)?
test_term("g(1)('ilikephp')(QD)", App(App(g(1), encode_bytes_list(b"ilikephp")), QD))

# What if sys8 needs the password as a raw string (not Scott list)?
# Try: sys8 with the EXACT bytes of "ilikephp" encoded differently
# Church-encode each character and cons them

# What about g(3) with specific args? (not-implemented syscall)
test_term("g(3)('ilikephp')(QD)", App(App(g(3), encode_bytes_list(b"ilikephp")), QD))

# What about calling sys8 with the backdoor pair as continuation?
# backdoor(nil)(λpair. pair(λa.λb. sys8(nil)(λres. a(res)(b(res)))))
# This is complex — skip for now

# What if echo(g(8)) produces something special?
test_term("echo(g(8))(QD)", App(App(g(14), g(8)), QD))

# What if we need to read file 8 with readfile using raw Var(8) not encode_byte_term?
# readfile expects a Scott numeral, but what if it also accepts raw?
test_term("readfile(Var(8))(QD) [raw]", App(App(g(7), g(8)), QD))
test_term("name(Var(8))(QD) [raw]", App(App(g(6), g(8)), QD))

# What about sys8 with the ENTIRE mail content?
mail_content = b"From: admin@brownos\nSubject: Welcome!\n\nHi dloser,\nwelcome to BrownOS!\nYour password is: ilikephp\n\nCheers,\nThe Admin"
mail_term = encode_bytes_list(mail_content)
mail_payload = encode_term(App(App(g(8), mail_term), QD)) + bytes([FF])
if len(mail_payload) <= 2000:
    test_term("sys8(mail_content)(QD)", App(App(g(8), mail_term), QD))
else:
    print(f"[TOOBIG     ] sys8(mail_content)(QD) ({len(mail_payload)} bytes)")

# What about sys8 with just "dloser"?
test_term("sys8('dloser')(QD)", App(App(g(8), encode_bytes_list(b"dloser")), QD))

# What about sys8 with "admin"?
test_term("sys8('admin')(QD)", App(App(g(8), encode_bytes_list(b"admin")), QD))


# ============================================================
print("\n" + "=" * 70)
print(f"SUMMARY: {len(novel_list)} novel responses")
print("=" * 70)
if novel_list:
    for label, hex_resp, text_resp in novel_list:
        print(f"  {label}: hex={hex_resp[:60]} text={repr(text_resp[:80])}")
else:
    print("  No novel responses found.")
print(f"\nTotal tests run. Check LEFT responses above for potential leads.")
