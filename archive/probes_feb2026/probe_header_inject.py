#!/usr/bin/env python3
"""
probe_header_inject.py — Test two genuinely novel hypotheses:

HYPOTHESIS A: The mail says "start with 00 FE FE". What if the VM checks
the raw bytecode of the ENTIRE program and requires it to literally start
with bytes 00 FE FE?

HYPOTHESIS B: Two-term injection / parser confusion. What if sending two
terms separated by FF causes the server to process both, with the second
running in a different context?
"""

import socket
import time
import sys

HOST = "wc3.wechall.net"
PORT = 61221
FF = 0xFF
FD = 0xFD
FE = 0xFE

QD_HEX = "0500fd000500fd03fdfefd02fdfefdfe"
QD = bytes.fromhex(QD_HEX)


def send_raw(payload, timeout_s=8.0):
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


novel_list = []


def test(label, payload_hex):
    payload = (
        bytes.fromhex(payload_hex) if isinstance(payload_hex, str) else payload_hex
    )
    if len(payload) > 2000:
        print(f"[TOOBIG      ] {label} ({len(payload)} bytes)")
        return
    time.sleep(0.45)
    resp = send_raw(payload)
    rh = resp.hex() if resp else "EMPTY"
    rt = resp.decode("utf-8", "replace") if resp else ""

    is_perm = "Permission denied" in rt
    is_r6 = "00030200fdfd" in rh
    is_empty = len(resp) == 0
    is_invalid = "Invalid term" in rt
    is_enc = "Encoding failed" in rt
    is_toobig = "Term too big" in rt
    is_error = rt.startswith("ERROR:")

    status = (
        "PERM_DENIED"
        if is_perm
        else "RIGHT6_RAW"
        if is_r6
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
    print(f"  Payload: {payload.hex()[:80]}{'...' if len(payload.hex()) > 80 else ''}")
    if resp and not is_empty:
        print(f"  Resp: {rh[:80]}{'...' if len(rh) > 80 else ''}")
    if status == "*** NOVEL ***":
        print(f"  !!! BREAKTHROUGH !!!")
        print(f"  Full hex: {rh}")
        print(f"  Full text: {repr(rt)}")
        novel_list.append((label, rh, rt))
    sys.stdout.flush()


# Standard sys8(nil)(QD) for reference
# sys8 = Var(8), nil = Lam(Lam(Var(0))) = 00 FE FE
# App(sys8, nil) = 08 00FEFE FD
# App(that, QD) = 08 00FEFE FD QD FD
# + FF
SYS8_NIL_QD = "0800fefefd" + QD_HEX + "fdff"

print("=" * 70)
print("HYPOTHESIS A: Programs starting with 00 FE FE")
print("nil(DUMMY)(sys8_call) — nil selects 2nd arg = sys8 call")
print("=" * 70)

# A1: nil(nil)(sys8(nil)(QD))
# Bytecode: 00FEFE 00FEFE FD 0800FEFEFD QD FD FD FF
test(
    "A1: nil(nil)(sys8(nil)(QD))",
    "00fefe" + "00fefe" + "fd" + "0800fefefd" + QD_HEX + "fd" + "fd" + "ff",
)

# A2: nil(g(0))(sys8(nil)(QD))
test(
    "A2: nil(g(0))(sys8(nil)(QD))",
    "00fefe" + "00" + "fd" + "0800fefefd" + QD_HEX + "fd" + "fd" + "ff",
)

# A3: nil(g(8))(sys8(nil)(QD))
test(
    "A3: nil(g(8))(sys8(nil)(QD))",
    "00fefe" + "08" + "fd" + "0800fefefd" + QD_HEX + "fd" + "fd" + "ff",
)

# A4: nil(g(201))(sys8(nil)(QD))
test(
    "A4: nil(g(201))(sys8(nil)(QD))",
    "00fefe" + "c9" + "fd" + "0800fefefd" + QD_HEX + "fd" + "fd" + "ff",
)

# A5: nil(g(14))(sys8(nil)(QD))
test(
    "A5: nil(g(14))(sys8(nil)(QD))",
    "00fefe" + "0e" + "fd" + "0800fefefd" + QD_HEX + "fd" + "fd" + "ff",
)

# A6: Baseline - sys8(nil)(QD) WITHOUT 00FEFE prefix
test("A6: baseline sys8(nil)(QD)", SYS8_NIL_QD)

# A7: What if 00 FE FE is a magic prefix BEFORE the term?
# Send 00 FE FE then a normal sys8 program (parser might skip prefix)
# This would parse as: nil on stack, then sys8(nil)(QD) on stack = 2 items = Invalid
test("A7: raw 00FEFE prefix + sys8(nil)(QD)", "00fefe" + SYS8_NIL_QD)

# A8: What if the prefix is 00 FE FE FF (nil term + end) then new term?
# Server processes first term (nil), ignores rest
test("A8: nil_term(FF) + sys8(nil)(QD)", "00fefeff" + SYS8_NIL_QD)

# A9: nil applied to sys8 directly: nil(sys8)(QD) — reduces to QD
test("A9: nil(sys8)(QD) = QD", "00fefe" + "08" + "fd" + QD_HEX + "fd" + "ff")

# A10: What about nil(sys8)(sys8(nil)(QD))?
# nil selects 2nd = sys8(nil)(QD), same as baseline but starts with 00FEFE
test(
    "A10: nil(sys8)(sys8(nil)(QD))",
    "00fefe" + "08" + "fd" + "0800fefefd" + QD_HEX + "fd" + "fd" + "ff",
)

# A11: What if "start with 00 FE FE" means the ARGUMENT to backdoor?
# backdoor expects nil = 00 FE FE. Already tested. But what about:
# backdoor(nil)(λpair. pair(sys8)(nil))
# = pair(sys8)(nil) = sys8(A)(B) where A,B are backdoor components
# Under 1 lambda: sys8=Var(9), nil needs shift
# pair = Var(0), pair(sys8) = App(Var(0), Var(9)), pair(sys8)(nil) = App(App(Var(0), Var(9)), nil_shifted)
# nil_shifted = Lam(Lam(Var(0))) (closed, no shift needed)
# cont = λ. App(App(Var(0), Var(9)), Lam(Lam(Var(0))))
# Bytecode: 00 09 FD 00FEFE FD FE
# Full: c9 00FEFE FD [cont] FD FF
cont_pair_sys8 = "00" + "09" + "fd" + "00fefe" + "fd" + "fe"
test(
    "A11: bd(nil)(λp. p(sys8)(nil))",
    "c9" + "00fefe" + "fd" + cont_pair_sys8 + "fd" + "ff",
)

# A12: What if we need to pass the BACKDOOR PAIR to sys8?
# backdoor(nil)(λeither. either(λpair. sys8(pair)(QD))(λerr. nil))
# Under λeither: Var(0)=either
# Under λeither.λpair: sys8=Var(10), QD needs +2 shift
# left_handler = λpair. sys8(pair)(QD_shifted)
# right_handler = λerr. nil
# But QD is closed? No, QD has free vars referencing globals 2,4,5
# Let's try with QD unshifted first (might work if QD is "mostly closed")
left_h = "0a" + "00" + "fd" + QD_HEX + "fd" + "fe"  # λ. App(App(Var(10), Var(0)), QD)
right_h = "00fefe" + "fe"  # λ. nil (but nil is closed, this is λerr. Lam(Lam(Var(0))))
# Hmm, right_h should be λerr. nil = Lam(nil) = 00 FE FE FE
# Actually: λerr. nil = λ. Lam(Lam(Var(0))) = 00 FE FE FE
# cont = λeither. either(left_h)(right_h)
# = λ. App(App(Var(0), left_h), right_h)
cont_extract = "00" + left_h + "fd" + "00fefefe" + "fd" + "fe"
test(
    "A12: bd(nil)(λe. e(λp.sys8(p)(QD))(λ_.nil))",
    "c9" + "00fefe" + "fd" + cont_extract + "fd" + "ff",
)

print()
print("=" * 70)
print("HYPOTHESIS B: Two-term injection / no-FF tests")
print("=" * 70)

# B1: Two sys8 programs separated by FF
test("B1: sys8(nil)(QD) FF sys8(nil)(QD)", SYS8_NIL_QD + SYS8_NIL_QD)

# B2: backdoor(nil)(QD) FF sys8(nil)(QD)
BD_NIL_QD = "c900fefefd" + QD_HEX + "fdff"
test("B2: bd(nil)(QD) FF sys8(nil)(QD)", BD_NIL_QD + SYS8_NIL_QD)

# B3: nil FF sys8(nil)(QD) — minimal first term
test("B3: nil(FF) + sys8(nil)(QD)", "00fefeff" + SYS8_NIL_QD)

# B4: sys8(nil)(QD) without trailing FF
test("B4: sys8(nil)(QD) no FF", "0800fefefd" + QD_HEX + "fd")

# B5: Empty first term (just FF) then sys8
test("B5: FF + sys8(nil)(QD)", "ff" + SYS8_NIL_QD)

# B6: What if we send ONLY 00 FE FE (no FF)?
test("B6: just 00 FE FE (no FF)", "00fefe")

# B7: 00 FE FE + FF (nil as complete term)
test("B7: 00 FE FE FF", "00fefeff")

# B8: backdoor(nil) as first term, sys8 as second
test(
    "B8: bd(nil)(QD) then sys8",
    "c900fefefd" + QD_HEX + "fdff" + "0800fefefd" + QD_HEX + "fdff",
)

# B9: What about sending backdoor result THEN sys8 with no separator?
# backdoor(nil)(sys8) — sys8 as continuation of backdoor
# = sys8(Left(pair)) — sys8 receives the Either directly
test("B9: bd(nil)(sys8) = sys8(Left(pair))", "c900fefefd08fdff")

# B10: What about: backdoor(nil)(λe. e(λp. sys8(p)(QD))(λ_.QD(nil)))
# This extracts the pair from backdoor and passes it to sys8
# Already similar to A12 but let's try with proper QD shifting
# Under 3 lambdas (e, left_handler's λp, and QD's own lambdas):
# Actually let's just try the simpler version
test(
    "B10: bd(nil) then raw sys8 bytes after FF",
    "c900fefefdff" + "0800fefefd" + QD_HEX + "fdff",
)

print()
print("=" * 70)
print(f"SUMMARY: {len(novel_list)} novel responses")
print("=" * 70)
if novel_list:
    for label, hx, tx in novel_list:
        print(f"  {label}")
        print(f"    Hex: {hx[:80]}")
        print(f"    Text: {repr(tx[:80])}")
else:
    print("  No novel responses found.")
