#!/usr/bin/env python3
"""Test Oracle's 3-leaf candidates + systematic brute force against BrownOS."""

import socket
import time
import sys

HOST = "wc3.wechall.net"
PORT = 61221
FF = 0xFF


def send_raw(payload_bytes: bytes, timeout_s: float = 5.0) -> bytes:
    """Send raw bytes to BrownOS, return response."""
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


results_summary = []


def test(label: str, payload_hex: str):
    """Test a payload and print results."""
    payload = bytes.fromhex(payload_hex)
    time.sleep(0.4)
    resp = send_raw(payload)
    resp_hex = resp.hex() if resp else "EMPTY"
    resp_text = ""
    try:
        resp_text = resp.decode("utf-8", "replace")
    except:
        pass

    is_perm_denied = "Permission denied" in resp_text
    is_right6_hex = "00030200fdfd" in resp_hex
    is_empty = len(resp) == 0
    is_invalid = "Invalid term" in resp_text
    is_error = resp_text.startswith("ERROR:")

    status = (
        "PERM_DENIED"
        if is_perm_denied
        else "RIGHT6_RAW"
        if is_right6_hex
        else "EMPTY"
        if is_empty
        else "INVALID"
        if is_invalid
        else "CONN_ERR"
        if is_error
        else "*** NOVEL ***"
    )

    print(f"[{status:12s}] {label}")
    print(f"  Payload: {payload_hex}")
    if not is_empty:
        print(f"  Resp hex: {resp_hex[:100]}")
    if resp_text and not is_empty and not is_error:
        safe = resp_text.replace("\n", "\\n")[:80]
        print(f"  Resp txt: {safe}")
    if status == "*** NOVEL ***":
        print(f"  !!! BREAKTHROUGH - NOVEL RESPONSE !!!")
        print(f"  Full hex: {resp_hex}")
        print(f"  Full text: {repr(resp_text)}")
    print()
    sys.stdout.flush()
    results_summary.append((status, label, resp_hex[:40]))


# QD continuation (hex)
QD = "0500fd000500fd03fdfefd02fdfefdfe"

print("=" * 70)
print("PHASE 1: Oracle's Top Candidates (raw 3-leaf, no observer)")
print("=" * 70)
test("A: sys8(backdoor)(nil) raw", "08c9fd00fefefdff")
test("B: sys8(backdoor)(echo) raw", "08c9fd0efdff")
test("C: backdoor(nil)(sys8) raw", "c900fefefd08fdff")
test("D: sys8(towel)(nil) raw", "082afd00fefefdff")

print("=" * 70)
print("PHASE 2: Oracle Candidates WITH QD observer")
print("=" * 70)
test("A+QD: sys8(backdoor)(QD)", "08c9fd" + QD + "fdff")
test("C+QD: backdoor(nil)(QD)", "c900fefefd" + QD + "fdff")
test("E: sys8(echo)(QD)", "080efd" + QD + "fdff")
test("F: echo(backdoor)(QD)", "0ec9fd" + QD + "fdff")
test("G: echo(sys8)(QD)", "0e08fd" + QD + "fdff")
test("H: echo(echo)(QD)", "0e0efd" + QD + "fdff")

print("=" * 70)
print("PHASE 3: sys8(g(b))(QD) for all key globals")
print("=" * 70)
for b in [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201, 248, 249, 250, 251, 252]:
    test(f"sys8(g({b}))(QD)", f"08{b:02x}fd" + QD + "fdff")

print("=" * 70)
print("PHASE 4: backdoor(g(b))(QD) for key globals")
print("=" * 70)
for b in [0, 1, 2, 8, 14, 42, 201, 251, 252]:
    test(f"backdoor(g({b}))(QD)", f"c9{b:02x}fd" + QD + "fdff")

print("=" * 70)
print("PHASE 5: echo(g(b))(QD) for high-index globals")
print("=" * 70)
for b in [248, 249, 250, 251, 252]:
    test(f"echo(g({b}))(QD)", f"0e{b:02x}fd" + QD + "fdff")

print("=" * 70)
print("PHASE 6: Shape 3 - sys8(g(b))(lam.Var(c))")
print("=" * 70)
# Under 1 lambda: Var(0)=bound, Var(3)=g(2)=write, Var(9)=g(8)
for b in [201, 14, 0, 2, 42, 251, 252]:
    for c in [0, 3, 9, 15, 202]:
        c_meaning = {
            0: "bound",
            3: "write=g(2)",
            9: "sys8=g(8)",
            15: "echo=g(14)",
            202: "bd=g(201)",
        }.get(c, f"g({c - 1})")
        test(f"sys8(g({b}))(lam.{c_meaning})", f"08{b:02x}fd{c:02x}fefdff")

print("=" * 70)
print("PHASE 7: Right-associated g(a)(g(b)(g(c)))")
print("=" * 70)
for a, b, c in [
    (8, 201, 14),
    (8, 14, 201),
    (201, 8, 14),
    (201, 14, 8),
    (14, 8, 201),
    (14, 201, 8),
    (8, 201, 0),
    (8, 0, 201),
    (201, 0, 8),
    (14, 0, 8),
    (8, 201, 2),
    (8, 2, 201),
]:
    test(f"g({a})(g({b})(g({c})))", f"{a:02x}{b:02x}{c:02x}fdfdff")

print("=" * 70)
print("PHASE 8: Programs starting with 00 FE FE (mail hint)")
print("=" * 70)
# "start with 00 FE FE" — nil as prefix
# nil = Lam(Lam(Var(0))), so nil(X)(Y) reduces to Y
# 00 FE FE = nil, then apply to something
for b in [8, 14, 201, 0, 2]:
    # nil(g(b))(QD) = QD (nil selects 2nd arg)
    test(f"nil(g({b}))(QD) = QD", f"00fefe{b:02x}fd" + QD + "fdff")

# What if "start with 00 FE FE" means the BACKDOOR call starts with those bytes?
# backdoor(nil) = g(201)(00 FE FE) — this IS "starting with 00 FE FE" as the argument
# Already tested above. But what about chaining?

print("=" * 70)
print("PHASE 9: Multi-step: backdoor(nil) -> extract -> sys8")
print("=" * 70)
# backdoor(nil)(λresult. result(λleft_payload. sys8(left_payload)(QD))(λright. QD(right)))
# This extracts the Left payload from backdoor and passes it to sys8
# But this is more than 3 leaves...
# Let's try: backdoor(nil)(λr. sys8(r)(QD))
# Under 1 lam: Var(0)=r, Var(9)=g(8)=sys8
# Body: sys8(r)(QD) = 09 00 FD QD_shifted FD
# But QD needs shifting under lambda... this gets complex
# Instead, let's try the raw approach: chain backdoor -> sys8 in CPS

# backdoor(nil)(λeither. either(λpayload. sys8(payload)(QD))(λerr. QD(err)))
# This is complex. Let's try simpler: backdoor(nil)(sys8)
# = sys8(Left(pair(A,B))) — sys8 receives the entire Either
test(
    "backdoor(nil) -> sys8 as cont", "c900fefefd08fdff"
)  # already tested but let's confirm

# backdoor(nil)(λr. r(λl. l)(λr2. r2))
# This unwraps Either: Left(x)(λl.l)(λr.r) = (λl.l)(x) = x
# So we get pair(A,B)
# Then sys8(pair(A,B))(QD)
# But this needs to be in one program...

print("=" * 70)
print("SUMMARY")
print("=" * 70)
novel = [r for r in results_summary if r[0] == "*** NOVEL ***"]
if novel:
    print(f"\n!!! FOUND {len(novel)} NOVEL RESPONSES !!!")
    for status, label, hex_preview in novel:
        print(f"  {label}: {hex_preview}")
else:
    print("\nNo novel responses found.")

counts = {}
for status, _, _ in results_summary:
    counts[status] = counts.get(status, 0) + 1
print(f"\nTotal tests: {len(results_summary)}")
for status, count in sorted(counts.items()):
    print(f"  {status}: {count}")
