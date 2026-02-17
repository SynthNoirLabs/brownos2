#!/usr/bin/env python3
"""probe_oracle_fresh.py — Test 4 fresh Oracle hypotheses."""

import socket
import time
import sys

HOST = "wc3.wechall.net"
PORT = 61221
FF = 0xFF
FD = 0xFD
FE = 0xFE

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


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


test_num = 0
novel_results = []


def test(label, payload):
    global test_num
    test_num += 1
    time.sleep(0.4)
    resp = send_raw(payload)
    if not resp:
        tag = "EMPTY"
    elif b"Permission denied" in resp:
        tag = "Right(6)=PermDenied"
    elif b"Invalid term" in resp:
        tag = "InvalidTerm"
    elif b"Term too big" in resp:
        tag = "TooBig"
    else:
        tag = f"DATA[{len(resp)}b]: {resp[:80].hex()}"

    is_novel = (
        bool(resp)
        and b"Permission denied" not in resp
        and b"Invalid term" not in resp
        and b"Term too big" not in resp
    )
    if is_novel:
        novel_results.append((label, resp))
    status = " *** NOVEL ***" if is_novel else ""
    print(f"  [{test_num:02d}] {label}: {tag}{status}")
    if is_novel:
        try:
            print(f"       ASCII: {resp.decode('ascii', errors='replace')}")
        except:
            pass
        print(f"       HEX: {resp.hex()}")
    return resp


def encode_app(f_bytes, x_bytes):
    return f_bytes + x_bytes + bytes([FD])


def encode_lam(body_bytes):
    return body_bytes + bytes([FE])


# Key terms as raw bytes
nil_bytes = bytes([0x00, FE, FE])  # Lam(Lam(Var(0)))
sys8_bytes = bytes([0x08])  # Var(8)
bd_bytes = bytes([0xC9])  # Var(201)

# sys8(nil)(QD) + FF — standard test
sys8_nil_qd = encode_app(encode_app(sys8_bytes, nil_bytes), QD) + bytes([FF])


# Read file by ID: readfile(int_id)(QD)
def make_read_file(file_id):
    if file_id < 253:
        id_bytes = bytes([file_id])
    else:
        id_bytes = bytes([252, file_id - 252, FD])
    return encode_app(encode_app(bytes([0x07]), id_bytes), QD) + bytes([FF])


# backdoor(nil)(QD)
bd_nil_qd = encode_app(encode_app(bd_bytes, nil_bytes), QD) + bytes([FF])

print("=" * 60)
print("HYPOTHESIS 1: Cross-connection state toggle via backdoor")
print("=" * 60)

# H1a: Baseline — sys8(nil)(QD) on fresh connection
print("\n[H1a] Baseline: sys8(nil)(QD)")
baseline = test("H1a-baseline", sys8_nil_qd)

# H1b: Conn-1: backdoor(nil)(QD), then close. Conn-2: sys8(nil)(QD)
print("\n[H1b] Conn-1: backdoor(nil)(QD), Conn-2: sys8(nil)(QD)")
test("H1b-conn1-backdoor", bd_nil_qd)
time.sleep(0.5)
test("H1b-conn2-sys8", sys8_nil_qd)

# H1c: Conn-1: bd(nil)(λ_.sys8(nil)(QD)) — backdoor then sys8 in same term
# Under 1 lambda: sys8 = Var(9), nil stays closed, QD stays closed
print("\n[H1c] bd(nil)(λ_.sys8(nil)(QD)) — backdoor then sys8 in same CPS")
inner = encode_app(encode_app(bytes([0x09]), nil_bytes), QD)
bd_then_sys8 = encode_app(encode_app(bd_bytes, nil_bytes), encode_lam(inner)) + bytes(
    [FF]
)
test("H1c-bd-then-sys8", bd_then_sys8)

# H1d: After backdoor call, check sys8 on new connection
print("\n[H1d] Conn-1: backdoor(nil)(QD), Conn-2: sys8(nil)(QD)")
test("H1d-conn1-bd", bd_nil_qd)
time.sleep(1.0)  # longer wait
test("H1d-conn2-sys8", sys8_nil_qd)

print("\n" + "=" * 60)
print("HYPOTHESIS 2: Three-leaf kernel interrupt (minimal bytecodes)")
print("=" * 60)

# H2a: 08 00 FD FF — App(Var(8), Var(0)) = sys8(g(0)) no continuation
print("\n[H2a] Raw: 08 00 FD FF — sys8(g(0)) no continuation")
test("H2a-sys8-g0-nocont", bytes([0x08, 0x00, FD, FF]))

# H2b: 08 FF — just Var(8) alone
print("\n[H2b] Raw: 08 FF — Var(8) alone")
test("H2b-var8-alone", bytes([0x08, FF]))

# H2c: C9 FF — just Var(201) alone
print("\n[H2c] Raw: C9 FF — Var(201) alone")
test("H2c-var201-alone", bytes([0xC9, FF]))

# H2d: 08 C9 FD FF — sys8(g(201)) no continuation
print("\n[H2d] Raw: 08 C9 FD FF — sys8(g(201)) no continuation")
test("H2d-sys8-bd-nocont", bytes([0x08, 0xC9, FD, FF]))

# H2e: 00 FE FE 08 FD FF — nil(sys8) = sys8 (nil selects 2nd arg, but only has 1)
print("\n[H2e] Raw: 00 FE FE 08 FD FF — nil applied to sys8")
test("H2e-nil-sys8", bytes([0x00, FE, FE, 0x08, FD, FF]))

# H2f: C9 00 FE FE FD 08 FD FF — backdoor(nil)(sys8) — sys8 as continuation
print("\n[H2f] Raw: backdoor(nil)(sys8) — sys8 as raw continuation")
test(
    "H2f-bd-nil-sys8",
    encode_app(encode_app(bd_bytes, nil_bytes), sys8_bytes) + bytes([FF]),
)

print("\n" + "=" * 60)
print("HYPOTHESIS 3: Log-file exfiltration — check files after sys8")
print("=" * 60)

# H3a: Read access.log baseline
print("\n[H3a] Read access.log (id 46) — baseline")
log_baseline = test("H3a-log-baseline", make_read_file(46))

# H3b: Call sys8, then read access.log
print("\n[H3b] sys8(nil)(QD), then read access.log")
test("H3b-sys8", sys8_nil_qd)
time.sleep(0.5)
log_after = test("H3b-log-after", make_read_file(46))

# H3c: Compare
if log_baseline != log_after:
    print("  *** ACCESS LOG CHANGED AFTER SYS8! ***")
else:
    print("  Access log unchanged.")

# H3d: Check previously-nonexistent file IDs
print("\n[H3d] Check file IDs 7, 8, 10, 12, 13")
for fid in [7, 8, 10, 12, 13]:
    test(f"H3d-file-{fid}", make_read_file(fid))

print("\n" + "=" * 60)
print("HYPOTHESIS 4: 3-arg pair destructor")
print("=" * 60)

# H4a: backdoor(nil)(QD) — baseline
print("\n[H4a] Baseline: backdoor(nil)(QD)")
test("H4a-bd-baseline", bd_nil_qd)

# H4b: backdoor→pair→pair(QD)(nil)(nil) — 3-arg application
# CPS: bd(nil)(λe. e(λp. p(QD)(nil)(nil))(λr. nil))
# Under λe: e=Var(0)
# Under λe.λp: p=Var(0), QD closed, nil closed
# p(QD)(nil)(nil) = App(App(App(Var(0), QD), nil), nil)
print("\n[H4b] backdoor→pair→pair(QD)(nil)(nil) — 3-arg destructor")
inner_p = encode_app(encode_app(encode_app(bytes([0x00]), QD), nil_bytes), nil_bytes)
lam_p = encode_lam(inner_p)
lam_r = encode_lam(nil_bytes)
either_app = encode_app(encode_app(bytes([0x00]), lam_p), lam_r)
continuation = encode_lam(either_app)
h4b_payload = encode_app(encode_app(bd_bytes, nil_bytes), continuation) + bytes([FF])
test("H4b-3arg-pair", h4b_payload)

# H4c: backdoor→pair→pair(λa.λb.λc.write(a)(λ_.nil))(nil)(nil)
# Under λe.λp.λa.λb.λc: write=Var(2+5)=Var(7)... no, write=g(2)
# Under 5 lambdas (e,p,a,b,c): g(2)=Var(7), a=Var(2), nil closed
# write(a)(λ_.nil) = App(App(Var(7), Var(2)), Lam(nil))
print("\n[H4c] backdoor→pair→pair(λa.λb.λc.write(a))(nil)(nil)")
write_a = encode_app(encode_app(bytes([0x07]), bytes([0x02])), encode_lam(nil_bytes))
lam_abc = encode_lam(encode_lam(encode_lam(write_a)))
inner_p2 = encode_app(
    encode_app(encode_app(bytes([0x00]), lam_abc), nil_bytes), nil_bytes
)
lam_p2 = encode_lam(inner_p2)
either_app2 = encode_app(encode_app(bytes([0x00]), lam_p2), lam_r)
continuation2 = encode_lam(either_app2)
h4c_payload = encode_app(encode_app(bd_bytes, nil_bytes), continuation2) + bytes([FF])
test("H4c-3arg-write", h4c_payload)

print("\n" + "=" * 60)
print(f"SUMMARY: {test_num} tests, {len(novel_results)} novel results")
print("=" * 60)
if novel_results:
    print("\n*** NOVEL RESULTS ***")
    for label, resp in novel_results:
        print(f"  {label}:")
        print(f"    HEX: {resp.hex()}")
        try:
            print(f"    ASCII: {resp.decode('ascii', errors='replace')}")
        except:
            pass
else:
    print("No novel results found.")
