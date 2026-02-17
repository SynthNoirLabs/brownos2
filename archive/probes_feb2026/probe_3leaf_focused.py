#!/usr/bin/env python3
"""
probe_3leaf_focused.py — Focused 3-leaf term tests.
Tests the most promising 3-Var-node programs combining sys8, backdoor, echo, and nil.
"""

import socket
import time
import sys

HOST = "wc3.wechall.net"
PORT = 61221
FF = 0xFF
FD = 0xFD
FE = 0xFE

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


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


test_num = 0
novel_results = []


def test(label, payload):
    global test_num
    test_num += 1
    time.sleep(0.38)
    resp = send_raw(payload)

    is_empty = len(resp) == 0
    is_denied = b"Permission denied" in resp
    is_invalid = b"Invalid" in resp
    is_right6 = b"\x00\x03\x02\x00" in resp
    is_error = resp.startswith(b"ERROR:")
    is_encoding = b"Encoding failed" in resp

    status = (
        "EMPTY"
        if is_empty
        else "DENIED"
        if is_denied
        else "INVALID"
        if is_invalid
        else "RIGHT6"
        if is_right6
        else "ENC_FAIL"
        if is_encoding
        else "CONN_ERR"
        if is_error
        else "*** NOVEL ***"
    )

    print(f"  [{test_num:3d}] [{status:10s}] {label}  |  {payload.hex()}")

    if status == "*** NOVEL ***":
        print(f"         !!! NOVEL RESPONSE !!!")
        print(f"         Resp hex: {resp.hex()[:120]}")
        try:
            print(f"         Resp txt: {resp.decode('utf-8', 'replace')[:80]}")
        except:
            pass
        novel_results.append((label, payload.hex(), resp.hex()))

    sys.stdout.flush()
    return status


# Key globals
g = {
    "nil": 0x00,  # g(0) = exception handler? Actually nil = Lam(Lam(Var(0))) = 00 FE FE
    "exc": 0x00,  # g(0) = exception
    "err": 0x01,  # g(1) = error
    "wr": 0x02,  # g(2) = write
    "qt": 0x04,  # g(4) = quote
    "rd": 0x05,  # g(5) = readdir
    "nm": 0x06,  # g(6) = name
    "rf": 0x07,  # g(7) = readfile
    "s8": 0x08,  # g(8) = solution (LOCKED)
    "ec": 0x0E,  # g(14) = echo
    "tw": 0x2A,  # g(42) = towel
    "bd": 0xC9,  # g(201) = backdoor
}

# ================================================================
print("=" * 70)
print("SECTION 1: Left-associated g(a)(g(b))(g(c)) — CPS pattern")
print("  Most important: sys8 and backdoor combinations")
print("=" * 70)

# All key triples involving sys8 or backdoor
key_vals = [0x00, 0x02, 0x04, 0x08, 0x0E, 0x2A, 0xC9]
for a in key_vals:
    for b in key_vals:
        for c in key_vals:
            payload = bytes([a, b, FD, c, FD, FF])
            a_name = {
                0: "exc",
                2: "wr",
                4: "qt",
                8: "s8",
                14: "ec",
                42: "tw",
                201: "bd",
            }.get(a, str(a))
            b_name = {
                0: "exc",
                2: "wr",
                4: "qt",
                8: "s8",
                14: "ec",
                42: "tw",
                201: "bd",
            }.get(b, str(b))
            c_name = {
                0: "exc",
                2: "wr",
                4: "qt",
                8: "s8",
                14: "ec",
                42: "tw",
                201: "bd",
            }.get(c, str(c))
            test(f"({a_name} {b_name}) {c_name}", payload)

# ================================================================
print(f"\n{'=' * 70}")
print("SECTION 2: Right-associated g(a)(g(b)(g(c)))")
print("=" * 70)

for a in key_vals:
    for b in key_vals:
        for c in key_vals:
            payload = bytes([a, b, c, FD, FD, FF])
            a_name = {
                0: "exc",
                2: "wr",
                4: "qt",
                8: "s8",
                14: "ec",
                42: "tw",
                201: "bd",
            }.get(a, str(a))
            b_name = {
                0: "exc",
                2: "wr",
                4: "qt",
                8: "s8",
                14: "ec",
                42: "tw",
                201: "bd",
            }.get(b, str(b))
            c_name = {
                0: "exc",
                2: "wr",
                4: "qt",
                8: "s8",
                14: "ec",
                42: "tw",
                201: "bd",
            }.get(c, str(c))
            test(f"{a_name} ({b_name} {c_name})", payload)

# ================================================================
print(f"\n{'=' * 70}")
print("SECTION 3: Programs starting with 00 FE FE (nil prefix)")
print("  nil(g(b))(g(c)) — mail hint: 'start with 00 FE FE'")
print("=" * 70)

for b in key_vals:
    for c in key_vals:
        payload = bytes([0x00, FE, FE, b, FD, c, FD, FF])
        b_name = {
            0: "exc",
            2: "wr",
            4: "qt",
            8: "s8",
            14: "ec",
            42: "tw",
            201: "bd",
        }.get(b, str(b))
        c_name = {
            0: "exc",
            2: "wr",
            4: "qt",
            8: "s8",
            14: "ec",
            42: "tw",
            201: "bd",
        }.get(c, str(c))
        test(f"nil({b_name})({c_name})", payload)

# ================================================================
print(f"\n{'=' * 70}")
print("SECTION 4: Lambda continuations g(a)(g(b))(λ.V)")
print("  Under 1 lambda: V(0)=bound, V(N+1)=g(N)")
print("=" * 70)

# Most important: sys8 and backdoor with lambda continuations
for a in [0x08, 0xC9, 0x0E]:
    for b in [0x00, 0x08, 0xC9, 0x0E, 0x02]:
        for v in [0, 1, 3, 9, 15, 202]:
            # v=0: bound var, v=1: g(0), v=3: g(2)=write, v=9: g(8)=sys8, v=15: g(14)=echo, v=202: g(201)=bd
            payload = bytes([a, b, FD, v, FE, FD, FF])
            a_name = {8: "s8", 201: "bd", 14: "ec"}.get(a, str(a))
            b_name = {0: "nil", 8: "s8", 201: "bd", 14: "ec", 2: "wr"}.get(b, str(b))
            v_name = {
                0: "bound",
                1: "g(0)",
                3: "g(2)=wr",
                9: "g(8)=s8",
                15: "g(14)=ec",
                202: "g(201)=bd",
            }.get(v, f"V{v}")
            test(f"({a_name} {b_name})(λ.{v_name})", payload)

# ================================================================
print(f"\n{'=' * 70}")
print("SECTION 5: g(a)(λ.V)(g(c)) — lambda as argument")
print("=" * 70)

for a in [0x08, 0xC9]:
    for v in [0, 1, 3, 9, 15, 202]:
        for c in [0x00, 0x08, 0xC9, 0x0E, 0x02]:
            payload = bytes([a, v, FE, FD, c, FD, FF])
            a_name = {8: "s8", 201: "bd"}.get(a, str(a))
            v_name = {
                0: "bound",
                1: "g(0)",
                3: "g(2)=wr",
                9: "g(8)=s8",
                15: "g(14)=ec",
                202: "g(201)=bd",
            }.get(v, f"V{v}")
            c_name = {0: "nil", 8: "s8", 201: "bd", 14: "ec", 2: "wr"}.get(c, str(c))
            test(f"{a_name}(λ.{v_name})({c_name})", payload)

# ================================================================
print(f"\n{'=' * 70}")
print("SECTION 6: Special — 3-leaf with QD as one of the leaves")
print("  QD has many Var nodes, so QD + 2 more = not 3 leafs")
print("  But what about g(a)(g(b))(QD) — standard CPS with QD?")
print("  These have MORE than 3 leafs but are the standard observation pattern")
print("=" * 70)

# Already tested extensively, skip this section
print("  (Skipped — already tested in previous probes)")

# ================================================================
print(f"\n{'=' * 70}")
print(f"SUMMARY: {test_num} tests total")
print("=" * 70)

if novel_results:
    print(f"\n!!! FOUND {len(novel_results)} NOVEL RESPONSES !!!")
    for label, phex, rhex in novel_results:
        print(f"  {label}")
        print(f"    Payload: {phex}")
        print(f"    Response: {rhex[:120]}")
else:
    print("\nNo novel responses found.")
