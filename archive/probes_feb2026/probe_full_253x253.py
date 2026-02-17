#!/usr/bin/env python3
"""
probe_full_253x253.py — Exhaustive scan of ((Var(x) Var(y)) QD) for ALL x,y in 0..252.

dloser says: "The different outputs betray some core structures"
dloser says: "figuring out the meaning of the input codes is the most important thing"

We only tested x=0..20, y=0..20 before. Now test ALL 253x253 = 64,009 combinations.
Focus on finding ANY result that is NOT one of the known patterns:
- EMPTY (x=0, non-syscall globals)
- Right(1) = NotImpl (most globals 9-252 except known syscalls)
- Right(2) = InvalidArg (syscalls 1,2,5,6,7 with raw global args)
- Right(6) = PermDenied (syscall 8)
- Left(...) (syscalls 4, 14)

Any DEVIATION from these patterns is potentially the key to solving the challenge.
"""

import socket
import time
import sys

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE
FF = 0xFF
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def recv_all(sock, timeout_s=4.0):
    sock.settimeout(timeout_s)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    return out


def query(payload, timeout_s=4.0):
    delay = 0.3
    for attempt in range(2):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s)
        except Exception as e:
            if attempt == 1:
                return b"CONN_ERR"
            time.sleep(delay)
            delay *= 2
    return b""


# Known response patterns (hex)
KNOWN_RIGHT6 = "00030200fdfdfefefefefefefefefefdfefeff"  # Right(6) = PermDenied
KNOWN_RIGHT1 = "00030100fdfdfefefefefefefefefefdfefeff"  # Right(1) = NotImpl
KNOWN_RIGHT2 = "00030200fdfdfefefefefefefefefefdfefeff"  # Right(2) = InvalidArg

# Actually let me compute these properly
# Right(n) = λl.λr. r(n) where n is a 9-lambda byte term
# The QD output for Right(6) is the raw bytes we've seen


# Let me just categorize by the first few bytes
def categorize(resp):
    if not resp:
        return "EMPTY"
    h = resp.hex()
    if h.startswith("00030200fdfd"):
        return "R2"  # Right(2) = InvalidArg
    if h.startswith("00030100fdfd"):
        return "R1"  # Right(1) = NotImpl
    if h.startswith("00030600fdfd"):
        return "R6"  # Right(6) = PermDenied
    if h.startswith("00030700fdfd"):
        return "R7"  # Right(7) = RateLimit
    if h.startswith("00030000fdfd"):
        return "R0"  # Right(0) = Exception
    if h.startswith("00030300fdfd"):
        return "R3"  # Right(3) = NoSuchFile
    if h.startswith("00030400fdfd"):
        return "R4"  # Right(4) = NotDir
    if h.startswith("00030500fdfd"):
        return "R5"  # Right(5) = NotFile
    if h.startswith("0103"):
        return "L"  # Left(something)
    try:
        text = resp.decode("ascii", errors="strict")
        if text.startswith("Invalid"):
            return "INV"
        if text.startswith("Encoding"):
            return "ENC"
        if text.startswith("Term"):
            return "TERM_ERR"
    except:
        pass
    if resp == b"CONN_ERR":
        return "CONN"
    return f"?:{h[:20]}"


def main():
    print("=" * 70)
    print("EXHAUSTIVE 253x253 SCAN: ((Var(x) Var(y)) QD)")
    print("=" * 70)

    # Track all categories
    categories = {}
    anomalies = []

    # Known syscall behavior
    known_patterns = {
        "EMPTY": "expected for x=0 and non-syscall globals",
        "R1": "Right(1) = NotImpl",
        "R2": "Right(2) = InvalidArg",
        "R6": "Right(6) = PermDenied",
        "L": "Left(something) = success",
    }

    total = 253 * 253
    count = 0

    # First, do a quick scan of x=0..252 with y=0 to map all syscalls
    print("\n--- Phase 1: Quick scan x=0..252, y=0 ---")
    x_categories = {}

    for x in range(253):
        payload = bytes([x, 0x00, FD]) + QD + bytes([FD, FF])
        resp = query(payload)
        cat = categorize(resp)
        x_categories[x] = cat

        if cat not in ("EMPTY", "R1", "R2", "R6", "L"):
            print(
                f"  *** x={x:3d} y=0: {cat} raw={resp[:30].hex() if resp else 'EMPTY'}"
            )
            anomalies.append((x, 0, cat, resp))

        if x % 50 == 0:
            print(f"  Progress: x={x}/252")

        time.sleep(0.08)

    # Print category summary
    cat_counts = {}
    for x, cat in x_categories.items():
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    print(f"\n  Category summary (y=0):")
    for cat, cnt in sorted(cat_counts.items()):
        print(f"    {cat}: {cnt} globals")

    # List all non-NotImpl syscalls
    print(f"\n  Active syscalls (not NotImpl, not EMPTY):")
    for x in range(253):
        cat = x_categories[x]
        if cat not in ("R1", "EMPTY"):
            print(f"    x={x:3d}: {cat}")

    # Phase 2: For each ACTIVE syscall, test y=0..252
    active_syscalls = [x for x in range(253) if x_categories[x] not in ("R1", "EMPTY")]

    print(f"\n--- Phase 2: Full y-scan for {len(active_syscalls)} active syscalls ---")

    for x in active_syscalls:
        base_cat = x_categories[x]
        deviations = []

        for y in range(253):
            if y == 0:
                continue  # Already tested

            payload = bytes([x, y, FD]) + QD + bytes([FD, FF])
            resp = query(payload)
            cat = categorize(resp)

            if cat != base_cat:
                deviations.append((y, cat, resp))
                if cat not in ("EMPTY", "R1", "R2", "R6", "R7", "L"):
                    anomalies.append((x, y, cat, resp))

            time.sleep(0.08)

        if deviations:
            print(f"\n  x={x:3d} (base={base_cat}): {len(deviations)} deviations")
            for y, cat, resp in deviations[:20]:
                raw = resp[:30].hex() if resp else "EMPTY"
                print(f"    y={y:3d}: {cat} raw={raw}")
            if len(deviations) > 20:
                print(f"    ... and {len(deviations) - 20} more")
        else:
            print(f"  x={x:3d} (base={base_cat}): uniform across all y")

    # Phase 3: Spot-check some non-syscall globals with various y values
    # to see if any non-syscall global produces output with specific y
    print(f"\n--- Phase 3: Spot-check non-syscall globals ---")

    # Test a sample of non-syscall globals with y values that are known syscalls
    test_ys = [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]
    test_xs = [20, 30, 40, 50, 100, 150, 200, 250, 251, 252]

    for x in test_xs:
        if x_categories.get(x) != "R1":
            continue  # Only test NotImpl globals
        for y in test_ys:
            payload = bytes([x, y, FD]) + QD + bytes([FD, FF])
            resp = query(payload)
            cat = categorize(resp)
            if cat != "R1":
                print(f"  *** x={x:3d} y={y:3d}: {cat} (expected R1)")
                anomalies.append((x, y, cat, resp))
            time.sleep(0.08)

    print(f"\n--- Phase 3 complete ---")

    # Summary
    print(f"\n" + "=" * 70)
    print(f"SCAN COMPLETE")
    print(f"Total anomalies: {len(anomalies)}")
    for x, y, cat, resp in anomalies:
        raw = resp[:40].hex() if resp else "EMPTY"
        print(f"  x={x:3d} y={y:3d}: {cat} raw={raw}")
    print("=" * 70)


if __name__ == "__main__":
    main()
