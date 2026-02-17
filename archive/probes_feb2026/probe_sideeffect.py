#!/usr/bin/env python3
"""
probe_sideeffect.py — Test if sys8 succeeds silently + state-change detection.

Oracle hypothesis: sys8 might succeed as a SIDE EFFECT when called minimally
(without QD observer), but FAIL when we add observation. The author confirmed
"EMPTY = success if you didn't want it to return anything."
"""

import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221
FD, FE, FF = 0xFD, 0xFE, 0xFF
QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
DELAY = 0.5


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
        return f"ERROR:{e}".encode()


def syscall_qd(syscall_byte, arg_bytes):
    """Standard CPS syscall with QD observer: syscall(arg)(QD)"""
    payload = (
        bytes([syscall_byte]) + arg_bytes + bytes([FD]) + QD_BYTES + bytes([FD, FF])
    )
    time.sleep(DELAY)
    return send_raw(payload)


def capture_state(label):
    """Capture system state snapshot"""
    print(f"\n--- State Snapshot: {label} ---")
    state = {}

    # Read access.log (file 46)
    r = syscall_qd(0x07, bytes([46]))
    state["access_log"] = r.hex() if r else "EMPTY"
    print(f"  access.log: {state['access_log'][:80]}")

    # Backdoor pair
    r = syscall_qd(0xC9, bytes([0x00, FE, FE]))
    state["backdoor"] = r.hex() if r else "EMPTY"
    print(f"  backdoor: {state['backdoor'][:80]}")

    # Root directory listing
    r = syscall_qd(0x05, bytes([0x00]))
    state["rootdir"] = r.hex() if r else "EMPTY"
    print(f"  rootdir: {state['rootdir'][:80]}")

    # Mystery file IDs
    for fid in [7, 8, 10, 12, 13]:
        r = syscall_qd(0x07, bytes([fid]))
        state[f"file_{fid}"] = r.hex() if r else "EMPTY"
        print(f"  file_{fid}: {state[f'file_{fid}'][:60]}")

    return state


def compare_states(s1, s2, label1, label2):
    """Compare two state snapshots"""
    diffs = []
    for key in s1:
        if key in s2 and s1[key] != s2[key]:
            diffs.append(key)
            print(f"  *** DIFF in {key}! ***")
            print(f"    {label1}: {s1[key][:80]}")
            print(f"    {label2}: {s2[key][:80]}")
    if not diffs:
        print(f"  No differences between {label1} and {label2}")
    return diffs


def main():
    print("=" * 72)
    print("probe_sideeffect.py — Side-Effect Detection for sys8")
    print("=" * 72)

    # PHASE 1: Baseline
    state1 = capture_state("PHASE 1: Baseline (before sys8)")

    # PHASE 2: Minimal sys8 calls
    print("\n=== PHASE 2: Minimal sys8 calls ===")
    tests = [
        ("P2a: bare sys8 (08 FF)", bytes([0x08, FF])),
        ("P2b: sys8(nil)", bytes([0x08, 0x00, FE, FE, FD, FF])),
        ("P2c: sys8(bd(nil))", bytes([0x08, 0xC9, 0x00, FE, FE, FD, FD, FF])),
        ("P2d: nil(sys8)", bytes([0x00, FE, FE, 0x08, FD, FF])),
        ("P2e: sys8(sys8)", bytes([0x08, 0x08, FD, FF])),
    ]
    for label, bc in tests:
        time.sleep(DELAY)
        r = send_raw(bc)
        if not r:
            print(f"  [{label}] -> EMPTY")
        elif r.startswith(b"ERROR:"):
            print(f"  [{label}] -> {r.decode()}")
        elif b"Invalid term" in r:
            print(f"  [{label}] -> INVALID_TERM")
        else:
            print(f"  [{label}] -> hex={r.hex()[:80]}")

    # PHASE 3: Post-sys8 state
    state3 = capture_state("PHASE 3: After minimal sys8 calls")

    print("\n=== Comparing Phase 1 vs Phase 3 ===")
    diffs_1_3 = compare_states(state1, state3, "Phase1", "Phase3")

    # PHASE 4: Oracle's specific bytecodes
    print("\n=== PHASE 4: Oracle's specific bytecodes ===")
    oracle_tests = [
        (
            "P4a: 00 FE FE 00 08 FE FF (multi-stack)",
            bytes([0x00, FE, FE, 0x00, 0x08, FE, FF]),
        ),
        ("P4b: backdoor(sys8)", bytes([0xC9, 0x08, FD, FF])),
        ("P4c: backdoor(nil)(sys8)", bytes([0xC9, 0x00, FE, FE, FD, 0x08, FD, FF])),
        ("P4d: sys8(backdoor)", bytes([0x08, 0xC9, FD, FF])),
        ("P4e: backdoor(sys8)(nil)", bytes([0xC9, 0x08, FD, 0x00, FE, FE, FD, FF])),
        (
            "P4f: backdoor(sys8)(QD)",
            bytes([0xC9, 0x08, FD]) + QD_BYTES + bytes([FD, FF]),
        ),
    ]
    for label, bc in oracle_tests:
        time.sleep(DELAY)
        r = send_raw(bc)
        if not r:
            print(f"  [{label}] -> EMPTY")
        elif r.startswith(b"ERROR:"):
            print(f"  [{label}] -> {r.decode()}")
        elif b"Invalid term" in r:
            print(f"  [{label}] -> INVALID_TERM")
        else:
            rhex = r.hex()
            # Decode known patterns
            if rhex == "00030200fdfdfefefefefefefefefefdfefeff":
                print(f"  [{label}] -> Right(6) = PermDenied")
            elif rhex == "000100fdfefefefefefefefefefdfefeff":
                print(f"  [{label}] -> Right(1) = NotImpl")
            elif rhex == "000200fdfefefefefefefefefefdfefeff":
                print(f"  [{label}] -> Right(2) = InvalidArg")
            else:
                print(f"  [{label}] -> *** INTERESTING *** hex={rhex[:80]}")

    # PHASE 5: Post-Phase4 state
    state5 = capture_state("PHASE 5: After Oracle bytecodes")

    print("\n=== Comparing Phase 1 vs Phase 5 ===")
    diffs_1_5 = compare_states(state1, state5, "Phase1", "Phase5")

    # PHASE 6: Scan new file IDs
    print("\n=== PHASE 6: Scanning file IDs 100-130, 200-210, 250-256 ===")
    RIGHT3 = "000300fdfefefefefefefefefefdfefeff"  # Right(3) = NoSuchFile
    new_files = []
    for fid in list(range(100, 131)) + list(range(200, 211)) + list(range(250, 253)):
        r = syscall_qd(0x06, bytes([fid]))  # name(fid)
        rhex = r.hex() if r else "EMPTY"
        if rhex != RIGHT3 and rhex != "EMPTY":
            new_files.append((fid, rhex[:60]))
            print(f"  *** file {fid}: hex={rhex[:60]} ***")

    if not new_files:
        print("  No new files found")
    else:
        print(f"  Found {len(new_files)} interesting file IDs!")

    # SUMMARY
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    all_diffs = set(diffs_1_3 + diffs_1_5)
    if all_diffs:
        print(f"*** STATE CHANGES DETECTED: {all_diffs} ***")
    else:
        print("No state changes detected across any phase.")
    if new_files:
        print(f"*** NEW FILES: {new_files} ***")
    print("=" * 72)


if __name__ == "__main__":
    main()
