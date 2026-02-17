#!/usr/bin/env python3
"""
Systematically test ALL valid 3-leaf bytecode programs using key global indices.
'3 leafs' = 3 Var bytes + structural FD/FE/FF bytes.
Focus on syscall-relevant Var values: 8 (sys8), 14 (echo), 201 (backdoor), 0 (exception/Var0).
"""

import socket, time, sys
from itertools import permutations, product

HOST = "wc3.wechall.net"
PORT = 61221
SLEEP = 0.4


def send_raw(payload, timeout=8.0):
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout) as s:
            s.sendall(payload)
            s.shutdown(socket.SHUT_WR)
            s.settimeout(timeout)
            out = b""
            while True:
                try:
                    c = s.recv(4096)
                    if not c:
                        break
                    out += c
                except:
                    break
            return out
    except Exception as e:
        return f"ERROR:{e}".encode()


def is_valid_sequence(seq):
    stack = 0
    for s in seq:
        if s == "V":
            stack += 1
        elif s == "F":
            if stack < 2:
                return False
            stack -= 1
        elif s == "L":
            if stack < 1:
                return False
    return stack == 1


def gen_structures(max_lam=2):
    """Generate all valid 3-leaf structures with 0..max_lam lambdas."""
    structures = []
    for num_lam in range(max_lam + 1):
        items = ["V"] * 3 + ["F"] * 2 + ["L"] * num_lam
        seen = set()
        for perm in permutations(items):
            if perm not in seen:
                seen.add(perm)
                if is_valid_sequence(perm):
                    structures.append(perm)
    return structures


def structure_to_bytecode(structure, var_values):
    """Convert structure + var values to bytecode."""
    bc = bytearray()
    vi = 0
    for s in structure:
        if s == "V":
            bc.append(var_values[vi])
            vi += 1
        elif s == "F":
            bc.append(0xFD)
        elif s == "L":
            bc.append(0xFE)
    bc.append(0xFF)
    return bytes(bc)


def classify_response(r):
    if not r or r == b"":
        return "EMPTY"
    if r == b"Invalid term!":
        return "INVALID"
    if b"Encoding failed" in r:
        return "ENC_FAIL"
    if b"Term too big" in r:
        return "TOO_BIG"

    h = r.hex()
    # Right(6) = Permission denied = 00030200fdfdfefefefefefefefefefdfefeff (19B)
    if h == "00030200fdfdfefefefefefefefefefdfefeff":
        return "RIGHT(6)=PermDenied"
    # Right(2) = InvalidArg
    if h == "000200fdfefefefefefefefefefdfefeff":
        return "RIGHT(2)=InvalidArg"
    # Right(1) = NotImpl
    if h == "000100fdfefefefefefefefefefdfefeff":
        return "RIGHT(1)=NotImpl"
    # Right(7) = RateLimit
    if h == "00030300fdfdfefefefefefefefefefdfefeff":
        return "RIGHT(7)=RateLimit"
    # Right(3) = NoSuchFile
    if h == "000300fdfefefefefefefefefefdfefeff":
        return "RIGHT(3)=NoSuchFile"
    # Left = starts with 01...
    if len(r) > 2 and r[0] == 0x01:
        return f"LEFT(hex={h})"

    # Try decode as text
    try:
        txt = r.decode("utf-8")
        return f"TEXT={txt}"
    except:
        return f"RAW(hex={h})"


def main():
    # Key var values: syscalls and related
    # 8=sys8, 14=echo, 201(0xC9)=backdoor, 0=exception/var0
    # Also 2=write, 4=quote, 5=readdir, 7=readfile, 42=towel
    key_vars = [0, 2, 4, 5, 7, 8, 14, 42, 201]

    structures = gen_structures(max_lam=2)
    print(f"Structures: {len(structures)}")

    # For the minimal (no-lambda) structures, test ALL combos of key vars
    # For structures with lambdas, only test the most promising combos

    minimal_structs = [s for s in structures if "L" not in s]
    lam1_structs = [s for s in structures if s.count("L") == 1]
    lam2_structs = [s for s in structures if s.count("L") == 2]

    print(f"  No-lambda: {len(minimal_structs)}")
    print(f"  1-lambda: {len(lam1_structs)}")
    print(f"  2-lambda: {len(lam2_structs)}")

    # Focus on key combinations involving backdoor(C9), echo(0E), sys8(08)
    focus_vars = [8, 14, 201]  # sys8, echo, backdoor
    # Also include 0 (nil/exception) since mail says "start with 00 FE FE"
    extended_vars = [0, 8, 14, 201]

    tested = 0
    interesting = []

    out = open("probe_3leaf_systematic_output.log", "w")

    def log(msg):
        print(msg)
        out.write(msg + "\n")
        out.flush()

    log("=" * 70)
    log("probe_3leaf_systematic.py — All 3-leaf programs with key globals")
    log("=" * 70)
    log("")

    # Phase 1: All no-lambda structures with focus vars
    log("=== PHASE 1: No-lambda structures, vars from {8, 14, 201} ===")
    for struct in minimal_structs:
        for vals in product(focus_vars, repeat=3):
            bc = structure_to_bytecode(struct, vals)
            r = send_raw(bc)
            cls = classify_response(r)
            tested += 1

            is_interesting = cls not in (
                "EMPTY",
                "RIGHT(6)=PermDenied",
                "RIGHT(2)=InvalidArg",
                "RIGHT(1)=NotImpl",
                "RIGHT(7)=RateLimit",
                "INVALID",
                "RIGHT(3)=NoSuchFile",
            )

            struct_str = "".join({"V": "v", "F": "@", "L": "λ"}[x] for x in struct)
            var_str = ",".join(str(v) for v in vals)
            marker = "***" if is_interesting else "   "
            log(
                f"  {marker} [{tested:4d}] {struct_str} vars=({var_str}) bc={bc[:-1].hex()} → {cls}"
            )

            if is_interesting:
                interesting.append((struct, vals, bc, cls))

            time.sleep(SLEEP)

    # Phase 2: No-lambda with extended vars (includes 0)
    log("")
    log("=== PHASE 2: No-lambda structures, vars from {0, 8, 14, 201} ===")
    for struct in minimal_structs:
        for vals in product(extended_vars, repeat=3):
            if all(v in focus_vars for v in vals):
                continue  # already tested in phase 1
            bc = structure_to_bytecode(struct, vals)
            r = send_raw(bc)
            cls = classify_response(r)
            tested += 1

            is_interesting = cls not in (
                "EMPTY",
                "RIGHT(6)=PermDenied",
                "RIGHT(2)=InvalidArg",
                "RIGHT(1)=NotImpl",
                "RIGHT(7)=RateLimit",
                "INVALID",
                "RIGHT(3)=NoSuchFile",
            )

            struct_str = "".join({"V": "v", "F": "@", "L": "λ"}[x] for x in struct)
            var_str = ",".join(str(v) for v in vals)
            marker = "***" if is_interesting else "   "
            log(
                f"  {marker} [{tested:4d}] {struct_str} vars=({var_str}) bc={bc[:-1].hex()} → {cls}"
            )

            if is_interesting:
                interesting.append((struct, vals, bc, cls))

            time.sleep(SLEEP)

    # Phase 3: 1-lambda structures with the most promising combos
    log("")
    log("=== PHASE 3: 1-lambda structures, key combos ===")
    # Only test combos where at least one var is backdoor or echo
    for struct in lam1_structs:
        for vals in product(focus_vars, repeat=3):
            if 201 not in vals and 14 not in vals:
                continue
            bc = structure_to_bytecode(struct, vals)
            r = send_raw(bc)
            cls = classify_response(r)
            tested += 1

            is_interesting = cls not in (
                "EMPTY",
                "RIGHT(6)=PermDenied",
                "RIGHT(2)=InvalidArg",
                "RIGHT(1)=NotImpl",
                "RIGHT(7)=RateLimit",
                "INVALID",
                "RIGHT(3)=NoSuchFile",
            )

            struct_str = "".join({"V": "v", "F": "@", "L": "λ"}[x] for x in struct)
            var_str = ",".join(str(v) for v in vals)
            marker = "***" if is_interesting else "   "
            log(
                f"  {marker} [{tested:4d}] {struct_str} vars=({var_str}) bc={bc[:-1].hex()} → {cls}"
            )

            if is_interesting:
                interesting.append((struct, vals, bc, cls))

            time.sleep(SLEEP)

    log("")
    log("=" * 70)
    log(f"SUMMARY: {tested} programs tested, {len(interesting)} interesting results")
    if interesting:
        log("INTERESTING RESULTS:")
        for struct, vals, bc, cls in interesting:
            struct_str = "".join({"V": "v", "F": "@", "L": "λ"}[x] for x in struct)
            var_str = ",".join(str(v) for v in vals)
            log(f"  {struct_str} vars=({var_str}) bc={bc.hex()} → {cls}")
    log("=" * 70)
    out.close()


if __name__ == "__main__":
    main()
