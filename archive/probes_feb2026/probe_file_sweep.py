#!/usr/bin/env python3
"""
Comprehensive file ID sweep.

Oracle insight: the existence of unlinked file 256 proves the directory tree
does NOT cover all files. There may be hidden files at IDs we never checked.

Known IDs from readdir:
  0(root), 1(bin), 2(etc), 3(brownos), 4(var), 5(log), 6(brownos_subdir),
  9(sbin), 11(passwd), 14(sh), 15(sudo), 16(false), 22(home), 25(spool),
  39(gizmore), 43(mail), 46(access.log), 50(dloser), 65(.history), 88(dloser_mail)
  256(wtf) — UNLINKED

Gaps we NEVER explicitly checked with name():
  7, 8, 10, 12, 13, 17-21, 23, 24, 26-38, 40-42, 44, 45, 47-49, 51-64, 66-87, 89-255

CRITICAL: File ID 8 is especially interesting — same number as syscall 8!
"""

from __future__ import annotations

import hashlib
import socket
import sys
import time
from pathlib import Path

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    QD,
    FF,
    encode_term,
    parse_term,
    decode_either,
    decode_byte_term,
    decode_bytes_list,
    encode_byte_term,
)

HOST = "wc3.wechall.net"
PORT = 61221

TARGET_HASH = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
HASH_ROUNDS = 56154


def recv_until_ff(sock: socket.socket, timeout_s: float = 5.0) -> bytes:
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
        if 0xFF in chunk:
            break
    return out


def query(payload: bytes, retries: int = 3, timeout_s: float = 5.0) -> bytes:
    delay = 0.15
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_until_ff(sock, timeout_s=timeout_s)
        except Exception:
            time.sleep(delay)
            delay *= 2
    return b""


def call_syscall_qd(syscall_num: int, arg_term: object) -> bytes:
    payload = (
        bytes([syscall_num])
        + encode_term(arg_term)
        + bytes([0xFD])
        + QD
        + bytes([0xFD, FF])
    )
    return query(payload)


def check_hash(candidate: str) -> bool:
    cur = candidate.encode("utf-8", "ignore")
    for _ in range(HASH_ROUNDS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET_HASH


def check_hash_case_insensitive(candidate: str) -> bool:
    return (
        check_hash(candidate)
        or check_hash(candidate.lower())
        or check_hash(candidate.upper())
    )


def main():
    # Determine scan range
    if len(sys.argv) > 1:
        max_id = int(sys.argv[1])
    else:
        max_id = 4096

    print(f"=" * 70)
    print(f"FILE ID SWEEP: name(id) for id = 0..{max_id}")
    print(f"=" * 70)

    known_ids = {
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        9,
        11,
        14,
        15,
        16,
        22,
        25,
        39,
        43,
        46,
        50,
        65,
        88,
        256,
    }

    # Phase 1: Sweep name() for ALL IDs
    discovered = {}  # id -> name_string
    errors = {}  # id -> error_code

    progress_file = Path("sweep_progress.txt")
    already_done = set()
    if progress_file.exists():
        for line in progress_file.read_text().splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                fid = int(parts[0])
                already_done.add(fid)
                if parts[1] != "R3":
                    discovered[fid] = parts[1]

    batch_size = 50
    for batch_start in range(0, max_id + 1, batch_size):
        batch_end = min(batch_start + batch_size, max_id + 1)
        batch_ids = [i for i in range(batch_start, batch_end) if i not in already_done]

        if not batch_ids:
            continue

        print(f"\n  Scanning IDs {batch_start}-{batch_end - 1}...", flush=True)

        for fid in batch_ids:
            arg = encode_byte_term(fid)
            out = call_syscall_qd(0x06, arg)  # name(id)

            result = "?"
            if out and 0xFF in out:
                try:
                    term = parse_term(out)
                    tag, payload = decode_either(term)
                    if tag == "Left":
                        name_str = decode_bytes_list(payload).decode("utf-8", "replace")
                        discovered[fid] = name_str
                        result = name_str
                        is_known = fid in known_ids
                        marker = "  KNOWN" if is_known else "  *** NEW ***"
                        print(
                            f"    ID {fid:5d}: name = {name_str!r}{marker}", flush=True
                        )
                    elif tag == "Right":
                        code = decode_byte_term(payload)
                        errors[fid] = code
                        result = f"R{code}"
                except Exception as e:
                    result = f"ERR:{e}"
            else:
                result = "NODATA"

            # Save progress
            with open(progress_file, "a") as f:
                f.write(f"{fid}\t{result}\n")

            time.sleep(0.05)  # Rate limit

    # Phase 2: Summary of discoveries
    print(f"\n{'=' * 70}")
    print(f"SUMMARY: Found {len(discovered)} named entries")
    print(f"{'=' * 70}")

    new_discoveries = {
        fid: name
        for fid, name in sorted(discovered.items())
        if fid not in known_ids or fid == 256
    }

    if new_discoveries:
        print("\n  NEW/UNLINKED entries:")
        for fid, name in sorted(new_discoveries.items()):
            print(f"    ID {fid:5d}: {name!r}")
    else:
        print("\n  No new entries found beyond known filesystem.")

    # Phase 3: For all discovered files, try readfile
    print(f"\n{'=' * 70}")
    print(f"READING ALL DISCOVERED FILES")
    print(f"{'=' * 70}")

    answer_candidates = set()

    for fid, name in sorted(discovered.items()):
        # Try readfile
        out = call_syscall_qd(0x07, encode_byte_term(fid))
        if out and 0xFF in out:
            try:
                term = parse_term(out)
                tag, payload = decode_either(term)
                if tag == "Left":
                    content = decode_bytes_list(payload).decode("utf-8", "replace")
                    print(f"\n  ID {fid} ({name}): FILE, {len(content)} bytes")
                    print(f"    Content: {content!r}")

                    # Extract answer candidates
                    answer_candidates.add(content.strip())
                    answer_candidates.add(name)
                    for line in content.splitlines():
                        line = line.strip()
                        if line:
                            answer_candidates.add(line)
                            # Also individual words
                            for word in line.split():
                                answer_candidates.add(word)
                elif tag == "Right":
                    code = decode_byte_term(payload)
                    if code == 5:
                        print(f"  ID {fid} ({name}): DIRECTORY (Right(5))")
                    elif code == 4:
                        print(f"  ID {fid} ({name}): Not a directory (Right(4))")
                    else:
                        print(f"  ID {fid} ({name}): Error {code}")
            except Exception as e:
                print(f"  ID {fid} ({name}): Parse error: {e}")
        time.sleep(0.05)

    # Phase 4: Hash check ALL candidates
    print(f"\n{'=' * 70}")
    print(f"HASH CHECK: {len(answer_candidates)} candidates")
    print(f"{'=' * 70}")

    for cand in sorted(answer_candidates):
        if not cand or len(cand) > 200:
            continue
        # Check original, lower, upper
        for variant in [cand, cand.lower(), cand.upper()]:
            if check_hash(variant):
                print(f"\n  *** MATCH FOUND: {variant!r} ***")
                return

    print(f"  No hash matches found among {len(answer_candidates)} candidates.")

    print(f"\n{'=' * 70}")
    print(f"SWEEP COMPLETE")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
