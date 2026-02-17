#!/usr/bin/env python3
"""
Probe large filesystem IDs. We only scanned 0-100 and 256-1024 before.
The hash iteration count 56154 might be a hidden file ID.
Also check ID 8 specifically (gap in known IDs, matches syscall 8).

Key IDs to test:
- 8 (gap, matches sys8)
- 56154 (hash iteration count)
- Other meaningful numbers
"""

from __future__ import annotations

import socket
import time

from solve_brownos_answer import (
    HOST,
    PORT,
    FD,
    FE,
    FF,
    QD,
    encode_term,
    encode_byte_term,
    parse_term,
    decode_either,
    decode_byte_term,
    decode_bytes_list,
    query,
)


def call_syscall(syscall_num: int, argument: object) -> object:
    payload = (
        bytes([syscall_num])
        + encode_term(argument)
        + bytes([FD])
        + QD
        + bytes([FD, FF])
    )
    out = query(payload, timeout_s=8.0)
    return parse_term(out)


def probe_id(file_id: int) -> dict:
    """Test name(), readfile(), readdir() for a given ID."""
    result = {}

    # name(id)
    try:
        term = call_syscall(0x06, encode_byte_term(file_id))
        tag, payload = decode_either(term)
        if tag == "Left":
            bs = decode_bytes_list(payload)
            result["name"] = f"Left('{bs.decode('utf-8', 'replace')}')"
        else:
            errcode = decode_byte_term(payload)
            result["name"] = f"Right({errcode})"
    except Exception as e:
        result["name"] = f"ERROR({e})"
    time.sleep(0.1)

    # readfile(id) — only if name didn't return NoSuchFile
    if "Right(3)" not in result.get("name", ""):
        try:
            term = call_syscall(0x07, encode_byte_term(file_id))
            tag, payload = decode_either(term)
            if tag == "Left":
                bs = decode_bytes_list(payload)
                text = bs.decode("utf-8", "replace")
                result["readfile"] = f"Left('{text[:100]}')"
            else:
                errcode = decode_byte_term(payload)
                result["readfile"] = f"Right({errcode})"
        except Exception as e:
            result["readfile"] = f"ERROR({e})"
        time.sleep(0.1)

    # readdir(id) — only if name didn't return NoSuchFile
    if "Right(3)" not in result.get("name", ""):
        try:
            term = call_syscall(0x05, encode_byte_term(file_id))
            tag, payload = decode_either(term)
            if tag == "Left":
                result["readdir"] = "Left(dirlist)"
            else:
                errcode = decode_byte_term(payload)
                result["readdir"] = f"Right({errcode})"
        except Exception as e:
            result["readdir"] = f"ERROR({e})"
        time.sleep(0.1)

    return result


def main():
    print("=" * 60)
    print("LARGE ID FILESYSTEM PROBE")
    print("=" * 60)

    # Priority IDs to test
    priority_ids = [
        (8, "gap ID matching sys8"),
        (10, "gap near sys8"),
        (12, "gap"),
        (13, "gap"),
        (7, "readfile syscall"),
        (17, "gap after false(16)"),
        (18, "gap"),
        (19, "gap"),
        (20, "gap"),
        (21, "gap"),
        (23, "gap"),
        (24, "gap"),
        (42, "towel syscall / hitchhiker"),
        (201, "backdoor syscall"),
        (253, "near reserved"),
        (254, "near reserved"),
        (255, "max byte"),
        (256, "known hidden file"),
        (257, "after hidden file"),
        (512, "2*256"),
        (1000, "gizmore UID"),
        (1002, "dloser UID"),
        (1337, "leet"),
        (2024, "year"),
        (2025, "year"),
        (2026, "year"),
        (4096, "page size"),
        (8192, "2*4096"),
        (9252, "hash prefix"),
        (31337, "elite"),
        (37458, "0x9252 decimal"),
        (56154, "hash iteration count"),
        (61221, "port number"),
        (65535, "max uint16"),
    ]

    print("\n--- Priority IDs ---")
    for file_id, desc in priority_ids:
        result = probe_id(file_id)
        name_str = result.get("name", "?")

        # Only show interesting results (not NoSuchFile)
        if "Right(3)" in name_str:
            print(f"  ID {file_id:6d} ({desc:25s}): NoSuchFile")
        else:
            print(f"  ID {file_id:6d} ({desc:25s}): name={name_str}")
            if "readfile" in result:
                print(f"         readfile={result['readfile']}")
            if "readdir" in result:
                print(f"         readdir={result['readdir']}")

        time.sleep(0.05)

    # Also scan the gaps we know about: IDs 7-21 that aren't in our tree
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
    print("\n--- Gap scan 0-100 (showing only hits) ---")
    for i in range(101):
        if i in known_ids:
            continue
        result = probe_id(i)
        name_str = result.get("name", "?")
        if "Right(3)" not in name_str:
            print(f"  ID {i:3d}: name={name_str}")
            if "readfile" in result:
                print(f"       readfile={result['readfile']}")
            if "readdir" in result:
                print(f"       readdir={result['readdir']}")
        time.sleep(0.05)

    print("\n" + "=" * 60)
    print("LARGE ID PROBE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
