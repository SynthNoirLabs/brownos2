#!/usr/bin/env python3
"""Quick probe: check file IDs 257+ for name/content. Did we miss any?"""

from __future__ import annotations

import time

from probe_mail_focus import (
    NIL,
    NConst,
    apps,
    classify,
    g,
    lam,
    query_named,
    v,
    write_marker,
    int_term,
)
from solve_brownos_answer import (
    encode_bytes_list,
    encode_byte_term,
    parse_term,
    QD,
    decode_bytes_list,
    decode_either,
)


QD_TERM = NConst(parse_term(QD))


def probe_name_qd(file_id: int) -> tuple[str, bytes]:
    """name(file_id) via QD — returns raw bytes."""
    term = apps(g(6), NConst(int_term(file_id)), QD_TERM)
    out = query_named(term, timeout_s=10.0)
    return classify(out), out


def probe_readfile_qd(file_id: int) -> tuple[str, bytes]:
    """readfile(file_id) via QD."""
    term = apps(g(7), NConst(int_term(file_id)), QD_TERM)
    out = query_named(term, timeout_s=10.0)
    return classify(out), out


def decode_qd_result(out: bytes) -> str:
    """Try to decode QD output as Either(bytes)."""
    try:
        term = parse_term(out)
        tag, payload = decode_either(term)
        if tag == "Left":
            return f"Left: {decode_bytes_list(payload).decode('utf-8', 'replace')!r}"
        else:
            return f"Right: (error)"
    except Exception as e:
        return f"decode_error: {e}"


def main():
    print("=== File ID Scanner (257+) ===")

    # First check 256 (known: "wtf")
    print("\n[1] Verify known file 256")
    cls, out = probe_name_qd(256)
    print(f"  name(256) -> {cls} decoded={decode_qd_result(out)}")
    cls, out = probe_readfile_qd(256)
    print(f"  readfile(256) -> {cls} decoded={decode_qd_result(out)}")
    time.sleep(0.1)

    # Now scan 257-512
    print("\n[2] Scan file IDs 257-512")
    found = []
    for fid in range(257, 513):
        cls, out = probe_name_qd(fid)
        if "R" not in cls or len(out) > 5:
            # Might be a real file
            decoded = decode_qd_result(out)
            if "Right" not in decoded:
                print(f"  *** name({fid}) -> {cls} decoded={decoded}")
                found.append(fid)
        time.sleep(0.02)

    if found:
        print(f"\n[3] Reading found files: {found}")
        for fid in found:
            cls, out = probe_readfile_qd(fid)
            decoded = decode_qd_result(out)
            print(f"  readfile({fid}) -> {cls} decoded={decoded}")
            time.sleep(0.1)
    else:
        print("\n  No new files found in 257-512.")

    # Also check 0-255 for any we might have missed
    print("\n[4] Quick scan 100-255 for missed files")
    for fid in range(100, 256):
        if fid in (201,):
            continue  # skip backdoor
        cls, out = probe_name_qd(fid)
        if "R" not in cls or len(out) > 5:
            decoded = decode_qd_result(out)
            if "Right" not in decoded:
                print(f"  *** name({fid}) -> {cls} decoded={decoded}")
        time.sleep(0.02)

    # Check some high IDs
    print("\n[5] Spot check high IDs: 1000, 1337, 2048, 4096, 65535")
    for fid in [1000, 1337, 2048, 4096, 65535]:
        cls, out = probe_name_qd(fid)
        decoded = decode_qd_result(out)
        if "Right" not in decoded:
            print(f"  *** name({fid}) -> {cls} decoded={decoded}")
        time.sleep(0.05)

    print("\n=== Scan Complete ===")


if __name__ == "__main__":
    main()
