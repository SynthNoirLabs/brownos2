#!/usr/bin/env python3
"""Probe sys1 (error->string) with out-of-range codes to find hidden messages."""

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


def probe_sys1(code: int) -> tuple[str, str]:
    """Call sys1(error_code) via QD and decode the result."""
    term = apps(g(1), NConst(int_term(code)), QD_TERM)
    out = query_named(term, timeout_s=10.0)
    try:
        t = parse_term(out)
        tag, payload = decode_either(t)
        if tag == "Left":
            text = decode_bytes_list(payload).decode("utf-8", "replace")
            return tag, text
        else:
            return "Right", "(error)"
    except Exception as e:
        cls = classify(out)
        return cls, str(e)


def main():
    print("=== Sys1 (Error String) Hidden Message Probe ===")

    # First verify known error codes
    print("\n[1] Known error codes 0-7:")
    for code in range(8):
        tag, text = probe_sys1(code)
        print(f"  sys1({code:3d}) -> {tag}: {text!r}")
        time.sleep(0.03)

    # Scan 8-255
    print("\n[2] Scan codes 8-255:")
    for code in range(8, 256):
        tag, text = probe_sys1(code)
        if tag == "Left" and text not in (
            "",
            "Unexpected exception",
            "Not implemented",
            "Invalid argument",
            "No such directory or file",
            "Not a directory",
            "Not a file",
            "Permission denied",
            "Not so fast!",
        ):
            print(f"  *** sys1({code:3d}) -> {tag}: {text!r}")
        elif tag != "Left":
            print(f"  sys1({code:3d}) -> {tag}: {text!r}")
        time.sleep(0.02)

    # Scan 256-1024 (sampling)
    print("\n[3] Scan codes 256-1024:")
    for code in range(256, 1025):
        tag, text = probe_sys1(code)
        if tag == "Left" and text not in ("", "Unexpected exception"):
            print(f"  *** sys1({code:3d}) -> {tag}: {text!r}")
        time.sleep(0.02)

    # Spot check high values
    print("\n[4] Spot check high codes:")
    for code in [2048, 4096, 8192, 16384, 32768, 65535, 42, 201, 253, 254, 255]:
        tag, text = probe_sys1(code)
        print(f"  sys1({code:5d}) -> {tag}: {text!r}")
        time.sleep(0.05)

    print("\n=== Sys1 Scan Complete ===")


if __name__ == "__main__":
    main()
