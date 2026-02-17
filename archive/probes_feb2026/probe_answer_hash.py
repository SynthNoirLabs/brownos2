#!/usr/bin/env python3
"""
probe_answer_hash.py — Test if the WeChall answer is derived from BrownOS bytecodes/outputs.

The answer is verified by: sha1^56154(answer) == "9252ed65ffac2aa763adb21ef72c0178f1d83286"

Maybe the answer is:
1. The bytecode of the solution program
2. The hex of the solution program
3. The output of a specific program
4. A string derived from the global structure
5. The decoded pair from the backdoor
"""

import hashlib
import sys

TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ROUNDS = 56154


def check(candidate):
    """Check if candidate string matches the target hash."""
    cur = candidate.encode("utf-8") if isinstance(candidate, str) else candidate
    for _ in range(ROUNDS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET


def check_and_report(label, candidate):
    """Check and print result."""
    if isinstance(candidate, bytes):
        candidate = candidate.decode("utf-8", "replace")
    result = check(candidate)
    if result:
        print(f"  !!! MATCH !!! {label}: {candidate!r}")
    return result


def main():
    print("=" * 72)
    print("Testing answer hash candidates derived from BrownOS structure")
    print(f"Target: {TARGET}")
    print(f"Rounds: {ROUNDS}")
    print("=" * 72)
    print()

    candidates = []

    # Category 1: Bytecodes of known programs
    # The "3 leaf" minimal programs
    for a in range(253):
        for b in range(253):
            # 2-leaf: a b FD FF
            bc = bytes([a, b, 0xFD, 0xFF])
            candidates.append((f"2leaf_{a}_{b}", bc.hex()))

    # But that's 253^2 = 64009 candidates... too many for sha1^56154
    # Let's focus on the interesting ones
    candidates = []

    # Key globals
    key = [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]

    # 3-leaf programs with key globals (left-associated)
    for a in key:
        for b in key:
            for c in key:
                bc = bytes([a, b, 0xFD, c, 0xFD, 0xFF])
                candidates.append((f"3L_L({a},{b},{c})", bc.hex()))
                # Also without FF
                bc2 = bytes([a, b, 0xFD, c, 0xFD])
                candidates.append((f"3L_L_noFF({a},{b},{c})", bc2.hex()))

    # 3-leaf programs with key globals (right-associated)
    for a in key:
        for b in key:
            for c in key:
                bc = bytes([a, b, c, 0xFD, 0xFD, 0xFF])
                candidates.append((f"3L_R({a},{b},{c})", bc.hex()))
                bc2 = bytes([a, b, c, 0xFD, 0xFD])
                candidates.append((f"3L_R_noFF({a},{b},{c})", bc2.hex()))

    # The global structure: each global encodes [N, 255]
    # Maybe the answer is related to this encoding
    for n in range(256):
        candidates.append((f"byte_pair_{n}_255", f"{n},255"))
        candidates.append((f"byte_pair_hex_{n}_ff", f"{n:02x}ff"))
        candidates.append((f"byte_pair_dec_{n}_255", f"{n} 255"))

    # Backdoor pair components
    # A = λa.λb.(b b) = 00 00 FD FE FE
    # B = λa.λb.(a b) = 01 00 FD FE FE
    candidates.append(("A_hex", "0000fdfefe"))
    candidates.append(("B_hex", "0100fdfefe"))
    candidates.append(("pair_hex", "010000fdfefe0100fdfefefdfefe"))
    candidates.append(("A_lambda", "\\a.\\b.(b b)"))
    candidates.append(("B_lambda", "\\a.\\b.(a b)"))
    candidates.append(("A_debruijn", "\\\\(0 0)"))
    candidates.append(("B_debruijn", "\\\\(1 0)"))

    # The quoted form of g(8)
    g8_hex = "01010400fdfefefefefefefefefefd01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe"
    candidates.append(("g8_quoted_hex", g8_hex))
    candidates.append(("g8_quoted_hex_ff", g8_hex + "ff"))

    # The common suffix
    suffix = "01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe"
    candidates.append(("common_suffix", suffix))

    # QD bytes
    qd = "0500fd000500fd03fdfefd02fdfefdfe"
    candidates.append(("QD_hex", qd))
    candidates.append(("QD_hex_ff", qd + "ff"))

    # Right(6) output
    r6 = "00030200fdfdfefefefefefefefefefdfefe"
    candidates.append(("Right6_hex", r6))
    candidates.append(("Right6_hex_ff", r6 + "ff"))

    # The "input codes" — maybe the answer is about the encoding pattern
    # Each code N maps to [N, 255] internally
    candidates.append(("encoding_pattern", "[N, 255]"))
    candidates.append(("encoding_pattern2", "N,255"))
    candidates.append(("encoding_pattern3", "[N,FF]"))

    # nil = 00 FE FE
    candidates.append(("nil_hex", "00fefe"))
    candidates.append(("nil_hex_ff", "00fefeff"))

    # The cheat sheet examples
    candidates.append(("cs1", "QD ?? FD"))
    candidates.append(("cs2", "?? ?? FD QD FD"))

    # Syscall 8 with nil: 08 00 FE FE FD QD FD FF
    sys8_nil = "0800fefefd" + qd + "fdff"
    candidates.append(("sys8_nil_full", sys8_nil))

    # Maybe the answer is a specific error message
    candidates.append(("perm_denied", "Permission denied"))
    candidates.append(("not_impl", "Not implemented"))
    candidates.append(("invalid_arg", "Invalid argument"))

    # The number 255 in various forms
    for fmt in ["255", "0xff", "0xFF", "FF", "ff", "11111111"]:
        candidates.append((f"num255_{fmt}", fmt))

    # Combinations of special bytes
    for combo in [
        "FDFEFF",
        "fdfeff",
        "FDFE",
        "fdfe",
        "FEFF",
        "feff",
        "FD",
        "fd",
        "FE",
        "fe",
    ]:
        candidates.append((f"special_{combo}", combo))

    # The answer might be the EMPTY string!
    candidates.append(("empty", ""))

    # Or just whitespace
    candidates.append(("space", " "))
    candidates.append(("newline", "\n"))

    # dloser's hints as answers
    candidates.append(("hint_3leafs", "3 leafs"))
    candidates.append(("hint_3leaves", "3 leaves"))

    # The backdoor mail content
    candidates.append(
        ("mail_backdoor", "Backdoor is ready at syscall 201; start with 00 FE FE.")
    )
    candidates.append(("mail_start", "00 FE FE"))
    candidates.append(("mail_start_nospace", "00FEFE"))

    print(f"Testing {len(candidates)} candidates...")
    print()

    found = False
    for i, (label, candidate) in enumerate(candidates):
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i + 1}/{len(candidates)}", flush=True)
        if check_and_report(label, candidate):
            found = True
            break

    if not found:
        print(f"  No match found among {len(candidates)} candidates.")

    print()
    print("Done.")


if __name__ == "__main__":
    main()
