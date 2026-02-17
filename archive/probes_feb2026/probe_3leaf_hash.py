#!/usr/bin/env python3
"""Test 3-leaf program bytecodes as WeChall answer candidates.

The hypothesis: the answer is the hex string of a 3-leaf program.
The program backdoor(nil)(Var(xx)) = C9 00 FE FE FD xx FD FF
has exactly 3 Var nodes (leaves): Var(0xC9), Var(0) inside nil, Var(xx).

We test ALL 256 possible xx values (0x00 through 0xFF).
We also test other 3-leaf program shapes.
"""

import hashlib
import time

TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ITERATIONS = 56154


def check_hash(candidate_str):
    """Check if sha1^56154(candidate) matches target."""
    cur = candidate_str.encode("utf-8")
    for _ in range(ITERATIONS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET


def main():
    print("=" * 60)
    print("3-Leaf Program Bytecode Hash Test")
    print(f"Target: {TARGET}")
    print(f"Iterations: {ITERATIONS}")
    print("=" * 60)

    candidates = []

    # SHAPE 1: backdoor(nil)(Var(xx)) = C9 00 FE FE FD xx FD FF
    # 3 leaves: Var(0xC9), Var(0), Var(xx)
    for xx in range(256):
        # Raw hex lowercase no spaces
        bytecode = bytes([0xC9, 0x00, 0xFE, 0xFE, 0xFD, xx, 0xFD, 0xFF])
        hex_lower = bytecode.hex()
        hex_upper = bytecode.hex().upper()
        hex_spaced = " ".join(f"{b:02x}" for b in bytecode)
        hex_spaced_upper = " ".join(f"{b:02X}" for b in bytecode)
        # Without FF terminator
        hex_no_ff = bytecode[:-1].hex()

        candidates.append((f"S1 xx={xx:02x} hex", hex_lower))
        candidates.append((f"S1 xx={xx:02x} HEX", hex_upper))
        candidates.append((f"S1 xx={xx:02x} spaced", hex_spaced))
        candidates.append((f"S1 xx={xx:02x} SPACED", hex_spaced_upper))
        candidates.append((f"S1 xx={xx:02x} no-ff", hex_no_ff))

    # SHAPE 2: sys8(nil)(Var(xx)) = 08 00 FE FE FD xx FD FF
    # 3 leaves: Var(8), Var(0), Var(xx)
    for xx in range(256):
        bytecode = bytes([0x08, 0x00, 0xFE, 0xFE, 0xFD, xx, 0xFD, 0xFF])
        candidates.append((f"S2 xx={xx:02x}", bytecode.hex()))
        candidates.append((f"S2 xx={xx:02x} no-ff", bytecode[:-1].hex()))

    # SHAPE 3: echo(nil)(Var(xx)) = 0E 00 FE FE FD xx FD FF
    for xx in range(256):
        bytecode = bytes([0x0E, 0x00, 0xFE, 0xFE, 0xFD, xx, 0xFD, 0xFF])
        candidates.append((f"S3 xx={xx:02x}", bytecode.hex()))

    # SHAPE 4: Var(a)(Var(b))(Var(c)) = a b FD c FD FF
    # All 3-leaf programs with just 3 vars and 2 apps
    for a in range(256):
        for b in range(256):
            for c in range(256):
                # This would be 256^3 = 16M candidates - too many!
                # Only test interesting values
                pass

    # Instead, test specific interesting 3-leaf programs:
    interesting_triples = [
        (0xC9, 0x08, 0x00),  # backdoor(sys8)(nil-like)
        (0x08, 0xC9, 0x00),  # sys8(backdoor)(nil-like)
        (0x08, 0x00, 0xC9),  # sys8(nil-like)(backdoor)
        (0xC9, 0x00, 0x08),  # backdoor(nil-like)(sys8)
        (0x00, 0x08, 0xC9),  # g(0)(sys8)(backdoor)
        (0x00, 0xC9, 0x08),  # g(0)(backdoor)(sys8)
        (0x08, 0x08, 0x08),  # sys8(sys8)(sys8)
        (0xC9, 0xC9, 0xC9),  # bd(bd)(bd)
        (0x00, 0x00, 0x00),  # g(0)(g(0))(g(0))
        (0x2A, 0x00, 0x00),  # towel(nil-like)(nil-like)
        (0x0E, 0x08, 0xC9),  # echo(sys8)(backdoor)
    ]

    for a, b, c in interesting_triples:
        # Left-associated: (a b) c
        bytecode = bytes([a, b, 0xFD, c, 0xFD, 0xFF])
        candidates.append((f"S4L {a:02x}({b:02x})({c:02x})", bytecode.hex()))
        candidates.append((f"S4L {a:02x}({b:02x})({c:02x}) no-ff", bytecode[:-1].hex()))

        # Right-associated: a (b c)
        bytecode2 = bytes([a, b, c, 0xFD, 0xFD, 0xFF])
        candidates.append((f"S4R {a:02x}({b:02x} {c:02x})", bytecode2.hex()))

    # SHAPE 5: Programs with lambdas that have 3 leaves
    # λ.Var(a)(Var(b))(Var(c)) = a b FD c FD FE FF
    for a, b, c in [
        (0, 0, 0),
        (1, 0, 0),
        (0, 1, 0),
        (0, 0, 1),
        (8, 0, 0),
        (0xC9, 0, 0),
    ]:
        bytecode = bytes([a, b, 0xFD, c, 0xFD, 0xFE, 0xFF])
        candidates.append((f"S5 lam({a},{b},{c})", bytecode.hex()))

    # SHAPE 6: The raw bytes as a string (not hex)
    for xx in [0x00, 0x08, 0x0E, 0x2A, 0xC9]:
        bytecode = bytes([0xC9, 0x00, 0xFE, 0xFE, 0xFD, xx, 0xFD, 0xFF])
        try:
            as_str = bytecode.decode("latin-1")
            candidates.append((f"S6 latin1 xx={xx:02x}", as_str))
        except:
            pass

    print(f"\nTotal candidates: {len(candidates)}")
    print("Testing...\n")

    t0 = time.time()
    found = False
    for i, (label, cand) in enumerate(candidates):
        if check_hash(cand):
            print(f"\n{'*' * 60}")
            print(f"*** MATCH FOUND: {label} ***")
            print(f"*** Answer: {cand!r} ***")
            print(
                f"*** Hex: {cand.encode('utf-8').hex() if len(cand) < 100 else 'too long'} ***"
            )
            print(f"{'*' * 60}\n")
            found = True
            break

        if (i + 1) % 100 == 0:
            elapsed = time.time() - t0
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            eta = (len(candidates) - i - 1) / rate if rate > 0 else 0
            print(
                f"  [{i + 1}/{len(candidates)}] {elapsed:.1f}s, {rate:.1f}/s, ETA {eta:.0f}s"
            )

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.1f}s")
    if not found:
        print("NO MATCH FOUND")

    return found


if __name__ == "__main__":
    import sys

    found = main()
    sys.exit(0 if found else 1)
