#!/usr/bin/env python3
"""Brute-force all printable ASCII 1/2/3-char strings against BrownOS answer hash.

Hash: sha1^56154(candidate) == "9252ed65ffac2aa763adb21ef72c0178f1d83286"
Chars: printable ASCII 32-126 (95 chars)
Space: 95 + 95^2 + 95^3 = 95 + 9025 + 857375 = 866495 candidates
"""

import hashlib
import itertools
import multiprocessing
import os
import sys
import time

TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ITERATIONS = 56154
PRINTABLE = [chr(c) for c in range(32, 127)]  # space through tilde


def check_candidate(candidate_str):
    """Apply sha1() exactly 56154 times, compare to target."""
    cur = candidate_str.encode("utf-8")
    for _ in range(ITERATIONS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET


def check_batch(batch):
    """Check a batch of candidates. Returns match or None."""
    for candidate in batch:
        if check_candidate(candidate):
            return candidate
    return None


def generate_candidates(length):
    """Generate all printable ASCII strings of given length."""
    for combo in itertools.product(PRINTABLE, repeat=length):
        yield "".join(combo)


def main():
    ncpus = os.cpu_count() or 4
    print(f"BrownOS answer hash brute-force")
    print(f"Target: {TARGET}")
    print(f"Iterations: {ITERATIONS}")
    print(f"CPUs: {ncpus}")
    print(f"Charset: printable ASCII (32-126), {len(PRINTABLE)} chars")
    print()

    # Collect all candidates: 1-char, 2-char, 3-char
    total_expected = len(PRINTABLE) + len(PRINTABLE) ** 2 + len(PRINTABLE) ** 3
    print(f"Expected candidates: {total_expected}")
    print(f"  1-char: {len(PRINTABLE)}")
    print(f"  2-char: {len(PRINTABLE) ** 2}")
    print(f"  3-char: {len(PRINTABLE) ** 3}")
    print()

    # Build batches for multiprocessing
    BATCH_SIZE = 500
    all_candidates = []

    # 1-char
    for c in PRINTABLE:
        all_candidates.append(c)

    # 2-char
    for combo in itertools.product(PRINTABLE, repeat=2):
        all_candidates.append("".join(combo))

    # 3-char
    for combo in itertools.product(PRINTABLE, repeat=3):
        all_candidates.append("".join(combo))

    assert len(all_candidates) == total_expected, (
        f"Got {len(all_candidates)}, expected {total_expected}"
    )

    # Split into batches
    batches = []
    for i in range(0, len(all_candidates), BATCH_SIZE):
        batches.append(all_candidates[i : i + BATCH_SIZE])

    print(f"Total candidates: {len(all_candidates)}")
    print(f"Batches: {len(batches)} (size {BATCH_SIZE})")
    print()

    t0 = time.time()
    checked = 0
    match = None

    with multiprocessing.Pool(processes=ncpus) as pool:
        for result in pool.imap_unordered(check_batch, batches):
            checked += BATCH_SIZE
            if checked % 10000 < BATCH_SIZE:
                elapsed = time.time() - t0
                rate = checked / elapsed if elapsed > 0 else 0
                eta = (len(all_candidates) - checked) / rate if rate > 0 else 0
                print(
                    f"  [{checked:>7}/{len(all_candidates)}] "
                    f"{elapsed:.1f}s elapsed, {rate:.1f}/s, "
                    f"ETA {eta:.0f}s",
                    flush=True,
                )
            if result is not None:
                match = result
                pool.terminate()
                break

    elapsed = time.time() - t0

    print()
    print(f"{'=' * 60}")
    if match is not None:
        print(f"MATCH FOUND: {match!r}")
        print(f"  (length={len(match)}, bytes={match.encode('utf-8').hex()})")
        # Verify
        assert check_candidate(match), "Verification failed!"
        print(f"  Verified: sha1^{ITERATIONS}({match!r}) == {TARGET}")
    else:
        print(f"NO MATCH across {len(all_candidates)} candidates")

    print(f"Time: {elapsed:.1f}s")
    print(f"Rate: {len(all_candidates) / elapsed:.1f} candidates/s")
    print(f"{'=' * 60}")

    return match


if __name__ == "__main__":
    match = main()
    sys.exit(0 if match is not None else 1)
