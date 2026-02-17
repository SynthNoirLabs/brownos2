#!/usr/bin/env python3
"""Fast 2-byte + 3-byte raw brute force using multiprocessing."""

import hashlib, multiprocessing, time, sys

TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ROUNDS = 56154


def check_range(args):
    start, end = args
    for i in range(start, end):
        if i < 65536:
            candidate = bytes([i >> 8, i & 0xFF])
        else:
            # 3-byte: i - 65536
            j = i - 65536
            candidate = bytes([j >> 16, (j >> 8) & 0xFF, j & 0xFF])
        cur = candidate
        for _ in range(ROUNDS):
            cur = hashlib.sha1(cur).hexdigest().encode("ascii")
        if cur.decode("ascii") == TARGET:
            return (i, candidate.hex(), candidate)
    return None


if __name__ == "__main__":
    # 2-byte: 65536 candidates, 3-byte: 16777216 candidates
    total_2byte = 65536
    total_3byte = 16777216
    total = total_2byte + total_3byte

    print(f"Testing {total_2byte} 2-byte + {total_3byte} 3-byte raw sequences")
    print(f"Target: {TARGET}")
    print(f"Using {multiprocessing.cpu_count()} cores")

    chunk = 512
    tasks = [(i, min(i + chunk, total)) for i in range(0, total, chunk)]

    start = time.time()
    found = None
    done = 0

    with multiprocessing.Pool() as pool:
        for result in pool.imap_unordered(check_range, tasks):
            done += chunk
            if done % (chunk * 32) == 0:
                elapsed = time.time() - start
                rate = done / elapsed
                pct = 100 * done / total
                eta = (total - done) / rate if rate > 0 else 0
                print(
                    f"  [{pct:5.1f}%] {done}/{total} | {rate:.0f}/s | ETA {eta:.0f}s",
                    flush=True,
                )
            if result is not None:
                found = result
                print(
                    f"\n!!! MATCH FOUND: idx={result[0]} hex={result[1]} raw={result[2]} !!!"
                )
                pool.terminate()
                break

    elapsed = time.time() - start
    if found:
        print(f"\n*** ANSWER: {found[2]} (hex: {found[1]}) ***")
    else:
        print(f"\nNo match in 2-byte or 3-byte raw space. Elapsed: {elapsed:.0f}s")
