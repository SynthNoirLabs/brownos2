#!/usr/bin/env python3
"""
Brute force all 2-byte sequences (0x0000 to 0xFFFF) against target SHA1 hash.
Single-threaded with progress reporting.
"""

import hashlib
import logging
import sys
import time

# Target hash
TARGET_HASH = "9252ed65ffac2aa763adb21ef72c0178f1d83286"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("brute_2byte_raw_output.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


def sha1_56154(data):
    """Compute SHA1 hash 56154 times (matching brute_3char.py logic)."""
    cur = data
    for _ in range(56154):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii")


def main():
    logger.info("=" * 70)
    logger.info("Starting 2-byte brute force (0x0000 to 0xFFFF)")
    logger.info(f"Target hash: {TARGET_HASH}")
    logger.info(f"Total candidates: 65536")
    logger.info("=" * 70)

    start_time = time.time()
    matches = []

    for i in range(65536):
        # Convert to 2-byte sequence (big-endian)
        candidate = bytes([i >> 8, i & 0xFF])
        hash_result = sha1_56154(candidate)

        if hash_result == TARGET_HASH:
            matches.append((i, candidate.hex()))
            logger.info(f"✓✓✓ MATCH FOUND: 0x{i:04X} ({candidate.hex()}) ✓✓✓")

        # Progress logging every 1024 values
        if (i + 1) % 1024 == 0:
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed
            remaining = (65536 - i - 1) / rate if rate > 0 else 0
            logger.info(
                f"Progress: {i + 1:5d}/65536 ({100 * (i + 1) / 65536:5.1f}%) | "
                f"Rate: {rate:.1f} cand/s | ETA: {remaining:.0f}s"
            )

    # Report results
    logger.info("=" * 70)
    if matches:
        logger.info(f"✓✓✓ FOUND {len(matches)} MATCH(ES) ✓✓✓")
        for value, hex_str in matches:
            logger.info(f"  → 0x{value:04X} = {hex_str}")
    else:
        logger.info("✗ No matches found in 2-byte space")
    logger.info("=" * 70)

    return len(matches) > 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
