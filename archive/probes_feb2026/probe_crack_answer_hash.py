#!/usr/bin/env python3
"""
Crack the BrownOS static answer hash from public challenge source.

Reference checker logic in gwf3:
  answer_hash = sha1(sha1(...sha1(answer)...))  # 56154 rounds
  compare with 9252ed65ffac2aa763adb21ef72c0178f1d83286
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import multiprocessing as mp
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable


DEFAULT_TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
DEFAULT_ROUNDS = 56154

DEFAULT_PATTERNS = (
    "BROWNOS_MASTER.md",
    "README.md",
    "FINAL_ANALYSIS.md",
    "SESSION_FINDINGS.md",
    "CHATGPT_HANDOFF.md",
    "CHATGPT_QUICKREF.md",
    "challenge.html",
    "archive/docs/*.md",
    "forums/*.html",
    "archive/forums_extracted.json",
    "probe_*.py",
    "solve_brownos*.py",
    "utils/*.py",
)

INTEREST_WORDS = (
    "brownos",
    "mail",
    "backdoor",
    "syscall",
    "echo",
    "special",
    "bytes",
    "permission",
    "denied",
    "ilikephp",
    "gizmore",
    "dloser",
    "omega",
    "towel",
    "wtf",
    "access",
    "history",
    "password",
    "ready",
    "start",
    "boss",
    "evil",
    "kernel",
    "record",
    "three",
    "leaf",
    "leafs",
    "3",
    "201",
    "8",
    "08",
    "00fefe",
    "fefe",
    "fdfeff",
)

MANUAL_CANDIDATES = (
    "omega",
    "towel",
    "ilikephp",
    "dloser",
    "gizmore",
    "brownos",
    "backdoor",
    "mail",
    "syscall",
    "syscall8",
    "syscall_8",
    "syscall08",
    "echo",
    "special",
    "bytes",
    "permission",
    "denied",
    "permission denied",
    "permissiondenied",
    "password",
    "history",
    "access",
    "log",
    "wtf",
    "nil",
    "fefe",
    "fdfefeff",
    "00fefe",
    "00fefeff",
    "3leafs",
    "threeleafs",
    "threeleaf",
    "leafs",
    "leaf",
    "boss",
    "evil",
    "boss@evil.com",
    "mailer",
    "delivery",
    "failure",
    "ready",
    "start",
    "ohgochokeonatowel",
    "oh_go_choke_on_a_towel",
    "gochokeonatowel",
    "backdoorisreadyatsyscall201startwith00fefe",
)

CHALLENGEISH_SUBSTRINGS = (
    "brown",
    "sys",
    "call",
    "mail",
    "door",
    "echo",
    "towel",
    "gizmo",
    "dlos",
    "php",
    "perm",
    "deny",
    "leaf",
    "boss",
    "evil",
    "fefe",
    "fd",
    "fe",
    "ff",
)

NUM_SUFFIXES = ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "42", "201", "256")
SEPARATORS = ("", "_", "-", " ")


def iter_sha1_hex_bytes(data: bytes, rounds: int) -> str:
    cur = data
    for _ in range(rounds):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii")


def matches_target(candidate: str, target: str, rounds: int) -> bool:
    return iter_sha1_hex_bytes(candidate.encode("utf-8", "ignore"), rounds) == target


def dedupe_keep_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def read_local_corpus(patterns: Iterable[str]) -> tuple[str, list[Path]]:
    files: list[Path] = []
    text_parts: list[str] = []
    for pattern in patterns:
        for path in Path(".").glob(pattern):
            if not path.is_file():
                continue
            files.append(path)
            try:
                text_parts.append(path.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                continue
    return "\n".join(text_parts), files


def fetch_live_thread(timeout_s: float = 10.0) -> str:
    url = "https://www.wechall.net/forum-t1575/Disappointment_Thread-p2.html"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) BrownOS-research-script",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            data = resp.read()
        return data.decode("utf-8", "ignore")
    except (urllib.error.URLError, TimeoutError, OSError):
        return ""


def extract_tokens(text: str) -> list[str]:
    return dedupe_keep_order(re.findall(r"[A-Za-z0-9_@.\-+/]+", text))


def build_candidates(
    tokens: list[str],
    docs_for_lines: Iterable[Path],
    full_mode: bool,
) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    def add(cand: str) -> None:
        cand = cand.strip("\x00\r\n\t")
        if not cand:
            return
        if len(cand) > 64:
            return
        if cand.startswith("http"):
            return
        if cand in seen:
            return
        seen.add(cand)
        candidates.append(cand)

    for cand in MANUAL_CANDIDATES:
        add(cand)

    for token in tokens:
        if not (1 <= len(token) <= 64):
            continue
        add(token)
        add(token.lower())
        stripped = re.sub(r"[^A-Za-z0-9]", "", token)
        if stripped:
            add(stripped)
            add(stripped.lower())

    simple_keywords = [
        c
        for c in candidates
        if 2 <= len(c) <= 18 and re.fullmatch(r"[a-z0-9]+", c) is not None
    ]

    base_words: list[str] = [w for w in INTEREST_WORDS if w in simple_keywords]
    challengeish = [
        word
        for word in simple_keywords
        if any(sub in word for sub in CHALLENGEISH_SUBSTRINGS)
    ]
    base_words.extend(challengeish[:500])
    base_words = dedupe_keep_order(base_words)

    for word in base_words[:200]:
        for suffix in NUM_SUFFIXES:
            if len(word) + len(suffix) <= 40:
                add(word + suffix)
                add(suffix + word)

    # Line-based normalization for challenge docs.
    rm_chars = re.compile(r"[`*_#>|\-:.,()\[\]\\\"'!?]")
    for path in docs_for_lines:
        try:
            for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.strip()
                if not line or len(line) > 120:
                    continue
                norm = rm_chars.sub("", line)
                norm = " ".join(norm.split())
                if not (3 <= len(norm) <= 60):
                    continue
                add(norm)
                add(norm.lower())
                add(norm.replace(" ", ""))
                add(norm.lower().replace(" ", ""))
        except OSError:
            continue

    if full_mode:
        # 2-word combinations.
        for a, b in itertools.product(base_words, repeat=2):
            if a == b and len(a) < 3:
                continue
            for sep in SEPARATORS:
                combo = f"{a}{sep}{b}"
                if 2 <= len(combo) <= 40:
                    add(combo)

        # 3-word concatenations from a reduced subset.
        tiny = [w for w in base_words if len(w) <= 8][:60]
        for a, b, c in itertools.product(tiny, repeat=3):
            combo = f"{a}{b}{c}"
            if 3 <= len(combo) <= 28:
                add(combo)

    return candidates


def load_wordlist(path: Path) -> list[str]:
    out: list[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if word:
                    out.append(word)
    except OSError:
        return []
    return out


def worker_check_batch(args: tuple[list[str], str, int]) -> str | None:
    batch, target, rounds = args
    for cand in batch:
        if matches_target(cand, target, rounds):
            return cand
    return None


def run_bruteforce(
    candidates: list[str],
    target: str,
    rounds: int,
    workers: int,
    batch_size: int,
) -> str | None:
    if not candidates:
        return None

    def batches() -> Iterable[list[str]]:
        for i in range(0, len(candidates), batch_size):
            yield candidates[i : i + batch_size]

    start = time.time()
    checked = 0
    last_report = start

    if workers <= 1:
        for batch in batches():
            result = worker_check_batch((batch, target, rounds))
            checked += len(batch)
            now = time.time()
            if now - last_report >= 2.0:
                rate = checked / (now - start)
                print(f"[progress] checked={checked} rate={rate:.1f}/s", flush=True)
                last_report = now
            if result is not None:
                return result
        return None

    # Fork is fastest/most reliable here, but keep a fallback.
    try:
        ctx = mp.get_context("fork")
    except ValueError:
        ctx = mp.get_context()

    with ctx.Pool(processes=workers) as pool:
        work = ((batch, target, rounds) for batch in batches())
        for result in pool.imap_unordered(worker_check_batch, work, chunksize=1):
            checked += batch_size
            now = time.time()
            if now - last_report >= 2.0:
                rate = checked / (now - start)
                print(f"[progress] checked~{checked} rate~{rate:.1f}/s", flush=True)
                last_report = now
            if result is not None:
                pool.terminate()
                return result
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BrownOS static hash preimage search.")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Target hash to match.")
    parser.add_argument(
        "--rounds",
        type=int,
        default=DEFAULT_ROUNDS,
        help="Number of repeated sha1 rounds.",
    )
    parser.add_argument(
        "--stage",
        choices=("quick", "full"),
        default="quick",
        help="quick = smaller candidate set, full = broader combinatorics.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=max(1, min(16, (os.cpu_count() or 2) - 1)),
        help="Worker process count.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=96,
        help="Candidates per worker task.",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=0,
        help="If >0, cap candidate count after generation.",
    )
    parser.add_argument(
        "--wordlist",
        type=Path,
        help="Optional newline wordlist file to append.",
    )
    parser.add_argument(
        "--no-live-thread",
        action="store_true",
        help="Do not fetch the Jan 2026 forum page during candidate generation.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = args.target.lower().strip()

    print("[*] loading local corpus...", flush=True)
    local_text, local_files = read_local_corpus(DEFAULT_PATTERNS)
    corpus_parts = [local_text]

    if not args.no_live_thread:
        print("[*] fetching live thread page...", flush=True)
        live = fetch_live_thread(timeout_s=10.0)
        if live:
            corpus_parts.append(live)
            print("[*] fetched live thread text", flush=True)
        else:
            print("[*] live thread fetch failed; continuing with local corpus", flush=True)

    tokens = extract_tokens("\n".join(corpus_parts))
    docs_for_lines = [p for p in local_files if p.suffix.lower() in {".md", ".txt"}]
    full_mode = args.stage == "full"

    print(f"[*] generating candidates (stage={args.stage})...", flush=True)
    candidates = build_candidates(tokens, docs_for_lines, full_mode=full_mode)

    if args.wordlist:
        wl = load_wordlist(args.wordlist)
        print(f"[*] loaded wordlist entries: {len(wl)}", flush=True)
        candidates = dedupe_keep_order(candidates + wl)

    if args.max_candidates > 0:
        candidates = candidates[: args.max_candidates]

    print(f"[*] total candidates: {len(candidates)}", flush=True)
    print(
        f"[*] cracking target={target} rounds={args.rounds} workers={args.workers} batch_size={args.batch_size}",
        flush=True,
    )

    started = time.time()
    match = run_bruteforce(
        candidates=candidates,
        target=target,
        rounds=args.rounds,
        workers=max(1, args.workers),
        batch_size=max(1, args.batch_size),
    )
    elapsed = time.time() - started

    if match is None:
        print(f"[-] no match found in {len(candidates)} candidates ({elapsed:.2f}s)")
        return 2

    final_hash = iter_sha1_hex_bytes(match.encode("utf-8", "ignore"), args.rounds)
    print(f"[+] MATCH: {match!r}")
    print(f"[+] verify: {final_hash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
