#!/usr/bin/env python3
"""
probe_phase2_forum_mine.py — Exhaustively mine ALL forum HTML files and challenge.html
for potential answer strings, then test every extracted candidate against the BrownOS answer hash.

Target: sha1^56154(answer) == "9252ed65ffac2aa763adb21ef72c0178f1d83286"
"""

import hashlib
import re
import os
import glob
import codecs
import base64
import html
import time
from html.parser import HTMLParser
from urllib.parse import unquote

# ─── Constants ──────────────────────────────────────────────────────
TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ROUNDS = 56154
MAX_CANDIDATES = 20000
MAX_TIME_SECONDS = 900  # 15 minute hard limit for hash testing

BASE = os.path.dirname(os.path.abspath(__file__))
FORUM_DIR = os.path.join(BASE, "forums")
CHALLENGE_FILE = os.path.join(BASE, "challenge.html")


# ─── Hash check (optimized) ──────────────────────────────────────────
# Pre-convert target to bytes for faster comparison
_TARGET_BYTES = TARGET.encode("ascii")


def check(candidate: str) -> bool:
    cur = candidate.encode("utf-8")
    for _ in range(ROUNDS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur == _TARGET_BYTES


# ─── HTML content extractor ─────────────────────────────────────────
class ForumExtractor(HTMLParser):
    """Extract meaningful text from forum HTML, paying special attention to:
    - Post content (gwf_forum_post_*)
    - Spoiler sections (gwf_bb_spoiler)
    - White-text hints (color: #FFFFFF)
    - Code blocks
    - Signatures
    - All attribute values
    """

    def __init__(self):
        super().__init__()
        self.texts = []  # All visible text segments
        self.spoilers = []  # Spoiler content (CRITICAL)
        self.white_texts = []  # White-colored hidden text
        self.code_blocks = []  # Code/pre content
        self.signatures = []  # User signatures
        self.attr_values = []  # All attribute values
        self.post_contents = []  # Forum post bodies

        self._in_spoiler = False
        self._in_code = False
        self._in_sig = False
        self._in_post = False
        self._in_white = False
        self._current_text = []
        self._depth = 0

    def handle_starttag(self, tag, attrs):
        attr_dict = dict(attrs)

        # Track attribute values
        for name, val in attrs:
            if val and name in ("title", "alt", "value", "href", "content", "cite"):
                self.attr_values.append(val)

        # Spoiler sections
        cls = attr_dict.get("class", "")
        if "gwf_bb_spoiler" in cls:
            self._in_spoiler = True
            self._current_text = []

        # Post content
        id_val = attr_dict.get("id", "")
        if id_val.startswith("gwf_forum_post_"):
            self._in_post = True

        # Signature
        if "gwf_signature" in cls:
            self._in_sig = True
            self._current_text = []

        # White text (hidden hints)
        style = attr_dict.get("style", "")
        if "#FFFFFF" in style.upper() or "#FFF" in style.upper().replace(" ", ""):
            self._in_white = True
            self._current_text = []

        # Code blocks
        if tag in ("code", "pre") or "gwf_bb_code" in cls:
            self._in_code = True
            self._current_text = []

    def handle_endtag(self, tag):
        if tag == "section" and self._in_spoiler:
            text = "".join(self._current_text).strip()
            if text:
                self.spoilers.append(text)
            self._in_spoiler = False

        if tag == "span" and self._in_white:
            text = "".join(self._current_text).strip()
            if text:
                self.white_texts.append(text)
            self._in_white = False

        if tag == "div" and self._in_sig:
            text = "".join(self._current_text).strip()
            if text:
                self.signatures.append(text)
            self._in_sig = False

        if tag in ("code", "pre", "div") and self._in_code:
            text = "".join(self._current_text).strip()
            if text:
                self.code_blocks.append(text)
            self._in_code = False

    def handle_data(self, data):
        self.texts.append(data)

        if self._in_spoiler:
            self._current_text.append(data)
        if self._in_white:
            self._current_text.append(data)
        if self._in_sig:
            self._current_text.append(data)
        if self._in_code:
            self._current_text.append(data)

    def handle_entityref(self, name):
        char = html.unescape(f"&{name};")
        self.handle_data(char)

    def handle_charref(self, name):
        char = html.unescape(f"&#{name};")
        self.handle_data(char)


def extract_from_html(filepath):
    """Parse an HTML file and return structured extractions."""
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    extractor = ForumExtractor()
    try:
        extractor.feed(content)
    except Exception:
        pass

    return extractor, content


def extract_post_messages(html_content):
    """Extract raw text from forum post message divs."""
    posts = []
    pattern = r'<div id="gwf_forum_post_\d+">(.*?)</div>'
    for match in re.finditer(pattern, html_content, re.DOTALL):
        # Strip HTML tags from post content
        raw = match.group(1)
        text = re.sub(r"<[^>]+>", " ", raw)
        text = html.unescape(text)
        text = re.sub(r"\s+", " ", text).strip()
        if text:
            posts.append(text)
    return posts


# ─── Candidate generation strategies ────────────────────────────────


def generate_candidates(all_files):
    """Generate all candidate strings from forum HTML files."""
    candidates = set()

    # Accumulate all extracted data
    all_texts = []
    all_spoilers = []
    all_white_texts = []
    all_code_blocks = []
    all_signatures = []
    all_attr_values = []
    all_posts = []
    all_raw_html = []

    print(f"Reading {len(all_files)} HTML files...")

    for filepath in all_files:
        fname = os.path.basename(filepath)
        extractor, raw_html = extract_from_html(filepath)
        all_raw_html.append(raw_html)

        all_texts.extend(extractor.texts)
        all_spoilers.extend(extractor.spoilers)
        all_white_texts.extend(extractor.white_texts)
        all_code_blocks.extend(extractor.code_blocks)
        all_signatures.extend(extractor.signatures)
        all_attr_values.extend(extractor.attr_values)

        posts = extract_post_messages(raw_html)
        all_posts.extend(posts)

        print(
            f"  {fname}: {len(extractor.texts)} text nodes, "
            f"{len(extractor.spoilers)} spoilers, "
            f"{len(extractor.white_texts)} white-text, "
            f"{len(posts)} posts"
        )

    print(
        f"\nTotal: {len(all_posts)} posts, {len(all_spoilers)} spoilers, "
        f"{len(all_white_texts)} white-text hints"
    )

    # ── Strategy 1: Every word/token from post messages ──
    print("\n[S1] Extracting words from posts...")
    for post in all_posts:
        words = re.findall(r"[A-Za-z0-9_\-\.@:;!?#$%^&*+=]+", post)
        for w in words:
            candidates.add(w)

    # ── Strategy 2: Full post lines ──
    print("[S2] Extracting full post lines...")
    for post in all_posts:
        candidates.add(post)
        for line in post.split("."):
            line = line.strip()
            if 3 <= len(line) <= 200:
                candidates.add(line)

    # ── Strategy 3: SPOILER content (CRITICAL) ──
    print(f"[S3] Processing {len(all_spoilers)} spoiler texts...")
    for sp in all_spoilers:
        candidates.add(sp)
        words = re.findall(r"[A-Za-z0-9_\-\.]+", sp)
        for w in words:
            candidates.add(w)
        # 2-word and 3-word combos from spoilers
        for i in range(len(words) - 1):
            candidates.add(f"{words[i]} {words[i + 1]}")
            candidates.add(f"{words[i]}{words[i + 1]}")
            if i + 2 < len(words):
                candidates.add(f"{words[i]} {words[i + 1]} {words[i + 2]}")
                candidates.add(f"{words[i]}{words[i + 1]}{words[i + 2]}")

    # ── Strategy 4: WHITE TEXT (hidden hints) ──
    print(f"[S4] Processing {len(all_white_texts)} white-text hints...")
    for wt in all_white_texts:
        candidates.add(wt)
        words = re.findall(r"[A-Za-z0-9_\-\.]+", wt)
        for w in words:
            candidates.add(w)

    # ── Strategy 5: Signatures ──
    print(f"[S5] Processing {len(all_signatures)} signatures...")
    for sig in all_signatures:
        candidates.add(sig)
        words = re.findall(r"[A-Za-z0-9_\-\.@=]+", sig)
        for w in words:
            candidates.add(w)

    # ── Strategy 6: Code blocks ──
    print(f"[S6] Processing {len(all_code_blocks)} code blocks...")
    for cb in all_code_blocks:
        candidates.add(cb)
        lines = cb.split("\n")
        for line in lines:
            line = line.strip()
            if line:
                candidates.add(line)
        words = re.findall(r"[A-Za-z0-9_\-\.]+", cb)
        for w in words:
            candidates.add(w)

    # ── Strategy 7: Hex-looking strings ──
    print("[S7] Extracting hex strings...")
    for raw in all_raw_html:
        # Find hex sequences 2+ chars
        hexes = re.findall(r"\b[0-9a-fA-F]{2,40}\b", raw)
        for h in hexes:
            candidates.add(h)
            candidates.add(h.lower())
            candidates.add(h.upper())

    # ── Strategy 8: Base64 strings ──
    print("[S8] Finding base64 candidates...")
    for raw in all_raw_html:
        b64_matches = re.findall(r"[A-Za-z0-9+/]{4,}={0,2}", raw)
        for b in b64_matches:
            candidates.add(b)
            try:
                decoded = base64.b64decode(b).decode("utf-8", errors="replace")
                if decoded.isprintable():
                    candidates.add(decoded)
            except Exception:
                pass

    # ── Strategy 9: Attribute values ──
    print(f"[S9] Processing {len(all_attr_values)} attribute values...")
    for val in all_attr_values:
        candidates.add(val)
        # Also extract meaningful substrings
        if "/" in val:
            parts = val.split("/")
            for p in parts:
                if p:
                    candidates.add(p)

    # ── Strategy 10: Numbers ──
    print("[S10] Extracting numbers...")
    for raw in all_raw_html:
        nums = re.findall(r"\b\d{1,10}\b", raw)
        for n in nums:
            candidates.add(n)

    # ── Strategy 11: Specific dloser quotes and phrases ──
    print("[S11] Adding dloser-specific candidates...")
    dloser_phrases = [
        # Direct quotes from dloser
        "move your nose off the screen",
        "It's right there, ffs!",
        "Some people make challenges out of anything and nothing",
        "meaning of the input codes",
        "input codes",
        "core structures",
        "don't be too literal with the ??s",
        "don't be too literal",
        "too literal",
        "The second example in the cheat sheet",
        "besides providing a way to get some easy outputs",
        "crucial properties of the codes",
        "The different outputs betray some core structures",
        "substructures",
        "just like with QD",
        "No, only on valid inputs",
        "Have you heard? There is a new version of BrownOS out!",
        "whole new syscall",
        "Seems pretty useless so far",
        "Thank you",
        # Challenge page text
        "BrownOS",
        "BrownOS[<syscall> <argument> FD <rest> FD] -> BrownOS[<rest> <result> FD]",
        "Quick debug",
        "End Of Code marker",
        "cheat sheet",
        "dumpster divers",
        "wc3.wechall.net",
        "port 61221",
        "service at wc3.wechall.net port 61221",
        # QD from cheat sheet
        "05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE",
        "050 0FD 00 050 0FD 03 FD FE FD 02 FD FE FD FE",
        "QD ?? FD  or  ?? ?? FD QD FD",
        "QD ?? FD",
        "?? ?? FD QD FD",
        # Technical terms
        "lambda calculus",
        "lambda",
        "Lambda",
        "de Bruijn",
        "De Bruijn",
        "de Bruijn index",
        "De Bruijn index",
        "Church encoding",
        "Scott encoding",
        "continuation passing style",
        "CPS",
        "beta reduction",
        "normal form",
        "WHNF",
        "weak head normal form",
        "syscall",
        "Permission denied",
        "permission denied",
        "PermDenied",
        # Usernames (solvers)
        "l3st3r",
        "space",
        "dloser",
        "jusb3",
        "gizmore",
        "tehron",
        "benito255",
        "macplox",
        # Known server responses
        "a towel!",
        "towel",
        "42",
        "Don't Panic",
        "Don't Panic!",
        "dont panic",
        "Dont Panic",
        "The Answer to the Ultimate Question",
        "The Answer to the Ultimate Question of Life, the Universe, and Everything",
        "ilikephp",
        "ILIKEPHP",
        "ILikePHP",
        "ILikePhp",
        "i like php",
        "I like PHP",
        "I Like PHP",
        "php",
        "PHP",
        # Hitchhiker's references
        "hitchhiker",
        "Hitchhiker",
        "HHGTTG",
        "hhgttg",
        "Douglas Adams",
        "Deep Thought",
        "Marvin",
        "Zaphod",
        "Ford Prefect",
        "Arthur Dent",
        "Trillian",
        "Slartibartfast",
        "the meaning of life",
        "meaning of life",
        "life, the universe, and everything",
        "Life, the Universe, and Everything",
        # Binary/protocol terms
        "binary protocol",
        "binary tree",
        "AST",
        "abstract syntax tree",
        "term",
        "application",
        "abstraction",
        "variable",
        "Var",
        "Lam",
        "App",
        # Challenge-specific
        "BrownOS",
        "brownos",
        "BROWNOS",
        "brown os",
        "Brown OS",
        "BROWN OS",
        "brown",
        "Brown",
        "BROWN",
        # Error codes / syscall numbers
        "Exception",
        "NotImpl",
        "InvalidArg",
        "NoSuchFile",
        "NotDir",
        "NotFile",
        "PermDenied",
        "RateLimit",
        # Filesystem paths found in BrownOS
        "/bin/solution",
        "/etc/passwd",
        "/etc/history",
        "bin/solution",
        "etc/passwd",
        "etc/history",
        "solution",
        "passwd",
        "history",
        "/etc",
        "/bin",
        # From /etc/passwd content
        "gizmore:x:1000:1000::/home/gizmore",
        "gizmore:x:1000:1000",
        "root:x:0:0::/root",
        # Hex/byte sequences from cheat sheet
        "FF",
        "FD",
        "FE",
        "QD",
        "0xFF",
        "0xFD",
        "0xFE",
        "05 00 FD",
        "050 0FD",
        # Backdoor
        "backdoor",
        "Backdoor",
        # Possible simple answers
        "yes",
        "no",
        "true",
        "false",
        "True",
        "False",
        "YES",
        "NO",
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "success",
        "Success",
        "SUCCESS",
        "unlock",
        "Unlock",
        "UNLOCK",
        "open",
        "Open",
        "OPEN",
        "granted",
        "Granted",
        "GRANTED",
        "access",
        "Access",
        "ACCESS",
        "allow",
        "Allow",
        "ALLOW",
        "run",
        "exec",
        "execute",
        "admin",
        "Admin",
        "ADMIN",
        "su",
        "sudo",
        "root",
        "Root",
        "ROOT",
        # Common CTF flags
        "flag",
        "FLAG",
        "Flag",
        "flag{}",
        "FLAG{}",
        "flag{}",
        # Possible obscure answers
        "QD",
        "qd",
        "Qd",
        "quick debug",
        "Quick Debug",
        "Quick debug",
        "QUICK DEBUG",
        "quickdebug",
        "QuickDebug",
        # From gizmore's signature
        "The geeks shall inherit the properties and methods of object earth",
        "The geeks shall inherit the properties and methods of object earth.",
        # The ?? hint — possible interpretations
        "??",
        "?",
        "question mark",
        "question marks",
        "unknown",
        "Unknown",
        "UNKNOWN",
        "wildcard",
        "Wildcard",
        # space's encoded email
        "c3BhY2VAd2VjaGFsbC5uZXQ=",
        "space@wechall.net",
    ]
    for phrase in dloser_phrases:
        candidates.add(phrase)

    # ── Strategy 12: First letters of sentences (acrostic) ──
    print("[S12] Checking acrostics from posts...")
    for post in all_posts:
        sentences = re.split(r"[.!?]\s+", post)
        if len(sentences) >= 3:
            acrostic = "".join(s[0] for s in sentences if s)
            candidates.add(acrostic)
            candidates.add(acrostic.lower())
            candidates.add(acrostic.upper())

    # ── Strategy 13: 2-word combinations from post messages ──
    print("[S13] Building 2-word combos from key posts...")
    # Only from dloser posts to keep count manageable
    dloser_words = set()
    for post in all_posts:
        if any(
            kw in post.lower()
            for kw in [
                "meaning",
                "codes",
                "structures",
                "literal",
                "cheat",
                "spoiler",
                "syscall",
                "brownos",
                "valid inputs",
            ]
        ):
            words = re.findall(r"[A-Za-z]{2,}", post)
            dloser_words.update(words[:50])  # Limit per post

    dloser_words_list = sorted(dloser_words)[:100]
    for i in range(len(dloser_words_list)):
        for j in range(len(dloser_words_list)):
            if i != j:
                candidates.add(f"{dloser_words_list[i]} {dloser_words_list[j]}")
                if len(candidates) > MAX_CANDIDATES - 5000:
                    break
        if len(candidates) > MAX_CANDIDATES - 5000:
            break

    return candidates


def generate_derived(candidates):
    """Generate derived candidates: case variants, reversed, ROT13, etc."""
    derived = set()

    print(
        f"\n[D] Generating derived candidates from {len(candidates)} base candidates..."
    )

    for c in candidates:
        if not c or len(c) > 500:
            continue

        # Skip very long strings for derived
        if len(c) <= 100:
            # Case variants
            derived.add(c.lower())
            derived.add(c.upper())
            derived.add(c.title())
            derived.add(c.capitalize())
            derived.add(c.swapcase())

            # With/without trailing newline
            derived.add(c + "\n")
            derived.add(c.rstrip("\n"))

            # Stripped
            derived.add(c.strip())
            derived.add(c.lstrip())
            derived.add(c.rstrip())

        if len(c) <= 50:
            # Reversed
            derived.add(c[::-1])

            # ROT13
            derived.add(codecs.encode(c, "rot13"))

            # URL decoded
            try:
                decoded = unquote(c)
                if decoded != c:
                    derived.add(decoded)
            except Exception:
                pass

            # HTML entity decoded
            try:
                decoded = html.unescape(c)
                if decoded != c:
                    derived.add(decoded)
            except Exception:
                pass

    return derived


# ─── Main ────────────────────────────────────────────────────────────
def main():
    start_time = time.time()

    # Collect all HTML files
    forum_files = sorted(glob.glob(os.path.join(FORUM_DIR, "*.html")))
    all_files = forum_files + [CHALLENGE_FILE]

    print(f"=== BrownOS Forum Mining ===")
    print(f"Files: {len(all_files)} ({len(forum_files)} forum + 1 challenge)")
    print(f"Target: {TARGET}")
    print(f"Rounds: {ROUNDS}")
    print(f"Max candidates: {MAX_CANDIDATES}")
    print()

    # Generate base candidates
    base_candidates = generate_candidates(all_files)
    print(f"\nBase candidates: {len(base_candidates)}")

    # Generate derived candidates
    derived = generate_derived(base_candidates)
    print(f"Derived candidates: {len(derived)}")

    # Merge and deduplicate
    all_candidates = base_candidates | derived

    # Filter: remove empty and too-long strings
    all_candidates = {c for c in all_candidates if c and len(c) <= 500}

    print(f"Total unique candidates: {len(all_candidates)}")

    # Enforce limit
    if len(all_candidates) > MAX_CANDIDATES:
        print(f"Trimming to {MAX_CANDIDATES} (prioritizing shorter candidates)...")
        # Prioritize shorter strings
        sorted_cands = sorted(all_candidates, key=lambda x: (len(x), x))
        all_candidates = set(sorted_cands[:MAX_CANDIDATES])

    # Test all candidates
    print(f"\nTesting {len(all_candidates)} candidates against hash...")
    print(
        f"Estimated time: {len(all_candidates) * 0.025:.0f}s ({len(all_candidates) * 0.025 / 60:.1f}m)"
    )

    matches = []
    tested = 0
    check_start = time.time()

    timed_out = False
    for candidate in sorted(all_candidates, key=lambda x: (len(x), x)):
        tested += 1
        if tested % 1000 == 0:
            elapsed = time.time() - check_start
            rate = tested / elapsed if elapsed > 0 else 0
            eta = (len(all_candidates) - tested) / rate if rate > 0 else 0
            print(f"  [{tested}/{len(all_candidates)}] {rate:.1f}/s, ETA: {eta:.0f}s")
            if elapsed > MAX_TIME_SECONDS:
                print(f"  TIME LIMIT ({MAX_TIME_SECONDS}s) reached, stopping.")
                timed_out = True
                break

        if check(candidate):
            matches.append(candidate)
            print(f"\n  *** MATCH FOUND: {candidate!r} ***\n")

    elapsed = time.time() - start_time
    rate = (
        tested / (time.time() - check_start) if (time.time() - check_start) > 0 else 0
    )

    # Report results
    print(f"\n{'=' * 60}")
    print(f"RESULTS")
    print(f"{'=' * 60}")
    print(f"Total candidates tested: {tested}")
    print(f"Rate: {rate:.1f} candidates/sec")
    print(f"Elapsed: {elapsed:.1f}s ({elapsed / 60:.1f}m)")
    print(f"Matches found: {len(matches)}")
    if timed_out:
        print(
            f"NOTE: Timed out after {MAX_TIME_SECONDS}s — {len(all_candidates) - tested} candidates untested"
        )

    if matches:
        print(f"\n*** MATCHES ***")
        for m in matches:
            print(f"  {m!r}")
    else:
        print(f"\nNo matches found.")

    # Print some stats about what we mined
    print(f"\nExtraction summary:")
    print(f"  Forum files read: {len(forum_files)}")
    print(f"  Challenge page read: 1")
    print(f"  Base candidates: {len(base_candidates)}")
    print(f"  Derived candidates: {len(derived)}")
    print(f"  Unique tested: {tested}")

    return matches, tested, elapsed


if __name__ == "__main__":
    matches, tested, elapsed = main()
