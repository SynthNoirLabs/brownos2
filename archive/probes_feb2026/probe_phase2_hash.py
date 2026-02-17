#!/usr/bin/env python3
"""
probe_phase2_hash.py — Phase 2 hash cracking: NOVEL candidate categories.

Tests categories NOT already covered by probe_exact_hash.py or probe_crack_answer_hash.py.
Target: 9252ed65ffac2aa763adb21ef72c0178f1d83286  (56154 rounds of SHA1)
"""

from __future__ import annotations

import hashlib
import sys
import time


TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ROUNDS = 56154


def check(candidate: str) -> bool:
    """Check if candidate matches target after ROUNDS of SHA1."""
    cur = candidate.encode("utf-8")
    for _ in range(ROUNDS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET


def build_candidates() -> list[str]:
    seen: set[str] = set()
    candidates: list[str] = []

    def add(c: str) -> None:
        if c not in seen:
            seen.add(c)
            candidates.append(c)

    # =========================================================================
    # CATEGORY 1: Bytecode hex strings (novel ones not in probe_exact_hash.py)
    # =========================================================================
    cat1 = [
        "fefe",  # double lambda
        "FEFE",
        "00fefefd",  # App(nil, something)
        "00FEFEFD",
        "08",  # just the sys8 byte
        "0800fefefdff",  # sys8(nil) with end marker
        "0800FEFEFDFF",
        "c900fefefdff",  # backdoor(nil) with end marker
        "C900FEFEFDFF",
        "00fefe00fefefd01fefefdff",  # QD example bytes
        "00FEFE00FEFEFD01FEFEFDFF",
        "0500fd000500fd03fdfefd02fdfefdfe",  # Full QD bytes (already in exact but test uppercase)
        "0500FD000500FD03FDFEFD02FDFEFDFE",
        # Without quotes — raw hex digits with various separators
        "fe fe",
        "FE FE",
        "00 FE FE FD",
        "08 00 FE FE FD FF",
        "C9 00 FE FE FD FF",
        "00 FE FE 00 FE FE FD 01 FE FE FD FF",
        # Bytecode with 0x prefix
        "0xFE 0xFE",
        "0x00 0xFE 0xFE",
        "0x08 0x00 0xFE 0xFE 0xFD",
    ]
    for c in cat1:
        add(c)

    # =========================================================================
    # CATEGORY 2: Lambda notation strings
    # =========================================================================
    cat2 = [
        # Standard lambda notation
        "\\a.\\b.b b",  # A in lambda notation
        "\\a.\\b.a b",  # B in lambda notation
        r"\a.\b.b b",
        r"\a.\b.a b",
        # Unicode lambda
        "λa.λb.b b",  # A with unicode lambda
        "λa.λb.a b",  # B with unicode lambda
        # Pair expressions
        "\\f.f(\\a.\\b.b b)(\\a.\\b.a b)",  # the pair
        "(\\a.\\b.b b, \\a.\\b.a b)",  # pair as tuple
        r"\f.f(\a.\b.b b)(\a.\b.a b)",
        r"(\a.\b.b b, \a.\b.a b)",
        "λf.f(λa.λb.b b)(λa.λb.a b)",
        "(λa.λb.b b, λa.λb.a b)",
        # De Bruijn index notations
        "0 FE FE",  # A in bytecode-ish
        "1 0 FD FE FE",  # B in bytecode-ish
        # De Bruijn explicit
        "λ.λ.0 0",  # A = λ.λ.0 0  (de Bruijn)
        "λ.λ.1 0",  # B = λ.λ.1 0  (de Bruijn)
        "\\0.\\1.1 1",
        "\\0.\\1.0 1",
        # Lambda calculus single-letter forms
        "Mf = ff",
        "M = λf.ff",
        "λf.ff",
        "\\f.ff",
        # Backdoor pair in various notations
        "(M, λab.ab)",
        "(λf.ff, λab.ab)",
        "pair(M, λab.ab)",
        "pair(λf.ff, λab.ab)",
    ]
    for c in cat2:
        add(c)

    # =========================================================================
    # CATEGORY 3: Combinator names (novel ones NOT in probe_exact_hash.py)
    # =========================================================================
    cat3 = [
        "mockingbird",
        "Mockingbird",
        "MOCKINGBIRD",
        "warbler",
        "Warbler",
        "WARBLER",
        "kestrel",
        "Kestrel",
        "KESTREL",
        "starling",
        "Starling",
        "STARLING",
        "thrush",
        "Thrush",
        "THRUSH",
        "bluebird",
        "Bluebird",
        "BLUEBIRD",
        "cardinal",
        "Cardinal",
        "CARDINAL",
        "vireo",
        "Vireo",
        "VIREO",
        "lark",
        "Lark",
        "LARK",
        "sage",
        "Sage",
        "SAGE",
        "turing",
        "Turing",
        "TURING",
        "iota",
        "Iota",
        "IOTA",
        "jot",
        "Jot",
        "JOT",
        "SKI",
        "ski",
        "SK",
        "sk",
        "SII",
        "sii",
        "MM",
        "mm",
        "KI",
        "ki",
        "BCT",
        "bct",
        "CI",
        "ci",
        "SB",
        "sb",
        "CBM",
        "cbm",
        "SKK",
        "skk",
        "Y",
        "y",  # Y combinator
        "Z",
        "z",  # Z combinator (strict Y)
        "fix",
        "Fix",
        "FIX",
        "fixpoint",
        "Fixpoint",
        "fixed point",
        "Fixed Point",
        "identity",
        "Identity",
        "I",
        "K",
        "S",
        "B",
        "C",
        "W",
        "M",
        "T",
        "V",
        "L",
        "Ω",
        "ω",  # Unicode omega symbols
    ]
    for c in cat3:
        add(c)

    # =========================================================================
    # CATEGORY 4: German words
    # =========================================================================
    cat4 = [
        "Passwort",
        "passwort",
        "Lösung",
        "loesung",
        "losung",
        "LOESUNG",
        "Antwort",
        "antwort",
        "Geheimnis",
        "geheimnis",
        "Schlüssel",
        "schluessel",
        "SCHLUESSEL",
        "Erlaubnis",
        "erlaubnis",
        "Zugang",
        "zugang",
        "braun",
        "Braun",
        "BRAUN",
        "BraunOS",
        "braunos",
        "BRAUNOS",
        "Betriebssystem",
        "betriebssystem",  # operating system
        "Kern",
        "kern",  # kernel
        "Geist",
        "geist",  # ghost/spirit
        "Rätsel",
        "raetsel",  # puzzle/riddle
        "Hacker",
        "hacker",
        "Knacker",
        "knacker",  # cracker
        "Herausforderung",
        "herausforderung",  # challenge
        "Hintertür",
        "hintertuer",  # backdoor
        "Eingabe",
        "eingabe",  # input
        "Ausgabe",
        "ausgabe",  # output
        "Befehl",
        "befehl",  # command
        "Wurzel",
        "wurzel",  # root
        "Meister",
        "meister",  # master
        "Handtuch",
        "handtuch",  # towel
        "Anruf",
        "anruf",  # call (syscall)
        "Systemaufruf",
        "systemaufruf",  # syscall
        "richtig",
        "Richtig",  # correct/right
        "falsch",
        "Falsch",  # false/wrong
        "ja",
        "Ja",
        "nein",
        "Nein",
        "danke",
        "Danke",  # thanks
        "bitte",
        "Bitte",  # please
        "Hilfe",
        "hilfe",  # help
        "Willkommen",
        "willkommen",  # welcome
        "verboten",
        "Verboten",  # forbidden
        "Zugriff verweigert",  # access denied
        "Keine Berechtigung",  # no permission
    ]
    for c in cat4:
        add(c)

    # =========================================================================
    # CATEGORY 5: Challenge-specific computed values
    # =========================================================================
    cat5 = [
        "Right(6)",
        "Right 6",
        "right(6)",
        "right 6",
        "Right(0)",
        "Right 0",
        "right(0)",
        "right 0",
        "Left",
        "left",
        "Either",
        "either",
        "pair(A,B)",
        "(A,B)",
        "A,B",
        "pair(M,B)",
        "(M,B)",
        "M,B",
        "self-application",
        "selfapplication",
        "apply",
        "Apply",
        "APPLY",
        "bb",
        "ab",  # core of A and B
        "ff",  # core of mockingbird
        "\\b.bb",
        "\\b.ab",
        "λb.bb",
        "λb.ab",
        "\\x.xx",
        "\\x.yx",
        "λx.xx",
        "λx.yx",
        # Scott encoding variants
        "Scott",
        "scott",
        "Scott encoding",
        "scott encoding",
        "Church",
        "church",
        "Church encoding",
        "church encoding",
        # Pair-related
        "cons",
        "Cons",
        "CONS",
        "car",
        "cdr",
        "CAR",
        "CDR",
        "fst",
        "snd",
        "FST",
        "SND",
        "first",
        "second",
        "First",
        "Second",
        "head",
        "tail",
        "Head",
        "Tail",
        "nil",
        "NIL",
        "Nil",  # nil already tested as single but not NIL
        "null",
        "NULL",
        "Null",
        "empty",
        "Empty",
        "EMPTY",
        "void",
        "Void",
        "VOID",
        "unit",
        "Unit",
        "UNIT",
        "()",
        "[]",
        "{}",
        # Boolean encodings
        "True",
        "False",
        "TRUE",
        "FALSE",
        "true",
        "false",  # already tested but include for completeness
        "tt",
        "ff",
        "TT",
        "FF",
        # What sys8 might conceptually return
        "unlocked",
        "Unlocked",
        "UNLOCKED",
        "authenticated",
        "Authenticated",
        "authorized",
        "Authorized",
        "permitted",
        "Permitted",
        "access granted",
        "Access Granted",
        "welcome",
        "Welcome",
        "WELCOME",
        "congratulations",
        "Congratulations",
        "solved",
        "Solved",
        "SOLVED",
    ]
    for c in cat5:
        add(c)

    # =========================================================================
    # CATEGORY 6: Numbers and codes
    # =========================================================================
    # Integers 0-999
    for i in range(1000):
        add(str(i))

    # Hex values 0x00 through 0xFF
    for i in range(256):
        add(f"0x{i:02x}")
        add(f"0x{i:02X}")

    # Special numbers
    cat6_special = [
        "56154",  # hash rounds
        "61221",  # port number (already tested, but ensure)
        "0xDB5A",  # 56154 in hex
        "0xEF45",  # 61221 in hex
        "0x08",  # sys8 in hex (already but ensure)
        "0xC9",  # sys201 in hex
        "0xFF",  # end-of-code
        "0xFE",  # lambda
        "0xFD",  # application
        "255",
        "254",
        "253",  # FD, FE, FF as decimals
        "0b1000",  # 8 in binary
        "0o10",  # 8 in octal
    ]
    for c in cat6_special:
        add(c)

    # =========================================================================
    # CATEGORY 7: Phrases from forum hints
    # =========================================================================
    cat7 = [
        "meaning of the input codes",
        "input codes",
        "core structures",
        "don't be too literal",
        "dont be too literal",
        "three leafs",
        "3 leafs",
        "threeleafs",
        "3leafs",
        "three leaves",
        "3 leaves",
        "threeleaves",
        "3leaves",
        "new syscall",
        "kernel",  # already tested
        "binary tree",
        "AST",
        "abstract syntax tree",
        "parse tree",
        "de Bruijn index",
        "de Bruijn indices",
        "beta reduction",
        "normal form",
        "head normal form",
        "weak head normal form",
        "WHNF",
        "whnf",
        "HNF",
        "hnf",
        "NF",
        "nf",
        "reduction",
        "substitution",
        "alpha conversion",
        "eta reduction",
        "call by name",
        "call by value",
        "call by need",
        "lazy evaluation",
        "strict evaluation",
        "thunk",
        "continuation passing style",
        "CPS transform",
        "defunctionalization",
    ]
    for c in cat7:
        add(c)

    # =========================================================================
    # CATEGORY 8: File content hashes/transforms
    # =========================================================================
    # SHA1 of "ilikephp" (single round)
    sha1_ilikephp = hashlib.sha1(b"ilikephp").hexdigest()
    # MD5 of "ilikephp"
    md5_ilikephp = hashlib.md5(b"ilikephp").hexdigest()

    import base64

    b64_ilikephp = base64.b64encode(b"ilikephp").decode("ascii")

    import codecs

    rot13_ilikephp = codecs.encode("ilikephp", "rot13")

    cat8 = [
        sha1_ilikephp,  # SHA1("ilikephp")
        sha1_ilikephp.upper(),
        md5_ilikephp,  # MD5("ilikephp")
        md5_ilikephp.upper(),
        "GZKc.2/VQffio",  # crypt hash itself (already tested but ensure)
        b64_ilikephp,  # base64("ilikephp") = "aWxpa2VwaHA="
        "phpekili",  # reverse of "ilikephp"
        rot13_ilikephp,  # ROT13("ilikephp") = "vyvxrcuc"
        # SHA1 of other key strings
        hashlib.sha1(b"brownos").hexdigest(),
        hashlib.sha1(b"BrownOS").hexdigest(),
        hashlib.sha1(b"GZKc.2/VQffio").hexdigest(),
        hashlib.sha1(b"dloser").hexdigest(),
        hashlib.sha1(b"gizmore").hexdigest(),
        hashlib.sha1(b"42").hexdigest(),
        hashlib.sha1(b"towel").hexdigest(),
        # MD5 of other keys
        hashlib.md5(b"brownos").hexdigest(),
        hashlib.md5(b"BrownOS").hexdigest(),
        hashlib.md5(b"dloser").hexdigest(),
        hashlib.md5(b"gizmore").hexdigest(),
        # Crypt-related transforms
        "ilikephp" + "GZKc.2/VQffio",  # noqa: ISC003
        "GZKc.2/VQffio" + "ilikephp",
        "gizmore:ilikephp",
        "gizmore:GZKc.2/VQffio",
        "dloser:ilikephp",
        "root:ilikephp",
        # Various known hash prefixes / salt patterns
        "$1$GZKc$",  # MD5 crypt format
        "$5$GZKc$",  # SHA-256 crypt format
        "$6$GZKc$",  # SHA-512 crypt format
        "GZKc",  # Just the salt portion
        "VQffio",  # Second part of crypt hash
    ]
    for c in cat8:
        add(c)

    return candidates


def main() -> int:
    candidates = build_candidates()
    total = len(candidates)

    print(f"probe_phase2_hash.py — Phase 2 Hash Cracking")
    print(f"=" * 60)
    print(f"Target:     {TARGET}")
    print(f"Rounds:     {ROUNDS}")
    print(f"Candidates: {total}")
    print(f"=" * 60)
    print()

    if total > 3000:
        print(f"[!] WARNING: {total} candidates exceeds 3000 limit, truncating.")
        candidates = candidates[:3000]
        total = 3000

    started = time.time()
    match_found = None
    i = 0

    for i, cand in enumerate(candidates):
        if (i + 1) % 50 == 0:
            elapsed = time.time() - started
            rate = (i + 1) / elapsed if elapsed > 0 else 0
            eta = (total - i - 1) / rate if rate > 0 else 0
            print(
                f"  [{i + 1:4d}/{total}] "
                f"rate={rate:.1f}/s "
                f"ETA={eta:.0f}s "
                f"elapsed={elapsed:.0f}s",
                flush=True,
            )

        if check(cand):
            match_found = cand
            print(f"\n{'=' * 60}")
            print(f"[+] *** MATCH FOUND ***")
            print(f"[+] Candidate: {cand!r}")
            print(f"[+] Length:    {len(cand)}")
            print(f"[+] Hex:       {cand.encode('utf-8').hex()}")
            print(f"{'=' * 60}")
            break

    elapsed = time.time() - started

    print()
    print(f"{'=' * 60}")
    print(f"RESULTS")
    print(f"{'=' * 60}")
    print(f"Candidates tested: {min(i + 1, total)}")
    print(f"Time elapsed:      {elapsed:.1f}s")
    print(f"Rate:              {(i + 1) / elapsed:.1f}/s" if elapsed > 0 else "N/A")

    if match_found:
        print(f"\n[+] MATCH: {match_found!r}")
        return 0
    else:
        print(f"\n[-] No match found in {total} candidates.")
        # Print first 20 and last 20 candidates for verification
        print(f"\nFirst 10 candidates tested:")
        for j, c in enumerate(candidates[:10]):
            print(f"  {j + 1}. {c!r}")
        print(f"\nLast 10 candidates tested:")
        for j, c in enumerate(candidates[-10:]):
            print(f"  {total - 9 + j}. {c!r}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
