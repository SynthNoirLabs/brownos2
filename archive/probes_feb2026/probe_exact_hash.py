#!/usr/bin/env python3
"""
probe_exact_hash.py — Test EXACT strings from BrownOS against the answer hash.

Previous cracking stripped punctuation. This script tests exact byte-for-byte
strings including all punctuation, spacing, and newline variants.
"""

from __future__ import annotations

import hashlib
import sys


TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ROUNDS = 56154


def check(candidate: str) -> bool:
    cur = candidate.encode("utf-8")
    for _ in range(ROUNDS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET


def main():
    # All EXACT strings obtainable from the service
    candidates = [
        # Towel string (exact from sys42)
        "Oh, go choke on a towel!",
        "Oh, go choke on a towel!\n",
        "oh, go choke on a towel!",
        "oh, go choke on a towel",
        "Oh go choke on a towel",
        "Oh, go choke on a towel",
        # Hidden file 256
        "Uhm... yeah... no...",
        "Uhm... yeah... no...\n",
        "uhm... yeah... no...",
        "Uhm... yeah... no",
        # Error strings (exact from sys1)
        "Unexpected exception",
        "Not implemented",
        "Invalid argument",
        "No such directory or file",
        "Not a directory",
        "Not a file",
        "Permission denied",
        "Not so fast!",
        # Mail content (exact)
        "From: mailer@brownos\nTo: dloser@brownos\nSubject: Delivery failure\n\nFailed to deliver following message to boss@evil.com:\n\nBackdoor is ready at syscall 201; start with 00 FE FE.\n",
        "Backdoor is ready at syscall 201; start with 00 FE FE.",
        "Backdoor is ready at syscall 201; start with 00 FE FE",
        "backdoor is ready at syscall 201; start with 00 FE FE.",
        "Backdoor is ready at syscall 201",
        "backdoor is ready at syscall 201",
        "Failed to deliver following message to boss@evil.com:",
        "Delivery failure",
        # .history content
        "sodu deluser dloser\nilikephp\nsudo deluser dloser\n",
        "sodu deluser dloser",
        "sudo deluser dloser",
        "ilikephp",
        # passwd content (exact lines)
        "root:x:0:0:root:/:/bin/false",
        "mailer:x:100:100:mailer:/var:/bin/false",
        "gizmore:GZKc.2/VQffio:1000:1000:Gizmore:/home/gizmore:/bin/sh",
        "dloser:x:1002:1002:dloser:/home/dloser:/bin/false",
        "GZKc.2/VQffio",
        # File names
        "false",
        "sh",
        "sudo",
        "brownos",
        "passwd",
        ".history",
        "access.log",
        "dloser",
        "gizmore",
        "sbin",
        "var",
        "log",
        "spool",
        "mail",
        # Full paths
        "/bin/false",
        "/bin/sh",
        "/bin/sudo",
        "/etc/brownos",
        "/etc/passwd",
        "/home/dloser",
        "/home/gizmore",
        "/home/gizmore/.history",
        "/sbin",
        "/var/log/brownos/access.log",
        "/var/spool/mail/dloser",
        # Challenge-related
        "BrownOS",
        "brownos",
        "The BrownOS",
        "the brownos",
        "lambda",
        "Lambda",
        "lambda calculus",
        "Lambda Calculus",
        "de Bruijn",
        "De Bruijn",
        "de bruijn",
        "debruijn",
        "CPS",
        "cps",
        "continuation",
        "continuation-passing style",
        # Key concepts
        "omega",
        "Omega",
        "OMEGA",
        "self-application",
        "self application",
        "lambda x. x x",
        "(lambda x. x x)",
        "\\x.xx",
        "λx.xx",
        "Ω",
        # Backdoor pair values
        "lambda a. lambda b. b b",
        "lambda a. lambda b. a b",
        # Hex sequences
        "00fefe",
        "00 FE FE",
        "00FEFE",
        "0xC9",
        "0xc9",
        "C9",
        "c9",
        "201",
        "0x08",
        "FF",
        "FD",
        "FE",
        "FDFEFF",
        "fdfeff",
        # QD hex
        "0500fd000500fd03fdfefd02fdfefdfe",
        "05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE",
        # Cheat sheet phrases
        "End Of Code marker",
        "Quick debug",
        "QD",
        # Numbers
        "42",
        "8",
        "14",
        "201",
        "256",
        "0",
        "1",
        "6",
        # Users
        "root",
        "mailer",
        "gizmore",
        "dloser",
        "Gizmore",
        "boss@evil.com",
        "mailer@brownos",
        "dloser@brownos",
        # Possible narrative answers
        "Don't Panic",
        "don't panic",
        "42",
        "towel",
        "Towel",
        "kernel",
        "interrupt",
        "sudo",
        "su",
        "login",
        "deluser",
        "deluser dloser",
        # WeChall/challenge meta
        "wc3.wechall.net",
        "61221",
        "wc3.wechall.net:61221",
        # Author username
        "dloser",
        "DLOSER",
        # Possible short answers
        "yes",
        "no",
        "true",
        "false",
        "success",
        "granted",
        "allowed",
        "root",
        "admin",
        # Possible phrase answers
        "the answer is 42",
        "go choke on a towel",
        "choke on a towel",
        "permission denied",
        "Permission Denied",
        "not implemented",
        "Not Implemented",
        # Specific terms from the VM
        "Var",
        "Lam",
        "App",
        "var",
        "lam",
        "app",
        "Left",
        "Right",
        "left",
        "right",
        "Either",
        "either",
        "Scott",
        "scott",
        "Church",
        "church",
        # PHP-related (gizmore likes PHP)
        "php",
        "PHP",
        "ilikephp",
        "ILIKEPHP",
        "I like PHP",
        "i like php",
        # Concatenated file content tokens
        "sodudeluserdloser",
        "sudodeluserdloser",
        # Possible creative answers
        "BrownOS v2",
        "BrownOS v2.0",
        "brownos2",
        "BrownOS2",
        # What if the answer is what sys8 WOULD return if it succeeded?
        # Maybe it's the NAME of the syscall
        "solution",
        "Solution",
        "SOLUTION",
        "/bin/solution",
        "bin/solution",
        "solve",
        "Solve",
        "flag",
        "Flag",
        "FLAG",
        "answer",
        "Answer",
        "ANSWER",
        # Bytecode of minimal programs
        "08 00 FE FE FD",  # sys8(nil)
        "0800fefefd",
        # What if the answer is literally "Right(6)" or "Left(...)"
        "Right(6)",
        "right(6)",
        "Right 6",
        "Left",
        "Right",
        # Possible: the answer is a lambda term in some notation
        "\\f.f(\\a.\\b.bb)(\\a.\\b.ab)",  # backdoor pair
        "λf.f(λa.λb.bb)(λa.λb.ab)",
        # What if it's the hex of what the service returns for some query
        # towel response hex
        # Possible: number as answer (challenge gives 9 points)
        "9",
        # The copyright years
        "2014",
        # WeChall challenge ID or similar
        "142",
        # 56154 (number of hash rounds — might be significant)
        "56154",
        # Empty string
        "",
        # Space
        " ",
        # Newline
        "\n",
        # Common CTF flags
        "flag{brownos}",
        "FLAG{brownos}",
        "wechall{brownos}",
        # gizmore signature
        "The geeks shall inherit the properties and methods of object earth.",
        "The geeks shall inherit the properties and methods of object earth",
        # Specific long phrases from service
        "Oh, go choke on a towel!",
        "Uhm... yeah... no...",
        "Backdoor is ready at syscall 201; start with 00 FE FE.",
        "Not so fast!",
    ]

    # Also add case variants of everything
    extra = []
    for c in candidates:
        if c != c.lower():
            extra.append(c.lower())
        if c != c.upper():
            extra.append(c.upper())
        if c != c.title():
            extra.append(c.title())
    candidates.extend(extra)

    # Deduplicate
    seen = set()
    unique = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)

    print(f"Testing {len(unique)} candidates against target hash...")
    print(f"Target: {TARGET}")
    print(f"Rounds: {ROUNDS}")
    print()

    for i, cand in enumerate(unique):
        if (i + 1) % 20 == 0:
            print(f"  ...tested {i + 1}/{len(unique)}", flush=True)
        if check(cand):
            print(f"\n[+] MATCH FOUND: {cand!r}")
            return 0

    print(f"\n[-] No match found in {len(unique)} candidates.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
