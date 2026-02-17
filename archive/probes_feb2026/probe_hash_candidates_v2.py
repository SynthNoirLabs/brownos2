#!/usr/bin/env python3
"""
Test additional hash candidates that might have been overlooked.
Target: sha1^56154(answer) = 9252ed65ffac2aa763adb21ef72c0178f1d83286
"""

import hashlib


TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"


def sha1_iter(text, n):
    """Apply SHA1 n times."""
    h = text.encode() if isinstance(text, str) else text
    for _ in range(n):
        h = hashlib.sha1(h).hexdigest().encode()
    return h.decode()


def check(candidate):
    result = sha1_iter(candidate, 56154)
    match = result == TARGET
    if match:
        print(f"  *** MATCH *** : {candidate!r}")
    return match


# Candidates we might not have tested:

# 1. Direct from the challenge
candidates = [
    # Error codes
    "Permission denied",
    "permission denied",
    "PERMISSION DENIED",
    "Not implemented",
    "Invalid argument",
    "No such directory or file",
    "Not a directory",
    "Not a file",
    "Not so fast!",
    "Unexpected exception",
    # Towel
    "Oh, go choke on a towel!",
    "Oh, go choke on a towel",
    # File contents
    "ilikephp",
    "ILIKEPHP",
    "ILikePHP",
    # Common challenge answers
    "BrownOS",
    "brownos",
    "BROWNOS",
    "brown",
    "Brown",
    "kernel",
    "Kernel",
    "KERNEL",
    # Lambda calculus terms
    "lambda",
    "Lambda",
    "omega",
    "Omega",
    # Backdoor-related
    "backdoor",
    "Backdoor",
    "201",
    "0xC9",
    "C9",
    "c9",
    # Echo-related
    "echo",
    "Echo",
    "ECHO",
    "0x0E",
    "0E",
    "14",
    # System-related
    "root",
    "Root",
    "sudo",
    "Sudo",
    "gizmore",
    "Gizmore",
    "dloser",
    "Dloser",
    "mailer",
    # Numbers
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "42",
    "255",
    "256",
    # Hex
    "0x08",
    "08",
    "0xff",
    "ff",
    "FF",
    "0xFD",
    "FD",
    "0xFE",
    "FE",
    # Paths
    "/bin/solution",
    "/bin/sh",
    "/bin/sudo",
    "/bin/false",
    "/etc/passwd",
    "/var/spool/mail/dloser",
    "/home/gizmore/.history",
    # Challenge specific
    "sodu deluser dloser",
    "sudo deluser dloser",
    "sodu",
    # Byte sequences as strings
    "00FEFE",
    "00 FE FE",
    # "3 leafs" even though fabricated
    "3 leafs",
    "3 leaves",
    "three leafs",
    "three leaves",
    # Email from mail spool
    "boss@evil.com",
    "mailer@brownos",
    "dloser@brownos",
    "Backdoor is ready at syscall 201; start with 00 FE FE.",
    "Backdoor is ready at syscall 201",
    # passwd entries
    "root:x:0:0:root:/:/bin/false",
    "gizmore:GZKc.2/VQffio:1000:1000:Gizmore:/home/gizmore:/bin/sh",
    "dloser:x:1002:1002:dloser:/home/dloser:/bin/false",
    "GZKc.2/VQffio",
    # Crypt hash related
    "GZKc",
    # De Bruijn
    "de Bruijn",
    "De Bruijn",
    "debruijn",
    "DeBruijn",
    # Scott encoding
    "Scott",
    "scott",
    # CPS
    "CPS",
    "cps",
    "continuation",
    "Continuation",
    # Access log related
    "access.log",
    # "New syscall" thread
    "New syscall enabled",
    "SPOILER ALERT",
    "spoiler alert",
    "spoiler",
    # Possible direct answers
    "the answer",
    "The Answer",
    "42",
    "towel",
    "Towel",
    # Boolean
    "true",
    "True",
    "TRUE",
    "false",
    "False",
    "FALSE",
    # Common CTF answers
    "flag",
    "Flag",
    "FLAG",
    # WeChall specific
    "WeChall",
    "wechall",
    # Combinator names
    "S",
    "K",
    "I",
    "Y",
    "SKI",
    "KI",
    # Empty/nil
    "",
    "nil",
    "Nil",
    "NIL",
    # The hash itself (meta)
    "9252ed65ffac2aa763adb21ef72c0178f1d83286",
    # QD
    "QD",
    "qd",
    "Quick debug",
    "quick debug",
    # Challenge year
    "2014",
    "2018",
    "2025",
    "2026",
    # Mail-related
    "Delivery failure",
    "Failed to deliver",
    # Possible hidden messages
    "interrupt",
    "Interrupt",
    "transfer",
    "Transfer",
    "parameters",
    "Parameters",
    # From forum
    "ancients",
    "Ancients",
]

print(f"Testing {len(candidates)} candidates...")
found = False
for c in candidates:
    if check(c):
        found = True
        break

if not found:
    print("No match found among string candidates.")

    # Now try some raw byte candidates
    print("\nTrying raw byte candidates...")
    byte_candidates = [
        bytes([0x08, 0xFF]),
        bytes([0x08]),
        bytes([0xFF]),
        bytes([0x00, 0xFE, 0xFE]),  # nil encoding
        bytes([0x2A]),  # 42
        bytes([0xC9]),  # 201
        bytes([0x0E]),  # echo/14
        bytes([0x06]),  # Permission denied error code
        bytes([0x00]),
        bytes([0x01]),
        bytes(range(256)),
    ]

    for bc in byte_candidates:
        h = bc
        for _ in range(56154):
            h = hashlib.sha1(h).hexdigest().encode()
        result = h.decode()
        match = result == TARGET
        if match:
            print(f"  *** MATCH *** bytes: {bc.hex()}")
            found = True
            break

if not found:
    # Try case-insensitive: the problem says case-insensitive on input
    # So let's try uppercase versions of some candidates
    print("\nTrying case variants...")
    for c in [
        "permission denied",
        "oh, go choke on a towel!",
        "ilikephp",
        "brownos",
        "kernel",
        "backdoor",
        "echo",
    ]:
        for variant in [c, c.upper(), c.lower(), c.title(), c.capitalize()]:
            if check(variant):
                found = True
                break
        if found:
            break

if not found:
    print("\nNo match found. The answer likely requires solving sys8 first.")
