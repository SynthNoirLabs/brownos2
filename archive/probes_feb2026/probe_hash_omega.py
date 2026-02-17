#!/usr/bin/env python3
"""probe_hash_omega.py — Test omega-related candidates with multiple hash methods."""

import hashlib

TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ROUNDS = 56154


def hash_method_a(candidate):
    """Hex chain: sha1(utf8) -> hexdigest -> sha1(ascii hex) -> hexdigest -> ..."""
    cur = candidate.encode("utf-8")
    for _ in range(ROUNDS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii")


def hash_method_b(candidate):
    """Binary chain: sha1(utf8) -> digest -> sha1(binary) -> digest -> ..."""
    cur = candidate.encode("utf-8")
    for _ in range(ROUNDS):
        cur = hashlib.sha1(cur).digest()
    return cur.hex()


def hash_method_c(candidate):
    """Same as A but lowercase candidate first."""
    return hash_method_a(candidate.lower())


candidates = [
    # Omega variants
    "omega",
    "Omega",
    "OMEGA",
    "ω",
    "Ω",  # Unicode omega
    "\\omega",
    "\\Omega",  # LaTeX
    # Little omega = self-application
    "self-application",
    "selfapplication",
    "self_application",
    "self-apply",
    "selfapply",
    # Mockingbird (A is a mockingbird variant)
    "mockingbird",
    "Mockingbird",
    "MOCKINGBIRD",
    "mock",
    "Mock",
    # Combinator names
    "M",
    "MM",
    "WW",
    "SII",
    "W",
    "S",
    "I",
    "K",
    "B",
    "C",
    "SKI",
    "BCKW",
    # Lambda notation for omega
    "λx.xx",
    "\\x.xx",
    "(λx.xx)(λx.xx)",
    "λx.(x x)",
    "\\x.(x x)",
    "(\\x.xx)(\\x.xx)",
    "Lx.xx",
    # De Bruijn for omega
    "λ.(0 0)",
    "\\.(0 0)",
    "00fd",
    "0000fdfefe",  # A's bytecode
    "0100fdfefe",  # B's bytecode
    # The pair itself
    "pair",
    "Pair",
    "PAIR",
    "(A,B)",
    "A,B",
    "(M,I)",
    # Church pair bytecode
    "010000fdfefefd0100fdfefefdfefe",
    # "3 leafs" related
    "3",
    "three",
    "3leafs",
    "3 leafs",
    # Towel (sys42 returns this)
    "42",
    "towel",
    "Towel",
    "Oh, go choke on a towel!",
    # Password
    "ilikephp",
    # BrownOS specific
    "brownos",
    "BrownOS",
    "BROWNOS",
    "dloser",
    "gizmore",
    "mailer",
    # Backdoor
    "backdoor",
    "Backdoor",
    "BACKDOOR",
    "201",
    "0xC9",
    "c9",
    "C9",
    # Permission denied
    "Permission denied",
    "permission denied",
    "denied",
    "Denied",
    # File paths
    "/bin/solution",
    "solution",
    "Solution",
    "/bin/sh",
    "/bin/false",
    # Possible short answers
    "yes",
    "no",
    "true",
    "false",
    "ok",
    "OK",
    "done",
    "Done",
    "flag",
    "Flag",
    "FLAG",
    "win",
    "Win",
    "WIN",
    "key",
    "Key",
    "KEY",
    # Numbers
    "0",
    "1",
    "6",
    "8",
    "14",
    "42",
    "201",
    "253",
    "254",
    "255",
    # Empty/nil
    "",
    "nil",
    "NIL",
    "Nil",
    "null",
    "NULL",
    "Null",
    "void",
    "unit",
    "()",
    # Haskell/FP terms
    "fix",
    "Fix",
    "Y",
    "Z",
    "fold",
    "unfold",
    "rec",
    "bottom",
    "⊥",
    # German
    "Lösung",
    "loesung",
    "Antwort",
    "antwort",
    "Passwort",
    "passwort",
    "Geheimnis",
    "geheimnis",
    "verboten",
    "Verboten",
    "braun",
    "Braun",
    # The actual output of sys8 if it succeeded might be a string
    # What if the answer is what sys8 WOULD return?
    "Congratulations!",
    "congratulations",
    "Success",
    "success",
    "Granted",
    "granted",
    "Access granted",
    "access granted",
    "Welcome",
    "welcome",
]

print(f"Testing {len(candidates)} candidates with 3 hash methods...")
print(f"Target: {TARGET}")
print()

found = False
for i, cand in enumerate(candidates):
    if i % 20 == 0 and i > 0:
        print(f"  Progress: {i}/{len(candidates)}...")

    for method_name, method_fn in [
        ("A_hex", hash_method_a),
        ("B_bin", hash_method_b),
        ("C_lower", hash_method_c),
    ]:
        try:
            result = method_fn(cand)
            if result == TARGET:
                print(f"\n!!! MATCH FOUND !!!")
                print(f"  Candidate: {repr(cand)}")
                print(f"  Method: {method_name}")
                found = True
        except Exception as e:
            pass  # Skip encoding errors

if not found:
    print(f"\nNo matches found among {len(candidates)} candidates x 3 methods.")
print("Done.")
