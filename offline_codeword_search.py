#!/usr/bin/env python3
"""
offline_codeword_search.py

The paradigm shift: The VM is a teaching layer. The true answer is a codeword
representing the "3-leaf access program" or its evaluation result. The web server
hashes the answer 56,154 times (case-insensitive).

This script generates:
1. Canonical string representations of tiny 3-leaf programs involving 201.
2. Canonical serializations (de Bruijn, postfix hex) of those programs.
3. Normal forms and AST strings.
4. Exploit descriptions.
"""

import hashlib
from dataclasses import dataclass
from solve_brownos_answer import App, Lam, Var, encode_term

TARGET_HASH = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ITERATIONS = 56154


def sha1_iter(s: str) -> str:
    h = s.encode("utf-8")
    for _ in range(ITERATIONS):
        h = hashlib.sha1(h).digest()
    return h.hex()


def check_candidate(s: str):
    # Challenge is case-insensitive, we check original, lower, upper
    for variant in [s, s.lower(), s.upper()]:
        h = sha1_iter(variant)
        if h == TARGET_HASH:
            print(f"\n*** MATCH FOUND! ***\nAnswer: '{variant}'\nHash: {h}\n")
            return True
    return False


def generate_candidates():
    candidates = set()

    # 1. The literal AST notation of the 3-leaf program
    # Program: ((201 nil) X) where nil = 00 FE FE
    # Let's try some common X values and representations.

    xs = [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]

    for x in xs:
        # Standard notation
        candidates.add(f"App(App(Var(201), nil), Var({x}))")
        candidates.add(f"App(App(Var(201), Lam(Lam(Var(0)))), Var({x}))")
        candidates.add(f"((201 nil) {x})")
        candidates.add(f"((201 00FEFE) {x})")
        candidates.add(f"201 nil {x}")

        # Hex notation (postfix)
        # C9 00 FE FE FD XX FD FF
        hex_no_ff = f"c900fefefd{x:02x}fd"
        hex_with_ff = f"c900fefefd{x:02x}fdff"
        candidates.add(hex_no_ff)
        candidates.add(hex_with_ff)
        candidates.add(hex_no_ff.replace(" ", ""))
        candidates.add(hex_with_ff.replace(" ", ""))

        # What if "visit things" implies the tree itself?
        # Readdir 8 or Readdir 201 capability
        candidates.add(f"App(Var(5), App(Var(201), nil))")  # readdir(backdoor(nil))
        candidates.add(f"05c900fefefd")
        candidates.add(f"05c900fefefdff")

    # 2. De Bruijn index serializations (human readable)
    candidates.add("λ.λ.0")
    candidates.add("λa.λb.b")
    candidates.add("λa.λb.a")
    candidates.add("λa.λb.b(b)")
    candidates.add("λa.λb.a(b)")

    # Pair representation
    candidates.add("λs. s(λa.λb.b(b))(λa.λb.a(b))")
    candidates.add("Left(pair(A,B))")
    candidates.add("pair(A,B)")

    # 3. Canonical Exploit / Traversal words
    words = [
        "backdoor",
        "sys201",
        "sys8",
        "QD",
        "00 FE FE",
        "00fefe",
        "Permission denied",
        "visit things",
        "visit",
        "traversal",
        "visitor",
        "visitor pattern",
        "AST",
        "bytecode",
        "postfix",
        "de Bruijn",
        "deBruijn",
        "Scott encoding",
        "Church encoding",
        "Y combinator",
        "Omega",
        "omega",
        "nil",
        "cons",
        "Left",
        "Right",
        "Either",
        "shallow gate",
        "honeypot",
        "capability",
        "token",
        "the meaning of the input codes",
        "input codes",
    ]

    for w in words:
        candidates.add(w)
        candidates.add(w.replace(" ", ""))
        candidates.add(w.replace(" ", "_"))
        candidates.add(w.replace(" ", "-"))

    # 4. Try variations of the captured closure theory (LLM 1)
    # ((201 nil) λp.λx.p)
    candidates.add("App(App(Var(201), nil), Lam(Lam(Var(1))))")
    candidates.add("c900fefefd01fefefd")
    candidates.add("c900fefefd01fefefdff")
    candidates.add("λp.λx.p")
    candidates.add("K")
    candidates.add("True")

    return list(candidates)


def main():
    print(f"Target Hash: {TARGET_HASH}")
    print(f"Iterations: {ITERATIONS}")

    candidates = generate_candidates()
    print(f"Generated {len(candidates)} offline structural candidates.")

    print("Hashing...")
    count = 0
    for c in candidates:
        if check_candidate(c):
            return
        count += 1
        if count % 10 == 0:
            print(f"{count}/{len(candidates)} processed...")

    print("\nNo matches found in structural candidates.")


if __name__ == "__main__":
    main()
