#!/usr/bin/env python3
"""
offline_codeword_search_v2.py
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
    for variant in [s, s.lower(), s.upper()]:
        if sha1_iter(variant) == TARGET_HASH:
            print(f"\n*** MATCH FOUND! ***\nAnswer: '{variant}'\nHash: {TARGET_HASH}\n")
            return True
    return False


def generate_candidates():
    candidates = set()

    # 1. The literal AST notations of the pair and combinators
    A = Lam(Lam(App(Var(0), Var(0))))
    B = Lam(Lam(App(Var(1), Var(0))))
    pair = Lam(App(App(Var(0), A), B))

    candidates.add("00fdfefe")  # A hex
    candidates.add("0100fdfefe")  # B hex
    candidates.add("0000fdfefe")  # ?
    candidates.add(encode_term(A).hex())
    candidates.add(encode_term(B).hex())
    candidates.add(encode_term(pair).hex())

    # 2. String representations of combinations
    for c in ["sys8(A)(B)", "sys4(A)(B)", "sys201(nil)"]:
        candidates.add(c)
        candidates.add(c.replace(" ", ""))
        candidates.add(c.replace("sys", ""))

    # 3. Traversal words / Paths
    words = [
        "Left",
        "Right",
        "Left(pair)",
        "pair",
        "A",
        "B",
        "lambda",
        "lam",
        "app",
        "var",
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "201",
        "C9",
        "0xC9",
        "nil",
        "00 FE FE",
        "App(App(Var(201), nil), Var(8))",
        "App(App(Var(201), Lam(Lam(Var(0)))), Var(8))",
        "App(App(Var(8), A), B)",
        "App(Var(8), pair)",
        "App(Var(201), nil)",
        "Left(pair(A,B))",
        "App(App(Var(201), nil), Var(4))",
        "App(App(Var(201), nil), Var(2))",
        "App(App(Var(201), nil), Var(5))",
        "App(App(Var(201), nil), Var(7))",
    ]

    for w in words:
        candidates.add(w)
        candidates.add(w.replace(" ", ""))
        candidates.add(w.replace(" ", "_"))

    return list(candidates)


def main():
    print("Generating candidates...")
    cands = generate_candidates()
    print(f"Hashing {len(cands)} candidates...")

    for i, c in enumerate(cands):
        if check_candidate(c):
            return
        if i % 10 == 0:
            print(f"{i}/{len(cands)}...")
    print("No matches.")


if __name__ == "__main__":
    main()
