#!/usr/bin/env python3
"""
probe_hash_v3.py - Test hash candidates from oracle21 discoveries.

Key insight: backdoor pair decomposes into A=λab.(b b) and B=λab.(a b).
- A(B) = (λab.(b b))(B) = λb.(b b) = ω (little omega)
- ω(ω) = Ω (big omega, diverges)
- The pair encodes the omega combinator.

Also test: raw bytes from quoted pair, thematic answers, file-derived.

Target hash: sha1^56154(answer.lower()) = 9252ed65ffac2aa763adb21ef72c0178f1d83286
"""

import hashlib
import sys


TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"


def sha1_iterated(text: str, iterations: int = 56154) -> str:
    h = text.encode("utf-8")
    for _ in range(iterations):
        h = hashlib.sha1(h).digest()
    return h.hex()


def test_candidate(candidate: str) -> bool:
    result = sha1_iterated(candidate.lower())
    match = result == TARGET
    flag = " <<<< MATCH!" if match else ""
    print(f"  {candidate!r:50s} -> {result[:16]}...{flag}")
    return match


def main() -> None:
    print("=" * 80)
    print("probe_hash_v3.py - Hash candidate tests")
    print(f"Target: {TARGET}")
    print("=" * 80)

    candidates: list[str] = []

    # ===== OMEGA / COMBINATOR THEME =====
    # The backdoor pair gives A=λab.(bb), B=λab.(ab)
    # A(B)(y) = y(y) → self-application → omega combinator
    omega_variants = [
        "omega",
        "Omega",
        "OMEGA",
        "\u03c9",  # ω (lowercase omega)
        "\u03a9",  # Ω (uppercase omega)
        "ω",
        "Ω",
        "omega combinator",
        "the omega combinator",
        "self-application",
        "self application",
        "selfapplication",
        "self_application",
        "λx.xx",
        "lambda x. x x",
        "\\x.xx",
        "(\\x.xx)(\\x.xx)",
        "xx",
        "x x",
        "bb",
        "b b",
        "apply self",
    ]
    candidates.extend(omega_variants)

    # ===== LAMBDA CALCULUS TERMS =====
    lc_variants = [
        "lambda",
        "Lambda",
        "lambda calculus",
        "Lambda Calculus",
        "combinator",
        "combinatory logic",
        "fixed point",
        "fixpoint",
        "Y combinator",
        "ycombinator",
        "recursion",
        "diverge",
        "divergence",
        "infinite loop",
        "nontermination",
        "non-termination",
        "bottom",
        "_|_",
        "⊥",
    ]
    candidates.extend(lc_variants)

    # ===== RAW BYTES / ENCODING =====
    # Pair quoted: 010000fdfefefd0100fdfefefdfefe
    # A quoted: 0000fdfefe
    # B quoted: 0100fdfefe
    byte_variants = [
        "010000fdfefefd0100fdfefefdfefe",
        "0000fdfefe",
        "0100fdfefe",
        "010000fdfefefd0100fdfefefdfefeff",
        "0000fdfefeff",
        "0100fdfefeff",
        # Without leading zeros
        "00fdfefe",
        # Hex of just pair content
        "01 00 00 fd fe fe fd 01 00 fd fe fe fd fe fe",
    ]
    candidates.extend(byte_variants)

    # ===== BROWNOS / CHALLENGE THEME =====
    theme_variants = [
        "brownos",
        "BrownOS",
        "brown os",
        "Brown OS",
        "the brown os",
        "The BrownOS",
        "backdoor",
        "Backdoor",
        "the backdoor",
        "syscall 8",
        "syscall8",
        "permission denied",
        "Permission denied",
        "PermDenied",
        "permdenied",
        "permission granted",
        "Permission granted",
        "access granted",
        "Access Granted",
    ]
    candidates.extend(theme_variants)

    # ===== TOWEL / 42 / HITCHHIKER =====
    towel_variants = [
        "42",
        "towel",
        "Towel",
        "Oh, go choke on a towel!",
        "oh, go choke on a towel!",
        "don't panic",
        "Don't Panic",
        "dont panic",
        "hitchhiker",
        "the answer",
        "the answer to life the universe and everything",
    ]
    candidates.extend(towel_variants)

    # ===== CREDENTIALS =====
    cred_variants = [
        "ilikephp",
        "gizmore",
        "dloser",
        "GZKc.2/VQffio",
        "root",
        "mailer",
        "sudo deluser dloser",
        "sodu deluser dloser",
    ]
    candidates.extend(cred_variants)

    # ===== PAIR STRUCTURE AS TEXT =====
    pair_text = [
        "pair",
        "scott pair",
        "Scott pair",
        "cons",
        "scott cons",
        "(A,B)",
        "(λab.bb,λab.ab)",
        "λx.λy.(x(λa.λb.bb))(λa.λb.ab)",
        "\\x.\\y.(x(\\a.\\b.bb))(\\a.\\b.ab)",
    ]
    candidates.extend(pair_text)

    # ===== BACKDOOR MAIL CONTENT =====
    mail_variants = [
        "Backdoor is ready at syscall 201",
        "backdoor is ready at syscall 201",
        "Backdoor is ready at syscall 201; start with 00 FE FE.",
        "00 FE FE",
        "00fefe",
        "201",
        "syscall 201",
        "boss@evil.com",
    ]
    candidates.extend(mail_variants)

    # ===== MISC =====
    misc_variants = [
        "wtf",
        "WTF",
        "solution",
        "the solution",
        "/bin/solution",
        "success",
        "flag",
        "answer",
        "password",
        "secret",
        "kernel",
        "interrupt",
        "00fefe",
        "fdfeff",
        "brownos2",
    ]
    candidates.extend(misc_variants)

    # ===== De Bruijn / encoding-specific =====
    debruijn_variants = [
        "de bruijn",
        "De Bruijn",
        "de Bruijn",
        "debruijn",
        "DeBruijn",
    ]
    candidates.extend(debruijn_variants)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        key = c.lower()
        if key not in seen:
            seen.add(key)
            unique.append(c)

    print(f"\nTesting {len(unique)} unique candidates...\n")

    found = False
    for c in unique:
        if test_candidate(c):
            found = True
            print(f"\n*** ANSWER FOUND: {c!r} ***")
            break

    if not found:
        print(f"\nNo match found among {len(unique)} candidates.")


if __name__ == "__main__":
    main()
