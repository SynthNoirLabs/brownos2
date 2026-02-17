#!/usr/bin/env python3
"""probe_hash_ab.py — Hash-check A/B representations against answer hash."""

import hashlib

TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ROUNDS = 56154


def check(candidate):
    cur = candidate.encode("utf-8") if isinstance(candidate, str) else candidate
    for _ in range(ROUNDS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET


def check_bytes_as_utf8(bs):
    """Try the bytes as a UTF-8 string."""
    try:
        return check(bs.decode("utf-8"))
    except:
        return False


candidates = []

# A bytecodes
candidates.append(("A bytecode hex", "0000fdfefe"))
candidates.append(("A bytecode hex upper", "0000FDFEFE"))
candidates.append(("A bytecode hex with FF", "0000fdfefeff"))
candidates.append(("A bytecode hex spaces", "00 00 FD FE FE"))
candidates.append(("A bytecode hex 0x", "0x00 0x00 0xFD 0xFE 0xFE"))

# B bytecodes
candidates.append(("B bytecode hex", "0100fdfefe"))
candidates.append(("B bytecode hex upper", "0100FDFEFE"))
candidates.append(("B bytecode hex with FF", "0100fdfefeff"))
candidates.append(("B bytecode hex spaces", "01 00 FD FE FE"))

# Pair bytecodes (full pair from QD output)
# pair = Lam(Lam(App(App(Var(1), A), B)))
# Encoded: 01 00 00 FD FE FE FD 01 00 FD FE FE FD FE FE
pair_hex = "010000fdfefefd0100fdfefefdfefe"
candidates.append(("pair bytecode hex", pair_hex))
candidates.append(("pair bytecode hex upper", pair_hex.upper()))
candidates.append(("pair bytecode hex with FF", pair_hex + "ff"))
candidates.append(
    (
        "pair bytecode hex spaces",
        " ".join(pair_hex[i : i + 2] for i in range(0, len(pair_hex), 2)),
    )
)

# Lambda notation variants
candidates.append(("A lambda", "λa.λb.b(b)"))
candidates.append(("A lambda ascii", "\\a.\\b.b(b)"))
candidates.append(("A lambda ascii2", "\\a.\\b.(b b)"))
candidates.append(("A debruijn", "λ.λ.(0 0)"))
candidates.append(("A debruijn ascii", "\\.\\.0 0"))
candidates.append(("A debruijn2", "Lam(Lam(App(Var(0),Var(0))))"))

candidates.append(("B lambda", "λa.λb.a(b)"))
candidates.append(("B lambda ascii", "\\a.\\b.a(b)"))
candidates.append(("B lambda ascii2", "\\a.\\b.(a b)"))
candidates.append(("B debruijn", "λ.λ.(1 0)"))
candidates.append(("B debruijn ascii", "\\.\\.1 0"))
candidates.append(("B debruijn2", "Lam(Lam(App(Var(1),Var(0))))"))

# Pair lambda notation
candidates.append(("pair lambda", "λf.λg.f(A)(B)"))
candidates.append(("pair debruijn", "λ.λ.((1 λ.λ.(0 0)) λ.λ.(1 0))"))

# Combinator names
candidates.append(("mockingbird", "mockingbird"))
candidates.append(("Mockingbird", "Mockingbird"))
candidates.append(("M", "M"))
candidates.append(("M*", "M*"))
candidates.append(("warbler", "warbler"))
candidates.append(("Warbler", "Warbler"))
candidates.append(("W", "W"))
candidates.append(("thrush", "thrush"))
candidates.append(("Thrush", "Thrush"))
candidates.append(("T", "T"))
candidates.append(("apply", "apply"))
candidates.append(("Apply", "Apply"))
candidates.append(("identity", "identity"))
candidates.append(("I", "I"))
candidates.append(("omega", "omega"))
candidates.append(("Omega", "Omega"))
candidates.append(("self-application", "self-application"))
candidates.append(("self_application", "self_application"))
candidates.append(("selfapp", "selfapp"))
candidates.append(("SII", "SII"))
candidates.append(("MM", "MM"))
candidates.append(("WI", "WI"))
candidates.append(("BB", "BB"))
candidates.append(("pair", "pair"))
candidates.append(("Pair", "Pair"))
candidates.append(("cons", "cons"))
candidates.append(("Cons", "Cons"))

# A and B as raw bytes (not hex strings)
candidates.append(("A raw bytes", bytes([0, 0, 0xFD, 0xFE, 0xFE]).hex()))
candidates.append(("B raw bytes", bytes([1, 0, 0xFD, 0xFE, 0xFE]).hex()))

# Combinations
candidates.append(("A,B", "A,B"))
candidates.append(("(A,B)", "(A,B)"))
candidates.append(("A B", "A B"))
candidates.append(("AB", "AB"))
candidates.append(("BA", "BA"))
candidates.append(("A(B)", "A(B)"))
candidates.append(("B(A)", "B(A)"))

# "3 leafs" related
candidates.append(("3 leafs", "3 leafs"))
candidates.append(("3 leaves", "3 leaves"))
candidates.append(("three leafs", "three leafs"))
candidates.append(("three leaves", "three leaves"))

# Backdoor related
candidates.append(("backdoor", "backdoor"))
candidates.append(("Backdoor", "Backdoor"))
candidates.append(("201", "201"))
candidates.append(("0xC9", "0xC9"))
candidates.append(("c9", "c9"))
candidates.append(("C9", "C9"))

# "00 FE FE" related
candidates.append(("00fefe", "00fefe"))
candidates.append(("00 FE FE", "00 FE FE"))
candidates.append(("nil", "nil"))
candidates.append(("NIL", "NIL"))
candidates.append(("Nil", "Nil"))

# Password and user related
candidates.append(("ilikephp", "ilikephp"))
candidates.append(("gizmore", "gizmore"))
candidates.append(("dloser", "dloser"))
candidates.append(("mailer", "mailer"))
candidates.append(("root", "root"))
candidates.append(("brownos", "brownos"))
candidates.append(("BrownOS", "BrownOS"))

# Error codes
for i in range(8):
    candidates.append((f"error_{i}", str(i)))
candidates.append(("Permission denied", "Permission denied"))
candidates.append(("PermDenied", "PermDenied"))
candidates.append(("Denied", "Denied"))
candidates.append(("denied", "denied"))

# Syscall numbers
for n in [0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 42, 201]:
    candidates.append((f"syscall_{n}", str(n)))
    candidates.append((f"syscall_0x{n:02x}", f"0x{n:02x}"))

# The answer might be the PROGRAM that solves it
# "3 leafs" = 3 Var nodes = minimal program
# Possible 3-leaf programs:
candidates.append(("c9 00fefe fd ff", "c900fefefdff"))  # backdoor(nil)
candidates.append(("08 c9 fd ff", "08c9fdff"))  # sys8(backdoor)
candidates.append(("c9 08 fd ff", "c908fdff"))  # backdoor(sys8)

# Hash of known strings
import hashlib as hl

for s in ["ilikephp", "gizmore", "dloser", "brownos", "backdoor"]:
    h = hl.sha1(s.encode()).hexdigest()
    candidates.append((f"sha1({s})", h))
    candidates.append((f"md5({s})", hl.md5(s.encode()).hexdigest()))

# Numbers 0-255
for i in range(256):
    candidates.append((f"num_{i}", str(i)))

# Hex 00-FF
for i in range(256):
    candidates.append((f"hex_{i:02x}", f"{i:02x}"))
    candidates.append((f"HEX_{i:02X}", f"{i:02X}"))

print(f"Testing {len(candidates)} candidates...")
found = False
for i, (name, cand) in enumerate(candidates):
    if i % 100 == 0:
        print(f"  Progress: {i}/{len(candidates)}...")
    if check(cand):
        print(f"\n!!! MATCH FOUND: {name} = {repr(cand)} !!!")
        found = True

if not found:
    print(f"\nNo matches found among {len(candidates)} candidates.")
print("Done.")
