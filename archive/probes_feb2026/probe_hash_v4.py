#!/usr/bin/env python3
"""
Hash cracking v4: Test candidates we haven't tried yet.
Focus on:
1. The EXACT strings that BrownOS outputs (raw bytes, not decoded)
2. Bytecode representations of key terms
3. The backdoor pair in various notations
4. Combinations of A and B as strings
5. The "3 leafs" hint itself
6. dloser-specific strings
7. The towel response variations
8. File paths and IDs
"""

import hashlib
import time

TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ROUNDS = 56154


def check(candidate: str) -> bool:
    cur = candidate.encode("utf-8")
    for _ in range(ROUNDS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET


def check_bytes(candidate: bytes) -> bool:
    cur = candidate
    for _ in range(ROUNDS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET


tested = set()
found = False


def try_str(label, s):
    global found
    if s in tested or found:
        return
    tested.add(s)
    if check(s):
        print(f"!!! MATCH: {label} = {repr(s)} !!!")
        found = True
        return True
    return False


def try_bytes(label, b):
    global found
    key = b.hex()
    if key in tested or found:
        return
    tested.add(key)
    if check_bytes(b):
        print(f"!!! MATCH (bytes): {label} = {b.hex()} !!!")
        found = True
        return True
    return False


print("Testing hash candidates v4...")
start = time.time()

# Category 1: Raw server output bytes (as hex strings)
cat1 = [
    # Right(6) raw QD output
    "00030200fdfdfefefefefefefefefefdfefeff",
    # backdoor(nil) QD output
    "01010000fdfefefd0100fdfefefdfefefdfefeff",
    # echo(backdoor)(QD) output
    "01cbfdfefeff",
    # echo(sys8)(QD) output
    "010afdfefeff",
    # echo(echo)(QD) output
    "0110fdfefeff",
    # backdoor error QD output
    "000200fdfefefefefefefefefefdfefeff",
    # echo(g(250))(QD) output
    "01fcfdfefeff",
    # echo(g(249))(QD) output
    "01fbfdfefeff",
    # echo(g(248))(QD) output
    "01fafdfefeff",
]
for s in cat1:
    try_str(f"raw_hex:{s[:20]}", s)
    try_bytes(f"raw_bytes:{s[:20]}", bytes.fromhex(s))

# Category 2: Bytecode of key terms (without FF terminator)
cat2_terms = {
    "nil": "00fefe",
    "A": "0000fdfefe",
    "B": "0100fdfefe",
    "pair(A,B)": "010000fdfefefd0100fdfefefdfefefd",
    "I": "00fe",
    "K": "01fe",  # Wait, K = λa.λb.a = Lam(Lam(Var(1))) = 01 FE FE
    "K_full": "01fefe",
    "S": "0201fd0001fdfdfe",  # S combinator
    "omega": "0000fdfefe",  # ω = λx.xx = same as A!
    "Omega": "0000fdfefe0000fdfefdff",  # Ω = ωω (but this is a program, not a term)
    "sys8": "08",
    "backdoor": "c9",
    "echo": "0e",
    "write": "02",
    "quote": "04",
    "towel": "2a",
    "sys8_nil": "0800fefefd",
    "backdoor_nil": "c900fefefd",
}
for name, hexcode in cat2_terms.items():
    try_str(f"bytecode:{name}", hexcode)
    try_bytes(f"bytecode_raw:{name}", bytes.fromhex(hexcode))
    # Also with FF terminator
    try_str(f"bytecode+ff:{name}", hexcode + "ff")
    try_bytes(f"bytecode+ff_raw:{name}", bytes.fromhex(hexcode + "ff"))

# Category 3: Lambda notation strings for A and B
cat3 = [
    "\\a.\\b.b b",
    "\\a.\\b.a b",
    "λa.λb.b b",
    "λa.λb.a b",
    "\\x.\\y.y y",
    "\\x.\\y.x y",
    "λx.λy.y y",
    "λx.λy.x y",
    "\\a.\\b.bb",
    "\\a.\\b.ab",
    "λa.λb.bb",
    "λa.λb.ab",
    "(\\a.\\b.b b, \\a.\\b.a b)",
    "(λa.λb.bb,λa.λb.ab)",
    "pair(A,B)",
    "pair(\\a.\\b.bb,\\a.\\b.ab)",
    "A=\\a.\\b.bb",
    "B=\\a.\\b.ab",
    "M",
    "W",  # Mockingbird, Warbler
    "mockingbird",
    "warbler",
    "self-application",
    "self-apply",
    "SII",
    "S(KS)K",
    "SKK",
    "\\f.ff",
    "λf.ff",
    "Mf=ff",
    "Wfx=fxx",
]
for s in cat3:
    try_str(f"lambda:{s[:30]}", s)

# Category 4: De Bruijn notation
cat4 = [
    "λ.λ.0 0",
    "λ.λ.1 0",
    "\\0.\\1.1 1",
    "\\0.\\1.0 1",
    "Lam(Lam(App(Var(0),Var(0))))",
    "Lam(Lam(App(Var(1),Var(0))))",
    "λλ00",
    "λλ10",
    "λ.λ.(0 0)",
    "λ.λ.(1 0)",
]
for s in cat4:
    try_str(f"debruijn:{s[:30]}", s)

# Category 5: "3 leafs" related
cat5 = [
    "3 leafs",
    "3 leaves",
    "three leafs",
    "three leaves",
    "3leaf",
    "3leaves",
    "threeleafs",
    "threeleaves",
    "3-leaf",
    "3-leaves",
]
for s in cat5:
    try_str(f"3leaf:{s}", s)

# Category 6: Towel response variations
cat6 = [
    "Oh, go choke on a towel!",
    "Oh, go choke on a towel!\n",
    "go choke on a towel",
    "choke on a towel",
    "towel",
    "42",
    "TOWEL",
    "Don't Panic",
    "don't panic",
    "Don't panic",
    "42!",
    "the answer",
    "The Answer",
    "The Answer to the Ultimate Question of Life, the Universe, and Everything",
]
for s in cat6:
    try_str(f"towel:{s[:30]}", s)

# Category 7: File paths and special strings
cat7 = [
    "/bin/solution",
    "bin/solution",
    "solution",
    "/etc/passwd",
    "/home/gizmore/.history",
    "/var/spool/mail/dloser",
    "boss@evil.com",
    "mailer@brownos",
    "dloser@brownos",
    "Backdoor is ready at syscall 201; start with 00 FE FE.",
    "Backdoor is ready at syscall 201; start with 00 FE FE",
    "syscall 201",
    "00 FE FE",
    "00FEFE",
    "brownos",
    "BrownOS",
    "BROWNOS",
    "brown_os",
    "Brown OS",
    "dloser",
    "DLOSER",
    "Dloser",
    "gizmore",
    "GIZMORE",
    "Gizmore",
    "wtf",
    "WTF",
    "Wtf",
    "Uhm... yeah... no...",
    "Uhm... yeah... no...\n",
]
for s in cat7:
    try_str(f"path:{s[:30]}", s)

# Category 8: Error messages
cat8 = [
    "Permission denied",
    "permission denied",
    "PERMISSION DENIED",
    "Invalid argument",
    "Not implemented",
    "Encoding failed!",
    "Invalid term!",
    "Term too big!",
    "Right(6)",
    "Right 6",
    "Left",
    "Right",
]
for s in cat8:
    try_str(f"error:{s[:30]}", s)

# Category 9: Passwd file content
cat9 = [
    "root:x:0:0:root:/:/bin/false",
    "gizmore:GZKc.2/VQffio:1000:1000:Gizmore:/home/gizmore:/bin/sh",
    "dloser:x:1002:1002:dloser:/home/dloser:/bin/false",
    "mailer:x:100:100:mailer:/var:/bin/false",
    "GZ",
    "Kc",
    ".2",
    "/V",
    "Qf",
    "fi",
    "io",  # hash fragments
]
for s in cat9:
    try_str(f"passwd:{s[:30]}", s)

# Category 10: History file content
cat10 = [
    "passwd ilikephp",
    "passwd ilikephp\n",
    "su gizmore",
    "su gizmore\n",
    "sudo",
    "su",
    "cat /etc/passwd",
    "cat .history",
]
for s in cat10:
    try_str(f"history:{s[:30]}", s)

# Category 11: Numeric and hex patterns
cat11 = [
    "201",
    "0xC9",
    "0xc9",
    "C9",
    "c9",
    "14",
    "0x0E",
    "0x0e",
    "0E",
    "0e",
    "8",
    "0x08",
    "08",
    "253",
    "254",
    "255",
    "0xFD",
    "0xFE",
    "0xFF",
    "FD",
    "FE",
    "fd",
    "fe",
    "ff",
    "FDFEFF",
    "fdfeff",
    "FDFE",
    "fdfe",
    "0xFD0xFE0xFF",
]
for s in cat11:
    try_str(f"numeric:{s}", s)

# Category 12: Access log format (IP-based)
cat12 = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "wc3.wechall.net",
    "hes2013.wechall.net",
    "61221",
    "wechall",
    "WeChall",
    "WECHALL",
]
for s in cat12:
    try_str(f"network:{s}", s)

# Category 13: Combinations of key terms
cat13 = [
    "ilikephp42",
    "42ilikephp",
    "ilikephp201",
    "201ilikephp",
    "backdoor",
    "BACKDOOR",
    "Backdoor",
    "backdoor42",
    "42backdoor",
    "echo",
    "ECHO",
    "Echo",
    "solution",
    "SOLUTION",
    "Solution",
    "brownos_solution",
    "the_solution",
    "dark magic",
    "dark_magic",
    "darkmagic",
    "IT department",
    "IT",
]
for s in cat13:
    try_str(f"combo:{s}", s)

# Category 14: What if the answer is a specific byte sequence?
# The QD output of Right(6) without the FF terminator
cat14_bytes = [
    bytes([0x00, 0x03, 0x02, 0x00]),  # Right(6) prefix
    bytes([0x08, 0xFF]),  # quote(g(8))
    bytes([0xC9, 0xFF]),  # quote(g(201))
    bytes([0x0E, 0xFF]),  # quote(g(14))
    bytes([0x00, 0xFE, 0xFE]),  # nil bytecode
    bytes([0x00, 0xFE, 0xFE, 0xFF]),  # nil + FF
    bytes([0x08, 0xC9, 0xFD, 0x00, 0xFE, 0xFE, 0xFD, 0xFF]),  # sys8(bd)(nil)
]
for b in cat14_bytes:
    try_bytes(f"raw_bytes:{b.hex()}", b)
    try_str(f"raw_hex:{b.hex()}", b.hex())

elapsed = time.time() - start
print(f"\nTested {len(tested)} unique candidates in {elapsed:.1f}s")
if not found:
    print("No match found.")
else:
    print("MATCH FOUND!")
