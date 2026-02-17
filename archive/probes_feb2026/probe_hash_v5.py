#!/usr/bin/env python3
"""
Hash cracking v5: Focus on what /bin/solution might output.
Also test SHA1/MD5 of ilikephp and other transforms.
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


def try_candidate(label, s):
    global found
    if found:
        return
    if isinstance(s, bytes):
        key = "b:" + s.hex()
        if key in tested:
            return
        tested.add(key)
        if check_bytes(s):
            print(f"!!! MATCH (bytes): {label} = {s.hex()} !!!")
            found = True
            return True
    else:
        if s in tested:
            return
        tested.add(s)
        if check(s):
            print(f"!!! MATCH: {label} = {repr(s)} !!!")
            found = True
            return True
    return False


print("Testing hash candidates v5...")
start = time.time()

# SHA1 and MD5 of ilikephp
sha1_ilikephp = hashlib.sha1(b"ilikephp").hexdigest()
md5_ilikephp = hashlib.md5(b"ilikephp").hexdigest()
print(f"  sha1(ilikephp) = {sha1_ilikephp}")
print(f"  md5(ilikephp) = {md5_ilikephp}")

# Category 1: SHA1/MD5 transforms of key strings
transforms = {
    "ilikephp": b"ilikephp",
    "gizmore": b"gizmore",
    "dloser": b"dloser",
    "brownos": b"brownos",
    "GZKc.2/VQffio": b"GZKc.2/VQffio",
    "42": b"42",
    "towel": b"towel",
    "solution": b"solution",
    "backdoor": b"backdoor",
}

for name, val in transforms.items():
    sha1 = hashlib.sha1(val).hexdigest()
    md5 = hashlib.md5(val).hexdigest()
    try_candidate(f"sha1({name})", sha1)
    try_candidate(f"md5({name})", md5)
    try_candidate(f"SHA1({name})", sha1.upper())
    try_candidate(f"MD5({name})", md5.upper())

# Category 2: What /bin/solution might output
solution_outputs = [
    # Flag formats
    "flag{ilikephp}",
    "FLAG{ilikephp}",
    "flag{brownos}",
    "WC{ilikephp}",
    "wc{ilikephp}",
    "CTF{ilikephp}",
    "flag{backdoor}",
    "flag{42}",
    "flag{towel}",
    "flag{lambda}",
    "flag{echo}",
    "flag{permission_denied}",
    # Congratulations messages
    "Congratulations!",
    "congratulations",
    "CONGRATULATIONS",
    "You solved it!",
    "You win!",
    "Well done!",
    "Access granted",
    "ACCESS GRANTED",
    "access granted",
    "Welcome, gizmore",
    "Welcome gizmore",
    "Hello gizmore",
    "Welcome to BrownOS",
    "Welcome to brownos",
    # Solution strings
    "The solution is ilikephp",
    "gizmore's password is ilikephp",
    "password: ilikephp",
    "ilikephp\n",
    "ilikephp ",
    # Lambda/math themed
    "lambda",
    "Lambda",
    "LAMBDA",
    "λ",
    "Λ",
    "beta reduction",
    "normal form",
    "church",
    "Church",
    "CHURCH",
    "turing",
    "Turing",
    "TURING",
    "curry",
    "Curry",
    "CURRY",
    "scott",
    "Scott",
    "SCOTT",
    "debruijn",
    "de Bruijn",
    "De Bruijn",
    "combinator",
    "Combinator",
    "fixed point",
    "fixpoint",
    "fix",
    "Y combinator",
    "Y-combinator",
    # BrownOS themed
    "BrownOS v1.0",
    "BrownOS",
    "brownos",
    "brown",
    "Brown",
    "BROWN",
    "os",
    "OS",
    "kernel",
    "Kernel",
    "KERNEL",
    "root",
    "ROOT",
    "admin",
    "ADMIN",
    "superuser",
    "su",
    # Hacker/CTF themed
    "pwned",
    "PWNED",
    "h4ck3d",
    "hacked",
    "owned",
    "OWNED",
    "r00t",
    "r00ted",
    "shell",
    "SHELL",
    "bash",
    "BASH",
    # Numbers and codes
    "1337",
    "31337",
    "0xDEAD",
    "0xBEEF",
    "0xCAFE",
    "0xBABE",
    "0xC0DE",
    "secret",
    "SECRET",
    "Secret",
    # Specific to the challenge
    "dloser was here",
    "gizmore was here",
    "boss@evil.com",
    "evil.com",
    "dark magic",
    "Dark Magic",
    "IT department",
    "IT Department",
    "BBS",
    "bbs",
    "bulletin board",
    # The mail content as answer
    "Backdoor is ready",
    "backdoor is ready",
    "syscall 201",
    "syscall201",
    "00 FE FE",
    "00FEFE",
    "00fefe",
    # Pair (A,B) related
    "self-application",
    "self application",
    "Mockingbird",
    "mockingbird",
    "M",
    "Warbler",
    "warbler",
    "W",
    "MM",
    "WW",
    "MW",
    "WM",
    "bb",
    "ab",
    "BB",
    "AB",
    "λa.λb.bb",
    "λa.λb.ab",
    "(bb,ab)",
    "(BB,AB)",
    # File content hashes
    sha1_ilikephp,
    md5_ilikephp,
    # Crypt hash parts
    "GZKc",
    "Kc.2",
    ".2/V",
    "VQff",
    "ffio",
    "GZKc.2/VQffio",
    # History file content
    "sodu deluser dloser",
    "sudo deluser dloser",
    "sodu deluser dloser\nilikephp\nsudo deluser dloser\n",
    "sodu deluser dloser\nilikephp\nsudo deluser dloser",
    # Access log format
    "access.log",
    "access_log",
    # Hidden file
    "wtf",
    "WTF",
    "Wtf",
    "Uhm... yeah... no...",
    "Uhm... yeah... no...\n",
    # Encoding-related
    "Encoding failed!",
    "encoding failed",
    "Invalid term!",
    "invalid term",
    "Term too big!",
    "term too big",
    # What if it's just a UUID or random string?
    # Can't guess those, skip
    # What if it's the hex of the target hash itself?
    TARGET,
    "9252ed65ffac2aa763adb21ef72c0178f1d83286",
    # Reversed target
    TARGET[::-1],
    # What if it's empty?
    "",
    " ",
    "\n",
    # Single characters
    "0",
    "1",
    "6",
    "8",
    # Error code names
    "PermDenied",
    "perm_denied",
    "PERM_DENIED",
    "InvalidArg",
    "invalid_arg",
    "INVALID_ARG",
    "NotImpl",
    "not_impl",
    "NOT_IMPL",
    # PHP related (gizmore likes PHP)
    "php",
    "PHP",
    "Php",
    "<?php",
    "<?php?>",
    "<?=",
    "echo 'ilikephp';",
    "print('ilikephp')",
    # What if it's a URL?
    "https://www.wechall.net",
    "http://wc3.wechall.net:61221",
    "wc3.wechall.net:61221",
    "wc3.wechall.net",
    # Specific byte sequences as strings
    "\x08\xff",
    "\xc9\x00\xfe\xfe",
    "\x00\xfe\xfe",
]

for s in solution_outputs:
    try_candidate(f"solution:{s[:40]}", s)

# Category 3: Combinations with newlines and spaces
base_words = [
    "ilikephp",
    "gizmore",
    "dloser",
    "brownos",
    "solution",
    "backdoor",
    "42",
    "towel",
    "lambda",
    "echo",
    "permission",
]
for w in base_words:
    try_candidate(f"nl:{w}", w + "\n")
    try_candidate(f"sp:{w}", w + " ")
    try_candidate(f"tab:{w}", w + "\t")
    try_candidate(f"cr:{w}", w + "\r")
    try_candidate(f"crnl:{w}", w + "\r\n")

# Category 4: What if the answer is a specific integer?
for n in range(1000, 1100):
    try_candidate(f"int:{n}", str(n))
for n in [1337, 31337, 42, 201, 253, 254, 255, 256, 61221, 56154]:
    try_candidate(f"special_int:{n}", str(n))

# Category 5: What if it's a date?
dates = [
    "2014-05-24",
    "2018-12-31",
    "2022-08-08",
    "20140524",
    "20181231",
    "20220808",
    "May 24, 2014",
    "Dec 31, 2018",
]
for d in dates:
    try_candidate(f"date:{d}", d)

elapsed = time.time() - start
print(f"\nTested {len(tested)} unique candidates in {elapsed:.1f}s")
if not found:
    print("No match found.")
else:
    print("MATCH FOUND!")
