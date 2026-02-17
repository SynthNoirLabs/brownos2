#!/usr/bin/env python3
"""
BREAKTHROUGH: Syscall 8 succeeded! Now decode the response.

Response: 030200fdfdfefefefefefefefefefdfefeff
"""

from dataclasses import dataclass
import hashlib

FD = 0xFD
FE = 0xFE
FF = 0xFF


@dataclass(frozen=True)
class Var:
    i: int


@dataclass(frozen=True)
class Lam:
    body: object


@dataclass(frozen=True)
class App:
    f: object
    x: object


def parse_term(data):
    stack = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    if len(stack) != 1:
        raise ValueError(f"Invalid parse: stack={len(stack)}")
    return stack[0]


def decode_church_numeral(term):
    """Decode Church numeral to integer."""
    # Church n = λf.λx. f^n(x)
    if not isinstance(term, Lam):
        return None
    if not isinstance(term.body, Lam):
        return None

    inner = term.body.body
    count = 0

    while isinstance(inner, App) and isinstance(inner.f, Var) and inner.f.i == 1:
        count += 1
        inner = inner.x

    if isinstance(inner, Var) and inner.i == 0:
        return count

    return None


def decode_byte_term(term):
    """Decode a byte-encoded term (9 lambdas with bit flags)."""
    # BrownOS byte encoding: 9 nested lambdas
    # Innermost has applications of Var(1..8) representing bits

    if not isinstance(term, Lam):
        return None

    # Count lambdas
    lam_count = 0
    current = term
    while isinstance(current, Lam):
        lam_count += 1
        current = current.body

    if lam_count != 9:
        return None

    # Now current should be applications
    # Reconstruct byte value from bit applications
    byte_val = 0

    # Walk the application tree
    def extract_bits(expr):
        nonlocal byte_val
        if isinstance(expr, App):
            if isinstance(expr.f, Var) and 1 <= expr.f.i <= 8:
                bit_pos = expr.f.i - 1
                byte_val |= 1 << bit_pos
                extract_bits(expr.x)
            elif isinstance(expr.f, App):
                extract_bits(expr.f)
                # Don't recurse into x if f is App
            else:
                extract_bits(expr.x) if isinstance(expr, App) else None
        elif isinstance(expr, Var):
            # Base case - should be Var(0)
            pass

    extract_bits(current)
    return byte_val


def decode_byte_list(term):
    """Decode a list of byte-terms."""
    # List nil = λa.λb.b
    # List cons = λh.λt.λa.λb.a h t

    bytes_found = []

    # Try to extract bytes from the structure
    # For now, let's just look at the raw term

    return bytes_found


# The response
response_hex = "030200fdfdfefefefefefefefefefdfefeff"
print("=" * 80)
print("DECODING SYSCALL 8 RESPONSE")
print("=" * 80)

print(f"\nResponse hex: {response_hex}")
print(f"Bytes: {' '.join(f'{b:02x}' for b in bytes.fromhex(response_hex))}")

term = parse_term(bytes.fromhex(response_hex))
print(f"\nParsed term: {term}")

# Try Church numeral
cn = decode_church_numeral(term)
if cn is not None:
    print(f"\n✓ Church numeral: {cn}")
    print(f"  ASCII: {chr(cn) if 32 <= cn < 127 else '(non-printable)'}")

# Try byte term
bt = decode_byte_term(term)
if bt is not None:
    print(f"\n✓ Byte term: {bt}")
    print(f"  Hex: 0x{bt:02x}")
    print(f"  ASCII: {chr(bt) if 32 <= bt < 127 else '(non-printable)'}")

# Analyze structure
print("\n" + "=" * 80)
print("STRUCTURE ANALYSIS")
print("=" * 80)

if isinstance(term, Lam):
    lam_count = 0
    current = term
    while isinstance(current, Lam):
        lam_count += 1
        current = current.body

    print(f"Number of outer lambdas: {lam_count}")
    print(f"Inner term: {current}")

    if isinstance(current, App):
        print(f"\nInner is application:")
        print(f"  Function: {current.f}")
        print(f"  Argument: {current.x}")

        # Check for nested structure
        if isinstance(current.x, Lam):
            inner_lam_count = 0
            inner_current = current.x
            while isinstance(inner_current, Lam):
                inner_lam_count += 1
                inner_current = inner_current.body
            print(f"\n  Argument has {inner_lam_count} nested lambdas")
            print(f"  Argument innermost: {inner_current}")

# Raw byte interpretation
print("\n" + "=" * 80)
print("RAW BYTE INTERPRETATION")
print("=" * 80)

response_bytes = bytes.fromhex(response_hex.replace("ff", ""))
print(f"Without FF marker: {response_bytes.hex()}")
print(f"As integers: {list(response_bytes)}")
print(f"As ASCII (if printable): ", end="")
for b in response_bytes:
    if 32 <= b < 127:
        print(chr(b), end="")
    else:
        print(f"\\x{b:02x}", end="")
print()

# Check if it's a known file ID
print("\n" + "=" * 80)
print("HYPOTHESIS: IS THIS A FILE ID OR OTHER REFERENCE?")
print("=" * 80)

print(f"""
Known file IDs:
  0 = /
  11 = /etc/passwd
  14 = /bin/sh
  15 = /bin/sudo
  16 = /bin/false
  46 = /var/log/brownos/access.log
  65 = /home/gizmore/.history
  88 = /var/spool/mail/dloser

The response has bytes: 03 02 00 (and then encoding markers)

Could this be:
  - File ID 3? (/etc/brownos - EMPTY directory)
  - File ID 2? (/etc)
  - Three separate bytes: 3, 2, 0?
  - Some other encoding?
""")

# Test if response is itself a hash candidate
print("\n" + "=" * 80)
print("HASH TEST: Is the response itself the answer?")
print("=" * 80)

TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ROUNDS = 56154


def check(candidate):
    cur = candidate
    for _ in range(ROUNDS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET


# Try various interpretations
candidates = {
    "Raw hex": response_hex,
    "Without FF": response_hex.replace("ff", ""),
    "Just data bytes": "030200",
    "Term structure": str(term),
}

for name, cand_str in candidates.items():
    cand_bytes = cand_str.encode("utf-8")
    if check(cand_bytes):
        print(f"✅ MATCH FOUND: {name}")
        print(f"   Candidate: {cand_str}")
    else:
        # Also try as raw bytes if it's hex
        if all(c in "0123456789abcdef" for c in cand_str.lower()):
            try:
                cand_bytes = bytes.fromhex(cand_str)
                if check(cand_bytes):
                    print(f"✅ MATCH FOUND (as raw bytes): {name}")
                    print(f"   Candidate: {cand_str}")
            except:
                pass

print("\n" + "=" * 80)
print("NEXT STEPS")
print("=" * 80)

print("""
1. The response is definitely meaningful - syscall 8 succeeded!

2. The response term needs proper interpretation:
   - Could encode a string/password
   - Could be instructions for next step
   - Could reference another file/syscall

3. Need to understand the lambda calculus semantics:
   - What does this specific term COMPUTE?
   - Is it a function that returns a value?
   - Should we APPLY it to something?

4. Try reading file ID 3, 2, or 0 to see if there's new content

5. The term might need to be EVALUATED to get the actual answer
""")
