#!/usr/bin/env python3
"""
Decode the Left payload from successful syscall 8.

Full response: 00 030200fdfdfefefefefefefefefefdfefeff
  00 = Left marker
  Rest = payload term
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
    """Parse bytecode into term structure."""
    stack = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            if len(stack) < 2:
                raise ValueError(f"App needs 2 elements, stack has {len(stack)}")
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            if len(stack) < 1:
                raise ValueError(f"Lam needs 1 element, stack is empty")
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    if len(stack) != 1:
        raise ValueError(f"Expected 1 result, got {len(stack)}")
    return stack[0]


def term_to_string(term, depth=0):
    """Pretty-print term."""
    if isinstance(term, Var):
        return f"Var({term.i})"
    if isinstance(term, Lam):
        return f"λ{depth}.{term_to_string(term.body, depth + 1)}"
    if isinstance(term, App):
        f_str = term_to_string(term.f, depth)
        x_str = term_to_string(term.x, depth)
        return f"({f_str} {x_str})"
    return str(term)


def decode_byte_list(term):
    """
    Try to decode a list of bytes encoded as lambda calculus.

    BrownOS list encoding:
      nil = λa.λb.b
      cons h t = λa.λb.a h t

    So a list [1,2,3] would be:
      cons 1 (cons 2 (cons 3 nil))
    """
    # Check if this is nil (λλVar(0))
    if isinstance(term, Lam) and isinstance(term.body, Lam):
        if isinstance(term.body.body, Var) and term.body.body.i == 0:
            return []  # Empty list

    # Check if this is cons (λλ(Var(1) something something))
    if isinstance(term, Lam) and isinstance(term.body, Lam):
        inner = term.body.body
        if isinstance(inner, App) and isinstance(inner.f, App):
            # Extract head and tail
            # cons h t becomes λa.λb.a h t
            # After 2 lambdas: (a h) t where a=Var(1), h and t are shifted
            pass

    return None


def decode_church_numeral(term):
    """Decode Church numeral λf.λx.f^n(x)."""
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        return None

    inner = term.body.body
    count = 0

    while isinstance(inner, App) and isinstance(inner.f, Var) and inner.f.i == 1:
        count += 1
        inner = inner.x

    if isinstance(inner, Var) and inner.i == 0:
        return count

    return None


# Parse the Left payload
payload_hex = "030200fdfdfefefefefefefefefefdfefeff"

print("=" * 80)
print("DECODING SYSCALL 8 LEFT PAYLOAD")
print("=" * 80)

print(f"\nPayload hex: {payload_hex}")
payload_bytes = bytes.fromhex(payload_hex)
print(f"Bytes: {' '.join(f'{b:02x}' for b in payload_bytes)}")
print(f"Length: {len(payload_bytes)} bytes")

term = parse_term(payload_bytes)
print(f"\nParsed term:")
print(term_to_string(term))

# Check if it's a Church numeral
cn = decode_church_numeral(term)
if cn is not None:
    print(f"\n>>> CHURCH NUMERAL: {cn}")
    if 32 <= cn < 127:
        print(f">>> ASCII character: '{chr(cn)}'")
else:
    print("\nNot a simple Church numeral")

# Analyze structure
print("\n" + "=" * 80)
print("STRUCTURE ANALYSIS")
print("=" * 80)


def count_lambdas(t):
    count = 0
    while isinstance(t, Lam):
        count += 1
        t = t.body
    return count, t


lam_count, inner = count_lambdas(term)
print(f"Outer lambdas: {lam_count}")
print(f"Inner term: {term_to_string(inner)}")


# Check what variables appear
def collect_vars(t, depth=0, seen=None):
    if seen is None:
        seen = set()
    if isinstance(t, Var):
        seen.add((t.i, depth))
    elif isinstance(t, Lam):
        collect_vars(t.body, depth + 1, seen)
    elif isinstance(t, App):
        collect_vars(t.f, depth, seen)
        collect_vars(t.x, depth, seen)
    return seen


vars_found = collect_vars(term)
print(f"\nVariables used: {sorted(vars_found)}")

# Try interpreting the raw bytes differently
print("\n" + "=" * 80)
print("RAW BYTE INTERPRETATION")
print("=" * 80)

# The first few bytes before markers: 03 02 00
data_bytes = []
for b in payload_bytes:
    if b in [FD, FE, FF]:
        break
    data_bytes.append(b)

print(f"Data bytes before markers: {data_bytes}")
print(f"As decimal: {data_bytes}")
print(f"As hex: {[f'0x{b:02x}' for b in data_bytes]}")

if all(32 <= b < 127 for b in data_bytes):
    print(f"As ASCII: {''.join(chr(b) for b in data_bytes)}")
else:
    print("Not all printable ASCII")

# Could this be a byte-encoded number?
if len(data_bytes) > 0:
    # Try little-endian and big-endian
    if len(data_bytes) <= 4:
        le_val = sum(b << (8 * i) for i, b in enumerate(data_bytes))
        be_val = sum(b << (8 * i) for i, b in enumerate(reversed(data_bytes)))
        print(f"\nAs little-endian int: {le_val}")
        print(f"As big-endian int: {be_val}")

# The specific bytes are 03, 02, 00 - could these mean something?
print("\n" + "=" * 80)
print("HYPOTHESIS: FILE IDs OR SPECIAL VALUES")
print("=" * 80)

print("""
Bytes: 03 02 00

Possible meanings:
1. File IDs:
   - ID 3 = /etc/brownos (empty directory)
   - ID 2 = /etc
   - ID 0 = / (root)
   
2. Syscall numbers:
   - Syscall 3 = NotImplemented
   - Syscall 2 = write
   - Syscall 0 = exception
   
3. Sequence: 3, 2, 1, 0 countdown?
   (payload has 03 02 00, missing 01)
   
4. De Bruijn indices shifted by the 9 lambdas?

5. Actually encode a STRING when properly evaluated?
""")

# Try hash testing
print("\n" + "=" * 80)
print("HASH TESTING")
print("=" * 80)

TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ROUNDS = 56154


def check(candidate):
    cur = candidate
    for _ in range(ROUNDS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET


candidates = [
    ("Full payload hex", payload_hex),
    (
        "Data bytes as string",
        "".join(chr(b) if 32 <= b < 127 else f"\\x{b:02x}" for b in data_bytes),
    ),
    ("Just numbers: 3 2 0", "3 2 0"),
    ("Just numbers: 320", "320"),
    ("Reversed: 0 2 3", "0 2 3"),
    ("Reversed: 023", "023"),
]

for name, cand in candidates:
    if check(cand.encode("utf-8")):
        print(f"✅ MATCH: {name} = '{cand}'")

    # Also try as raw bytes if looks like hex
    if all(c in "0123456789abcdef" for c in cand.replace(" ", "").lower()):
        try:
            raw = bytes.fromhex(cand.replace(" ", ""))
            if check(raw):
                print(f"✅ MATCH (raw bytes): {name} = {raw.hex()}")
        except:
            pass

print("\n" + "=" * 80)
print("NEXT STEPS")
print("=" * 80)

print("""
The syscall 8 response is: λλ (after 9 more lambdas wrapping Apps)

This could be:
1. A LIST of bytes that need to be decoded
2. A FUNCTION that needs to be APPLIED to something
3. Instructions for ANOTHER syscall or file to read

Next actions:
1. Try APPLYING this term to various inputs (0, 1, etc.)
2. Try using this as argument to OTHER syscalls
3. Try reading the file IDs it might reference (0, 2, 3)
4. Look for a way to EVALUATE the lambda term to extract a string
""")
