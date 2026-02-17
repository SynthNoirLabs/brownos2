#!/usr/bin/env python3
"""
Analyze what the backdoor outputs actually mean.
"""

from dataclasses import dataclass

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


def simplify_church_numeral(term):
    """Try to identify Church numerals."""
    # Church numeral n = λf.λx. f^n(x)
    # 0 = λf.λx.x
    # 1 = λf.λx.f(x)
    # 2 = λf.λx.f(f(x))
    # etc.

    if not isinstance(term, Lam):
        return None
    if not isinstance(term.body, Lam):
        return None

    # Count how many times Var(1) is applied
    inner = term.body.body
    count = 0

    while isinstance(inner, App) and isinstance(inner.f, Var) and inner.f.i == 1:
        count += 1
        inner = inner.x

    # Check if we ended at Var(0)
    if isinstance(inner, Var) and inner.i == 0:
        return count

    return None


def analyze_term(hex_str, description):
    """Analyze a backdoor output."""
    print(f"\n{'=' * 80}")
    print(f"ANALYZING: {description}")
    print(f"{'=' * 80}")

    data = bytes.fromhex(hex_str)
    print(f"Hex: {hex_str}")
    print(f"Bytes: {' '.join(f'{b:02x}' for b in data)}")

    term = parse_term(data)
    print(f"\nParsed: {term}")

    # Try Church numeral
    cn = simplify_church_numeral(term)
    if cn is not None:
        print(f">>> Church numeral: {cn}")

    # Check pattern
    if isinstance(term, Lam) and isinstance(term.body, Lam):
        inner = term.body.body
        print(f"\nInner term (after 2 lambdas): {inner}")

        # Look for specific patterns
        if isinstance(inner, App):
            if isinstance(inner.f, Var):
                print(f"  -> Application of Var({inner.f.i}) to something")

            # Check for nested structure
            x = inner.x
            lam_count = 0
            while isinstance(x, Lam):
                lam_count += 1
                x = x.body
            if lam_count > 0:
                print(f"  -> Argument has {lam_count} nested lambdas")
                print(f"  -> Innermost: {x}")


# Common backdoor output (most globals)
# Response: 000200fdfefefefefefefefefefdfefeff
analyze_term(
    "000200fdfefefefefefefefefefdfefeff",
    "Backdoor(g(N)) - COMMON RESPONSE (for most N)",
)

# Special output for 00 FE FE
# Response: 01010000fdfefefd0100fdfefefdfefefdfefeff
analyze_term(
    "01010000fdfefefd0100fdfefefdfefefdfefeff",
    "Backdoor(λλVar(0)) - SPECIAL RESPONSE (00 FE FE)",
)

# A and B output
# Response: 0003020100fdfdfdfefefefefefefefefefdfefeff
analyze_term(
    "0003020100fdfdfdfefefefefefefefefefdfefeff",
    "Backdoor(A) and Backdoor(B) - IDENTICAL",
)

print("\n" + "=" * 80)
print("PATTERN ANALYSIS")
print("=" * 80)

print("""
OBSERVATION 1: Most inputs → SAME OUTPUT
  Backdoor(g(0)) = Backdoor(g(1)) = Backdoor(g(8)) = ... = Backdoor(g(252))
  
  Hex: 000200fdfefefefefefefefefefdfefeff
  
  This is: λλ(Var(0) applied to (9 nested lambdas wrapping App(Var(2), Var(0))))
  
  The 9 nested lambdas suggest Church numeral encoding.
  The innermost App(Var(2), Var(0)) is interesting.

OBSERVATION 2: Input 00 FE FE (Church 0) → DIFFERENT OUTPUT
  
  Hex: 01010000fdfefefd0100fdfefefdfefefdfefeff
  
  More complex structure. Contains the backdoor pair embedded?

OBSERVATION 3: Backdoor(A) = Backdoor(B)
  
  Hex: 0003020100fdfdfdfefefefefefefefefefdfefeff
  
  Even though A ≠ B, backdoor returns SAME result.
  Contains Var(3), Var(2), Var(1), Var(0) - using all 4 De Bruijn indices.

QUESTION: What do these outputs MEAN?
  - Are they Church-encoded numbers?
  - Are they instructions for how to use other syscalls?
  - Are they partial solutions that need to be combined?
  
HYPOTHESIS: The backdoor might be returning:
  1. A "key" or "token" to unlock syscall 8
  2. Instructions encoded as lambda terms
  3. A hint about what argument syscall 8 needs
""")

print("\n" + "=" * 80)
print("WHAT IF WE PASS BACKDOOR OUTPUT TO SYS8?")
print("=" * 80)

print("""
NEXT TEST: Take the backdoor outputs and feed them to syscall 8:
  
  1. sys8(backdoor(g(0)))(QD)
  2. sys8(backdoor(00 FE FE))(QD)  
  3. sys8(backdoor(A))(QD)
  
This might unlock syscall 8!
""")
