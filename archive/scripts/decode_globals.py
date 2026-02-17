#!/usr/bin/env python3
"""
decode_globals.py — Parse the quoted bytecodes of BrownOS globals to understand their structure.
"""

from dataclasses import dataclass

FD = 0xFD
FE = 0xFE
FF = 0xFF


@dataclass(frozen=True)
class Var:
    i: int

    def __repr__(self):
        return f"V{self.i}"


@dataclass(frozen=True)
class Lam:
    body: object

    def __repr__(self):
        return f"λ.{self.body}"


@dataclass(frozen=True)
class App:
    f: object
    x: object

    def __repr__(self):
        return f"({self.f} {self.x})"


def parse_term(data):
    """Parse postfix bytecode to AST."""
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
        return f"PARSE_ERROR(stack={len(stack)})"
    return stack[0]


def count_lambdas(term):
    """Count leading lambdas."""
    n = 0
    cur = term
    while isinstance(cur, Lam):
        n += 1
        cur = cur.body
    return n, cur


def count_leaves(term):
    """Count leaf (Var) nodes."""
    if isinstance(term, Var):
        return 1
    if isinstance(term, Lam):
        return count_leaves(term.body)
    if isinstance(term, App):
        return count_leaves(term.f) + count_leaves(term.x)
    return 0


def pretty(term, depth=0):
    """Pretty-print with indentation."""
    indent = "  " * depth
    if isinstance(term, Var):
        return f"{indent}V{term.i}"
    if isinstance(term, Lam):
        return f"{indent}λ.\n{pretty(term.body, depth + 1)}"
    if isinstance(term, App):
        return f"{indent}@\n{pretty(term.f, depth + 1)}\n{pretty(term.x, depth + 1)}"
    return f"{indent}???"


# Known global bytecodes from the probe
globals_hex = {
    0: "010100fefefefefefefefefefd01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe",
    1: "01010100fdfefefefefefefefefefd01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe",
    2: "01010200fdfefefefefefefefefefd01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe",
    3: "0101020100fdfdfefefefefefefefefefd01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe",
    4: "01010300fdfefefefefefefefefefd01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe",
    5: "0101030100fdfdfefefefefefefefefefd01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe",
    6: "0101030200fdfdfefefefefefefefefefd01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe",
    7: "010103020100fdfdfdfefefefefefefefefefd01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe",
    8: "01010400fdfefefefefefefefefefd01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe",
    14: "010104030200fdfdfdfefefefefefefefefefd01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe",
    42: "010106040200fdfdfdfefefefefefefefefefd01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe",
    201: "01010807040100fdfdfdfdfefefefefefefefefefd01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe",
}

# Also decode the Phase 2 results
phase2_hex = {
    "242_globals": "000100fdfefefefefefefefefefdfefe",
    "4_globals_1567": "000200fdfefefefefefefefefefdfefe",
    "g2_nil": "01fefe",
    "g8_nil": "00030200fdfdfefefefefefefefefefdfefe",
    "g14_nil": "0100fefefdfefe",
    "g201_nil": "01010000fdfefefd0100fdfefefdfefefdfefe",
}


def main():
    print("=" * 72)
    print("DECODING GLOBAL STRUCTURES")
    print("=" * 72)
    print()

    for idx in sorted(globals_hex.keys()):
        hex_str = globals_hex[idx]
        data = bytes.fromhex(hex_str) + bytes([FF])
        term = parse_term(data)
        nlam, body = count_lambdas(term)
        leaves = count_leaves(term)
        print(f"g({idx:3d}): {nlam} lambdas, {leaves} leaves")
        print(f"  Full: {term}")
        print(f"  Tree:")
        print(pretty(term))
        print()

    print()
    print("=" * 72)
    print("DECODING PHASE 2 RESULTS (g(a)(nil) outputs)")
    print("=" * 72)
    print()

    for label, hex_str in phase2_hex.items():
        data = bytes.fromhex(hex_str) + bytes([FF])
        term = parse_term(data)
        nlam, body = count_lambdas(term)
        leaves = count_leaves(term)
        print(f"{label}: {nlam} lambdas, {leaves} leaves")
        print(f"  Full: {term}")
        print()

    # Now let's understand the COMMON SUFFIX
    print()
    print("=" * 72)
    print("COMMON SUFFIX ANALYSIS")
    print("=" * 72)
    print()

    # The common suffix in all globals:
    # ...fefefefefefefefefefd01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe
    # Let's parse just this suffix
    suffix_hex = "01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe"
    suffix_data = bytes.fromhex(suffix_hex) + bytes([FF])
    suffix_term = parse_term(suffix_data)
    print(f"Common suffix term: {suffix_term}")
    print(f"  Tree:")
    print(pretty(suffix_term))
    print()

    # Parse the "Right 1" and "Right 2" patterns
    # Right(x) = λl.λr. r(x) = Lam(Lam(App(Var(0), x)))
    # Let's check: 00 FE FE = Lam(Lam(Var(0))) = nil
    # 00 FE FD FE FE = Lam(Lam(App(Var(0), ???)))... no
    # Let me parse the tail: 00fefefdfefefdfefefdfefe
    tail_hex = "00fefefdfefefdfefefdfefe"
    tail_data = bytes.fromhex(tail_hex) + bytes([FF])
    tail_term = parse_term(tail_data)
    print(f"Tail pattern: {tail_term}")
    print(f"  Tree:")
    print(pretty(tail_term))
    print()

    # Parse Right(1) = λl.λr. r(1)
    # 1 as 9-lambda: 0100fd fefefefefefefefe fe
    # Right(1) = λl.λr. App(Var(0), 1)
    # = 00 [1-encoding] FD FE FE
    # where 1-encoding = 0100fd fefefefefefefefe
    # So Right(1) = 00 0100fd fefefefefefefefe FD FE FE
    # hex: 00 01 00 fd fe fe fe fe fe fe fe fe fd fe fe
    r1_hex = "000100fdfefefefefefefefefefdfefe"
    r1_data = bytes.fromhex(r1_hex) + bytes([FF])
    r1_term = parse_term(r1_data)
    print(f"Right(1) candidate: {r1_term}")
    nlam, body = count_lambdas(r1_term)
    print(f"  {nlam} lambdas, body: {body}")
    print()

    r2_hex = "000200fdfefefefefefefefefefdfefe"
    r2_data = bytes.fromhex(r2_hex) + bytes([FF])
    r2_term = parse_term(r2_data)
    print(f"Right(2) candidate: {r2_term}")
    nlam, body = count_lambdas(r2_term)
    print(f"  {nlam} lambdas, body: {body}")
    print()

    # Now decode the FULL g(0) structure step by step
    print()
    print("=" * 72)
    print("STEP-BY-STEP g(0) DECODE")
    print("=" * 72)
    print()

    g0_hex = "010100fefefefefefefefefefd01080706050403020100fdfdfdfdfdfdfdfdfefefefefefefefefefd00fefefdfefefdfefefdfefe"
    g0_bytes = bytes.fromhex(g0_hex) + bytes([FF])
    print(f"g(0) raw bytes: {g0_bytes.hex()}")
    print(f"g(0) byte list: {[f'{b:02x}' for b in g0_bytes]}")
    print()

    # Manual step-by-step parse
    stack = []
    for i, b in enumerate(g0_bytes):
        if b == FF:
            print(f"  [{i:2d}] FF → END")
            break
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            result = App(f, x)
            stack.append(result)
            print(f"  [{i:2d}] FD → App: ({f}) ({x})")
        elif b == FE:
            body = stack.pop()
            result = Lam(body)
            stack.append(result)
            print(f"  [{i:2d}] FE → Lam: λ.{body}")
        else:
            stack.append(Var(b))
            print(f"  [{i:2d}] {b:02x} → V{b}")
        print(f"       stack depth: {len(stack)}")

    print()
    print(f"Final term: {stack[0]}")


if __name__ == "__main__":
    main()
