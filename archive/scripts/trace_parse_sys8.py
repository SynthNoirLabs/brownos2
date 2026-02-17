#!/usr/bin/env python3
"""
Carefully trace through the syscall 8 response parsing.

Response: 00030200fdfdfefefefefefefefefefdfefeff
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
        return f"λ({self.body})"


@dataclass(frozen=True)
class App:
    f: object
    x: object

    def __repr__(self):
        return f"({self.f} {self.x})"


response_hex = "00030200fdfdfefefefefefefefefefdfefeff"
print("=" * 80)
print("MANUAL PARSE TRACE")
print("=" * 80)

response_bytes = bytes.fromhex(response_hex)
print(f"\nInput: {response_hex}")
print(f"Bytes: {' '.join(f'{b:02x}' for b in response_bytes)}")
print(f"\nParsing step by step:\n")

stack = []
for i, b in enumerate(response_bytes):
    if b == FF:
        print(f"{i:3d}: 0xFF (END) -> Stop")
        break
    elif b == FD:
        if len(stack) < 2:
            print(f"{i:3d}: 0xFD (APP) -> ERROR: need 2 items, have {len(stack)}")
            break
        x = stack.pop()
        f = stack.pop()
        result = App(f, x)
        stack.append(result)
        print(f"{i:3d}: 0xFD (APP) -> pop {f}, pop {x}, push {result}")
    elif b == FE:
        if len(stack) < 1:
            print(f"{i:3d}: 0xFE (LAM) -> ERROR: stack empty")
            break
        body = stack.pop()
        result = Lam(body)
        stack.append(result)
        print(f"{i:3d}: 0xFE (LAM) -> pop {body}, push {result}")
    else:
        result = Var(b)
        stack.append(result)
        print(f"{i:3d}: 0x{b:02x} (VAR) -> push V{b}")

    print(f"     Stack ({len(stack)}): {stack}\n")

print(f"\n{'=' * 80}")
print(f"FINAL RESULT")
print(f"{'=' * 80}")
print(f"Stack size: {len(stack)}")
if len(stack) > 0:
    print(f"Top of stack: {stack[-1]}")

# Now analyze the structure
print(f"\n{'=' * 80}")
print("STRUCTURE ANALYSIS")
print(f"{'=' * 80}")

if len(stack) == 1:
    term = stack[0]
    print(f"\nTerm: {term}")

    # Check if it's an Either
    if isinstance(term, Lam) and isinstance(term.body, Lam):
        print("\n✓ Has 2 outer lambdas (could be Either)")
        inner = term.body.body
        print(f"Inner (after 2 λs): {inner}")

        if isinstance(inner, App) and isinstance(inner.f, Var):
            if inner.f.i == 0:
                print(f"\n>>> RIGHT (error {inner.f.i})")
                print(f">>> Error payload: {inner.x}")

                # Try to decode error as byte
                if isinstance(inner.x, Lam):
                    # Count lambdas
                    lam_count = 0
                    cur = inner.x
                    while isinstance(cur, Lam):
                        lam_count += 1
                        cur = cur.body
                    print(f">>> Error has {lam_count} lambdas")
                    print(f">>> Error inner: {cur}")
            elif inner.f.i == 1:
                print(f"\n>>> LEFT (success)")
                print(f">>> Payload: {inner.x}")
