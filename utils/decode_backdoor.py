#!/usr/bin/env python3
"""Decode the backdoor response more carefully."""

from dataclasses import dataclass

FD, FE, FF = 0xFD, 0xFE, 0xFF


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


def parse_term(data: bytes):
    stack = []
    for i, b in enumerate(data):
        if b == FF:
            break
        if b == FD:
            if len(stack) < 2:
                print(f"  Error at byte {i}: not enough elements for App")
                return None
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
            print(f"  Byte {i}: FD -> App, stack has {len(stack)} elements")
        elif b == FE:
            if len(stack) < 1:
                print(f"  Error at byte {i}: not enough elements for Lam")
                return None
            body = stack.pop()
            stack.append(Lam(body))
            print(f"  Byte {i}: FE -> Lam, stack has {len(stack)} elements")
        else:
            stack.append(Var(b))
            print(f"  Byte {i}: {hex(b)} -> Var({b}), stack has {len(stack)} elements")
    
    print(f"\nFinal stack size: {len(stack)}")
    return stack[0] if len(stack) == 1 else stack


def main():
    backdoor_hex = "01010000fdfefefd0100fdfefefdfefefdfefeff"
    backdoor_bytes = bytes.fromhex(backdoor_hex)
    
    print(f"Backdoor response: {backdoor_hex}")
    print(f"Bytes: {list(backdoor_bytes)}")
    print()
    print("Parsing step by step:")
    
    term = parse_term(backdoor_bytes)
    
    print(f"\nParsed term: {term}")
    
    if isinstance(term, Lam) and isinstance(term.body, Lam):
        print("\nThis is an Either (2 lambdas)")
        body = term.body.body
        print(f"Body: {body}")
        
        if isinstance(body, App) and isinstance(body.f, Var):
            selector = body.f.i
            payload = body.x
            if selector == 1:
                print(f"This is Left({payload})")
            else:
                print(f"This is Right({payload})")
            
            if isinstance(payload, Lam):
                print(f"\nPayload is a lambda: {payload}")
                inner = payload.body
                print(f"Inner body: {inner}")
                
                if isinstance(inner, Lam):
                    print("Payload is λλ.(...) - a Scott pair")
                    pair_body = inner.body
                    print(f"Pair body: {pair_body}")
                    
                    if isinstance(pair_body, App) and isinstance(pair_body.f, App):
                        selector_app = pair_body.f
                        if isinstance(selector_app.f, Var):
                            print(f"  Selector: Var({selector_app.f.i})")
                            print(f"  A (first): {selector_app.x}")
                            print(f"  B (second): {pair_body.x}")
                            
                            A = selector_app.x
                            B = pair_body.x
                            
                            if isinstance(A, Lam) and isinstance(A.body, Lam):
                                print(f"\n  A decoded: λλ.{A.body.body}")
                            if isinstance(B, Lam) and isinstance(B.body, Lam):
                                print(f"  B decoded: λλ.{B.body.body}")


if __name__ == "__main__":
    main()
