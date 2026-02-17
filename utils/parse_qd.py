#!/usr/bin/env python3
"""Parse QD to understand its structure."""

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
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    return stack[0] if len(stack) == 1 else stack


QD_hex = "0500fd000500fd03fdfefd02fdfefdfe"
QD = bytes.fromhex(QD_hex)

print(f"QD bytes: {list(QD)}")
print(f"QD hex: {QD_hex}")
print()

term = parse_term(QD)
print(f"Parsed QD: {term}")
print()

print("Analysis:")
print("QD is a 1-argument function (λ._)")
if isinstance(term, Lam):
    body = term.body
    print(f"  Body: {body}")
    
    if isinstance(body, App) and isinstance(body.f, App):
        outer_app = body
        print(f"  Structure: ((something) something)")
        print(f"    Inner app: {outer_app.f}")
        print(f"    Outer arg: {outer_app.x}")
        
        inner = outer_app.f
        if isinstance(inner.f, Var):
            print(f"    Syscall: V{inner.f.i}")
            
            inner_arg = inner.x
            if isinstance(inner_arg, App):
                print(f"    Inner arg is App: {inner_arg}")
                if isinstance(inner_arg.f, Var):
                    print(f"      First syscall: V{inner_arg.f.i} (quote=4, write=2)")
                if isinstance(inner_arg.x, App):
                    print(f"      That syscall's arg: {inner_arg.x}")

print()
print("So QD = λresult. ((V2 ((V5 result) V0)) ((V5 V0) ((V3 V0) V0)))")
print()
print("Under the outer lambda:")
print("  V0 = the result")
print("  V2 = write (syscall 2)")
print("  V3 = ? (probably 3 in context, but syscall 3 is 'not implemented')")
print("  V5 = readdir (syscall 5)?? No wait...")
print()
print("Actually, at TOP LEVEL:")
print("  V2 = write")
print("  V4 = quote")
print("  V5 = readdir")
print()
print("Inside λ._, everything shifts by 1, so:")
print("  V3 inside = V2 at top = write")
print("  V5 inside = V4 at top = quote")
print()
print("Let me re-parse with this understanding:")
print()

def explain_qd():
    print("QD at top level is: λresult. body")
    print()
    print("Inside the lambda, free vars are shifted:")
    print("  V0 = result (the bound variable)")
    print("  V1 = what was V0 at top (unused?)")
    print("  V2 = what was V1 at top (errorString)")
    print("  V3 = what was V2 at top (write)")  
    print("  V4 = what was V3 at top (not implemented)")
    print("  V5 = what was V4 at top (quote)")
    print()
    print("So QD = λresult. (write (quote result) continuation)")
    print("where continuation handles the Either from quote")
    print()
    print("QD body structure:")
    print("  ((V3 ...) ...)  where V3=write")
    print("  V3 takes: bytes, then continuation")
    print()
    
explain_qd()

print("Let me trace through QD byte by byte:")
print()
for i, b in enumerate(QD):
    if b < FD:
        print(f"  {i}: V{b}")
    elif b == FD:
        print(f"  {i}: App")
    elif b == FE:
        print(f"  {i}: Lam")

print()
print("Manually building the tree:")
print("05 00 FD -> (V5 V0)")
print("         -> (quote result)")
print("Then: (quote result) 00 -> that's the arg to V5?? No...")
print()
print("Let me be more careful. Stack-based parsing:")
stack = []
for i, b in enumerate(QD):
    if b < FD:
        stack.append(f"V{b}")
        print(f"  {i}: push V{b} -> {stack}")
    elif b == FD:
        x = stack.pop()
        f = stack.pop()
        stack.append(f"({f} {x})")
        print(f"  {i}: App -> {stack}")
    elif b == FE:
        body = stack.pop()
        stack.append(f"λ.{body}")
        print(f"  {i}: Lam -> {stack}")
