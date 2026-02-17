#!/usr/bin/env python3
"""
Analyze the probe results and decode the responses
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


def parse_term(data: bytes) -> object:
    stack: list[object] = []
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
        raise ValueError(f"Invalid parse: stack size {len(stack)}")
    return stack[0]


def pp_term(term: object, depth: int = 0) -> str:
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{pp_term(term.body, depth+1)}"
    if isinstance(term, App):
        return f"({pp_term(term.f, depth)} {pp_term(term.x, depth)})"
    return str(term)


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def decode_byte_term(term: object) -> int | None:
    if not isinstance(term, Lam):
        return None
    cur = term
    for _ in range(9):
        if not isinstance(cur, Lam):
            return None
        cur = cur.body
    
    def eval_expr(e: object) -> int:
        if isinstance(e, Var) and e.i in WEIGHTS:
            return WEIGHTS[e.i]
        if isinstance(e, App) and isinstance(e.f, Var) and e.f.i in WEIGHTS:
            return WEIGHTS[e.f.i] + eval_expr(e.x)
        raise ValueError(f"Not a byte expr: {e}")
    
    try:
        return eval_expr(cur)
    except:
        return None


def decode_either(term: object) -> tuple[str, object] | None:
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        return None
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var):
        if body.f.i == 1:
            return ("Left", body.x)
        if body.f.i == 0:
            return ("Right", body.x)
    return None


responses = {
    "syscall8_permission_denied": "00030200fdfdfefefefefefefefefefdfefeff",
    "syscall_not_implemented": "000100fdfefefefefefefefefefdjefeff",
}

print("Analyzing probe results:")
print("="*60)

resp_hex = "00030200fdfdfefefefefefefefefefdfefeff"
resp_bytes = bytes.fromhex(resp_hex)
term = parse_term(resp_bytes)
print(f"\nResponse from syscall 8: {resp_hex}")
print(f"Parsed term: {pp_term(term)}")
result = decode_either(term)
if result:
    tag, payload = result
    print(f"Either: {tag}")
    byte_val = decode_byte_term(payload)
    if byte_val is not None:
        print(f"Payload as byte: {byte_val}")
        if byte_val == 6:
            print("  → This is error code 6 = 'Permission denied'")

resp_hex2 = "000100fdfefefefefefefefefefdjefeff"
print(f"\nResponse from syscalls 202-252: (first few bytes similar)")
print(f"This pattern represents Right(1) = 'Not implemented'")

print("\n" + "="*60)
print("KEY INSIGHTS FROM PROBE:")
print("="*60)
print("""
1. ALL 3-byte payloads (λ.Var(x)) return EMPTY
   - This means these minimal terms don't produce any writable output
   - The VM evaluates them but there's nothing to serialize

2. Serialization hypothesis PARTIALLY CONFIRMED:
   - ((syscall8 nil) K_nil) returns EMPTY (K_nil ignores input, returns nil)
   - This means even with serializable output, if continuation doesn't 
     explicitly write, we get nothing
   - But this also shows syscall8 IS being called and returning something

3. echo(Var(251)) returns "Encoding failed!"
   - Confirms Var(253) cannot be serialized (as expected)

4. ALL 16 3-leaf terms return same "Permission denied" (Right(6))
   - Syscall 8 still locked for all of them

5. Syscalls 202-252 all return "Not implemented" (Right(1))
   - No hidden syscalls in that range

6. Malformed payloads return "Invalid term!" (parser rejects them)
   - No parser exploits via simple malformed sequences

7. The "interesting" responses are just because they're not the standard
   "Not implemented" - they're actually "Permission denied"
""")

print("\n" + "="*60)
print("NEXT HYPOTHESIS TO TEST:")
print("="*60)
print("""
The fact that ((syscall8 nil) K_nil) returns EMPTY (not Permission denied)
shows that:
- syscall8 DOES call its continuation
- The continuation receives the Permission denied result
- K_nil ignores it and returns nil
- nil has no side effects so we see nothing

This means we need a continuation that:
1. Receives the syscall result
2. Does something OBSERVABLE with it

What if we need to CHANGE the syscall8 result somehow?
Or what if there's a way to call syscall8 that bypasses permission check?

The echo syscall creates Var(253) which maps to 0xFD byte.
What if we could somehow use this in a CONTINUATION rather than as argument?
""")
