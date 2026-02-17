#!/usr/bin/env python3
"""Decode the novel responses from probe_3leaf_oracle.py"""

from dataclasses import dataclass

FD = 0xFD
FE = 0xFE
FF = 0xFF


@dataclass(frozen=True)
class Var:
    i: int

    def __repr__(self):
        return f"Var({self.i})"


@dataclass(frozen=True)
class Lam:
    body: object

    def __repr__(self):
        return f"Lam({self.body!r})"


@dataclass(frozen=True)
class App:
    f: object
    x: object

    def __repr__(self):
        return f"App({self.f!r}, {self.x!r})"


def parse_term(data: bytes):
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
        return f"PARSE ERROR: stack size {len(stack)}, stack={stack}"
    return stack[0]


def decode_either(term):
    """Decode Scott Either: Left x = λl.λr. l(x), Right y = λl.λr. r(y)"""
    if isinstance(term, Lam) and isinstance(term.body, Lam):
        body = term.body.body
        if isinstance(body, App) and isinstance(body.f, Var):
            if body.f.i == 1:
                return ("Left", body.x)
            elif body.f.i == 0:
                return ("Right", body.x)
    return ("Unknown", term)


def decode_scott_int(term):
    """Decode Scott natural: 0 = λs.λz.z, n+1 = λs.λz.s(n)"""
    if isinstance(term, Lam) and isinstance(term.body, Lam):
        body = term.body.body
        if isinstance(body, Var) and body.i == 0:
            return 0
        if isinstance(body, App) and isinstance(body.f, Var) and body.f.i == 1:
            inner = decode_scott_int(body.x)
            if inner is not None:
                return inner + 1
    return None


def pretty(term, depth=0):
    """Pretty print a term."""
    if isinstance(term, Var):
        return f"g({term.i})" if depth == 0 else f"Var({term.i})"
    if isinstance(term, Lam):
        return f"λ.{pretty(term.body, depth + 1)}"
    if isinstance(term, App):
        return f"({pretty(term.f, depth)}  {pretty(term.x, depth)})"
    return str(term)


# Decode the novel responses
print("=" * 70)
print("DECODING NOVEL RESPONSES")
print("=" * 70)

responses = {
    "backdoor(nil)(QD)": "01010000fdfefefd0100fdfefefdfefefdfefeff",
    "echo(backdoor)(QD)": "01cbfdfefeff",
    "echo(sys8)(QD)": "010afdfefeff",
    "echo(echo)(QD)": "0110fdfefeff",
    "backdoor(g(0))(QD)": "000200fdfefefefefefefefefefdfefeff",
    "echo(g(248))(QD)": "01fafdfefeff",
    "echo(g(249))(QD)": "01fbfdfefeff",
    "echo(g(250))(QD)": "01fcfdfefeff",
}

for label, hex_str in responses.items():
    data = bytes.fromhex(hex_str)
    print(f"\n--- {label} ---")
    print(f"  Raw hex: {hex_str}")
    print(f"  Raw bytes: {list(data)}")

    term = parse_term(data)
    print(f"  Parsed: {term!r}")
    print(f"  Pretty: {pretty(term)}")

    tag, payload = decode_either(term)
    print(f"  Either: {tag}")
    if tag in ("Left", "Right"):
        print(f"  Payload: {payload!r}")
        print(f"  Payload pretty: {pretty(payload)}")

        if tag == "Right":
            n = decode_scott_int(payload)
            if n is not None:
                error_names = {
                    0: "Exception",
                    1: "NotImpl",
                    2: "InvalidArg",
                    3: "NoSuchFile",
                    4: "NotDir",
                    5: "NotFile",
                    6: "PermDenied",
                    7: "RateLimit",
                }
                print(f"  Error code: {n} = {error_names.get(n, '???')}")

# Now let's understand the echo responses more carefully
print("\n" + "=" * 70)
print("ECHO ANALYSIS")
print("=" * 70)

print("""
echo(g(N)) returns Left(g(N)).
Left(x) = λl.λr. l(x)

When QD serializes Left(g(N)):
- Left(g(N)) = Lam(Lam(App(Var(1), Var(N+2))))
  (because g(N) = Var(N) at top level, but under 2 lambdas it becomes Var(N+2))
- Bytecode: 01 (N+2) FD FE FE FF

So:
- echo(g(248))(QD) → Left(g(248)) → 01 FA FD FE FE FF ✓ (FA = 250 = 248+2)
- echo(g(249))(QD) → Left(g(249)) → 01 FB FD FE FE FF ✓ (FB = 251 = 249+2)
- echo(g(250))(QD) → Left(g(250)) → 01 FC FD FE FE FF ✓ (FC = 252 = 250+2)
- echo(g(251))(QD) → Left(g(251)) → would need 01 FD FD FE FE FF
  But FD = App marker! Quote can't serialize Var(253)! → "Encoding failed!"
- echo(g(252))(QD) → Left(g(252)) → would need 01 FE FD FE FE FF
  But FE = Lam marker! Quote can't serialize Var(254)! → "Encoding failed!"

This confirms: echo creates terms with Var(253/254/255) that can't be serialized.
The question is: can these terms be USED (not serialized) to unlock sys8?
""")

# Decode backdoor(nil)(QD) more carefully
print("=" * 70)
print("BACKDOOR ANALYSIS")
print("=" * 70)

bd_hex = "01010000fdfefefd0100fdfefefdfefefdfefeff"
bd_data = bytes.fromhex(bd_hex)
bd_term = parse_term(bd_data)
print(f"backdoor(nil)(QD) = {bd_term!r}")
print(f"Pretty: {pretty(bd_term)}")

tag, payload = decode_either(bd_term)
print(f"Either: {tag}")
print(f"Payload: {payload!r}")
print(f"Payload pretty: {pretty(payload)}")

# The payload should be pair(A, B)
# Scott pair/cons: λc.λn. c(head)(tail)
# So payload = Lam(Lam(App(App(Var(1), A_shifted), B_shifted)))
if isinstance(payload, Lam) and isinstance(payload.body, Lam):
    body = payload.body.body
    print(f"\nPair body: {body!r}")
    if isinstance(body, App) and isinstance(body.f, App):
        if isinstance(body.f.f, Var) and body.f.f.i == 1:
            head = body.f.x
            tail = body.x
            print(f"Head (A, shifted +2): {head!r}")
            print(f"Tail (B, shifted +2): {tail!r}")
            print(f"Head pretty: {pretty(head)}")
            print(f"Tail pretty: {pretty(tail)}")

            # Unshift: under 2 lambdas of the pair, variables are shifted by 2
            # A = λa.λb. b b → under pair's 2 lambdas: λa.λb. b b (indices are local)
            # Actually the head/tail are already shifted by the pair's 2 lambdas
            # Let's just print them as-is

            if isinstance(head, Lam) and isinstance(head.body, Lam):
                print(f"\nA body (under 4 lambdas total): {head.body.body!r}")
            if isinstance(tail, Lam) and isinstance(tail.body, Lam):
                print(f"B body (under 4 lambdas total): {tail.body.body!r}")

# Decode backdoor error
print("\n--- backdoor(g(0))(QD) ---")
bd_err_hex = "000200fdfefefefefefefefefefdfefeff"
bd_err_data = bytes.fromhex(bd_err_hex)
bd_err_term = parse_term(bd_err_data)
print(f"Parsed: {bd_err_term!r}")
tag, payload = decode_either(bd_err_term)
print(f"Either: {tag}")
if tag == "Right":
    n = decode_scott_int(payload)
    print(f"Error code: {n}")
    error_names = {
        0: "Exception",
        1: "NotImpl",
        2: "InvalidArg",
        3: "NoSuchFile",
        4: "NotDir",
        5: "NotFile",
        6: "PermDenied",
        7: "RateLimit",
    }
    print(f"Error: {error_names.get(n, '???')}")
