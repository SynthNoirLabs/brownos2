#!/usr/bin/env python3
"""
Deep insight probe for BrownOS - testing specific hypotheses based on hints.

Key Insights:
1. "the mail points to the way to get access there" - backdoor combinators
2. "why would an OS even need an echo?" - echo manufactures special vars
3. "combining special bytes... froze my whole system" - FD/FE/FF
4. "3 leafs" - code golf minimal solution
5. Backdoor returns A and B where (A B) = omega

Hypotheses to test:
1. Apply pair DIRECTLY to syscall8: (pair syscall8) = ((syscall8 A) B)
2. Use omega as a continuation: what happens?
3. Try echo-manufactured vars in very specific patterns
4. Check if success outputs NOTHING (forum hint about no output on valid input)
"""

from __future__ import annotations
import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


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


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        if term.i >= 0xFD:
            raise ValueError(f"Cannot encode Var({term.i}) - reserved byte")
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported term: {type(term)}")


def parse_term(data: bytes) -> object:
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
    return stack[0] if stack else None


def query_raw(payload: bytes, timeout_s: float = 5.0) -> tuple[bytes, bool]:
    """Returns (response, got_any_data)"""
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

            sock.settimeout(timeout_s)
            out = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out += chunk
                    if FF in chunk:
                        break
                except socket.timeout:
                    break
            return out, len(out) > 0
    except Exception as e:
        return b"", False


# Build key terms
nil = Lam(Lam(Var(0)))  # λc.λn. n

# Identity
identity = Lam(Var(0))  # λx. x

# Syscalls as globals
syscall8 = Var(0x08)
syscall_backdoor = Var(0xC9)  # 201
syscall_echo = Var(0x0E)  # 14
syscall_write = Var(0x02)

# Build A and B combinators (what backdoor returns)
# A = λab.(b b)
A = Lam(Lam(App(Var(0), Var(0))))
# B = λab.(a b)
B = Lam(Lam(App(Var(1), Var(0))))

# omega = λx.(x x)
omega = Lam(App(Var(0), Var(0)))


# Scott pair encoding: pair x y = λf. f x y
def make_pair(x, y):
    # λf. f x y = λf. ((f x) y)
    # Under the lambda, x and y need to be shifted by 1
    return Lam(App(App(Var(0), x), y))


# The backdoor pair (A, B) with proper shifting
# Since pair is λf. f A B, inside the lambda A and B are closed terms
# A = λab.(b b) and B = λab.(a b) are closed so no shifting needed
backdoor_pair = make_pair(A, B)

# fst = λp. p (λxy. x)
fst = Lam(App(Var(0), Lam(Lam(Var(1)))))
# snd = λp. p (λxy. y)
snd = Lam(App(Var(0), Lam(Lam(Var(0)))))


def test_payload(name: str, payload: bytes):
    print(f"\n{'=' * 60}")
    print(f"Testing: {name}")
    print(f"Payload: {payload.hex()}")

    response, got_data = query_raw(payload)

    if not got_data:
        print("Result: NO OUTPUT (connection closed cleanly)")
        print("This could be SUCCESS according to forum hints!")
    elif response == b"Invalid term!":
        print("Result: Invalid term!")
    elif b"Encoding failed!" in response:
        print(f"Result: Encoding failed! ({response})")
    elif FF in response:
        print(f"Result: Got FF-terminated response")
        print(f"Raw: {response.hex()}")
        try:
            term = parse_term(response)
            print(f"Parsed: {term}")
        except:
            pass
    else:
        print(f"Result: Raw bytes: {response}")
        print(f"As text: {response.decode('utf-8', 'replace')}")

    time.sleep(0.3)  # Rate limiting
    return response, got_data


def main():
    print("BrownOS Deep Insight Probe")
    print("=" * 60)

    # Test 1: Apply backdoor pair directly to syscall8
    # (pair syscall8) = syscall8 A B = ((syscall8 A) B)
    # This uses A as the argument and B as the continuation!
    print("\n\n*** TEST 1: (pair syscall8) - uses backdoor pair as function ***")
    # pair = λf. f A B
    # (pair syscall8) = syscall8 A B
    # We need to call (backdoor nil) first, extract pair, then apply to syscall8

    # But we can also directly construct what this would be:
    # ((syscall8 A) B) where A = λab.(b b), B = λab.(a b)
    term1 = App(App(syscall8, A), B)
    payload1 = encode_term(term1) + bytes([FF])
    test_payload(
        "((syscall8 A) B) - syscall8 with A as arg, B as continuation", payload1
    )

    # Test 2: ((syscall8 B) A) - swap the order
    term2 = App(App(syscall8, B), A)
    payload2 = encode_term(term2) + bytes([FF])
    test_payload(
        "((syscall8 B) A) - syscall8 with B as arg, A as continuation", payload2
    )

    # Test 3: Apply omega as continuation to syscall8
    # ((syscall8 nil) omega)
    term3 = App(App(syscall8, nil), omega)
    payload3 = encode_term(term3) + bytes([FF])
    test_payload("((syscall8 nil) omega) - omega as continuation", payload3)

    # Test 4: Use (A B) which equals omega
    # ((syscall8 nil) (A B))
    ab = App(A, B)
    term4 = App(App(syscall8, nil), ab)
    payload4 = encode_term(term4) + bytes([FF])
    test_payload("((syscall8 nil) (A B)) - (A B) = omega as continuation", payload4)

    # Test 5: What if the backdoor pair IS the key?
    # Call backdoor, extract pair, apply pair to syscall8
    # But we can't do this in a single payload without CPS chaining...
    # Let's try: ((backdoor nil) (λp. p syscall8))
    # This unwraps Left, gets pair, applies pair to syscall8
    left_handler = Lam(App(Var(0), syscall8))  # λp. p syscall8
    right_handler = identity  # just return error
    either_handler = Lam(App(App(Var(0), left_handler), right_handler))

    term5 = App(App(syscall_backdoor, nil), either_handler)
    payload5 = encode_term(term5) + bytes([FF])
    test_payload(
        "((backdoor nil) handler) where handler applies pair to syscall8", payload5
    )

    # Test 6: Very minimal payload - just syscall 8 with identity as both arg and continuation
    # This has 3 leaves: Var(8), Var(0), Var(0)
    # Wait, but identity is Lam(Var(0)), so we need:
    # ((syscall8 identity) identity)
    term6 = App(App(syscall8, identity), identity)
    payload6 = encode_term(term6) + bytes([FF])
    test_payload("((syscall8 identity) identity)", payload6)

    # Test 7: Minimal possible - 3 raw vars
    # ((Var(8) Var(0)) Var(0))
    payload7 = bytes([0x08, 0x00, FD, 0x00, FD, FF])
    test_payload("Raw: 08 00 FD 00 FD FF - minimal 3 leaves", payload7)

    # Test 8: What if syscall 8's argument should be syscall 8 itself?
    # ((syscall8 syscall8) QD)
    term8 = App(App(syscall8, syscall8), parse_term(QD + bytes([FF])))
    payload8 = encode_term(term8) + bytes([FF])
    test_payload("((syscall8 syscall8) QD)", payload8)

    # Test 9: Chain echo to manufacture Var(253), then use it
    # echo(251) returns Left(Var(253))
    # We need to unwrap the Left and use Var(253) somehow
    # ((echo Var(251)) (λleft_val. ((syscall8 left_val) QD)))

    # Build: λv. ((syscall8 v) QD) - uses the unwrapped value as syscall8's argument
    qd_term = parse_term(QD + bytes([FF]))
    inner_handler = Lam(App(App(syscall8, Var(0)), qd_term))  # λv. ((syscall8 v) QD)
    left_unwrap = Lam(App(inner_handler, Var(0)))  # λx. (inner_handler x)
    right_ignore = identity
    either_for_echo = Lam(App(App(Var(0), left_unwrap), right_ignore))

    term9 = App(App(syscall_echo, Var(251)), either_for_echo)
    payload9 = encode_term(term9) + bytes([FF])
    test_payload("echo(251) -> use Var(253) as syscall8 arg", payload9)

    # Test 10: Try to use Var(253) as a SYSCALL itself
    # echo(251) gives Left(Var(253))
    # Then we want to call Var(253) as a syscall: ((Var(253) nil) QD)
    inner_handler2 = Lam(
        App(App(Var(0), nil), qd_term)
    )  # λv. ((v nil) QD) - uses v as syscall
    left_unwrap2 = Lam(App(inner_handler2, Var(0)))
    either_for_syscall = Lam(App(App(Var(0), left_unwrap2), right_ignore))

    term10 = App(App(syscall_echo, Var(251)), either_for_syscall)
    payload10 = encode_term(term10) + bytes([FF])
    test_payload("echo(251) -> use Var(253) AS syscall", payload10)

    # Test 11: What about applying omega to syscall8?
    # (omega syscall8) = (λx.(x x)) syscall8 = (syscall8 syscall8)
    term11 = App(omega, syscall8)
    payload11 = encode_term(term11) + bytes([FF])
    test_payload("(omega syscall8) = (syscall8 syscall8)", payload11)

    # Test 12: Check raw payloads that might have special meaning
    # What if the answer is literally in how we format the request?
    # Try: syscall 8 with the raw QD bytes as the argument
    # This is weird but let's try
    payload12 = bytes([0x08]) + QD + bytes([FD, 0x00, FD, FF])
    test_payload("Raw: 08 QD FD 00 FD FF", payload12)

    print("\n\n" + "=" * 60)
    print("ANALYSIS:")
    print("- If any test returned NO OUTPUT, that might be SUCCESS")
    print("- The 'freeze' hint suggests omega-related behavior")
    print("- The answer might not be from syscall8 at all")
    print("=" * 60)


if __name__ == "__main__":
    main()
