#!/usr/bin/env python3
"""
BrownOS Backdoor Unlock Probe

Key insight: "the mail points to the way to get access there"
- Backdoor returns Left(pair(A, B))
- We need to USE this pair somehow with syscall 8

Theories to test:
1. Pass the backdoor's pair AS THE ARGUMENT to syscall 8
2. Use the pair in some specific way (apply it, extract from it)
3. Chain backdoor -> syscall8 in CPS
4. The pair might be a "token" or "capability"
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
            if len(stack) < 2:
                return None
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            if not stack:
                return None
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    return stack[0] if stack else None


def query_raw(payload: bytes, timeout_s: float = 8.0) -> bytes:
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
            return out
    except Exception as e:
        print(f"Error: {e}")
        return b""


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def strip_lams(term, n):
    cur = term
    for _ in range(n):
        if not isinstance(cur, Lam):
            return None
        cur = cur.body
    return cur


def eval_bitset_expr(expr) -> int:
    if isinstance(expr, Var):
        return WEIGHTS.get(expr.i, 0)
    if isinstance(expr, App) and isinstance(expr.f, Var):
        return WEIGHTS.get(expr.f.i, 0) + eval_bitset_expr(expr.x)
    return 0


def decode_int_term(term) -> int:
    body = strip_lams(term, 9)
    if body:
        return eval_bitset_expr(body)
    return -1


def decode_either(term):
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        return None, None
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var):
        if body.f.i == 1:
            return "Left", body.x
        elif body.f.i == 0:
            return "Right", body.x
    return None, None


nil = Lam(Lam(Var(0)))
qd_term = parse_term(QD + bytes([FF]))

# Known combinators from backdoor
A = Lam(Lam(App(Var(0), Var(0))))  # λab.(b b)
B = Lam(Lam(App(Var(1), Var(0))))  # λab.(a b)


# Scott pair: pair x y = λf. f x y
def make_pair(x, y):
    return Lam(App(App(Var(0), x), y))


# The actual backdoor pair
backdoor_pair = make_pair(A, B)


def test_with_qd(name: str, term: object) -> str:
    """Test a term with QD continuation and decode result."""
    full_term = App(term, qd_term)
    payload = encode_term(full_term) + bytes([FF])
    response = query_raw(payload)

    if not response:
        return "NO OUTPUT"
    if b"Invalid term!" in response:
        return "Invalid term!"
    if b"Encoding failed!" in response:
        return "Encoding failed!"
    if FF not in response:
        return f"RAW: {response[:50]}"

    resp_term = parse_term(response)
    if not resp_term:
        return f"Parse failed: {response.hex()}"

    tag, payload_term = decode_either(resp_term)
    if tag == "Right":
        err = decode_int_term(payload_term)
        errors = {
            0: "Exception",
            1: "NotImpl",
            2: "InvalidArg",
            3: "NoSuchFile",
            4: "NotDir",
            5: "NotFile",
            6: "PermDenied",
            7: "RateLimit",
        }
        return f"Right({err}) = {errors.get(err, 'Unknown')}"
    elif tag == "Left":
        return f"Left(...) = SUCCESS!"
    return f"Unknown: {resp_term}"


def main():
    print("BrownOS Backdoor Unlock Probe")
    print("=" * 70)

    # THEORY 1: Chain backdoor -> syscall8 properly
    # ((backdoor nil) (λeither. ((either left_h) right_h)))
    # where left_h = λpair. ((syscall8 pair) QD)

    print("\n[1] CPS Chain: backdoor -> pass pair to syscall8")
    print("    ((backdoor nil) either_handler)")
    print("    where Left handler passes pair to syscall8")

    # Build the chain with proper de Bruijn indices
    # At top level: backdoor = Var(0xC9), syscall8 = Var(0x08)
    # Under λeither: backdoor = Var(0xCA), syscall8 = Var(0x09)
    # Under λeither.λpair: syscall8 = Var(0x0A)

    # Left handler: λpair. ((syscall8 pair) QD)
    # Under λeither.λpair, syscall8 is Var(10), pair is Var(0)
    # QD references globals, so it needs adjustment too... this is getting complex

    # Let's try a simpler approach: just pass the pair directly
    # Build QD inline... actually QD is complex. Let's use a simpler continuation.

    # Simpler: λpair. ((syscall8 pair) identity)
    # Then check if we get output

    # Under λeither.λpair: syscall8 = Var(10), pair = Var(0)
    left_handler_inner = App(App(Var(10), Var(0)), Lam(Var(0)))  # ((syscall8 pair) id)
    left_handler = Lam(left_handler_inner)  # λpair. ...

    # Right handler: λerr. identity (just return something)
    right_handler = Lam(Lam(Var(0)))  # λerr. id

    # Either handler: λeither. ((either left_h) right_h)
    either_body = App(App(Var(0), left_handler), right_handler)
    either_handler = Lam(either_body)

    # Full term: ((backdoor nil) either_handler)
    term = App(App(Var(0xC9), nil), either_handler)
    payload = encode_term(term) + bytes([FF])
    print(f"    Payload: {payload.hex()}")
    response = query_raw(payload)
    print(
        f"    Response: {'NO OUTPUT' if not response else response.hex() if FF in response else repr(response)}"
    )
    time.sleep(0.3)

    # THEORY 2: What if we need to pass the pair AND a proper continuation?
    # Let's use write to see what happens

    print("\n[2] Chain with write continuation to see result")

    # Left handler that writes "L" then calls syscall8 with pair
    # Then writes the syscall8 result

    # This is getting complex. Let me try something simpler:
    # Just call syscall8 with the reconstructed pair directly

    print("\n[3] Direct: syscall8(pair(A,B)) with QD")
    term = App(Var(0x08), backdoor_pair)
    result = test_with_qd("syscall8(pair(A,B))", term)
    print(f"    Result: {result}")
    time.sleep(0.3)

    # THEORY 3: What if syscall8 needs BOTH the pair AND something else?
    # Like syscall8(pair, something)

    print("\n[4] syscall8 with pair as first arg, nil as continuation")
    term = App(App(Var(0x08), backdoor_pair), nil)
    payload = encode_term(term) + bytes([FF])
    response = query_raw(payload)
    print(f"    Response: {'NO OUTPUT' if not response else response.hex()}")
    time.sleep(0.3)

    # THEORY 4: What if the pair needs to be applied to syscall8?
    # pair(syscall8) = (λf. f A B) syscall8 = syscall8 A B = ((syscall8 A) B)

    print("\n[5] Apply pair to syscall8: (pair syscall8) = ((syscall8 A) B)")
    term = App(backdoor_pair, Var(0x08))
    payload = encode_term(term) + bytes([FF])
    response = query_raw(payload)
    print(f"    Without QD: {'NO OUTPUT' if not response else response.hex()}")
    time.sleep(0.3)

    # Now with QD
    # (pair syscall8) reduces to ((syscall8 A) B)
    # But we need QD as continuation: (((pair syscall8)...) QD)... this doesn't work
    # Actually (pair syscall8) = syscall8 A B, which needs a continuation
    # So: ((pair syscall8) QD) = (((syscall8 A) B) QD) = ((syscall8 A) (B QD))? No...

    # Let me think about this differently
    # pair = λf. f A B
    # (pair syscall8) = syscall8 A B = (syscall8 A) B
    # In CPS: ((syscall8 A) continuation), and B would be passed as continuation
    # So (pair syscall8) = (syscall8 A) with B as continuation!

    print("    Note: (pair syscall8) = ((syscall8 A) B)")
    print("    This makes B the continuation for syscall8(A)")

    # THEORY 5: What if we need fst or snd of the pair?
    print("\n[6] Extract and use components of pair")

    # fst = λp. p (λxy.x)
    fst = Lam(App(Var(0), Lam(Lam(Var(1)))))
    # snd = λp. p (λxy.y)
    snd = Lam(App(Var(0), Lam(Lam(Var(0)))))

    # (fst pair) = A
    fst_pair = App(fst, backdoor_pair)
    term = App(Var(0x08), fst_pair)
    result = test_with_qd("syscall8(fst pair) = syscall8(A)", term)
    print(f"    syscall8(fst pair): {result}")
    time.sleep(0.3)

    # (snd pair) = B
    snd_pair = App(snd, backdoor_pair)
    term = App(Var(0x08), snd_pair)
    result = test_with_qd("syscall8(snd pair) = syscall8(B)", term)
    print(f"    syscall8(snd pair): {result}")
    time.sleep(0.3)

    # THEORY 6: What if we use A and B as argument AND continuation?
    print("\n[7] Combinations of A and B")

    combos = [
        ("((syscall8 A) A)", App(App(Var(0x08), A), A)),
        ("((syscall8 B) B)", App(App(Var(0x08), B), B)),
        ("((syscall8 (A A)) B)", App(App(Var(0x08), App(A, A)), B)),
        ("((syscall8 (B B)) A)", App(App(Var(0x08), App(B, B)), A)),
        (
            "((syscall8 (A B)) nil)",
            App(App(Var(0x08), App(A, B)), nil),
        ),  # (A B) = omega
    ]

    for name, term in combos:
        result = test_with_qd(name, term)
        print(f"    {name}: {result}")
        time.sleep(0.2)

    # THEORY 7: The real CPS chain - use backdoor result properly
    print("\n[8] Real CPS chain: backdoor -> extract pair -> syscall8")
    print("    This chains in a single program")

    # We need:
    # ((backdoor nil) (λresult. handle_either(result,
    #                           λpair. ((syscall8 (fst pair)) QD),
    #                           λerr. QD err)))

    # Let me build this step by step with correct indices
    # At depth 0: backdoor=0xC9, syscall8=0x08
    # At depth 1 (under λresult): +1 to all globals
    # At depth 2 (under λresult.λpair): +2 to all globals

    # First, let's just try to pass fst of the backdoor result to syscall8
    # The backdoor returns Either, so:
    # Left(pair) means we get pair when we apply the left handler

    # either_handler = λeither. ((either left_h) right_h)
    # left_h = λpair. (((fst pair) syscall8_continuation))
    # But we want: λpair. ((syscall8 (fst pair)) QD)

    # Under λeither.λpair (depth 2):
    # syscall8 = Var(0x0A), fst needs to be inlined, pair = Var(0)

    # fst = λp. p (λxy.x)
    # (fst Var(0)) = Var(0) (λxy.x) = apply pair to selector

    # Let me inline: fst pair = pair (λxy.x) = (Var(0) (λxy.x))
    fst_selector = Lam(Lam(Var(1)))  # λxy.x
    fst_of_pair = App(Var(0), fst_selector)  # At depth 2, Var(0) is the pair

    # syscall8 at depth 2 is Var(10)
    # We want ((syscall8 (fst pair)) QD_adjusted)
    # But QD references globals 2,3,5 which at depth 2 become 4,5,7

    # Actually, let's use a simpler continuation that just returns the result
    # ((syscall8 (fst pair)) (λr.r))

    inner_syscall = App(App(Var(10), fst_of_pair), Lam(Var(0)))
    left_h = Lam(inner_syscall)  # λpair. ((syscall8 (fst pair)) id)

    # right_h = λerr. id (just ignore errors from backdoor)
    right_h = Lam(Lam(Var(0)))

    # either_handler = λeither. ((either left_h) right_h)
    either_body = App(App(Var(0), left_h), right_h)
    either_handler = Lam(either_body)

    # Full: ((backdoor nil) either_handler)
    full_term = App(App(Var(0xC9), nil), either_handler)
    payload = encode_term(full_term) + bytes([FF])
    print(f"    Payload: {payload.hex()}")
    response = query_raw(payload)
    print(
        f"    Response: {'NO OUTPUT' if not response else response.hex() if len(response) < 100 else f'{len(response)} bytes'}"
    )
    time.sleep(0.3)

    # THEORY 8: What if the answer is about SELF-APPLICATION?
    print("\n[9] Self-application patterns")

    # (syscall8 syscall8)
    term = App(Var(0x08), Var(0x08))
    result = test_with_qd("syscall8(syscall8)", term)
    print(f"    syscall8(syscall8): {result}")
    time.sleep(0.2)

    # ((syscall8 syscall8) syscall8)
    term = App(App(Var(0x08), Var(0x08)), Var(0x08))
    result = test_with_qd("((syscall8 syscall8) syscall8)", term)
    print(f"    ((syscall8 syscall8) syscall8): {result}")
    time.sleep(0.2)

    # THEORY 9: What if omega applied to something special gives us the answer?
    print("\n[10] Omega combinations")

    omega = Lam(App(Var(0), Var(0)))  # λx.(x x)

    # (omega syscall8) = syscall8 syscall8
    # ((omega syscall8) QD) should work
    term = App(omega, Var(0x08))
    result = test_with_qd("(omega syscall8)", term)
    print(f"    (omega syscall8): {result}")
    time.sleep(0.2)

    # What about (omega backdoor)?
    term = App(omega, Var(0xC9))
    result = test_with_qd("(omega backdoor)", term)
    print(f"    (omega backdoor): {result}")
    time.sleep(0.2)

    print("\n" + "=" * 70)
    print("ANALYSIS")
    print("=" * 70)


if __name__ == "__main__":
    main()
