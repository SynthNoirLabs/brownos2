#!/usr/bin/env python3
"""
Properly decode syscall 8 response using reference client's decoder.
"""

import hashlib
from dataclasses import dataclass

FD = 0xFD
FE = 0xFE
FF = 0xFF

WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


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
    """Parse bytecode to term."""
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
        raise ValueError(f"Stack size {len(stack)} != 1")
    return stack[0]


def strip_lams(term, n):
    """Remove n outer lambdas."""
    cur = term
    for _ in range(n):
        if not isinstance(cur, Lam):
            raise ValueError("Not enough lambdas")
        cur = cur.body
    return cur


def eval_bitset_expr(expr):
    """Evaluate bit-encoded expression to integer."""
    if isinstance(expr, Var):
        return WEIGHTS[expr.i]
    if isinstance(expr, App):
        if not isinstance(expr.f, Var):
            raise ValueError("Expected Var in function position")
        return WEIGHTS[expr.f.i] + eval_bitset_expr(expr.x)
    raise ValueError(f"Unexpected: {type(expr)}")


def decode_byte_term(term):
    """Decode byte-encoded term (9 lambdas)."""
    body = strip_lams(term, 9)
    return eval_bitset_expr(body)


def uncons_scott_list(term):
    """
    Decode Scott list node.

    nil  = λc.λn. n      -> λλVar(0)
    cons = λc.λn. c h t  -> λλApp(App(Var(1), h), t)

    Returns (head, tail) or None for nil.
    """
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not a Scott list node")

    body = term.body.body

    # Check for nil
    if isinstance(body, Var) and body.i == 0:
        return None

    # Check for cons
    if (
        isinstance(body, App)
        and isinstance(body.f, App)
        and isinstance(body.f.f, Var)
        and body.f.f.i == 1
    ):
        return body.f.x, body.x

    raise ValueError(f"Unexpected Scott list shape: {body}")


def decode_bytes_list(term):
    """Decode Scott list of byte-terms to bytes."""
    out = []
    cur = term
    for _ in range(1_000_000):
        res = uncons_scott_list(cur)
        if res is None:
            return bytes(out)
        head, cur = res
        out.append(decode_byte_term(head))
    raise RuntimeError("List too long")


# Full syscall 8 response
full_response = "00030200fdfdfefefefefefefefefefdfefeff"

print("=" * 80)
print("DECODING SYSCALL 8 RESPONSE WITH REFERENCE DECODER")
print("=" * 80)

print(f"\nFull response: {full_response}")
print(f"First byte: {full_response[:2]} (should be 00 = Left)")

# Parse the response
response_bytes = bytes.fromhex(full_response)
response_term = parse_term(response_bytes)

print(f"\nParsed term type: {type(response_term)}")

# Decode as Either
if isinstance(response_term, Lam) and isinstance(response_term.body, Lam):
    body = response_term.body.body
    print(f"Either body: {body}")

    if isinstance(body, App) and isinstance(body.f, Var):
        if body.f.i == 1:
            print("\n✓ This is Left(payload)")
            payload = body.x
            print(f"Payload: {payload}")

            # Try to decode payload as byte list
            try:
                decoded_bytes = decode_bytes_list(payload)
                print(f"\n{'=' * 80}")
                print(f"DECODED BYTES: {decoded_bytes}")
                print(f"{'=' * 80}")
                print(f"Length: {len(decoded_bytes)}")
                print(f"Hex: {decoded_bytes.hex()}")
                print(f"As integers: {list(decoded_bytes)}")

                # Try as ASCII
                try:
                    ascii_str = decoded_bytes.decode("ascii")
                    print(f"\n✓ As ASCII string: '{ascii_str}'")
                except UnicodeDecodeError:
                    print("\nNot valid ASCII")
                    # Try UTF-8
                    try:
                        utf8_str = decoded_bytes.decode("utf-8")
                        print(f"✓ As UTF-8: '{utf8_str}'")
                    except:
                        print("Not valid UTF-8 either")

                # HASH TEST
                print(f"\n{'=' * 80}")
                print("HASH TESTING")
                print(f"{'=' * 80}")

                TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
                ROUNDS = 56154

                def check(candidate):
                    cur = candidate
                    for _ in range(ROUNDS):
                        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
                    return cur.decode("ascii") == TARGET

                # Test the decoded bytes as-is
                if check(decoded_bytes):
                    print(f"✅✅✅ SOLUTION FOUND! ✅✅✅")
                    print(f"Answer: {decoded_bytes}")
                    print(
                        f"As string: {decoded_bytes.decode('utf-8', errors='replace')}"
                    )
                else:
                    print("❌ Decoded bytes don't match hash")

                    # Try as string
                    try:
                        str_candidate = decoded_bytes.decode("utf-8")
                        if check(str_candidate.encode("utf-8")):
                            print(f"✅✅✅ STRING MATCH! ✅✅✅")
                            print(f"Answer: '{str_candidate}'")
                    except:
                        pass

            except Exception as e:
                print(f"\n❌ Failed to decode as byte list: {e}")
                import traceback

                traceback.print_exc()

        elif body.f.i == 0:
            print("\nThis is Right(error)")
            error_code = body.x
            print(f"Error: {error_code}")
