#!/usr/bin/env python3
"""
BrownOS Hidden Syscalls Probe

Key insight: Echo can manufacture Var(253), Var(254), Var(255) at RUNTIME.
These correspond to the reserved wire protocol bytes FD, FE, FF.

What if these are HIDDEN SYSCALLS that we can only access via echo?

The author said "combining special bytes froze my system" and
"why would an OS even need an echo?" - echo exists for a purpose!

Theory: Var(253), Var(254), or Var(255) might be special syscalls
that can bypass syscall 8's permission check or do something else.
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


def query_raw(payload: bytes, timeout_s: float = 10.0) -> bytes:
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


def decode_string(term) -> str:
    chars = []
    cur = term
    while True:
        inner = strip_lams(cur, 2)
        if inner is None:
            break
        if isinstance(inner, Var) and inner.i == 0:
            break
        if isinstance(inner, App) and isinstance(inner.f, App):
            head_app = inner.f
            if isinstance(head_app.f, Var) and head_app.f.i == 1:
                char_term = head_app.x
                ch = decode_int_term(char_term)
                if ch >= 0:
                    chars.append(chr(ch) if 0x20 <= ch < 0x7F else f"\\x{ch:02x}")
                cur = inner.x
                continue
        break
    return "".join(chars)


nil = Lam(Lam(Var(0)))
identity = Lam(Var(0))
qd_term = parse_term(QD + bytes([FF]))


def main():
    print("BrownOS Hidden Syscalls Probe")
    print("=" * 70)
    print()
    print("Testing if Var(253), Var(254), Var(255) are hidden syscalls")
    print("accessible only via echo manufacturing...")
    print()

    # echo(N) returns Left(Var(N+2))
    # So:
    # echo(251) -> Left(Var(253))  [253 = 0xFD = App marker]
    # echo(252) -> Left(Var(254))  [254 = 0xFE = Lam marker]
    # echo(253) -> Left(Var(255))  [255 = 0xFF = End marker]

    # To use Var(253) as a syscall, we need to:
    # 1. Call echo(251) to get Left(Var(253))
    # 2. Extract Var(253) from the Either
    # 3. Call ((Var(253) arg) continuation)

    # CPS chain: ((echo 251) handler)
    # handler = λeither. ((either left_h) right_h)
    # left_h = λv. ((v arg) continuation)  -- use v as syscall!

    for echo_arg, expected_var in [(251, 253), (252, 254), (253, 255)]:
        print(f"\n[Testing Var({expected_var}) as syscall via echo({echo_arg})]")

        # Build: ((echo echo_arg) handler)
        # handler extracts the var and calls it as a syscall with nil and identity

        # Under λeither.λv (depth 2):
        # - The manufactured var is Var(0)
        # - We want to call: ((Var(0) nil) identity_or_QD)
        # - nil at depth 2... nil is closed so stays same
        # - identity is λx.x = Lam(Var(0)), closed

        # Test 1: ((manufactured_var nil) identity) - use as syscall with nil arg
        inner_call = App(App(Var(0), nil), identity)  # ((v nil) id)
        left_h = Lam(inner_call)  # λv. ((v nil) id)
        right_h = Lam(identity)  # λerr. id (ignore errors)
        either_body = App(App(Var(0), left_h), right_h)
        handler = Lam(either_body)

        term = App(App(Var(0x0E), Var(echo_arg)), handler)
        payload = encode_term(term) + bytes([FF])

        print(f"  ((Var({expected_var}) nil) id):")
        print(f"    Payload: {payload.hex()}")
        response = query_raw(payload, timeout_s=5)
        print(f"    Response: {repr(response[:50]) if response else 'NO OUTPUT'}")
        time.sleep(0.3)

        # Test 2: Use manufactured var as syscall with QD-like continuation
        # We need to write something to see output
        # Let's use write syscall to output a marker

        # Under λeither.λv (depth 2):
        # - write is Var(4) at top, becomes Var(6) at depth 2
        # - Build: λv. ((write "X") id)  to see if we get output

        # Actually let's try: ((v nil) (λr. ((write "V") id)))
        # This calls v as syscall, then writes "V" to show it worked

        # Build "V" as a byte list
        V_byte = Lam(
            Lam(
                Lam(
                    Lam(
                        Lam(
                            Lam(
                                Lam(
                                    Lam(
                                        Lam(
                                            App(
                                                Var(7),
                                                App(
                                                    Var(6),
                                                    App(
                                                        Var(5),
                                                        App(
                                                            Var(2), App(Var(1), Var(0))
                                                        ),
                                                    ),
                                                ),
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )  # 86 = 64+16+4+2 = V7+V5+V3+V2
        V_list = Lam(Lam(App(App(Var(1), V_byte), nil)))  # cons V nil

        # Under λeither.λv.λr (depth 3):
        # write = Var(5)
        write_V = App(App(Var(5), V_list), identity)  # ((write V_list) id)
        result_handler = Lam(write_V)  # λr. ((write V) id)

        inner_call2 = App(App(Var(0), nil), result_handler)  # ((v nil) result_handler)
        left_h2 = Lam(inner_call2)
        either_body2 = App(App(Var(0), left_h2), right_h)
        handler2 = Lam(either_body2)

        term2 = App(App(Var(0x0E), Var(echo_arg)), handler2)
        payload2 = encode_term(term2) + bytes([FF])

        print(f"  ((Var({expected_var}) nil) write_handler):")
        print(f"    Payload: {payload2.hex()}")
        response2 = query_raw(payload2, timeout_s=5)
        print(f"    Response: {repr(response2[:50]) if response2 else 'NO OUTPUT'}")
        time.sleep(0.3)

        # Test 3: What if the manufactured var IS the answer somehow?
        # Apply it to syscall 8: ((syscall8 manufactured_var) QD)

        # Under λeither.λv (depth 2):
        # syscall8 = Var(10)
        # We need QD adjusted for depth 2... complex
        # Let's just use identity and check for non-error

        inner_call3 = App(App(Var(10), Var(0)), identity)  # ((syscall8 v) id)
        left_h3 = Lam(inner_call3)
        either_body3 = App(App(Var(0), left_h3), right_h)
        handler3 = Lam(either_body3)

        term3 = App(App(Var(0x0E), Var(echo_arg)), handler3)
        payload3 = encode_term(term3) + bytes([FF])

        print(f"  ((syscall8 Var({expected_var})) id):")
        print(f"    Payload: {payload3.hex()}")
        response3 = query_raw(payload3, timeout_s=5)
        print(f"    Response: {repr(response3[:50]) if response3 else 'NO OUTPUT'}")
        time.sleep(0.3)

    print("\n" + "=" * 70)
    print("Testing combinations of special vars...")

    # What if we need to combine Var(253) and Var(254)?
    # echo(251) gives Var(253), echo(252) gives Var(254)
    # We could chain: get both, then combine them somehow

    # This requires nested CPS which gets complex...
    # Let's try a simpler approach: what if we apply one to the other?

    print("\n[Testing (Var(253) Var(254)) combination]")

    # Chain: echo(251) -> λv253. (echo(252) -> λv254. ((v253 v254) k))
    # This is getting complex, let me build it step by step

    # Actually, let's try something simpler first:
    # What if the answer is in how echo itself behaves with special inputs?

    print("\n[Testing echo with boundary values]")

    for echo_input in [250, 251, 252, 253, 254]:
        term = App(App(Var(0x0E), Var(echo_input)), qd_term)
        try:
            payload = encode_term(term) + bytes([FF])
            response = query_raw(payload, timeout_s=3)
            if response and FF in response:
                # Try to decode
                resp_term = parse_term(response)
                tag, _ = decode_either(resp_term)
                print(f"  echo({echo_input}): {tag}")
            elif response:
                print(f"  echo({echo_input}): {repr(response[:30])}")
            else:
                print(f"  echo({echo_input}): NO OUTPUT")
        except Exception as e:
            print(f"  echo({echo_input}): Error - {e}")
        time.sleep(0.2)


if __name__ == "__main__":
    main()
