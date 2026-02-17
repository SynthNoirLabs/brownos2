#!/usr/bin/env python3
"""
Debug the chained syscall issue.
Why does syscall8 -> readfile(256) return NO OUTPUT when direct readfile(256) works?
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


def query_raw(payload: bytes, timeout_s: float = 5.0) -> bytes:
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


def encode_byte_term(n: int) -> object:
    expr = Var(0)
    base = n & 255
    extra_128s = (n - base) // 128

    for idx, weight in (
        (1, 1),
        (2, 2),
        (3, 4),
        (4, 8),
        (5, 16),
        (6, 32),
        (7, 64),
        (8, 128),
    ):
        if base & weight:
            expr = App(Var(idx), expr)
    for _ in range(extra_128s):
        expr = App(Var(8), expr)

    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


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
qd_term = parse_term(QD + bytes([FF]))


def main():
    print("Chain Debug")
    print("=" * 60)

    # Direct readfile(256) works
    print("\n[1] Direct readfile(256) + QD:")
    file256 = encode_byte_term(256)
    term = App(App(Var(0x07), file256), qd_term)
    payload = encode_term(term) + bytes([FF])
    print(f"Payload: {payload.hex()}")
    response = query_raw(payload)
    print(f"Response: {response.hex() if response else 'NO OUTPUT'}")
    if response and FF in response:
        resp_term = parse_term(response)
        tag, payload_term = decode_either(resp_term)
        print(f"Tag: {tag}")
        if tag == "Left":
            content = decode_string(payload_term)
            print(f"Content: {repr(content)}")
    time.sleep(0.3)

    # Chained version - the issue is likely de Bruijn index shifting
    print("\n[2] Chained: syscall8 -> readfile(256)")
    print("Building: ((syscall8 nil) (λr. ((readfile 256) QD)))")
    print("")
    print("Under the lambda, we need to shift syscall references!")
    print("  - readfile is Var(7), but under λr it becomes Var(8)")
    print("")

    # Build correctly with shifted indices
    # Inside (λr. body), global Var(n) becomes Var(n+1)
    file256_shifted = encode_byte_term(
        256
    )  # This is already a closed term (has 9 lambdas)

    # QD is also a term that references globals. Under one lambda, it needs shifting.
    # Actually, QD is tricky - it's designed to work at top level.
    # Let's just embed QD as-is and see if it breaks

    # First, let's just verify the structure
    # We want: ((syscall8 nil) continuation)
    # where continuation = λr. ((readfile file256) QD)

    # Under the lambda for continuation:
    # - Var(7) (readfile) becomes Var(8)
    # - file256 is closed (9 lambdas), doesn't change
    # - QD references Var(2,3,5) which become Var(3,4,6) - BROKEN!

    print("Problem: QD references globals that shift under the continuation lambda!")
    print("")
    print("Let's try a different approach: inline write instead of QD")
    print("")

    # Build: ((syscall8 nil) (λr. ((write (quote file256_content)) identity)))
    # This is getting complex. Let's try simpler tests first.

    print("\n[3] Simple chain test: readfile(11) -> write result")

    # ((readfile 11) (λresult. ((write result) identity)))
    # Under λresult: write is Var(3), identity needs to be built

    file11 = encode_byte_term(11)
    # write = syscall 2, under λ it's Var(3)
    # continuation receives Either result
    # If Left(content), we want to write content
    # Let's build: λeither. ((either (λcontent. ((write content) id))) (λerr. id))
    # This applies the either to handlers

    # Simpler: just ignore the result and write a constant
    # λr. ((write "X") id)

    X_byte = encode_byte_term(ord("X"))
    X_list = Lam(Lam(App(App(Var(1), X_byte), nil)))  # cons X nil, but closed

    # Under λr, write = Var(3)
    write_inner = App(App(Var(3), X_list), Lam(Var(0)))  # ((write X_list) id)
    continuation = Lam(write_inner)

    term = App(App(Var(0x07), file11), continuation)
    payload = encode_term(term) + bytes([FF])
    print(f"Payload: {payload.hex()}")
    response = query_raw(payload)
    print(f"Response: {repr(response) if response else 'NO OUTPUT'}")
    time.sleep(0.3)

    # Hmm, that should work. Let me check if the issue is something else.

    print("\n[4] Testing if syscall8 ACTUALLY calls continuation...")

    # Use the simple write-X continuation that worked before
    # But double-check the construction

    # We want: ((syscall8 nil) (λr. ((write X_list) id)))
    # Under λr: syscall refs shift by 1, so write(2) -> Var(3)

    # X_list needs to NOT shift because it's closed
    X_closed = Lam(Lam(App(App(Var(1), X_byte), Lam(Lam(Var(0))))))  # cons X nil

    # Under λr, our body is: ((Var(3) X_closed) Var(0))
    # Wait, Var(0) is r itself, not identity!
    # We need identity shifted: λx.x stays as Lam(Var(0))

    inner = App(App(Var(3), X_closed), Lam(Var(0)))  # ((write X_list) identity)
    cont = Lam(inner)

    print("Testing: ((syscall8 nil) (λr. ((write ['X']) identity)))")
    term = App(App(Var(0x08), nil), cont)
    payload = encode_term(term) + bytes([FF])
    print(f"Payload: {payload.hex()}")
    response = query_raw(payload)
    print(f"Response: {repr(response) if response else 'NO OUTPUT'}")
    time.sleep(0.3)

    # If this returns 'X', then syscall8's continuation IS being called
    # And we know the result is Right(6)

    print("\n[5] Testing actual Either handling...")

    # Now let's handle the Either properly
    # syscall8 returns Either, which is λl.λr. r error_code (Right)
    # To handle it: (either left_handler right_handler)
    # = (λl.λr. r error_code) left_handler right_handler
    # = right_handler error_code

    # So continuation should be: λeither. ((either left_h) right_h)
    # where left_h = λcontent. write("SUCCESS")
    # and right_h = λerr. write("FAIL")

    # Build "SUCCESS" list
    SUCCESS = b"SUCCESS"
    success_list = nil
    for b in reversed(SUCCESS):
        bt = encode_byte_term(b)
        success_list = Lam(Lam(App(App(Var(1), bt), success_list)))

    FAIL = b"FAIL"
    fail_list = nil
    for b in reversed(FAIL):
        bt = encode_byte_term(b)
        fail_list = Lam(Lam(App(App(Var(1), bt), fail_list)))

    # Under λeither:
    # - write is Var(3)
    # - identity stays Lam(Var(0))

    # Under λeither.λcontent (for left_h):
    # - write is Var(4)

    # Under λeither.λerr (for right_h):
    # - write is Var(4)

    # Let me think more carefully...
    # either = λl.λr. selector payload
    # (either left_h right_h) applies:
    # - left_h to payload if Left
    # - right_h to payload if Right

    # So we need:
    # continuation = λeither. ((either (λc. ((write success) id))) (λe. ((write fail) id)))

    # De Bruijn depths:
    # At top: write = Var(2)
    # Under λeither: write = Var(3)
    # Under λeither, λc: write = Var(4)
    # Under λeither, λe: write = Var(4)

    left_handler = Lam(
        App(App(Var(4), success_list), Lam(Var(0)))
    )  # λc. ((write success) id)
    right_handler = Lam(
        App(App(Var(4), fail_list), Lam(Var(0)))
    )  # λe. ((write fail) id)

    # continuation = λeither. ((either left_h) right_h)
    # Under λeither: either = Var(0), left_h and right_h need indices adjusted
    # Wait, left_h and right_h are defined at this level, they're not Vars

    cont_body = App(
        App(Var(0), left_handler), right_handler
    )  # ((either left_h) right_h)
    continuation = Lam(cont_body)

    print("Testing: ((syscall8 nil) either_handler)")
    print("  Left -> writes 'SUCCESS'")
    print("  Right -> writes 'FAIL'")

    term = App(App(Var(0x08), nil), continuation)
    payload = encode_term(term) + bytes([FF])
    print(f"Payload: {payload.hex()}")
    response = query_raw(payload)
    print(f"Response: {repr(response) if response else 'NO OUTPUT'}")

    if response == b"SUCCESS":
        print("\n*** SYSCALL 8 RETURNED LEFT (SUCCESS)! ***")
    elif response == b"FAIL":
        print("\n*** SYSCALL 8 RETURNED RIGHT (FAIL) AS EXPECTED ***")


if __name__ == "__main__":
    main()
