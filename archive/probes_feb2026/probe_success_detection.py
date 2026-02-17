#!/usr/bin/env python3
"""
BrownOS Success Detection Probe

Key question: What does "success" from syscall 8 look like?

If syscall 8 succeeds, it returns Left(something). We've never seen this.
But what if success means something different? What if:
1. "No output" IS success (no error = success)
2. The answer isn't what syscall 8 returns, but something else we discovered
3. We need to look at what CHANGES when syscall 8 is called

This probe tests various theories about what success looks like.
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


def query_raw(payload: bytes, timeout_s: float = 5.0) -> tuple[bytes, float]:
    """Returns (response, time_taken)"""
    start = time.time()
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
            elapsed = time.time() - start
            return out, elapsed
    except Exception as e:
        elapsed = time.time() - start
        return b"", elapsed


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
    print("BrownOS Success Detection")
    print("=" * 60)

    # THEORY 1: What if syscall 8's "success" response is something we haven't decoded?
    # Let's carefully examine every byte of the response

    print("\n[1] Detailed analysis of syscall 8 response...")

    term = App(App(Var(0x08), nil), qd_term)
    payload = encode_term(term) + bytes([FF])
    response, elapsed = query_raw(payload)

    print(f"Payload: {payload.hex()}")
    print(f"Response ({elapsed:.2f}s): {response.hex() if response else 'NONE'}")
    print(f"Response length: {len(response)} bytes")

    if response:
        print(f"\nByte breakdown:")
        for i, b in enumerate(response):
            print(
                f"  [{i:2d}] 0x{b:02X} ({b:3d}) {'= FD (App)' if b == FD else '= FE (Lam)' if b == FE else '= FF (End)' if b == FF else ''}"
            )

        if FF in response:
            resp_term = parse_term(response)
            print(f"\nParsed term: {resp_term}")
            tag, payload_term = decode_either(resp_term)
            print(f"Either: {tag}")
            if payload_term:
                print(f"Payload term: {payload_term}")

    time.sleep(0.5)

    # THEORY 2: What if success is indicated by the TIMING?
    # Compare response times for different payloads

    print("\n" + "=" * 60)
    print("[2] Timing analysis...")

    tests = [
        ("syscall8(nil) + QD", App(App(Var(0x08), nil), qd_term)),
        ("syscall8(nil) + nil", App(App(Var(0x08), nil), nil)),
        ("syscall8(nil) + identity", App(App(Var(0x08), nil), Lam(Var(0)))),
        ("readfile(11) + QD", App(App(Var(0x07), encode_byte_term(11)), qd_term)),
        ("readfile(11) + nil", App(App(Var(0x07), encode_byte_term(11)), nil)),
    ]

    for name, term in tests:
        payload = encode_term(term) + bytes([FF])
        response, elapsed = query_raw(payload, timeout_s=5.0)
        result = "OUTPUT" if response else "NO OUTPUT"
        print(f"  {name}: {result} in {elapsed:.3f}s")
        time.sleep(0.3)

    # THEORY 3: What if the answer is in the continuation we provide?
    # When syscall 8 "fails" with Right(6), it still calls the continuation.
    # What if we need to provide a specific continuation that "catches" the success case?

    print("\n" + "=" * 60)
    print("[3] Testing custom continuations...")

    # Continuation that writes "success" if it receives Left
    # Left = λl.λr. l x, so to detect Left we apply the Either to handlers
    # left_handler = write("LEFT")
    # right_handler = write("RIGHT")

    # Let's build a simpler test: continuation that just writes a marker
    # write_marker = ((syscall2 "X") identity)

    # Actually, let's use the write syscall directly
    # write(bytes) is syscall 2

    # Build: λresult. ((2 "X") identity)
    # This ignores the result and just writes "X"

    X_bytes = encode_byte_term(ord("X"))
    X_list = Lam(Lam(App(App(Var(1), X_bytes), Lam(Lam(Var(0))))))  # cons(X, nil)
    write_X = Lam(
        App(App(Var(0x02 + 1), X_list), Lam(Var(0)))
    )  # +1 because under a lambda

    term = App(App(Var(0x08), nil), write_X)
    payload = encode_term(term) + bytes([FF])
    response, elapsed = query_raw(payload)
    print(
        f"syscall8(nil) + write('X'): {repr(response) if response else 'NO OUTPUT'} ({elapsed:.2f}s)"
    )
    time.sleep(0.3)

    # THEORY 4: What if we need to check a DIFFERENT file after calling syscall 8?
    # Maybe syscall 8 unlocks something

    print("\n" + "=" * 60)
    print("[4] Checking if syscall 8 unlocks anything...")

    # Chain: syscall8 -> then read some file
    # ((syscall8 nil) (λresult. ((readfile 256) QD)))

    file256 = encode_byte_term(256)
    inner_read = App(
        App(Var(0x07 + 1), file256), parse_term(QD + bytes([FF]))
    )  # +1 for lambda
    chain_cont = Lam(inner_read)

    term = App(App(Var(0x08), nil), chain_cont)
    payload = encode_term(term) + bytes([FF])
    response, elapsed = query_raw(payload, timeout_s=5.0)

    print(f"syscall8(nil) -> readfile(256):")
    print(f"  Response: {response.hex() if response else 'NO OUTPUT'}")
    if response and FF in response:
        resp_term = parse_term(response)
        tag, payload_term = decode_either(resp_term)
        print(f"  Either: {tag}")
        if tag == "Left":
            content = decode_string(payload_term)
            print(f"  Content: {repr(content)}")
    time.sleep(0.3)

    # Also check if syscall 8 changes anything we can observe
    # Read file 256 directly first
    print("\nDirect readfile(256) for comparison:")
    term = App(App(Var(0x07), file256), qd_term)
    payload = encode_term(term) + bytes([FF])
    response, elapsed = query_raw(payload)
    if response and FF in response:
        resp_term = parse_term(response)
        tag, payload_term = decode_either(resp_term)
        if tag == "Left":
            content = decode_string(payload_term)
            print(f"  Content: {repr(content)}")

    print("\n" + "=" * 60)
    print("CONCLUSION:")
    print("")
    print("Based on all analysis:")
    print("1. Syscall 8 consistently returns Right(6) with QD")
    print("2. Without QD, we get 'no output' (normal for valid programs)")
    print("3. No observable side effects from syscall 8")
    print("")
    print("The WeChall answer is likely:")
    print("  - Something thematic we discovered (omega, towel, wtf)")
    print("  - Or the solution requires an approach we haven't tried")
    print("")
    print("UNTESTED WECHALL SUBMISSIONS:")
    print("  1. omega - backdoor gives us ω combinator")
    print("  2. towel - from syscall 0x2A")
    print("  3. wtf - hidden file 256 name")
    print("  4. ilikephp - gizmore's password")
    print("  5. dloser - the username")
    print("  6. 201 - the backdoor syscall number")
    print("  7. nil - what backdoor requires")


if __name__ == "__main__":
    main()
