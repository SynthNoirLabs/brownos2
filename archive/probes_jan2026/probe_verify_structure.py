#!/usr/bin/env python3
"""
Carefully verify the structure of (key anything).

We believe: (key x) -> Left(Right(Church1))
Let's confirm this by:
1. Using both Either branches
2. Quoting intermediate results
3. Tracing through step by step
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
PORT = 61221

FD, FE, FF = 0xFD, 0xFE, 0xFF
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


def encode_term(term) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unknown term type: {type(term)}")


def query(payload: bytes, timeout_s: float = 5.0) -> bytes:
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except:
                pass
            sock.settimeout(timeout_s)
            out = b""
            deadline = time.time() + timeout_s
            while time.time() < deadline:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out += chunk
                except socket.timeout:
                    break
            return out
    except Exception as e:
        return f"ERROR: {e}".encode()


nil = Lam(Lam(Var(0)))
identity = Lam(Var(0))


def make_church(n):
    expr = Var(0)
    for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_string(s: str):
    def encode_byte(n):
        expr = Var(0)
        for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
            if n & weight:
                expr = App(Var(idx), expr)
        term = expr
        for _ in range(9):
            term = Lam(term)
        return term
    def cons(h, t):
        return Lam(Lam(App(App(Var(1), h), t)))
    cur = nil
    for b in reversed(s.encode()):
        cur = cons(encode_byte(b), cur)
    return cur


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
    return stack[0] if len(stack) == 1 else None


def term_to_string(term, depth=0):
    if depth > 20:
        return "..."
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{term_to_string(term.body, depth+1)}"
    if isinstance(term, App):
        return f"({term_to_string(term.f, depth+1)} {term_to_string(term.x, depth+1)})"
    return "?"


def main():
    print("=" * 70)
    print("VERIFY STRUCTURE OF (key anything)")
    print("=" * 70)
    
    print("\n=== Step 1: Quote (key nil) directly ===")
    
    # Get key from echo(251), then quote (key nil)
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # key at Var(0)
                    # Quote (key nil)
                    App(
                        App(Var(6),  # quote syscall
                            App(Var(0), nil)  # (key nil)
                        ),
                        Lam(  # quote continuation
                            App(
                                App(Var(0),  # Either
                                    Lam(  # Left - got bytes
                                        App(App(Var(6), Var(0)), nil)  # write them
                                    )
                                ),
                                Lam(  # Right - quote failed
                                    App(App(Var(6), encode_string("QF")), nil)
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  quote(key nil) raw: {resp.hex() if resp else 'empty'}")
    
    if resp and resp != b'QF' and resp != b'ER':
        term = parse_term(resp)
        if term:
            print(f"  Parsed: {term_to_string(term)}")
    
    print("\n=== Step 2: Apply (key nil) to Either handlers ===")
    
    # (key nil) should be Either-shaped
    # Apply Left and Right handlers to see which fires
    test_term2 = Lam(
        App(
            App(Var(0),
                Lam(  # key
                    App(
                        App(
                            App(Var(0), nil),  # (key nil)
                            Lam(  # Left handler - receives inner
                                # Write "L:" then quote inner
                                App(
                                    App(Var(5), encode_string("L:")),
                                    App(
                                        App(Var(7),  # quote
                                            Var(0)  # inner
                                        ),
                                        Lam(
                                            App(
                                                App(Var(0),
                                                    Lam(App(App(Var(9), Var(0)), nil))
                                                ),
                                                Lam(App(App(Var(9), encode_string("QF")), nil))
                                            )
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(  # Right handler - receives inner
                            App(
                                App(Var(5), encode_string("R:")),
                                App(
                                    App(Var(7), Var(0)),
                                    Lam(
                                        App(
                                            App(Var(0),
                                                Lam(App(App(Var(9), Var(0)), nil))
                                            ),
                                            Lam(App(App(Var(9), encode_string("QF")), nil))
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term2) + bytes([FD, FF])
    resp = query(payload)
    print(f"  Result: {resp}")
    
    if resp.startswith(b'L:'):
        print("  -> Hit LEFT branch!")
        inner_bytes = resp[2:]
        if inner_bytes and inner_bytes != b'QF':
            inner_term = parse_term(inner_bytes)
            if inner_term:
                print(f"  Inner term: {term_to_string(inner_term)}")
    elif resp.startswith(b'R:'):
        print("  -> Hit RIGHT branch!")
        inner_bytes = resp[2:]
        if inner_bytes and inner_bytes != b'QF':
            inner_term = parse_term(inner_bytes)
            if inner_term:
                print(f"  Inner term: {term_to_string(inner_term)}")
    
    print("\n=== Step 3: If Left(inner), check if inner is Either ===")
    
    # We expect Left(Right(Church1))
    # So inner = Right(Church1)
    # Apply Either handlers to inner
    test_term3 = Lam(
        App(
            App(Var(0),
                Lam(  # key
                    App(
                        App(
                            App(Var(0), nil),  # (key nil) = Left(something)
                            Lam(  # Left handler - inner = Var(0)
                                # inner should be Right(Church1)
                                # Apply Either handlers to inner
                                App(
                                    App(
                                        Var(0),  # inner, should be Either
                                        Lam(  # inner's Left handler
                                            App(App(Var(7), encode_string("LL:")), nil)
                                        )
                                    ),
                                    Lam(  # inner's Right handler - should fire
                                        # Write "LR:" then try to extract the Church numeral
                                        App(
                                            App(Var(7), encode_string("LR:")),
                                            # Var(0) should be Church numeral
                                            # Write it as a byte
                                            App(
                                                App(Var(8),  # write
                                                    Lam(Lam(App(App(Var(1), Var(2)), nil)))  # [Var(2)]
                                                ),
                                                nil
                                            )
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(  # Right handler for outer
                            App(App(Var(5), encode_string("R:")), nil)
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term3) + bytes([FD, FF])
    resp = query(payload)
    print(f"  Result: {resp}")
    
    if resp.startswith(b'LR:'):
        print("  -> Structure confirmed: Left(Right(...))")
        byte_val = resp[3:4]
        if byte_val:
            print(f"  -> Extracted byte: {byte_val[0]}")


if __name__ == "__main__":
    main()
