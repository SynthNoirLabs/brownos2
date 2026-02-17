#!/usr/bin/env python3
"""
The payload from (Var(253) sc8Result) is ITSELF a Right!
So we have: Left(Right(something))

Let's unwrap the nested Either and see what's inside.
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
PORT = 61221

FD, FE, FF = 0xFD, 0xFE, 0xFF


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
    raise TypeError


def query(payload: bytes, timeout_s: float = 8.0) -> bytes:
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


def test(desc: str, payload: bytes):
    resp = query(payload)
    if not resp:
        result = "(empty)"
    elif b"Encoding failed" in resp:
        result = "Encoding failed!"
    elif b"Invalid term" in resp:
        result = "Invalid term!"
    else:
        try:
            text = resp.decode('utf-8', 'replace')
            result = f"OUTPUT: {repr(text[:200])}"
        except:
            result = f"hex: {resp.hex()[:200]}"
    print(f"{desc}: {result}")
    return resp


def encode_string(s: str):
    nil = Lam(Lam(Var(0)))
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


def main():
    print("=" * 70)
    print("NESTED EITHER: (Var(253) sc8Result) -> Left(Right(?))")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print("\n=== Unwrap the nested Right and see what's inside ===\n")
    
    # The payload IS a Right, so unwrap it:
    # (Var(253) sc8Result) -> Left(outerPayload)
    # outerPayload is Right(innerPayload)
    # Extract innerPayload
    
    unwrap_nested = Lam(
        App(
            App(Var(0),  # echoResult
                Lam(  # Left handler - key=Var(253)
                    App(
                        App(Var(10), nil),  # syscall8(nil)
                        Lam(  # sc8 continuation - receives Right(6)
                            App(
                                App(
                                    App(Var(1), Var(0)),  # (key sc8Result)
                                    Lam(  # Left handler - outerPayload
                                        App(
                                            App(Var(0),  # outerPayload is Right
                                                Lam(App(App(Var(7), encode_string("NESTED-L\n")), nil))
                                            ),
                                            Lam(  # Right handler - innerPayload
                                                # Write innerPayload directly
                                                App(App(Var(7), Var(0)), nil)
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("OUTER-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("Unwrap: (Var(253) sc8Result) -> Left(Right(inner)) -> write(inner):")
    payload = bytes([0x0E, 251, FD]) + encode_term(unwrap_nested) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW BYTES: {resp}")
        print(f"  HEX: {resp.hex()}")
    
    print("\n=== Quote the inner payload ===\n")
    
    quote_inner = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(  # outer = Right(inner)
                                        App(
                                            App(Var(0),
                                                Lam(App(App(Var(7), encode_string("N-L\n")), nil))
                                            ),
                                            Lam(  # inner
                                                App(
                                                    App(Var(8), Var(0)),  # quote(inner)
                                                    Lam(
                                                        App(
                                                            App(Var(0),
                                                                Lam(App(App(Var(10), Var(0)), nil))  # write quoted
                                                            ),
                                                            Lam(App(App(Var(10), encode_string("QR\n")), nil))
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("O-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E-R\n")), nil))
        )
    )
    
    print("quote(inner) -> write:")
    payload = bytes([0x0E, 251, FD]) + encode_term(quote_inner) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW: {resp}")
        print(f"  HEX: {resp.hex()}")
    
    print("\n=== Treat inner as an Either too ===\n")
    
    inner_as_either = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(  # outer = Right(inner)
                                        App(
                                            App(Var(0),
                                                Lam(App(App(Var(7), encode_string("N-L\n")), nil))
                                            ),
                                            Lam(  # inner - treat as Either
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(8), encode_string("I-L\n")), nil))
                                                    ),
                                                    Lam(App(App(Var(8), encode_string("I-R\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("O-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E-R\n")), nil))
        )
    )
    
    print("Is inner ALSO an Either?")
    payload = bytes([0x0E, 251, FD]) + encode_term(inner_as_either) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Apply inner to various arguments ===\n")
    
    # Maybe inner is a function?
    apply_inner_nil = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(  # outer = Right(inner)
                                        App(
                                            App(Var(0),
                                                Lam(App(App(Var(7), encode_string("N-L\n")), nil))
                                            ),
                                            Lam(  # inner - apply to nil
                                                App(
                                                    App(Var(0), nil),
                                                    Lam(App(App(Var(8), encode_string("GOT\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("O-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E-R\n")), nil))
        )
    )
    
    print("(inner nil) -> ?")
    payload = bytes([0x0E, 251, FD]) + encode_term(apply_inner_nil) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Apply Var(253) AGAIN to the inner ===\n")
    
    # What if we need to apply Var(253) again?
    double_transform = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(  # outer = Right(inner)
                                        App(
                                            App(Var(0),
                                                Lam(App(App(Var(7), encode_string("N-L\n")), nil))
                                            ),
                                            Lam(  # inner
                                                # Apply Var(253) again! Var(2) is now the key
                                                App(
                                                    App(
                                                        App(Var(2), Var(0)),
                                                        Lam(App(App(Var(9), Var(0)), nil))  # Left: write it
                                                    ),
                                                    Lam(App(App(Var(9), encode_string("D-R\n")), nil))  # Right
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("O-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E-R\n")), nil))
        )
    )
    
    print("Apply Var(253) to inner again: (key inner) -> ?")
    payload = bytes([0x0E, 251, FD]) + encode_term(double_transform) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW: {resp}")


if __name__ == "__main__":
    main()
