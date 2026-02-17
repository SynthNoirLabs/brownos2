#!/usr/bin/env python3
"""
We know:
- (Var(253) sc8Result) -> Left(outerPayload)
- outerPayload behaves as Right(innerValue)
- (outerPayload identity k) -> k runs (prints D)

So Right = λl.λr. r x  where x is the inner value
When we do (Right id k) = k x

We need to capture x and write it!
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
    print("EXTRACT THE INNER VALUE FROM Right(innerValue)")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    print("\nRight = λl.λr. r x")
    print("(Right id (λval. ...)) = (λval. ...) x")
    print("So the second argument (the Right handler) receives x as its argument!\n")
    
    extract_inner_write = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(
                                        App(
                                            App(Var(0), identity),
                                            Lam(App(App(Var(7), Var(0)), nil))
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("X\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("Y\n")), nil))
        )
    )
    
    print("1. (outerPayload id (λval. write val nil)):")
    payload = bytes([0x0E, 251, FD]) + encode_term(extract_inner_write) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW: {resp}")
        print(f"  HEX: {resp.hex()}")
    
    print("\n2. Quote the inner value:")
    
    extract_inner_quote = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(
                                        App(
                                            App(Var(0), identity),
                                            Lam(
                                                App(
                                                    App(Var(8), Var(0)),
                                                    Lam(
                                                        App(
                                                            App(Var(0),
                                                                Lam(App(App(Var(11), Var(0)), nil))
                                                            ),
                                                            Lam(App(App(Var(11), encode_string("QF\n")), nil))
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("X\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("Y\n")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(extract_inner_quote) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW: {resp}")
        print(f"  HEX: {resp.hex()}")
    
    print("\n3. Inner value as Either:")
    
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
                                    Lam(
                                        App(
                                            App(Var(0), identity),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(9), encode_string("IL\n")), nil))
                                                    ),
                                                    Lam(App(App(Var(9), encode_string("IR\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("X\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("Y\n")), nil))
        )
    )
    
    print("Is inner value ALSO an Either?")
    payload = bytes([0x0E, 251, FD]) + encode_term(inner_as_either) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n4. Chain deeper - if inner is Right, extract ITS value:")
    
    double_extract = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(
                                        App(
                                            App(Var(0), identity),
                                            Lam(
                                                App(
                                                    App(Var(0), identity),
                                                    Lam(App(App(Var(9), Var(0)), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("X\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("Y\n")), nil))
        )
    )
    
    print("(outer id (λv1. (v1 id (λv2. write v2)))):")
    payload = bytes([0x0E, 251, FD]) + encode_term(double_extract) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW: {resp}")
        print(f"  HEX: {resp.hex()}")
    
    print("\n5. What if inner value is a Church numeral? Decode it:")
    
    decode_church = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(
                                        App(
                                            App(Var(0), identity),
                                            Lam(
                                                App(
                                                    App(Var(0), Lam(Lam(App(Var(1), App(Var(1), Var(0)))))),
                                                    Lam(
                                                        App(
                                                            App(Var(0), Lam(Var(0))),
                                                            Lam(App(App(Var(10), encode_string("N\n")), nil))
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("X\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("Y\n")), nil))
        )
    )
    
    print("If Church numeral, apply to successor and zero:")
    payload = bytes([0x0E, 251, FD]) + encode_term(decode_church) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n6. Inner value is probably small - maybe it's the error code 6?")
    print("   Let's apply Var(253) to IT:")
    
    transform_inner = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(
                                        App(
                                            App(Var(0), identity),
                                            Lam(
                                                App(
                                                    App(
                                                        App(Var(2), Var(0)),
                                                        Lam(App(App(Var(9), encode_string("TL\n")), nil))
                                                    ),
                                                    Lam(App(App(Var(9), encode_string("TR\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("X\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("Y\n")), nil))
        )
    )
    
    print("(Var(253) innerValue) -> ?")
    payload = bytes([0x0E, 251, FD]) + encode_term(transform_inner) + bytes([FD, FF])
    test("  result", payload)


if __name__ == "__main__":
    main()
