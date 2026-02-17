#!/usr/bin/env python3
"""
Careful verification of what each level gives us.

Using CONSISTENT test structure at each level.
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
            result = f"OUTPUT: {repr(text[:300])}"
        except:
            result = f"hex: {resp.hex()[:300]}"
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
    print("VERIFY TRANSFORMATION CHAIN")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    # Level 0: sc8Result
    # Level 1: (key sc8Result) = p1
    # Level 2: (key p1)
    # etc.
    
    # For each level, test:
    # A) Direct Either: (result leftH rightH)
    # B) Extracted: if Left(x), test x as Either
    
    print("\n=== Level 0: sc8Result directly ===")
    
    level0 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), encode_string("L0-L\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("L0-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("sc8Result as Either:")
    payload = bytes([0x0E, 251, FD]) + encode_term(level0) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Level 1: (key sc8Result) ===")
    
    level1 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(App(Var(1), Var(0)),
                                    Lam(App(App(Var(6), encode_string("L1-L\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("L1-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("(key sc8Result) as Either:")
    payload = bytes([0x0E, 251, FD]) + encode_term(level1) + bytes([FD, FF])
    test("  result", payload)
    
    # Level 1 extracted
    level1_extract = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(App(Var(1), Var(0)),
                                    Lam(
                                        App(
                                            App(Var(0),
                                                Lam(App(App(Var(7), encode_string("L1x-L\n")), nil))
                                            ),
                                            Lam(App(App(Var(7), encode_string("L1x-R\n")), nil))
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("L1-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("L1 Left payload as Either:")
    payload = bytes([0x0E, 251, FD]) + encode_term(level1_extract) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Level 2: (key (key sc8Result)) ===")
    
    level2 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(App(Var(1), App(Var(1), Var(0))),
                                    Lam(App(App(Var(6), encode_string("L2-L\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("L2-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("(key (key sc8Result)) as Either:")
    payload = bytes([0x0E, 251, FD]) + encode_term(level2) + bytes([FD, FF])
    test("  result", payload)
    
    # Level 2 extracted
    level2_extract = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(App(Var(1), App(Var(1), Var(0))),
                                    Lam(
                                        App(
                                            App(Var(0),
                                                Lam(App(App(Var(7), encode_string("L2x-L\n")), nil))
                                            ),
                                            Lam(App(App(Var(7), encode_string("L2x-R\n")), nil))
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("L2-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("L2 Left payload as Either:")
    payload = bytes([0x0E, 251, FD]) + encode_term(level2_extract) + bytes([FD, FF])
    test("  result", payload)
    
    # Level 2 double extracted (inner of inner)
    level2_double = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(App(Var(1), App(Var(1), Var(0))),
                                    Lam(
                                        App(
                                            App(Var(0), identity),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(9), encode_string("L2y-L\n")), nil))
                                                    ),
                                                    Lam(App(App(Var(9), encode_string("L2y-R\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("L2-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("L2 -> Right(inner) -> inner as Either:")
    payload = bytes([0x0E, 251, FD]) + encode_term(level2_double) + bytes([FD, FF])
    test("  result", payload)
    
    # Quote the L2 inner
    level2_quote = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(App(Var(1), App(Var(1), Var(0))),
                                    Lam(
                                        App(
                                            App(Var(0), identity),
                                            Lam(
                                                App(
                                                    App(Var(9), Var(0)),
                                                    Lam(
                                                        App(
                                                            App(Var(0),
                                                                Lam(App(App(Var(12), Var(0)), nil))
                                                            ),
                                                            Lam(App(App(Var(12), encode_string("QF\n")), nil))
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("L2-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("L2 -> Right(inner) -> quote(inner):")
    payload = bytes([0x0E, 251, FD]) + encode_term(level2_quote) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")


if __name__ == "__main__":
    main()
