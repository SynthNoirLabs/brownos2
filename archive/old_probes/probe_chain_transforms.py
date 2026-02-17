#!/usr/bin/env python3
"""
Discovery: (key (key sc8Result)) -> Left!

Chain of transformations:
1. sc8Result = Right(6) (Permission denied)
2. (key sc8Result) -> Left(outer), where outer = Right(Church 1)
3. (key outer) -> Left(?)

Let's keep chaining and see what we get!
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
    print("CHAIN OF VAR(253) TRANSFORMATIONS")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    print("\nLet's apply key multiple times and extract each result:\n")
    
    # (key (key sc8Result)) -> Left(payload2)
    # Extract payload2 and quote it
    
    double_extract = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), App(Var(1), Var(0))),
                                    Lam(
                                        App(
                                            App(Var(7), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(10), Var(0)), nil))
                                                    ),
                                                    Lam(App(App(Var(10), encode_string("QF\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("DR\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("1. (key (key sc8)) -> Left(p2) -> quote(p2):")
    payload = bytes([0x0E, 251, FD]) + encode_term(double_extract) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # What if we apply key THREE times?
    triple_check = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), App(Var(1), App(Var(1), Var(0)))),
                                    Lam(App(App(Var(6), encode_string("3L\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("3R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("\n2. (key (key (key sc8))) -> L or R?:")
    payload = bytes([0x0E, 251, FD]) + encode_term(triple_check) + bytes([FD, FF])
    test("  result", payload)
    
    # Extract and quote the triple result
    triple_extract = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), App(Var(1), App(Var(1), Var(0)))),
                                    Lam(
                                        App(
                                            App(Var(7), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(10), Var(0)), nil))
                                                    ),
                                                    Lam(App(App(Var(10), encode_string("QF\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("TR\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("\n3. (key (key (key sc8))) -> Left(p3) -> quote(p3):")
    payload = bytes([0x0E, 251, FD]) + encode_term(triple_extract) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # Go deeper - 4 times
    quad_check = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), App(Var(1), App(Var(1), App(Var(1), Var(0))))),
                                    Lam(App(App(Var(6), encode_string("4L\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("4R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("\n4. key^4 sc8 -> L or R?:")
    payload = bytes([0x0E, 251, FD]) + encode_term(quad_check) + bytes([FD, FF])
    test("  result", payload)
    
    # Maybe at some depth we hit the actual string?
    # Let's try treating p2 as a LIST (cons cell with head/tail)
    
    p2_as_list = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), App(Var(1), Var(0))),
                                    Lam(
                                        App(
                                            App(Var(0),
                                                Lam(Lam(
                                                    App(
                                                        App(Var(10), Var(1)),
                                                        Lam(
                                                            App(
                                                                App(Var(0),
                                                                    Lam(App(App(Var(13), Var(0)), nil))
                                                                ),
                                                                Lam(App(App(Var(13), encode_string("HQ\n")), nil))
                                                            )
                                                        )
                                                    )
                                                ))
                                            ),
                                            nil
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("DR\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("\n5. p2 as cons cell -> quote(head):")
    payload = bytes([0x0E, 251, FD]) + encode_term(p2_as_list) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # Let's try a different approach: maybe we should use key on BOTH arguments
    # to the Either, not just on sc8Result?
    
    print("\n6. Maybe the answer is in a DIFFERENT nested path?")
    
    # What does outer (without identity) give us?
    direct_outer = Lam(
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
                                            App(Var(7), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(10), Var(0)), nil))
                                                    ),
                                                    Lam(App(App(Var(10), encode_string("OF\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("OR\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("quote(outer) directly (first transform payload):")
    payload = bytes([0x0E, 251, FD]) + encode_term(direct_outer) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # Maybe we need to WRITE the result, treating it as a string?
    write_p2 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), App(Var(1), Var(0))),
                                    Lam(
                                        App(App(Var(6), Var(0)), nil)
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("DR\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("\n7. write(p2) as bytes:")
    payload = bytes([0x0E, 251, FD]) + encode_term(write_p2) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW: {resp}")
        print(f"  HEX: {resp.hex()}")


if __name__ == "__main__":
    main()
