#!/usr/bin/env python3
"""
The key keeps transforming to Left, but we can't serialize the payload.
Let's explore what operations we CAN do on these payloads.

Key insight: The payload at each level might be:
1. An Either (with Left/Right structure)
2. A list (cons/nil)
3. A function we need to call with specific arguments
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
    print("EXPLORING PAYLOAD STRUCTURE")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    print("\nWe know:")
    print("  p1 = (key sc8Result) -> Left(outer) where outer = Right(Church 1)")
    print("  p2 = (key outer) = (key (key sc8)) -> Left(?)")
    print("  etc...")
    print("")
    print("Let's explore the STRUCTURE of p2:")
    
    # p2 as Either
    p2_either = Lam(
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
                                                Lam(App(App(Var(7), encode_string("P2-L\n")), nil))
                                            ),
                                            Lam(App(App(Var(7), encode_string("P2-R\n")), nil))
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
    
    print("\n1. p2 as Either (L/R):")
    payload = bytes([0x0E, 251, FD]) + encode_term(p2_either) + bytes([FD, FF])
    test("  result", payload)
    
    # p2 applied to something
    p2_apply = Lam(
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
                                            App(Var(0), nil),
                                            Lam(App(App(Var(7), encode_string("AP\n")), nil))
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
    
    print("\n2. (p2 nil) then continuation:")
    payload = bytes([0x0E, 251, FD]) + encode_term(p2_apply) + bytes([FD, FF])
    test("  result", payload)
    
    # Apply p2 to identity twice (simulating Either extraction)
    p2_double_id = Lam(
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
                                Lam(App(App(Var(5), encode_string("DR\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("\n3. (p2 id cont) -> quote the result:")
    payload = bytes([0x0E, 251, FD]) + encode_term(p2_double_id) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # What if we need to use SYSCALL 42 on the payload?
    # Syscall 42 returns the "answer" string when given the right argument
    
    print("\n4. Try syscall42 on different payloads:")
    
    # syscall42(p1)
    sc42_p1 = Lam(
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
                                            App(Var(46), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(9), Var(0)), nil))
                                                    ),
                                                    Lam(App(App(Var(9), encode_string("42F\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("syscall42(p1):")
    payload = bytes([0x0E, 251, FD]) + encode_term(sc42_p1) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # syscall42 with inner Church byte
    sc42_inner = Lam(
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
                                                    App(Var(48), Var(0)),
                                                    Lam(
                                                        App(
                                                            App(Var(0),
                                                                Lam(App(App(Var(10), Var(0)), nil))
                                                            ),
                                                            Lam(App(App(Var(10), encode_string("42F\n")), nil))
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("syscall42(inner Church byte):")
    payload = bytes([0x0E, 251, FD]) + encode_term(sc42_inner) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # Maybe we're supposed to pass the KEY to syscall42?
    sc42_key = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(46), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(7), Var(0)), nil))
                                ),
                                Lam(App(App(Var(7), encode_string("42F\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("\n5. syscall42(key=Var(253)):")
    payload = bytes([0x0E, 251, FD]) + encode_term(sc42_key) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # What about syscall 8 with the key as its ARGUMENT?
    sc8_with_key = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
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
                                Lam(App(App(Var(5), encode_string("R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("\n6. syscall8(key) -> quote if Left:")
    payload = bytes([0x0E, 251, FD]) + encode_term(sc8_with_key) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")


if __name__ == "__main__":
    main()
