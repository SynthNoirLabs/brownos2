#!/usr/bin/env python3
"""
We know:
- Inner value quotes to: 0100fdfefefefefefefefefeff
- This is: λλλλλλλλλ. (Var(1) Var(0)) = Church byte for value 1

But the password/answer is probably a STRING.
Maybe outer is a LIST of bytes, not just Right(byte).

Let me check if (Var(253) sc8Result) gives us a list.
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
    print("ANALYZE THE OUTER PAYLOAD STRUCTURE")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    # We've confirmed:
    # (Var(253) sc8Result) -> Left(outer)
    # outer behaves as Right(inner) where inner is Church byte 1
    
    # But wait! We should try calling (Var(253) sc8Result) with the FULL Either
    # pattern, not just get the Left payload. Maybe the Right branch has data too?
    
    print("\n1. Quote the ENTIRE (Var(253) sc8Result):")
    
    quote_full = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(Var(7), App(Var(1), Var(0))),
                                Lam(
                                    App(
                                        App(Var(0),
                                            Lam(App(App(Var(9), Var(0)), nil))
                                        ),
                                        Lam(App(App(Var(9), encode_string("QF\n")), nil))
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("quote((key sc8Result)):")
    payload = bytes([0x0E, 251, FD]) + encode_term(quote_full) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    print("\n2. What if we need to transform AGAIN? (double Var(253))")
    
    # (Var(253) (Var(253) sc8Result)) -> ?
    double_key = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), App(Var(1), Var(0))),
                                    Lam(App(App(Var(6), encode_string("DL\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("DR\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("(key (key sc8Result)):")
    payload = bytes([0x0E, 251, FD]) + encode_term(double_key) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n3. Try DIFFERENT arguments to syscall 8:")
    
    # Instead of nil, try other args
    for arg_name, arg in [("identity", identity), ("Var(251)", Var(251)), ("Var(1)", Var(1))]:
        try_arg = Lam(
            App(
                App(Var(0),
                    Lam(
                        App(
                            App(Var(10), arg),
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
                                    Lam(App(App(Var(5), encode_string("R\n")), nil))
                                )
                            )
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("E\n")), nil))
            )
        )
        
        print(f"syscall8({arg_name}) -> (key result) -> Right(val) -> quote(val):")
        payload = bytes([0x0E, 251, FD]) + encode_term(try_arg) + bytes([FD, FF])
        resp = test(f"  {arg_name}", payload)
        if resp and b"QF" not in resp:
            print(f"  HEX: {resp.hex()}")
    
    print("\n4. What if we use BACKDOOR PAIR as syscall8 argument?")
    
    # Need to call backdoor first, get pair, then use it with syscall8
    backdoor_then_sc8 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(16), nil),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
                                        App(
                                            App(Var(12), Var(0)),
                                            Lam(
                                                App(
                                                    App(
                                                        App(Var(3), Var(0)),
                                                        Lam(
                                                            App(
                                                                App(Var(0), identity),
                                                                Lam(
                                                                    App(
                                                                        App(Var(12), Var(0)),
                                                                        Lam(
                                                                            App(
                                                                                App(Var(0),
                                                                                    Lam(App(App(Var(15), Var(0)), nil))
                                                                                ),
                                                                                Lam(App(App(Var(15), encode_string("QF\n")), nil))
                                                                            )
                                                                        )
                                                                    )
                                                                )
                                                            )
                                                        )
                                                    ),
                                                    Lam(App(App(Var(9), encode_string("TR\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("BR\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER\n")), nil))
        )
    )
    
    print("echo(251) -> backdoor -> syscall8(pair) -> (key result) -> ...")
    payload = bytes([0x0E, 251, FD]) + encode_term(backdoor_then_sc8) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    print("\n5. Use the key as the argument to syscall8 directly:")
    
    key_as_arg = Lam(
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
    
    print("syscall8(key) directly:")
    payload = bytes([0x0E, 251, FD]) + encode_term(key_as_arg) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")


if __name__ == "__main__":
    main()
