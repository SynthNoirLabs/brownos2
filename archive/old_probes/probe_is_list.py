#!/usr/bin/env python3
"""
What if (Var(253) sc8Result) returns a LIST of bytes?
The structure might be: cons(byte1, cons(byte2, ... nil))

Let's check if we can iterate.
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
    print("IS THE RESULT A LIST?")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    # We know: (key sc8) -> Left(outer)
    # outer behaves as Right(church1)
    # But what if outer is actually: cons(church1, tail)?
    
    # Scott list: cons(h, t) = λc.λn. c h t
    # When applied to (λh.λt. ...) and nil, it calls the first handler with h and t
    
    # Scott Right: Right(x) = λl.λr. r x
    # When applied to handlers, it calls the second with x
    
    # These have SAME arity (2 args)!
    # cons(h, t) leftH rightH = leftH h t
    # Right(x) leftH rightH = rightH x
    
    # So our "outer" behaves as Right means it takes 2 args and calls second!
    # If it were cons, it would call the FIRST handler!
    
    print("\nScott encoding:")
    print("  cons(h, t) = λc.λn. c h t -> calls 1st handler with 2 args")
    print("  nil        = λc.λn. n    -> calls 2nd handler with 0 args")
    print("  Right(x)   = λl.λr. r x  -> calls 2nd handler with 1 arg")
    print("  Left(x)    = λl.λr. l x  -> calls 1st handler with 1 arg")
    print("")
    print("If outer called 2nd handler, it could be Right OR nil!")
    print("Let's check if the handler gets an argument or not.\n")
    
    # Test: does the Right handler get an argument?
    check_arg = Lam(
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
                                        # outer
                                        App(
                                            App(Var(0),
                                                Lam(Lam(App(App(Var(9), encode_string("1st-2args\n")), nil)))
                                            ),
                                            Lam(
                                                # This is the handler that gets called
                                                # If Right(x), this lambda receives x
                                                # If nil, this lambda receives nothing and is just called
                                                # Let's write something to see if we get an arg
                                                App(App(Var(7), encode_string("2nd-")), 
                                                    Lam(
                                                        # Check if there's a "real" arg by trying to quote it
                                                        App(
                                                            App(Var(10), Var(1)),
                                                            Lam(
                                                                App(
                                                                    App(Var(0),
                                                                        Lam(App(App(Var(13), Var(0)), nil))
                                                                    ),
                                                                    Lam(App(App(Var(13), encode_string("QF\n")), nil))
                                                                )
                                                            )
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("TransformR\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("Check what outer does - 1st handler or 2nd? And does it pass args?")
    payload = bytes([0x0E, 251, FD]) + encode_term(check_arg) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # Actually, we already know outer behaves as Right(inner) because:
    # (outer id handler) makes handler run and inner quotes to Church byte 1
    
    # The question is: is there MORE after Church1?
    # What if the inner is actually cons(Church1, tail)?
    
    print("\n\nMaybe the inner value is a LIST, not just a single byte?")
    
    inner_as_list = Lam(
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
                                                # inner = Var(0)
                                                # If inner is cons(h, t), then (inner f g) = f h t
                                                # If inner is a single Church byte, (inner f g) depends on the byte
                                                App(
                                                    App(Var(0),
                                                        Lam(Lam(
                                                            # Got 2 args: head and tail
                                                            App(
                                                                App(Var(10), encode_string("HEAD:")),
                                                                Lam(
                                                                    App(
                                                                        App(Var(13), Var(3)),
                                                                        Lam(
                                                                            App(
                                                                                App(Var(0),
                                                                                    Lam(App(App(Var(16), Var(0)), nil))
                                                                                ),
                                                                                Lam(App(App(Var(16), encode_string("HQF\n")), nil))
                                                                            )
                                                                        )
                                                                    )
                                                                )
                                                            )
                                                        ))
                                                    ),
                                                    Lam(
                                                        App(App(Var(9), encode_string("NOT-LIST\n")), nil)
                                                    )
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
    
    print("Is inner a cons cell?")
    payload = bytes([0x0E, 251, FD]) + encode_term(inner_as_list) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")


if __name__ == "__main__":
    main()
