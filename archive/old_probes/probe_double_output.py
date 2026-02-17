#!/usr/bin/env python3
"""
The test (key val) printed BOTH "KL" and "KR"!
This is strange - Either should only trigger ONE handler.

Investigate what's happening with val and key.
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
    print("INVESTIGATING DOUBLE OUTPUT")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    # The issue: (key val) prints BOTH KL and KR
    # val is the Church byte, key is Var(253)
    
    # Church byte for 1 = λb7...b0.λacc. (b0 acc)
    # When we apply key to it... what happens?
    
    # Var(253) is special - it's manufactured by echo(251)+2
    # What IS Var(253) as a term?
    
    # Let's try applying the Church byte to different patterns
    print("\nFirst, verify val is the Church byte:")
    
    # val at depth 5, key at depth 3
    # We want to apply val to 8 functions + accumulator
    
    # Actually, let me just verify (key val) behavior more carefully
    
    key_val_detailed = Lam(
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
                                                # At d5: val=0, key=3, write=7
                                                # First, print A to confirm we're here
                                                App(
                                                    App(Var(7), encode_string("A")),
                                                    Lam(
                                                        # Now apply (key val)
                                                        App(
                                                            App(
                                                                App(Var(4), Var(1)),
                                                                Lam(
                                                                    App(
                                                                        App(Var(9), encode_string("L")),
                                                                        Lam(App(App(Var(10), encode_string("-")), nil))
                                                                    )
                                                                )
                                                            ),
                                                            Lam(
                                                                App(
                                                                    App(Var(9), encode_string("R")),
                                                                    Lam(App(App(Var(10), encode_string(".")), nil))
                                                                )
                                                            )
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
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("1. (key val) with detailed tracing (A first, then L- or R.):")
    payload = bytes([0x0E, 251, FD]) + encode_term(key_val_detailed) + bytes([FD, FF])
    test("  result", payload)
    
    # Maybe val itself causes double execution?
    # Let's test: what does (val f g) do?
    
    val_as_either = Lam(
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
                                                # val at d5
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(8), encode_string("V-L\n")), nil))
                                                    ),
                                                    Lam(App(App(Var(8), encode_string("V-R\n")), nil))
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
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("\n2. (val leftH rightH) - val as Either:")
    payload = bytes([0x0E, 251, FD]) + encode_term(val_as_either) + bytes([FD, FF])
    test("  result", payload)
    
    # What if Var(253) is actually a PAIR?
    # pair = λs. s A B
    # (pair f g) = f A, then g B? No that's not how it works...
    
    # Actually, what if the Church byte evaluation causes both paths?
    # Church byte = λb7...b0.λacc. (possibly many applications)
    # If b0 is identity, then (b0 acc) = acc
    # But Church 1 should just be λ^9. (b0 acc) = λb7...b0.λacc. b0 acc
    
    # Wait, the Church encoding in BrownOS is:
    # byte n = λb7.λb6...λb0.λacc. (bi (bi-1 (... acc))) for each set bit
    # For n=1, only b0 is applied: λb7...b0.λacc. b0 acc
    
    # If we pass this as first arg to Either...
    # (ChurchByte leftH rightH) = ?
    # ChurchByte expects 9 args (8 bits + acc), but Either expects 2
    
    # This could be the issue! Church byte is NOT an Either!
    
    print("\n3. What happens when we apply Church byte to 2 args?")
    print("   Church byte expects 9 args, Either expects 2")
    print("   Partial application might cause weird behavior")
    
    # Let's apply val to 9 handlers and see:
    val_full_apply = Lam(
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
                                                # val=0, apply to 9 args
                                                App(
                                                    App(
                                                        App(
                                                            App(
                                                                App(
                                                                    App(
                                                                        App(
                                                                            App(
                                                                                App(Var(0),
                                                                                    Lam(App(App(Var(9), encode_string("7")), Var(0)))
                                                                                ),
                                                                                Lam(App(App(Var(9), encode_string("6")), Var(0)))
                                                                            ),
                                                                            Lam(App(App(Var(9), encode_string("5")), Var(0)))
                                                                        ),
                                                                        Lam(App(App(Var(9), encode_string("4")), Var(0)))
                                                                    ),
                                                                    Lam(App(App(Var(9), encode_string("3")), Var(0)))
                                                                ),
                                                                Lam(App(App(Var(9), encode_string("2")), Var(0)))
                                                            ),
                                                            Lam(App(App(Var(9), encode_string("1")), Var(0)))
                                                        ),
                                                        Lam(App(App(Var(9), encode_string("0")), Var(0)))
                                                    ),
                                                    Lam(App(App(Var(9), encode_string("_")), nil))
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
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("(val b7 b6 b5 b4 b3 b2 b1 b0 acc) where each prints a digit:")
    payload = bytes([0x0E, 251, FD]) + encode_term(val_full_apply) + bytes([FD, FF])
    test("  result", payload)


if __name__ == "__main__":
    main()
