#!/usr/bin/env python3
"""
At each level, extract the inner Right value and quote it.
Maybe each level gives a different byte -> forming a STRING!
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
    print("QUOTE INNER VALUE AT EACH LEVEL")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    # L1: (key sc8) -> Left(outer) -> outer=Right(inner1) -> quote(inner1)
    l1_quote = Lam(
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
                                Lam(App(App(Var(5), encode_string("L1-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("\nL1 inner value (Church byte):")
    payload = bytes([0x0E, 251, FD]) + encode_term(l1_quote) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp and b"QF" not in resp and b"L1-R" not in resp:
        print(f"  HEX: {resp.hex()}")
        
    # We know L1 gives: 0100fdfefefefefefefefefeff = Church byte for 1
    # Now check L2, L3, etc.
    
    # The issue is at L2, when we try to apply (outer id handler),
    # we get empty. Let me try a different approach:
    # Instead of extracting, just keep transforming and check the RAW structure.
    
    # Actually wait - at L1, outer is Right(Church1).
    # L2 = key(outer) = key(Right(Church1))
    # But Right is λl.λr. r x
    # So key(Right) = Var(253)(λl.λr. r x) = (λl.λr. r x) applied to something...
    
    # Hmm, this depends on what Var(253) actually IS as a lambda term.
    # It must be something special in the runtime.
    
    print("\nLet me check: what happens when we quote Var(253) itself?")
    
    quote_key = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(6), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(8), Var(0)), nil))
                                ),
                                Lam(App(App(Var(8), encode_string("QF\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("quote(key=Var(253)):")
    payload = bytes([0x0E, 251, FD]) + encode_term(quote_key) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # Maybe we need to call the key as a FUNCTION with specific args?
    # Var(253) = 0xFD byte
    # What if we apply it to things?
    
    print("\nLet me apply key to various arguments:")
    
    for arg_name, arg in [("nil", nil), ("id", identity), ("0", Var(0))]:
        key_apply = Lam(
            App(
                App(Var(0),
                    Lam(
                        App(
                            App(Var(6), App(Var(0), arg)),
                            Lam(
                                App(
                                    App(Var(0),
                                        Lam(App(App(Var(8), Var(0)), nil))
                                    ),
                                    Lam(App(App(Var(8), encode_string("QF\n")), nil))
                                )
                            )
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("E\n")), nil))
            )
        )
        
        print(f"quote(key {arg_name}):")
        payload = bytes([0x0E, 251, FD]) + encode_term(key_apply) + bytes([FD, FF])
        resp = test(f"  result", payload)
        if resp and b"QF" not in resp:
            print(f"  HEX: {resp.hex()}")
    
    # What is the structure of (key sc8)?
    # Let's test if it's a cons cell (list)
    
    print("\nIs L1 a cons cell?")
    
    l1_as_cons = Lam(
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
                                                Lam(Lam(App(App(Var(9), encode_string("CONS\n")), nil)))
                                            ),
                                            nil
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
    
    print("(L1_payload consHandler nil):")
    payload = bytes([0x0E, 251, FD]) + encode_term(l1_as_cons) + bytes([FD, FF])
    test("  result", payload)
    
    # What if the OUTER level (L1 itself, not its payload) is a list?
    # i.e., Left(outer) where outer contains multiple things?
    
    # Actually, we're iterating KEY applications.
    # Maybe we should be iterating a DIFFERENT way.
    
    # Hypothesis: The answer is a STRING, and each character is in Right(charN)
    # at successive depths. But they all quote to similar structure...
    
    # Let me try: print the ACTUAL wire bytes of each transform result
    # by trying to write them directly (even if they fail, we learn something)
    
    print("\nDirect write attempts:")
    
    for n in range(1, 5):
        key_apps = Var(0)
        for _ in range(n):
            key_apps = App(Var(1), key_apps)
        
        write_direct = Lam(
            App(
                App(Var(0),
                    Lam(
                        App(
                            App(Var(10), nil),
                            Lam(
                                App(
                                    App(key_apps,
                                        Lam(
                                            App(App(Var(n+5), Var(0)), nil)
                                        )
                                    ),
                                    Lam(App(App(Var(n+4), encode_string(f"L{n}R\n")), nil))
                                )
                            )
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("E\n")), nil))
            )
        )
        
        print(f"key^{n}(sc8) -> Left(p) -> write(p):")
        payload = bytes([0x0E, 251, FD]) + encode_term(write_direct) + bytes([FD, FF])
        resp = test(f"  L{n}", payload)
        if resp:
            print(f"  RAW: {resp}")


if __name__ == "__main__":
    main()
