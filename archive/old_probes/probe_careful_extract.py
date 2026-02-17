#!/usr/bin/env python3
"""
Careful de Bruijn tracking to extract the inner value.

Confirmed: (Var(253) sc8Result) -> Left(outerPayload)
          outerPayload behaves as Right(inner)
          (outerPayload id k) -> k runs

Let's carefully extract 'inner' with correct indices.
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
    print("CAREFUL EXTRACTION WITH EXPLICIT DEPTH TRACKING")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    # Syscalls at depth 0: write=2, quote=4, syscall8=8, echo=14
    # Each lambda adds 1 to the depth
    
    print("\nBase structure that WORKS:")
    print("echo(251) cont where cont = λechoResult. ...")
    print("  depth 1: echoResult=Var(0), write=Var(3), syscall8=Var(9)")
    print("")
    
    # Base: just print GOT-L to confirm
    base_check = Lam(  # depth 1: echoResult=0, write=3, syscall8=9
        App(
            App(Var(0),  # echoResult (Left(Var(253)))
                Lam(  # depth 2: key=0, echoResult=1, write=4, syscall8=10
                    App(
                        App(Var(10), nil),  # syscall8(nil)
                        Lam(  # depth 3: sc8Result=0, key=1, write=5, syscall8=11
                            App(
                                App(
                                    App(Var(1), Var(0)),  # (key sc8Result)
                                    Lam(  # depth 4: outer=0, key=2, write=6
                                        App(App(Var(6), encode_string("L\n")), nil)
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
    
    print("1. Sanity check - should print L:")
    payload = bytes([0x0E, 251, FD]) + encode_term(base_check) + bytes([FD, FF])
    test("  result", payload)
    
    # Now at depth 4, outer=0 and it's a Right
    # Right = λl.λr. r x
    # (outer f g) = g x
    # So if we do (outer id handler), handler gets x
    
    extract_v1 = Lam(  # d1
        App(
            App(Var(0),
                Lam(  # d2
                    App(
                        App(Var(10), nil),
                        Lam(  # d3
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(  # d4: outer=0, write=6
                                        # outer is Right(x), apply to id and a handler
                                        App(
                                            App(Var(0), identity),  # outer id
                                            Lam(  # d5: val=0, outer=1, write=7
                                                App(App(Var(7), encode_string("G\n")), nil)
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
    
    print("\n2. (outer id (λval. print G)) - should print G if outer is Right:")
    payload = bytes([0x0E, 251, FD]) + encode_term(extract_v1) + bytes([FD, FF])
    test("  result", payload)
    
    # Now try to write val directly
    extract_val_write = Lam(  # d1
        App(
            App(Var(0),
                Lam(  # d2
                    App(
                        App(Var(10), nil),
                        Lam(  # d3
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(  # d4: outer=0, write=6
                                        App(
                                            App(Var(0), identity),
                                            Lam(  # d5: val=0, write=7
                                                App(App(Var(7), Var(0)), nil)
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
    
    print("\n3. write(val) directly - if val is a string:")
    payload = bytes([0x0E, 251, FD]) + encode_term(extract_val_write) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW: {resp}")
        print(f"  HEX: {resp.hex()}")
    
    # Quote val
    extract_val_quote = Lam(  # d1
        App(
            App(Var(0),
                Lam(  # d2: key=0, write=4, quote=6, syscall8=10
                    App(
                        App(Var(10), nil),
                        Lam(  # d3: sc8=0, key=1, write=5, quote=7
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(  # d4: outer=0, write=6, quote=8
                                        App(
                                            App(Var(0), identity),
                                            Lam(  # d5: val=0, write=7, quote=9
                                                App(
                                                    App(Var(9), Var(0)),  # quote(val)
                                                    Lam(  # d6: qResult=0, val=1, write=8
                                                        App(
                                                            App(Var(0),  # qResult Either
                                                                Lam(  # d7: bytes=0, write=9
                                                                    App(App(Var(9), Var(0)), nil)
                                                                )
                                                            ),
                                                            Lam(App(App(Var(9), encode_string("QF\n")), nil))
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
    
    print("\n4. quote(val) -> write:")
    payload = bytes([0x0E, 251, FD]) + encode_term(extract_val_quote) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW: {resp}")
        print(f"  HEX: {resp.hex()}")
    
    # What if val is ALSO an Either?
    val_as_either = Lam(  # d1
        App(
            App(Var(0),
                Lam(  # d2
                    App(
                        App(Var(10), nil),
                        Lam(  # d3
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(  # d4: outer=0, write=6
                                        App(
                                            App(Var(0), identity),
                                            Lam(  # d5: val=0, write=7
                                                App(
                                                    App(Var(0),  # val as Either
                                                        Lam(App(App(Var(8), encode_string("VL\n")), nil))
                                                    ),
                                                    Lam(App(App(Var(8), encode_string("VR\n")), nil))
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
    
    print("\n5. Is val ALSO an Either? (VL or VR):")
    payload = bytes([0x0E, 251, FD]) + encode_term(val_as_either) + bytes([FD, FF])
    test("  result", payload)
    
    # Apply key (Var(253)) to val
    key_to_val = Lam(  # d1
        App(
            App(Var(0),
                Lam(  # d2: key=0
                    App(
                        App(Var(10), nil),
                        Lam(  # d3: sc8=0, key=1
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(  # d4: outer=0, key=2, write=6
                                        App(
                                            App(Var(0), identity),
                                            Lam(  # d5: val=0, key=3, write=7
                                                App(
                                                    App(
                                                        App(Var(3), Var(0)),  # (key val)
                                                        Lam(App(App(Var(8), encode_string("KL\n")), nil))
                                                    ),
                                                    Lam(App(App(Var(8), encode_string("KR\n")), nil))
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
    
    print("\n6. (key val) -> L or R?:")
    payload = bytes([0x0E, 251, FD]) + encode_term(key_to_val) + bytes([FD, FF])
    test("  result", payload)


if __name__ == "__main__":
    main()
