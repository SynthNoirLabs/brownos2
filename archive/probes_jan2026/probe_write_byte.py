#!/usr/bin/env python3
"""
The inner value is Church byte 1.
Try to write this byte by encoding it properly.

The write syscall expects a list of Church bytes.
Let's wrap our inner Church byte in a list and write it.
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
    print("WRITE THE INNER BYTE AS CHARACTER")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    def cons(h, t):
        return Lam(Lam(App(App(Var(1), h), t)))
    
    print("\nThe inner value 'val' is a Church byte.")
    print("write expects a list of Church bytes.")
    print("So: write(cons(val, nil)) should print the character.\n")
    
    write_byte = Lam(
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
                                                # val = Var(0) at d5
                                                # write = Var(7) at d5
                                                # cons(val, nil) = λc.λn. c val nil
                                                # To build this inline, we need cons function
                                                # Easier: write expects list. Let's build: λc.λn. c val nil
                                                # But val is a Church byte, not sure if direct...
                                                
                                                # Actually simpler: just write [val]
                                                # [val] = cons val nil = λc.λn. c val nil
                                                # At d5, nil shifted becomes different...
                                                # Let me just try:
                                                App(
                                                    App(Var(7),
                                                        Lam(Lam(App(App(Var(1), Var(2)), Lam(Lam(Var(0))))))
                                                    ),
                                                    nil
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
    
    print("1. write(cons(val, nil)):")
    payload = bytes([0x0E, 251, FD]) + encode_term(write_byte) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW: {resp}")
        print(f"  HEX: {resp.hex()}")
    
    # Actually, simpler approach: use syscall 0x2A (42) with the inner value
    # syscall 42 seems to return strings
    
    print("\n2. syscall42(inner_byte):")
    
    sc42_byte = Lam(
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
                                                    App(Var(47), Var(0)),
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
    
    payload = bytes([0x0E, 251, FD]) + encode_term(sc42_byte) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # What if the "answer" syscall expects the result structure directly?
    # syscall42 outer
    
    print("\n3. syscall42(outer) directly:")
    
    sc42_outer = Lam(
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
    
    payload = bytes([0x0E, 251, FD]) + encode_term(sc42_outer) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # What about syscall42 with the FULL transformed result?
    # (key sc8Result) is an Either. Pass to syscall42?
    
    print("\n4. syscall42((key sc8Result)) - the full transform:")
    
    sc42_full = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(Var(45), App(Var(1), Var(0))),
                                Lam(
                                    App(
                                        App(Var(0),
                                            Lam(App(App(Var(8), Var(0)), nil))
                                        ),
                                        Lam(App(App(Var(8), encode_string("42F\n")), nil))
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
    
    payload = bytes([0x0E, 251, FD]) + encode_term(sc42_full) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")


if __name__ == "__main__":
    main()
