#!/usr/bin/env python3
"""
We got byte value 1.
What if this is:
1. An index into something
2. A key/password
3. The first byte of an answer

Let's try various interpretations.
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
    print("INTERPRETING BYTE VALUE 1")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    # Maybe syscall8(Church1) gives the answer?
    print("\n1. syscall8(Church1) with transform:")
    
    church1 = Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(App(Var(1), Var(0)))))))))))
    
    sc8_church1 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), church1),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(
                                        App(
                                            App(Var(0), identity),
                                            Lam(
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
    
    payload = bytes([0x0E, 251, FD]) + encode_term(sc8_church1) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW: {resp}")
    
    # Use the inner byte as syscall8 argument
    print("\n2. Get inner byte, use as syscall8 arg, transform again:")
    
    chain_byte = Lam(
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
                                                # inner byte is Var(0)
                                                # Use it as arg to another syscall8
                                                App(
                                                    App(Var(13), Var(0)),
                                                    Lam(
                                                        App(
                                                            App(
                                                                App(Var(4), Var(0)),
                                                                Lam(
                                                                    App(
                                                                        App(Var(0), identity),
                                                                        Lam(
                                                                            App(
                                                                                App(Var(11),
                                                                                    Lam(Lam(App(App(Var(1), Var(2)), Lam(Lam(Var(0))))))
                                                                                ),
                                                                                nil
                                                                            )
                                                                        )
                                                                    )
                                                                )
                                                            ),
                                                            Lam(App(App(Var(9), encode_string("2R\n")), nil))
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("1R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(chain_byte) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW: {resp}")
    
    # What if "1" means file descriptor 1 = stdout?
    # Or directory index 1?
    
    print("\n3. Read file at index 1 (maybe /etc/passwd line 1?):")
    
    read_line1 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(9), encode_string("/etc/passwd")),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
                                        # Got file contents - first line?
                                        # contents is a list of bytes
                                        # Take bytes until newline
                                        App(App(Var(6), Var(0)), nil)
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("RF\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(read_line1) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp and b"RF" not in resp:
        print(f"  (first 100 chars)")


if __name__ == "__main__":
    main()
