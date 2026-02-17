#!/usr/bin/env python3
"""
Try different arguments to syscall 8, then apply Var(253).
Maybe the argument determines WHICH secret we get.
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
    print("SYSCALL 8 WITH DIFFERENT ARGUMENTS + VAR(253)")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    # For each test:
    # echo(251) -> get key
    # syscall8(ARG) -> get result
    # (key result) -> Left(outer)
    # (outer id handler) -> Right(inner)
    # quote(inner) and write
    
    def make_test(arg, arg_name):
        return Lam(
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
                                                        App(Var(9), Var(0)),
                                                        Lam(
                                                            App(
                                                                App(Var(0),
                                                                    Lam(App(App(Var(12), Var(0)), nil))
                                                                ),
                                                                Lam(App(App(Var(12), encode_string("QF")), nil))
                                                            )
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    ),
                                    Lam(App(App(Var(5), encode_string("R")), nil))
                                )
                            )
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("E")), nil))
            )
        )
    
    tests = [
        (nil, "nil"),
        (identity, "id"),
        (Var(0), "Var(0)"),
        (Var(1), "Var(1)"),
        (Lam(Lam(Var(1))), "true"),
        (Lam(Lam(Var(0))), "false"),
        (Lam(App(Var(0), Var(0))), "omega"),
    ]
    
    for arg, name in tests:
        term = make_test(arg, name)
        print(f"\nsyscall8({name}) -> (key result) -> inner -> quote:")
        payload = bytes([0x0E, 251, FD]) + encode_term(term) + bytes([FD, FF])
        resp = test(f"  {name}", payload)
        if resp and b"QF" not in resp and b"R" not in resp and b"E" not in resp:
            print(f"  HEX: {resp.hex()}")
    
    # What about using the KEY itself as argument?
    print("\n=== Using key as syscall8 argument ===")
    
    key_as_arg = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), Var(0)),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
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
                                                            Lam(App(App(Var(12), encode_string("QF")), nil))
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("R")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    print("syscall8(key) -> (key result) -> inner -> quote:")
    payload = bytes([0x0E, 251, FD]) + encode_term(key_as_arg) + bytes([FD, FF])
    resp = test("  key", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # What about using backdoor pair as argument?
    print("\n=== Backdoor pair as syscall8 argument ===")
    
    bd_as_arg = Lam(
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
                                                                        App(Var(14), Var(0)),
                                                                        Lam(
                                                                            App(
                                                                                App(Var(0),
                                                                                    Lam(App(App(Var(17), Var(0)), nil))
                                                                                ),
                                                                                Lam(App(App(Var(17), encode_string("QF")), nil))
                                                                            )
                                                                        )
                                                                    )
                                                                )
                                                            )
                                                        )
                                                    ),
                                                    Lam(App(App(Var(10), encode_string("TR")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("BR")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    print("backdoor -> syscall8(pair) -> (key result) -> inner -> quote:")
    payload = bytes([0x0E, 251, FD]) + encode_term(bd_as_arg) + bytes([FD, FF])
    resp = test("  bd_pair", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")


if __name__ == "__main__":
    main()
