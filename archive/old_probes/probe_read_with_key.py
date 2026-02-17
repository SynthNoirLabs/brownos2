#!/usr/bin/env python3
"""
Maybe syscall 8 is meant to be used AFTER reading something?
Or the key transforms file read results?

Let's try reading sensitive files with the key transformation.
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
    print("FILE READ WITH KEY TRANSFORMATION")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    # syscall 7 = read file
    # echo(251) -> key
    # read("/secret") or similar
    # (key readResult) -> ?
    
    files_to_try = [
        "/etc/secret",
        "/secret",
        "/flag",
        "/etc/flag",
        "/home/gizmore/.secret",
        "/answer",
        "/etc/answer",
    ]
    
    for filepath in files_to_try:
        read_and_transform = Lam(
            App(
                App(Var(0),
                    Lam(
                        App(
                            App(Var(9), encode_string(filepath)),
                            Lam(
                                App(
                                    App(
                                        App(Var(2), Var(0)),
                                        Lam(
                                            App(
                                                App(Var(0), identity),
                                                Lam(
                                                    App(
                                                        App(Var(10), Var(0)),
                                                        Lam(
                                                            App(
                                                                App(Var(0),
                                                                    Lam(App(App(Var(13), Var(0)), nil))
                                                                ),
                                                                Lam(App(App(Var(13), encode_string("QF")), nil))
                                                            )
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    ),
                                    Lam(App(App(Var(5), encode_string("R:")), nil))
                                )
                            )
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("E")), nil))
            )
        )
        
        print(f"\nread({filepath}) -> (key result) -> inner -> quote:")
        payload = bytes([0x0E, 251, FD]) + encode_term(read_and_transform) + bytes([FD, FF])
        resp = test(f"  {filepath}", payload)
        if resp and b"QF" not in resp and b"R:" not in resp:
            print(f"  HEX: {resp.hex()}")
    
    # What about just reading and writing the key-transformed result?
    print("\n=== Direct approach: what does syscall 8 return with nil? ===")
    
    # Just check what error code we get
    sc8_err = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), encode_string("L:")), nil))
                                ),
                                Lam(
                                    App(
                                        App(Var(7), Var(0)),
                                        Lam(
                                            App(
                                                App(Var(0),
                                                    Lam(App(App(Var(10), Var(0)), nil))
                                                ),
                                                Lam(App(App(Var(10), encode_string("QF")), nil))
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    print("syscall8(nil) -> Right(errCode) -> quote(errCode):")
    payload = bytes([0x0E, 251, FD]) + encode_term(sc8_err) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # The error code is 6 = Church 6 = λ^9.(Var(3) (Var(2) (Var(1) Var(0))))
    # Let's check if different args give different error codes
    print("\n=== Error codes for different syscall8 args ===")
    
    for arg_name, arg in [("nil", nil), ("id", identity), ("true", Lam(Lam(Var(1))))]:
        sc8_code = Lam(
            App(
                App(Var(0),
                    Lam(
                        App(
                            App(Var(10), arg),
                            Lam(
                                App(
                                    App(Var(0),
                                        Lam(App(App(Var(6), encode_string("L")), nil))
                                    ),
                                    Lam(
                                        App(
                                            App(Var(7), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(10), Var(0)), nil))
                                                    ),
                                                    Lam(App(App(Var(10), encode_string("QF")), nil))
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("E")), nil))
            )
        )
        
        print(f"syscall8({arg_name}) error code:")
        payload = bytes([0x0E, 251, FD]) + encode_term(sc8_code) + bytes([FD, FF])
        resp = test(f"  {arg_name}", payload)
        if resp and b"QF" not in resp and b"L" not in resp:
            print(f"  HEX: {resp.hex()}")


if __name__ == "__main__":
    main()
