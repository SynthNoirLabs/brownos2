#!/usr/bin/env python3
"""
VAR(253) TRANSFORMS SYSCALL 8's RESULT!

When we do (Var(253) sc8Result) and branch on it as Either, we get LEFT!
This suggests Var(253) might be a key that unlocks syscall 8.

Let's extract what's in that Left!
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
PORT = 61221

FD, FE, FF = 0xFD, 0xFE, 0xFF
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


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


def query(payload: bytes, timeout_s: float = 5.0) -> bytes:
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
            result = f"OUTPUT: {repr(text[:100])}"
        except:
            result = f"hex: {resp.hex()[:100]}"
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
    print("VAR(253) TRANSFORMS SYSCALL 8 RESULT!")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print("\n=== EXTRACT the Left payload from (Var(253) sc8Result) ===\n")
    
    extract_left_payload = Lam(
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
                                        App(App(Var(6), Var(0)), nil)
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("STILL-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("(Var(253) sc8Result) -> Left(payload) -> write(payload):")
    payload = bytes([0x0E, 251, FD]) + encode_term(extract_left_payload) + bytes([FD, FF])
    resp = test("  result", payload)
    
    print("\n=== Try to QUOTE the Left payload ===\n")
    
    quote_left_payload = Lam(
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
                                            App(Var(7), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(8), Var(0)), nil))
                                                    ),
                                                    nil
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("STILL-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("(Var(253) sc8Result) -> Left(payload) -> quote(payload) -> write:")
    payload = bytes([0x0E, 251, FD]) + encode_term(quote_left_payload) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Maybe payload IS bytes - try to write them directly ===\n")
    
    write_bytes_directly = Lam(
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
                                        App(App(Var(5), Var(0)), nil)
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER\n")), nil))
        )
    )
    
    print("(Var(253) sc8Result) -> Left(bytes?) -> write(bytes):")
    payload = bytes([0x0E, 251, FD]) + encode_term(write_bytes_directly) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  Raw bytes: {resp}")
        print(f"  Hex: {resp.hex()}")
    
    print("\n=== What if Var(254) or Var(255) also work? ===\n")
    
    for base in [250, 251, 252]:
        var_num = base + 2
        
        test_transform = Lam(
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
                                            App(App(Var(5), Var(0)), nil)
                                        )
                                    ),
                                    Lam(App(App(Var(5), encode_string("R\n")), nil))
                                )
                            )
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("ER\n")), nil))
            )
        )
        
        payload = bytes([0x0E, base, FD]) + encode_term(test_transform) + bytes([FD, FF])
        resp = test(f"Var({var_num}) transform", payload)
        if resp and b"R\n" not in resp and b"ER\n" not in resp:
            print(f"  RAW: {resp}")
        time.sleep(0.2)
    
    print("\n=== Let's try ALL the transforms ===\n")
    
    for echo_arg in range(245, 253):
        var_num = echo_arg + 2
        
        test_transform = Lam(
            App(
                App(Var(0),
                    Lam(
                        App(
                            App(Var(10), nil),
                            Lam(
                                App(
                                    App(
                                        App(Var(1), Var(0)),
                                        Lam(App(App(Var(5), Var(0)), nil))
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
        
        payload = bytes([0x0E, echo_arg, FD]) + encode_term(test_transform) + bytes([FD, FF])
        resp = test(f"Var({var_num})", payload)
        time.sleep(0.15)


if __name__ == "__main__":
    main()
