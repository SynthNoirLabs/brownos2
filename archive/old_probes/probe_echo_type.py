#!/usr/bin/env python3
"""
Echo returns Left(term), not Left(bytes).
Let's verify and work with this.
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
        result = "(empty/timeout)"
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
    print("ECHO TYPE ANALYSIS")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print("\n=== Test: echo(nil) with QD (should work - quote can encode nil+2) ===\n")
    
    payload = bytes([0x0E]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    test("echo(nil) -> QD", payload)
    
    print("\n=== Test: echo(Var(0)) with QD ===\n")
    
    payload = bytes([0x0E, 0x00, FD]) + QD + bytes([FD, FF])
    test("echo(Var(0)) -> QD (becomes Var(2))", payload)
    
    print("\n=== Test: echo(Var(251)) with QD ===\n")
    
    payload = bytes([0x0E, 251, FD]) + QD + bytes([FD, FF])
    test("echo(Var(251)) -> QD (becomes Var(253) = FD!)", payload)
    
    print("\n=== Test: echo then extract Left, then APPLY it ===\n")
    print("If echo returns Left(term), maybe we can USE the term, not print it")
    
    echo_extract_apply = Lam(
        App(
            App(Var(0),
                Lam(
                    App(Var(0), nil)
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-RIGHT\n")), nil))
        )
    )
    
    print("echo(nil) -> extract Left(term) -> apply term to nil:")
    payload = bytes([0x0E]) + encode_term(nil) + bytes([FD]) + encode_term(echo_extract_apply) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Test: echo then use result with syscall 8 ===\n")
    
    echo_sc8_chain = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(9), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), encode_string("SC8-LEFT!\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("SC8-RIGHT!\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-RIGHT\n")), nil))
        )
    )
    
    print("echo(nil) -> syscall8(nil+2):")
    payload = bytes([0x0E]) + encode_term(nil) + bytes([FD]) + encode_term(echo_sc8_chain) + bytes([FD, FF])
    test("  result", payload)
    
    print("\necho(Var(251)) -> syscall8(Var(253)):")
    payload = bytes([0x0E, 251, FD]) + encode_term(echo_sc8_chain) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Test: backdoor then use pair with syscall 8 ===\n")
    
    backdoor_sc8_chain = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(9), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), encode_string("SC8-LEFT!\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("SC8-RIGHT!\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD-RIGHT\n")), nil))
        )
    )
    
    print("backdoor(nil) -> syscall8(pair):")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_sc8_chain) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Test: simpler - just print a fixed string after echo ===\n")
    
    echo_then_print = Lam(
        App(
            App(Var(0),
                Lam(App(App(Var(4), encode_string("GOT-LEFT\n")), nil))
            ),
            Lam(App(App(Var(4), encode_string("GOT-RIGHT\n")), nil))
        )
    )
    
    print("echo(nil) -> print 'GOT-LEFT' or 'GOT-RIGHT':")
    payload = bytes([0x0E]) + encode_term(nil) + bytes([FD]) + encode_term(echo_then_print) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Test: use QD inside continuation ===\n")
    
    echo_then_qd_left = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(5), Var(0)),
                        Lam(
                            App(
                                App(Var(0), Lam(App(App(Var(5), Var(0)), nil))),
                                nil
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-RIGHT\n")), nil))
        )
    )
    
    print("echo(nil) -> extract Left -> quote -> write:")
    payload = bytes([0x0E]) + encode_term(nil) + bytes([FD]) + encode_term(echo_then_qd_left) + bytes([FD, FF])
    test("  result", payload)


if __name__ == "__main__":
    main()
