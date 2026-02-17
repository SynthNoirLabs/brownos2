#!/usr/bin/env python3
"""
Test the simplest possible write-based continuations.
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
    raise TypeError(f"Unknown term: {term}")


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
    print("SIMPLE WRITE-BASED CONTINUATION TESTS")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    write = Var(2)
    
    print("\n=== Test 1: Write a literal string directly ===\n")
    
    hello = encode_string("Hello\n")
    payload = encode_term(write) + encode_term(hello) + bytes([FD]) + encode_term(nil) + bytes([FD, FF])
    test("write('Hello')", payload)
    
    print("\n=== Test 2: Use QD on syscall 0x2A (should work) ===\n")
    
    payload = bytes([0x2A, 0x00, FD]) + QD + bytes([FD, FF])
    test("syscall 0x2A with QD", payload)
    
    print("\n=== Test 3: Syscall 1 (errorString) then write ===\n")
    
    int_6 = Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(
        App(Var(2), App(Var(3), Var(0)))
    )))))))))
    
    error_then_write = Lam(
        App(
            App(
                Var(0),
                Lam(App(App(write, Var(0)), nil))
            ),
            nil
        )
    )
    
    payload = bytes([0x01]) + encode_term(int_6) + bytes([FD]) + encode_term(error_then_write) + bytes([FD, FF])
    test("errorString(6) -> write", payload)
    
    print("\n=== Test 4: Direct syscall 8 with simple continuation ===\n")
    
    simple_print_either = Lam(
        App(
            App(
                Var(0),
                Lam(App(App(write, Var(0)), nil))
            ),
            Lam(
                App(
                    App(Var(1), Var(0)),
                    Lam(
                        App(
                            App(
                                Var(0),
                                Lam(App(App(write, Var(0)), nil))
                            ),
                            nil
                        )
                    )
                )
            )
        )
    )
    
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(simple_print_either) + bytes([FD, FF])
    test("syscall8(nil) -> simple either handler", payload)
    
    print("\n=== Test 5: Even simpler - just pass to Left branch ===\n")
    
    just_left = Lam(
        App(
            App(Var(0), Lam(App(App(write, Var(0)), nil))),
            nil
        )
    )
    
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(just_left) + bytes([FD, FF])
    test("syscall8(nil) -> extract Left -> write", payload)
    
    print("\n=== Test 6: Using QD on syscall 8 for comparison ===\n")
    
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    test("syscall8(nil) with QD", payload)
    
    print("\n=== Test 7: Echo then extract then print with write ===\n")
    
    echo_extract_write = Lam(
        App(
            App(Var(0), Lam(App(App(write, encode_string("Got Left!")), nil))),
            Lam(App(App(write, encode_string("Got Right!")), nil))
        )
    )
    
    payload = bytes([0x0E]) + encode_term(nil) + bytes([FD]) + encode_term(echo_extract_write) + bytes([FD, FF])
    test("echo(nil) -> branch on Left/Right", payload)
    
    print("\n=== Test 8: Backdoor then print which branch ===\n")
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(echo_extract_write) + bytes([FD, FF])
    test("backdoor(nil) -> branch on Left/Right", payload)


if __name__ == "__main__":
    main()
