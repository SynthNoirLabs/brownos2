#!/usr/bin/env python3
"""
Debug continuations by testing minimal patterns.
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
    print("DEBUG CONTINUATIONS")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print("\n=== Test: QD works ===\n")
    payload = bytes([0x2A, 0x00, FD]) + QD + bytes([FD, FF])
    test("QD on syscall 0x2A", payload)
    
    print("\n=== Test: Identity continuation ===\n")
    identity = Lam(Var(0))
    payload = bytes([0x2A, 0x00, FD]) + encode_term(identity) + bytes([FD, FF])
    test("Identity on syscall 0x2A", payload)
    
    print("\n=== Test: Continuation that ignores result and writes fixed string ===\n")
    
    hello = encode_string("HELLO\n")
    ignore_write = Lam(App(App(Var(2), hello), nil))
    payload = bytes([0x2A, 0x00, FD]) + encode_term(ignore_write) + bytes([FD, FF])
    test("Ignore result, write HELLO", payload)
    
    print("\n=== Test: Direct write without syscall ===\n")
    
    payload = encode_term(Var(2)) + encode_term(hello) + bytes([FD]) + encode_term(nil) + bytes([FD, FF])
    test("Direct: write HELLO nil", payload)
    
    print("\n=== Test: Chain syscall then write ===\n")
    
    syscall_2a = Var(0x2A)
    chain = Lam(App(App(Var(2), encode_string("AFTER\n")), nil))
    payload = encode_term(syscall_2a) + encode_term(nil) + bytes([FD]) + encode_term(chain) + bytes([FD, FF])
    test("syscall 0x2A then write AFTER", payload)
    
    print("\n=== Test: Access the result and print it with QD ===\n")
    
    print_result_with_qd = Lam(
        App(
            App(Var(4), Var(0)),
            Lam(
                App(
                    App(Var(0), Lam(App(App(Var(2), Var(0)), nil))),
                    nil
                )
            )
        )
    )
    payload = bytes([0x2A, 0x00, FD]) + encode_term(print_result_with_qd) + bytes([FD, FF])
    test("syscall 0x2A -> quote -> print", payload)
    
    print("\n=== Test: Simplest possible Either handler ===\n")
    
    left_h = Lam(App(App(Var(2), encode_string("L\n")), nil))
    right_h = Lam(App(App(Var(2), encode_string("R\n")), nil))
    either_test = Lam(App(App(Var(0), left_h), right_h))
    
    print("Testing either on known Left (syscall 0x2A):")
    payload = bytes([0x2A, 0x00, FD]) + encode_term(either_test) + bytes([FD, FF])
    test("syscall 0x2A -> either L/R", payload)
    
    print("\nTesting either on known Right (syscall 8):")
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(either_test) + bytes([FD, FF])
    test("syscall 8(nil) -> either L/R", payload)
    
    print("\n=== Test: Just apply the Either to two args directly ===\n")
    
    raw_either_apply = Lam(
        App(
            App(Var(0), Lam(App(App(Var(2), encode_string("GOT-LEFT\n")), nil))),
            Lam(App(App(Var(2), encode_string("GOT-RIGHT\n")), nil))
        )
    )
    
    print("syscall 0x2A (Left):")
    payload = bytes([0x2A, 0x00, FD]) + encode_term(raw_either_apply) + bytes([FD, FF])
    test("  result", payload)
    
    print("syscall 8 (Right):")
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(raw_either_apply) + bytes([FD, FF])
    test("  result", payload)
    
    print("echo (Left):")
    payload = bytes([0x0E]) + encode_term(nil) + bytes([FD]) + encode_term(raw_either_apply) + bytes([FD, FF])
    test("  result", payload)
    
    print("backdoor (Left):")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(raw_either_apply) + bytes([FD, FF])
    test("  result", payload)


if __name__ == "__main__":
    main()
