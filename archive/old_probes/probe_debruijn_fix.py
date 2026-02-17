#!/usr/bin/env python3
"""
Fix de Bruijn indexing in continuations.

At top level:
  Var(2) = write

Inside λ._:
  Var(0) = bound variable
  Var(3) = what was Var(2) at top = write

Inside λ.λ._:
  Var(0) = inner bound
  Var(1) = outer bound
  Var(4) = what was Var(2) at top = write
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
    print("FIXED DE BRUIJN INDEXING")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print("\n=== Test: Direct write (no lambda) ===\n")
    
    hello = encode_string("HELLO\n")
    payload = bytes([0x02]) + encode_term(hello) + bytes([FD]) + encode_term(nil) + bytes([FD, FF])
    test("write 'HELLO' nil", payload)
    
    print("\n=== Test: Continuation that writes fixed string ===\n")
    print("Inside λ.body, write is Var(3) not Var(2)")
    
    ignore_write_fixed = Lam(App(App(Var(3), hello), nil))
    payload = bytes([0x2A, 0x00, FD]) + encode_term(ignore_write_fixed) + bytes([FD, FF])
    test("syscall 0x2A -> (λ_. write 'HELLO' nil)", payload)
    
    print("\n=== Test: Either handler with correct indices ===\n")
    print("Inside λresult. (result leftH rightH):")
    print("  leftH = λpayload. write payload nil")
    print("  Inside λresult.λpayload, write is Var(4)")
    
    left_h_fixed = Lam(App(App(Var(4), Var(0)), nil))
    right_h_fixed = Lam(App(App(Var(4), encode_string("RIGHT\n")), nil))
    either_fixed = Lam(App(App(Var(0), left_h_fixed), right_h_fixed))
    
    print("\nsyscall 0x2A (Left of bytes):")
    payload = bytes([0x2A, 0x00, FD]) + encode_term(either_fixed) + bytes([FD, FF])
    test("  result", payload)
    
    print("\nsyscall 8 (Right of error code):")
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(either_fixed) + bytes([FD, FF])
    test("  result", payload)
    
    print("\necho (Left):")
    payload = bytes([0x0E]) + encode_term(nil) + bytes([FD]) + encode_term(either_fixed) + bytes([FD, FF])
    test("  result", payload)
    
    print("\nbackdoor (Left of pair):")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(either_fixed) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Test: Print error string for syscall 8 ===\n")
    print("Inside λresult. (result leftH rightH):")
    print("  rightH = λcode. errorString code (λerr. (err leftH' rightH'))")
    print("  where leftH' writes the error string")
    print()
    print("Syscall indices at top level:")
    print("  1 = errorString")
    print("  2 = write")
    print()
    print("Inside 1 lambda: +1 to all")
    print("Inside 2 lambdas: +2 to all")
    print("Inside 3 lambdas: +3 to all")
    
    left_bytes_handler = Lam(App(App(Var(4), Var(0)), nil))
    
    right_code_handler = Lam(
        App(
            App(Var(3), Var(0)),
            Lam(
                App(
                    App(Var(0), Lam(App(App(Var(6), Var(0)), nil))),
                    Lam(App(App(Var(6), encode_string("INNER-RIGHT\n")), nil))
                )
            )
        )
    )
    
    full_either = Lam(App(App(Var(0), left_bytes_handler), right_code_handler))
    
    print("\nsyscall 8 with full error handler:")
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(full_either) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Now chain: echo -> syscall8 with error printing ===\n")
    
    echo_then_sc8 = Lam(
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
                                Lam(
                                    App(
                                        App(Var(4), Var(0)),
                                        Lam(
                                            App(
                                                App(Var(0), Lam(App(App(Var(8), Var(0)), nil))),
                                                nil
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-RIGHT?!\n")), nil))
        )
    )
    
    print("echo(nil) -> Left -> syscall8 -> print error:")
    payload = bytes([0x0E]) + encode_term(nil) + bytes([FD]) + encode_term(echo_then_sc8) + bytes([FD, FF])
    test("  result", payload)
    
    print("\necho(Var(251)) -> Left -> syscall8(Var(253)) -> print error:")
    payload = bytes([0x0E, 251, FD]) + encode_term(echo_then_sc8) + bytes([FD, FF])
    test("  result", payload)


if __name__ == "__main__":
    main()
