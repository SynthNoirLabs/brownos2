#!/usr/bin/env python3
"""
Fix the Either handling.

Either:
  Left(x)  = λl.λr. l x   -- when given l and r, calls l with x
  Right(y) = λl.λr. r y   -- when given l and r, calls r with y

So to use: (either leftHandler rightHandler)
  If either = Left(x):  result = leftHandler x
  If either = Right(y): result = rightHandler y
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
    print("CORRECT EITHER HANDLING")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    write = Var(2)
    errorString = Var(1)
    
    print("\n=== Either handling: (either leftHandler rightHandler) ===\n")
    
    left_msg = encode_string("LEFT!\n")
    right_msg = encode_string("RIGHT!\n")
    
    left_handler = Lam(App(App(write, left_msg), nil))
    right_handler = Lam(App(App(write, right_msg), nil))
    
    either_cont = Lam(
        App(
            App(Var(0), left_handler),
            right_handler
        )
    )
    
    print("\n=== Test with syscall 0x2A (returns Left) ===\n")
    
    payload = bytes([0x2A, 0x00, FD]) + encode_term(either_cont) + bytes([FD, FF])
    test("syscall 0x2A -> either_cont", payload)
    
    print("\n=== Test with syscall 8 (returns Right) ===\n")
    
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(either_cont) + bytes([FD, FF])
    test("syscall8(nil) -> either_cont", payload)
    
    print("\n=== Test with echo (returns Left) ===\n")
    
    payload = bytes([0x0E]) + encode_term(nil) + bytes([FD]) + encode_term(either_cont) + bytes([FD, FF])
    test("echo(nil) -> either_cont", payload)
    
    print("\n=== Test with backdoor (returns Left) ===\n")
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(either_cont) + bytes([FD, FF])
    test("backdoor(nil) -> either_cont", payload)
    
    print("\n=== Now with actual content printing ===\n")
    
    left_handler_write = Lam(App(App(write, Var(0)), nil))
    right_handler_error = Lam(
        App(
            App(errorString, Var(0)),
            Lam(
                App(
                    App(Var(0), Lam(App(App(write, Var(0)), nil))),
                    nil
                )
            )
        )
    )
    
    either_cont_content = Lam(
        App(
            App(Var(0), left_handler_write),
            right_handler_error
        )
    )
    
    print("\n=== Syscall 0x2A with content print ===\n")
    payload = bytes([0x2A, 0x00, FD]) + encode_term(either_cont_content) + bytes([FD, FF])
    test("syscall 0x2A -> print Left content", payload)
    
    print("\n=== Syscall 8 with content print ===\n")
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(either_cont_content) + bytes([FD, FF])
    test("syscall8(nil) -> print Right error", payload)
    
    print("\n=== Echo then syscall8 in the Left branch ===\n")
    
    echo_then_sc8 = Lam(
        App(
            App(
                Var(0),
                Lam(
                    App(
                        App(Var(8), Var(0)),
                        Lam(
                            App(
                                App(Var(0), Lam(App(App(write, encode_string("SC8 LEFT!")), nil))),
                                Lam(App(App(write, encode_string("SC8 RIGHT!")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(write, encode_string("ECHO RIGHT?!")), nil))
        )
    )
    
    payload = bytes([0x0E]) + encode_term(nil) + bytes([FD]) + encode_term(echo_then_sc8) + bytes([FD, FF])
    test("echo(nil) -> Left -> syscall8(payload) -> branch", payload)
    
    print("\n=== Echo(Var(251)) then syscall8 ===\n")
    
    echo_var_then_sc8 = Lam(
        App(
            App(
                Var(0),
                Lam(
                    App(
                        App(Var(8), Var(0)),
                        Lam(
                            App(
                                App(Var(0), Lam(App(App(write, encode_string("LEFT!")), nil))),
                                Lam(App(App(write, encode_string("RIGHT!")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(write, encode_string("ECHO-RIGHT")), nil))
        )
    )
    
    for base in [251, 252, 250]:
        payload = bytes([0x0E, base, FD]) + encode_term(echo_var_then_sc8) + bytes([FD, FF])
        test(f"echo(Var({base})) -> Left -> syscall8(Var({base+2}))", payload)
        time.sleep(0.3)


if __name__ == "__main__":
    main()
