#!/usr/bin/env python3
"""
Author hints:
1. "combining special bytes froze my system" - FD/FE/FF
2. "why would an OS even need an echo?" - echo is key

Echo creates Left(Var(n+2)) from Var(n).
- echo(Var(251)) → Left(Var(253)) where 253 = FD
- echo(Var(252)) → Left(Var(254)) where 254 = FE  
- echo(Var(253)) → Left(Var(255)) where 255 = FF

What if we:
1. Create a term with special indices inside it
2. Pass that term to syscall 8 or another syscall
3. The "special" term triggers different behavior

Or what if we can construct a term that, when quoted (serialized),
produces a DIFFERENT program that gets executed?
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


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError


def query(payload: bytes, timeout_s: float = 5.0) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except:
            pass
        sock.settimeout(timeout_s)
        out = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                out += chunk
                if FF in chunk:
                    break
            except socket.timeout:
                break
        return out


def test(desc: str, payload: bytes) -> None:
    try:
        resp = query(payload)
        if not resp:
            print(f"{desc}: (empty)")
        elif b"Encoding failed" in resp:
            print(f"{desc}: Encoding failed!")
        elif b"Invalid term" in resp:
            print(f"{desc}: Invalid term!")
        elif b"Term too big" in resp:
            print(f"{desc}: Term too big!")
        elif resp.hex().startswith("01"):
            print(f"{desc}: Left! len={len(resp)} hex={resp.hex()[:60]}")
        else:
            print(f"{desc}: {resp.hex()[:80]}")
    except Exception as e:
        print(f"{desc}: ERROR - {e}")
    time.sleep(0.2)


def main():
    print("=== Special Bytes Investigation ===\n")
    
    nil = Lam(Lam(Var(0)))
    echo = Var(0x0E)
    syscall8 = Var(8)
    
    print("1. Echo high variables to manufacture special indices:\n")
    
    for i in [250, 251, 252, 253]:
        cont = Lam(Var(0))
        payload = bytes([0x0E, i, FD]) + encode_term(cont) + bytes([FD, FF])
        test(f"echo(Var({i})) → identity", payload)
    
    print("\n2. Chain echoes to get even higher:\n")
    
    extract_echo = Lam(
        App(
            App(Var(0), Lam(App(App(echo, Var(0)), Lam(Var(0))))),
            nil
        )
    )
    
    for i in [249, 250, 251]:
        payload = bytes([0x0E, i, FD]) + encode_term(extract_echo) + bytes([FD, FF])
        test(f"echo({i}) → extract → echo → identity", payload)
    
    print("\n3. Try raw special bytes in payloads (parser tricks):\n")
    
    raw_payloads = [
        ("FD FD FD FF", bytes([FD, FD, FD, FF])),
        ("FE FE FE FF", bytes([FE, FE, FE, FF])),
        ("00 FD FD FF", bytes([0x00, FD, FD, FF])),
        ("00 FE FD FF", bytes([0x00, FE, FD, FF])),
        ("00 00 FD FE FF", bytes([0x00, 0x00, FD, FE, FF])),
        ("C9 00 FE FE FD 08 FD FF", bytes([0xC9, 0x00, FE, FE, FD, 0x08, FD, FF])),
    ]
    
    for desc, payload in raw_payloads:
        test(desc, payload)
    
    print("\n4. Echo then pass to write (output the special term):\n")
    
    write = Var(2)
    quote = Var(4)
    
    for i in [251, 252]:
        extract_then_write = Lam(
            App(
                App(Var(0), Lam(App(App(write, Var(0)), nil))),
                nil
            )
        )
        payload = bytes([0x0E, i, FD]) + encode_term(extract_then_write) + bytes([FD, FF])
        test(f"echo({i}) → extract → write", payload)
    
    print("\n5. What if we quote the echoed term?\n")
    
    for i in [251, 252]:
        extract_then_quote = Lam(
            App(
                App(Var(0), Lam(App(App(quote, Var(0)), Lam(Var(0))))),
                nil
            )
        )
        payload = bytes([0x0E, i, FD]) + encode_term(extract_then_quote) + bytes([FD, FF])
        test(f"echo({i}) → extract → quote", payload)
    
    print("\n6. Backdoor + echo combination:\n")
    
    backdoor_echo_cont = Lam(
        App(
            App(echo, Var(0)),
            Lam(
                App(
                    App(Var(0), Lam(
                        App(App(write, Var(0)), nil)
                    )),
                    nil
                )
            )
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_echo_cont) + bytes([FD, FF])
    test("backdoor(nil) → echo(pair) → extract → write", payload)
    
    print("\n7. Raw injection: what if we send bytes that look like a program?\n")
    
    injections = [
        ("07 0B ... QD", bytes([0x07, 0x0B]) + bytes([FE]*9) + bytes([FD]) + QD + bytes([FD, FF])),
        ("Direct syscall 42", bytes([0x2A, 0x00, FD]) + QD + bytes([FD, FF])),
    ]
    
    for desc, payload in injections:
        test(desc, payload)


if __name__ == "__main__":
    main()
