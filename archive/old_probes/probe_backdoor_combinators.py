#!/usr/bin/env python3
"""
Use backdoor combinators A and B with syscall 8.

Backdoor returns pair(A, B) where:
- A = λab.bb (self-apply second)
- B = λab.ab (apply first to second)

The "mail points to the way" - maybe we need to construct something using A and B.
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

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
    raise TypeError(f"Unsupported: {type(term)}")


def query(payload: bytes, timeout_s: float = 5.0) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
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
                if FF in chunk:
                    break
            except socket.timeout:
                break
        return out


def test(desc: str, payload: bytes) -> None:
    try:
        resp = query(payload)
        resp_str = resp.hex() if resp else "(empty)"
        if b"Encoding failed" in resp:
            resp_str = "Encoding failed!"
        elif b"Invalid term" in resp:
            resp_str = "Invalid term!"
        elif "000600fdfe" in resp.hex():
            resp_str = "Right(6) = Permission denied"
        elif b"Term too big" in resp:
            resp_str = "Term too big!"
        print(f"{desc:60} -> {resp_str[:80]}")
    except Exception as e:
        print(f"{desc:60} -> ERROR: {e}")
    time.sleep(0.15)


def main():
    print("=== Backdoor Combinators with Syscall 8 ===\n")
    
    nil = Lam(Lam(Var(0)))
    I = Lam(Var(0))
    K = Lam(Lam(Var(1)))
    syscall8 = Var(8)
    backdoor = Var(0xC9)
    
    A = Lam(Lam(App(Var(0), Var(0))))
    B = Lam(Lam(App(Var(1), Var(0))))
    
    omega = Lam(App(Var(0), Var(0)))
    
    print("Direct tests with standalone A and B:\n")
    
    tests = [
        ("syscall8(A)", bytes([0x08]) + encode_term(A) + bytes([FD]) + QD + bytes([FD, FF])),
        ("syscall8(B)", bytes([0x08]) + encode_term(B) + bytes([FD]) + QD + bytes([FD, FF])),
        ("syscall8(omega)", bytes([0x08]) + encode_term(omega) + bytes([FD]) + QD + bytes([FD, FF])),
        
        ("(A syscall8 nil)", encode_term(App(App(A, syscall8), nil)) + QD + bytes([FD, FF])),
        ("(B syscall8 nil)", encode_term(App(App(B, syscall8), nil)) + QD + bytes([FD, FF])),
        
        ("((A nil) syscall8)", encode_term(App(App(A, nil), syscall8)) + QD + bytes([FD, FF])),
        ("((B nil) syscall8)", encode_term(App(App(B, nil), syscall8)) + QD + bytes([FD, FF])),
    ]
    
    for desc, payload in tests:
        test(desc, payload)
    
    print("\n=== Using backdoor result inline ===\n")
    
    use_first = Lam(
        App(
            App(Var(0), I),
            K
        )
    )
    
    use_second = Lam(
        App(
            App(Var(0), K),
            I
        )
    )
    
    backdoor_use_A = (
        bytes([0xC9]) + encode_term(nil) + bytes([FD]) +
        Lam(
            App(
                App(
                    App(App(Var(0), I), K),
                    syscall8
                ),
                Lam(Lam(Var(0)))
            )
        ).__class__.__name__
    )
    
    pair_apply_to_syscall8 = Lam(
        App(
            App(Var(0), syscall8),
            Lam(Lam(Var(0)))
        )
    )
    payload1 = (
        bytes([0xC9]) + encode_term(nil) + bytes([FD]) +
        encode_term(pair_apply_to_syscall8) + bytes([FD, FF])
    )
    test("backdoor(nil) >>= \\p. p syscall8 nil", payload1)
    
    pair_apply_sc8_to_nil = Lam(
        App(
            App(Var(0), Lam(Lam(App(Var(0), nil)))),
            Lam(Lam(App(App(syscall8, nil), Var(0))))
        )
    )
    payload2 = (
        bytes([0xC9]) + encode_term(nil) + bytes([FD]) +
        encode_term(pair_apply_sc8_to_nil) + bytes([FD, FF])
    )
    test("backdoor(nil) >>= complex", payload2)
    
    print("\n=== Try syscall8 INSIDE the CPS chain ===\n")
    
    inner_syscall8 = Lam(
        App(
            App(
                syscall8,
                Var(0)
            ),
            Lam(Lam(Var(0)))
        )
    )
    
    payload3 = (
        bytes([0xC9]) + encode_term(nil) + bytes([FD]) +
        encode_term(inner_syscall8) + bytes([FD]) +
        QD + bytes([FD, FF])
    )
    test("(backdoor(nil) inner_syscall8) QD", payload3)
    
    print("\n=== Nested CPS: backdoor first, then syscall8 ===\n")
    
    nested_cps = Lam(
        App(
            App(
                syscall8,
                App(App(Var(0), I), K)
            ),
            Lam(Lam(Var(0)))
        )
    )
    payload4 = (
        bytes([0xC9]) + encode_term(nil) + bytes([FD]) +
        encode_term(nested_cps) + bytes([FD]) +
        QD + bytes([FD, FF])
    )
    test("backdoor(nil) >>= \\p. (syscall8 (p I K)) nil >> QD", payload4)
    
    print("\n=== Applying pair to echo and syscall8 ===\n")
    
    pair_with_echo = Lam(
        App(
            App(Var(0), Var(0x0E)),
            Lam(Lam(App(Var(0), Var(0))))
        )
    )
    payload5 = (
        bytes([0xC9]) + encode_term(nil) + bytes([FD]) +
        encode_term(pair_with_echo) + bytes([FD]) +
        QD + bytes([FD, FF])
    )
    test("backdoor(nil) >>= \\p. (p echo) selfapp >> QD", payload5)


if __name__ == "__main__":
    main()
