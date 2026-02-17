#!/usr/bin/env python3
"""
Deep investigation of syscall 8 behavior.

Key finding: ((syscall8 nil) A) returns empty but we can chain writes after.
This means syscall8 DOES return something, but A doesn't print it.

Let's systematically understand what syscall8 actually returns and how to use it.
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
    raise TypeError(f"Unknown term type: {type(term)}")


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
            while True:
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


nil = Lam(Lam(Var(0)))
identity = Lam(Var(0))
A = Lam(Lam(App(Var(0), Var(0))))
B = Lam(Lam(App(Var(1), Var(0))))


def encode_string(s: str):
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


def encode_int(n: int):
    expr = Var(0)
    remaining = n
    for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        while remaining >= weight:
            expr = App(Var(idx), expr)
            remaining -= weight
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def test_syscall8_returns_what():
    print("=" * 70)
    print("WHAT DOES SYSCALL8 ACTUALLY RETURN?")
    print("=" * 70)
    
    print("\n1. With QD continuation (standard debug):")
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    print(f"   Raw: {resp.hex()}")
    
    print("\n2. With custom handler that extracts the Either:")
    handler = Lam(
        App(
            App(Var(0),
                Lam(App(App(Var(4), encode_string("LEFT:")), nil))),
            Lam(App(App(Var(4), encode_string("RIGHT:")), nil))
        )
    )
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(handler) + bytes([FD, FF])
    resp = query(payload)
    print(f"   Response: {resp!r}")


def test_syscall8_with_different_continuations():
    print("\n" + "=" * 70)
    print("SYSCALL8 WITH DIFFERENT CONTINUATION SHAPES")
    print("=" * 70)
    
    continuations = [
        ("QD", QD),
        ("identity (λx.x)", encode_term(identity)),
        ("nil (λλ.0)", encode_term(nil)),
        ("A (λλ.00FD)", encode_term(A)),
        ("B (λλ.10FD)", encode_term(B)),
        ("true (λλ.1)", encode_term(Lam(Lam(Var(1))))),
        ("false (λλ.0)", encode_term(Lam(Lam(Var(0))))),
        ("const_write", encode_term(Lam(App(App(Var(2), encode_string("GOT")), nil)))),
    ]
    
    for name, cont in continuations:
        payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + cont + bytes([FD, FF])
        resp = query(payload, timeout_s=3)
        status = resp.hex()[:40] if resp else "EMPTY"
        print(f"  {name}: {status}")
        time.sleep(0.2)


def test_try_different_args_to_syscall8():
    print("\n" + "=" * 70)
    print("DIFFERENT ARGS TO SYSCALL8 (with write continuation)")
    print("=" * 70)
    
    cont = Lam(
        App(
            App(Var(0),
                Lam(App(App(Var(4), encode_string("L")), nil))),
            Lam(App(App(Var(4), encode_string("R")), nil))
        )
    )
    
    args = [
        ("nil", nil),
        ("identity", identity),
        ("A", A),
        ("B", B),
        ("int 0", encode_int(0)),
        ("int 1", encode_int(1)),
        ("int 8", encode_int(8)),
        ("int 201", encode_int(201)),
        ("int 253", encode_int(253)),
        ("string 'ilikephp'", encode_string("ilikephp")),
    ]
    
    for name, arg in args:
        payload = bytes([0x08]) + encode_term(arg) + bytes([FD]) + encode_term(cont) + bytes([FD, FF])
        resp = query(payload, timeout_s=3)
        print(f"  syscall8({name}): {resp!r}")
        time.sleep(0.2)


def test_backdoor_provides_key():
    print("\n" + "=" * 70)
    print("USE BACKDOOR RESULT WITH SYSCALL8")
    print("=" * 70)
    
    print("\nBackdoor returns pair containing A and B.")
    print("What if we extract A or B and use with syscall8?")
    
    handler_extract_first = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(0), Lam(Lam(Var(1)))),
                        Lam(
                            App(
                                App(Var(11), Var(0)),
                                Lam(
                                    App(
                                        App(Var(0),
                                            Lam(App(App(Var(6), encode_string("L")), nil))),
                                        Lam(App(App(Var(6), encode_string("R")), nil))
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD")), nil))
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(handler_extract_first) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  syscall8(first of backdoor): {resp!r}")


def test_chain_backdoor_echo_syscall8():
    print("\n" + "=" * 70)
    print("CHAIN: BACKDOOR -> ECHO -> SYSCALL8")
    print("=" * 70)
    
    chain = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(16), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
                                        App(
                                            App(Var(12), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(8), encode_string("S8L")), nil))),
                                                    Lam(App(App(Var(8), encode_string("S8R")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("ER")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD")), nil))
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(chain) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  backdoor -> echo -> syscall8: {resp!r}")


def test_try_file_ids_with_syscall8():
    print("\n" + "=" * 70)
    print("TRY FILE/DIR IDS AS ARG TO SYSCALL8")
    print("=" * 70)
    
    cont = Lam(
        App(
            App(Var(0),
                Lam(App(App(Var(4), encode_string("L")), nil))),
            Lam(App(App(Var(4), encode_string("R")), nil))
        )
    )
    
    file_ids = [0, 1, 2, 11, 39, 65, 88, 256]
    
    for fid in file_ids:
        payload = bytes([0x08]) + encode_term(encode_int(fid)) + bytes([FD]) + encode_term(cont) + bytes([FD, FF])
        resp = query(payload, timeout_s=3)
        print(f"  syscall8(id {fid}): {resp!r}")
        time.sleep(0.2)


def test_syscall8_with_readfile_result():
    print("\n" + "=" * 70)
    print("CHAIN: READFILE -> SYSCALL8")
    print("=" * 70)
    
    print("\nTry reading a file and passing its content to syscall8...")
    
    chain = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(9), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), encode_string("L")), nil))),
                                Lam(App(App(Var(6), encode_string("R")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("RF")), nil))
        )
    )
    
    payload = bytes([0x07]) + encode_term(encode_int(65)) + bytes([FD]) + encode_term(chain) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  syscall8(.history content): {resp!r}")


def main():
    test_syscall8_returns_what()
    time.sleep(0.3)
    
    test_syscall8_with_different_continuations()
    time.sleep(0.3)
    
    test_try_different_args_to_syscall8()
    time.sleep(0.3)
    
    test_backdoor_provides_key()
    time.sleep(0.3)
    
    test_chain_backdoor_echo_syscall8()
    time.sleep(0.3)
    
    test_try_file_ids_with_syscall8()
    time.sleep(0.3)
    
    test_syscall8_with_readfile_result()
    
    print("\n" + "=" * 70)
    print("DEEP INVESTIGATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
