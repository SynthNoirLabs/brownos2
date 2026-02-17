#!/usr/bin/env python3
"""
Properly chain echo and syscall 8 using the client's encoding.
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


def call_syscall(num: int, arg: object) -> bytes:
    payload = bytes([num]) + encode_term(arg) + bytes([FD]) + QD + bytes([FD, FF])
    return query(payload)


def test(desc: str, payload_fn):
    try:
        resp = payload_fn()
        resp_str = resp.hex() if resp else "(empty)"
        if b"Encoding failed" in resp:
            resp_str = "Encoding failed!"
        elif b"Invalid term" in resp:
            resp_str = "Invalid term!"
        elif resp.hex() == "000600fdfefefefefefefefefefdfefeff":
            resp_str = "Right(6) = Permission denied"
        elif b"Term too big" in resp:
            resp_str = "Term too big!"
        print(f"{desc:60} -> {resp_str[:80]}")
    except socket.timeout:
        print(f"{desc:60} -> TIMEOUT")
    except Exception as e:
        print(f"{desc:60} -> ERROR: {e}")
    time.sleep(0.15)


def main():
    print("=== Proper Echo + Syscall 8 Tests ===\n")
    
    nil = Lam(Lam(Var(0)))
    I = Lam(Var(0))
    syscall8 = Var(8)
    echo = Var(0x0E)
    backdoor = Var(0xC9)
    
    test("echo(nil)", lambda: call_syscall(0x0E, nil))
    test("echo(I)", lambda: call_syscall(0x0E, I))
    test("echo(Var(8))", lambda: call_syscall(0x0E, Var(8)))
    test("echo(Var(251))", lambda: call_syscall(0x0E, Var(251)))
    test("echo(Var(252))", lambda: call_syscall(0x0E, Var(252)))
    
    print("\n=== Chained syscalls ===\n")
    
    UNWRAP_LEFT = Lam(Lam(App(Var(1), Var(0))))
    SYSCALL8_NIL = App(App(syscall8, nil), QD)
    
    chain_cont = Lam(App(App(syscall8, Var(0)), Lam(Lam(Var(0)))))
    payload_echo_then_syscall8 = (
        bytes([0x0E]) + encode_term(nil) + bytes([FD]) +
        encode_term(chain_cont) + bytes([FD, FF])
    )
    test("echo(nil) >>= (\\x. syscall8(x) nil)", lambda: query(payload_echo_then_syscall8))
    
    print("\n=== Use extracted from echo ===\n")
    
    test("syscall8(Var(0))", lambda: call_syscall(0x08, Var(0)))
    test("syscall8(Var(1))", lambda: call_syscall(0x08, Var(1)))
    test("syscall8(Var(251))", lambda: call_syscall(0x08, Var(251)))
    test("syscall8(Var(252))", lambda: call_syscall(0x08, Var(252)))
    
    print("\n=== Use backdoor result in syscall 8 ===\n")
    
    chain_backdoor_to_syscall8 = Lam(
        App(
            App(syscall8, Var(0)),
            Lam(Lam(Var(0)))
        )
    )
    payload_bd_sc8 = (
        bytes([0xC9]) + encode_term(nil) + bytes([FD]) +
        encode_term(chain_backdoor_to_syscall8) + bytes([FD, FF])
    )
    test("backdoor(nil) >>= (\\pair. syscall8(pair) nil)", lambda: query(payload_bd_sc8))
    
    extract_A = Lam(App(App(Var(0), I), Lam(Var(1))))
    chain_use_A = Lam(
        App(
            App(
                App(Var(0), I),
                Lam(Var(1))
            ),
            Lam(
                App(
                    App(syscall8, Var(0)),
                    Lam(Lam(Var(0)))
                )
            )
        )
    )
    payload_use_A = (
        bytes([0xC9]) + encode_term(nil) + bytes([FD]) +
        encode_term(chain_use_A) + bytes([FD, FF])
    )
    test("backdoor(nil) >>= (\\pair. pair I K >>= syscall8)", lambda: query(payload_use_A))
    
    print("\n=== Apply backdoor pair to syscall 8 ===\n")
    
    chain_pair_to_sc8 = Lam(
        App(
            App(Var(0), syscall8),
            Lam(Lam(Var(0)))
        )
    )
    payload_pair_sc8 = (
        bytes([0xC9]) + encode_term(nil) + bytes([FD]) +
        encode_term(chain_pair_to_sc8) + bytes([FD, FF])
    )
    test("backdoor(nil) >>= (\\pair. pair syscall8 nil)", lambda: query(payload_pair_sc8))
    
    chain_sc8_to_pair = Lam(
        App(
            App(
                syscall8,
                App(App(Var(0), nil), nil)
            ),
            Lam(Lam(Var(0)))
        )
    )
    payload_sc8_pair = (
        bytes([0xC9]) + encode_term(nil) + bytes([FD]) +
        encode_term(chain_sc8_to_pair) + bytes([FD, FF])
    )
    test("backdoor(nil) >>= (\\pair. syscall8(pair nil nil))", lambda: query(payload_sc8_pair))


if __name__ == "__main__":
    main()
