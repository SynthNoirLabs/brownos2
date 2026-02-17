#!/usr/bin/env python3
"""
Echo creates unserializable terms (Var 253+).
What if syscall 8 needs THAT unserializable term?

Strategy: echo(Var(251)) creates Var(253) in the VM.
Pass that directly to syscall 8 BEFORE trying to serialize.
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
        elif b"Term too big" in resp:
            resp_str = "Term too big!"
        elif resp_str.startswith("01"):
            resp_str = f"Left! = {resp_str[:60]}"
        elif "000600" in resp_str:
            resp_str = "Right(6) = PermDenied"
        elif "000200" in resp_str:
            resp_str = "Right(2) = InvalidArg"
        elif "000100" in resp_str:
            resp_str = "Right(1) = NoSyscall"
        print(f"{desc:65} -> {resp_str}")
    except Exception as e:
        print(f"{desc:65} -> ERROR: {e}")
    time.sleep(0.15)


def main():
    print("=== Echo then Syscall 8 (no serialization in between) ===\n")
    
    nil = Lam(Lam(Var(0)))
    syscall8 = Var(8)
    echo = Var(0x0E)
    
    print("Strategy: echo creates Left(shifted_term), extract and pass to syscall8\n")
    
    for base_idx in [251, 252, 250, 249, 248]:
        extract_and_syscall8 = Lam(
            App(
                App(Var(0), Lam(
                    App(
                        App(syscall8, Var(0)),
                        Lam(Lam(Var(0)))
                    )
                )),
                Lam(Lam(Var(0)))
            )
        )
        
        payload = (
            bytes([0x0E]) + bytes([base_idx]) + bytes([FD]) +
            encode_term(extract_and_syscall8) + bytes([FD]) +
            QD + bytes([FD, FF])
        )
        test(f"echo(Var({base_idx})) >>= extract Left >>= syscall8", payload)
    
    print("\n=== Double echo for even higher index ===\n")
    
    double_echo_then_sc8 = Lam(
        App(
            App(Var(0), Lam(
                App(
                    App(echo, Var(0)),
                    Lam(
                        App(
                            App(Var(0), Lam(
                                App(
                                    App(syscall8, Var(0)),
                                    Lam(Lam(Var(0)))
                                )
                            )),
                            Lam(Lam(Var(0)))
                        )
                    )
                )
            )),
            Lam(Lam(Var(0)))
        )
    )
    
    payload = (
        bytes([0x0E]) + bytes([249]) + bytes([FD]) +
        encode_term(double_echo_then_sc8) + bytes([FD]) +
        QD + bytes([FD, FF])
    )
    test("echo(249) >>= extract >>= echo >>= extract >>= syscall8", payload)
    
    print("\n=== Use backdoor + echo ===\n")
    
    backdoor_then_echo_then_syscall8 = Lam(
        App(
            App(echo, Var(0)),
            Lam(
                App(
                    App(Var(0), Lam(
                        App(
                            App(syscall8, Var(0)),
                            Lam(Lam(Var(0)))
                        )
                    )),
                    Lam(Lam(Var(0)))
                )
            )
        )
    )
    
    payload = (
        bytes([0xC9]) + encode_term(nil) + bytes([FD]) +
        encode_term(backdoor_then_echo_then_syscall8) + bytes([FD]) +
        QD + bytes([FD, FF])
    )
    test("backdoor(nil) >>= echo >>= extract Left >>= syscall8", payload)
    
    print("\n=== Direct: echo the backdoor pair itself ===\n")
    
    echo_pair_then_sc8 = Lam(
        App(
            App(echo, Var(0)),
            Lam(
                App(
                    App(Var(0), Lam(
                        App(
                            App(syscall8, Var(0)),
                            Lam(Lam(Var(0)))
                        )
                    )),
                    Lam(Lam(Var(0)))
                )
            )
        )
    )
    
    payload = (
        bytes([0xC9]) + encode_term(nil) + bytes([FD]) +
        encode_term(echo_pair_then_sc8) + bytes([FD]) +
        QD + bytes([FD, FF])
    )
    test("backdoor(nil) >>= \\pair. echo(pair) >>= extract >>= syscall8", payload)
    
    print("\n=== Extract A from pair, echo it, then syscall8 ===\n")
    
    I = Lam(Var(0))
    K = Lam(Lam(Var(1)))
    
    extract_A_echo_sc8 = Lam(
        App(
            App(Var(0), I),
            Lam(
                App(
                    App(echo, Var(0)),
                    Lam(
                        App(
                            App(Var(0), Lam(
                                App(
                                    App(syscall8, Var(0)),
                                    Lam(Lam(Var(0)))
                                )
                            )),
                            Lam(Lam(Var(0)))
                        )
                    )
                )
            )
        )
    )
    
    payload = (
        bytes([0xC9]) + encode_term(nil) + bytes([FD]) +
        encode_term(extract_A_echo_sc8) + bytes([FD]) +
        QD + bytes([FD, FF])
    )
    test("backdoor >>= \\p. p I (\\A. echo(A) >>= extract >>= syscall8)", payload)


if __name__ == "__main__":
    main()
