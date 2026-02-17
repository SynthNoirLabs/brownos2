#!/usr/bin/env python3
"""
Focused test: Use backdoor result to unlock syscall 8.

Hypothesis: The backdoor pair contains the "key" to syscall 8.
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
            resp_str = f"Right(6) = Permission denied [{resp.hex()[:40]}]"
        elif b"Term too big" in resp:
            resp_str = "Term too big!"
        print(f"{desc:60} -> {resp_str[:80]}")
    except Exception as e:
        print(f"{desc:60} -> ERROR: {e}")
    time.sleep(0.15)


def main():
    print("=== Backdoor as Key to Syscall 8 ===\n")
    
    nil = Lam(Lam(Var(0)))
    I = Lam(Var(0))
    K = Lam(Lam(Var(1)))
    syscall8 = Var(8)
    
    print("Test 1: Call syscall8 with the pair itself\n")
    
    cont1 = Lam(App(App(syscall8, Var(0)), Lam(Lam(Var(0)))))
    payload1 = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(cont1) + bytes([FD]) + QD + bytes([FD, FF])
    test("backdoor >>= \\pair. syscall8(pair)", payload1)
    
    print("\nTest 2: Extract A from pair, pass to syscall8\n")
    
    extract_A_cont = Lam(
        App(
            App(Var(0), I),
            Lam(
                App(
                    App(syscall8, Var(0)),
                    Lam(Lam(Var(0)))
                )
            )
        )
    )
    payload2 = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(extract_A_cont) + bytes([FD]) + QD + bytes([FD, FF])
    test("backdoor >>= \\pair. pair I (\\A. syscall8(A))", payload2)
    
    print("\nTest 3: Extract B from pair, pass to syscall8\n")
    
    extract_B_cont = Lam(
        App(
            App(Var(0), K),
            Lam(
                App(
                    App(syscall8, Var(0)),
                    Lam(Lam(Var(0)))
                )
            )
        )
    )
    payload3 = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(extract_B_cont) + bytes([FD]) + QD + bytes([FD, FF])
    test("backdoor >>= \\pair. pair K (\\B. syscall8(B))", payload3)
    
    print("\nTest 4: Apply pair to syscall8 directly\n")
    
    pair_to_sc8 = Lam(
        App(
            App(Var(0), syscall8),
            Lam(Lam(Var(0)))
        )
    )
    payload4 = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(pair_to_sc8) + bytes([FD]) + QD + bytes([FD, FF])
    test("backdoor >>= \\pair. pair syscall8", payload4)
    
    print("\nTest 5: A applied to syscall8\n")
    
    A_to_sc8 = Lam(
        App(
            App(Var(0), I),
            Lam(
                App(
                    App(Var(0), syscall8),
                    Lam(Lam(Var(0)))
                )
            )
        )
    )
    payload5 = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(A_to_sc8) + bytes([FD]) + QD + bytes([FD, FF])
    test("backdoor >>= \\pair. pair I (\\A. A syscall8)", payload5)
    
    print("\nTest 6: B applied to syscall8\n")
    
    B_to_sc8 = Lam(
        App(
            App(Var(0), K),
            Lam(
                App(
                    App(Var(0), syscall8),
                    Lam(Lam(Var(0)))
                )
            )
        )
    )
    payload6 = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(B_to_sc8) + bytes([FD]) + QD + bytes([FD, FF])
    test("backdoor >>= \\pair. pair K (\\B. B syscall8)", payload6)
    
    print("\nTest 7: syscall8(A B) where A and B are extracted\n")
    
    both_extracted = Lam(
        App(
            App(Var(0), I),
            Lam(
                App(
                    App(Var(1), K),
                    Lam(
                        App(
                            App(syscall8, App(Var(1), Var(0))),
                            Lam(Lam(Var(0)))
                        )
                    )
                )
            )
        )
    )
    payload7 = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(both_extracted) + bytes([FD]) + QD + bytes([FD, FF])
    test("backdoor >>= extract A, B -> syscall8(A B)", payload7)
    
    print("\nTest 8: syscall8(B A)\n")
    
    both_reversed = Lam(
        App(
            App(Var(0), I),
            Lam(
                App(
                    App(Var(1), K),
                    Lam(
                        App(
                            App(syscall8, App(Var(0), Var(1))),
                            Lam(Lam(Var(0)))
                        )
                    )
                )
            )
        )
    )
    payload8 = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(both_reversed) + bytes([FD]) + QD + bytes([FD, FF])
    test("backdoor >>= extract A, B -> syscall8(B A)", payload8)


if __name__ == "__main__":
    main()
