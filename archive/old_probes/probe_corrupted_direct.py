#!/usr/bin/env python3
"""
Feed corrupted terms to syscall 8 DIRECTLY via backdoor bypass.

The key: echo creates Var(253/254/255) internally, which can't be serialized.
We must use these terms IN THE SAME PROGRAM without trying to quote/serialize them.

Strategy: echo -> extract Left -> pass directly to syscall 8 -> use backdoor B as continuation
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


def query(payload: bytes, timeout_s: float = 8.0) -> bytes:
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


def test(desc: str, payload: bytes) -> str:
    resp = query(payload)
    if not resp:
        result = "(empty/timeout)"
    elif b"Encoding failed" in resp:
        result = "Encoding failed!"
    elif b"Invalid term" in resp:
        result = "Invalid term!"
    elif b"Term too big" in resp:
        result = "Term too big!"
    elif resp.hex().startswith("01"):
        result = f"Left! len={len(resp)}"
    else:
        result = resp.hex()[:60]
    print(f"{desc}: {result}")
    return result


def main():
    print("=" * 70)
    print("CORRUPTED TERMS DIRECTLY TO SYSCALL 8")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    syscall8 = Var(8)
    echo = Var(0x0E)
    write = Var(2)
    
    print("\n=== Strategy: echo(Var(N)) -> extract -> syscall8 -> backdoor B as cont ===\n")
    print("B = λab.ab applies first arg to second, so if syscall8 returns result,")
    print("B result nil = result nil might produce output\n")
    
    B = Lam(Lam(App(Var(1), Var(0))))
    
    for base in [251, 252, 250, 249]:
        extract_to_sc8_B = Lam(
            App(
                App(Var(0), Lam(
                    App(App(syscall8, Var(0)), B)
                )),
                nil
            )
        )
        payload = bytes([0x0E, base, FD]) + encode_term(extract_to_sc8_B) + bytes([FD, FF])
        test(f"echo(Var({base})) -> extract -> syscall8(Var({base+2})) -> B", payload)
        time.sleep(0.2)
    
    print("\n=== Chain: backdoor -> get pair -> use A as syscall8 arg, B as cont ===\n")
    
    backdoor_pair_sc8 = Lam(
        App(
            App(Var(0), Lam(Lam(
                App(App(syscall8, Var(1)), Var(0))
            ))),
            nil
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_pair_sc8) + bytes([FD, FF])
    test("backdoor -> pair (λA.λB. syscall8 A B) nil", payload)
    time.sleep(0.2)
    
    print("\n=== Echo the backdoor pair, then use shifted result ===\n")
    
    backdoor_then_echo_sc8 = Lam(
        App(
            App(echo, Var(0)),
            Lam(
                App(
                    App(Var(0), Lam(
                        App(App(syscall8, Var(0)), nil)
                    )),
                    nil
                )
            )
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_then_echo_sc8) + bytes([FD, FF])
    test("backdoor -> echo(pair) -> extract -> syscall8", payload)
    time.sleep(0.2)
    
    print("\n=== Use write directly as continuation (no QD) ===\n")
    
    for base in [251, 252]:
        extract_sc8_write = Lam(
            App(
                App(Var(0), Lam(
                    App(App(syscall8, Var(0)), write)
                )),
                nil
            )
        )
        payload = bytes([0x0E, base, FD]) + encode_term(extract_sc8_write) + bytes([FD, FF])
        test(f"echo(Var({base})) -> extract -> syscall8 -> write", payload)
        time.sleep(0.2)
    
    print("\n=== Triple chain: backdoor -> echo -> syscall8 ===\n")
    
    triple_chain = Lam(
        App(
            App(echo, Var(0)),
            Lam(
                App(
                    App(Var(0), Lam(
                        App(
                            App(echo, Var(0)),
                            Lam(
                                App(
                                    App(Var(0), Lam(
                                        App(App(syscall8, Var(0)), nil)
                                    )),
                                    nil
                                )
                            )
                        )
                    )),
                    nil
                )
            )
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(triple_chain) + bytes([FD, FF])
    test("backdoor -> echo -> extract -> echo -> extract -> syscall8", payload)
    time.sleep(0.2)
    
    print("\n=== Use backdoor B combinator as direct continuation ===\n")
    
    backdoor_extract_B_then_sc8 = Lam(
        App(
            App(Var(0), Lam(Lam(Var(0)))),
            Lam(
                App(App(syscall8, Var(251)), Var(0))
            )
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_extract_B_then_sc8) + bytes([FD, FF])
    test("backdoor -> extract B -> syscall8(Var(251), B)", payload)
    time.sleep(0.2)
    
    print("\n=== Minimal: use raw bytes for echo + syscall8 ===\n")
    
    raw_patterns = [
        ("0E FB FD 08 FD FF", bytes([0x0E, 0xFB, FD, 0x08, FD, FF])),
        ("0E FC FD 08 FD FF", bytes([0x0E, 0xFC, FD, 0x08, FD, FF])),
        ("C9 00 FE FE FD 0E FD 08 FD FF", bytes([0xC9, 0x00, FE, FE, FD, 0x0E, FD, 0x08, FD, FF])),
    ]
    
    for desc, payload in raw_patterns:
        test(desc, payload)
        time.sleep(0.2)


if __name__ == "__main__":
    main()
