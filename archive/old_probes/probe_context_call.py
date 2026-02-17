#!/usr/bin/env python3
"""
Try calling syscall 8 from different CONTEXTS.

Hypothesis: syscall 8's permission check might depend on:
1. The evaluation context (what bindings are in scope)
2. The "call site" (where the call originates)
3. Some hidden state set by other syscalls
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
    print("CONTEXT-BASED SYSCALL 8 TESTS")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    sc8_either_handler = Lam(
        App(
            App(Var(0),
                Lam(App(App(Var(4), encode_string("SC8-LEFT!\n")), nil))
            ),
            Lam(App(App(Var(4), encode_string("SC8-RIGHT\n")), nil))
        )
    )
    
    print("\n=== Test 1: syscall 8 directly (baseline) ===\n")
    
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(sc8_either_handler) + bytes([FD, FF])
    test("syscall8(nil)", payload)
    
    print("\n=== Test 2: backdoor then syscall 8 (sequential) ===\n")
    
    backdoor_then_sc8 = Lam(
        App(
            App(Var(0x09), Var(0)),
            sc8_either_handler
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_then_sc8) + bytes([FD, FF])
    test("backdoor(nil) -> (syscall8 result)", payload)
    
    print("\n=== Test 3: Use backdoor pair's A combinator as syscall 8's continuation ===\n")
    
    backdoor_use_A_as_cont = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(0),
                            Lam(Lam(
                                App(
                                    App(Var(10), nil),
                                    Var(0)
                                )
                            ))
                        ),
                        Lam(Lam(App(App(Var(6), encode_string("PAIR-RIGHT\n")), nil)))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD-RIGHT\n")), nil))
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_use_A_as_cont) + bytes([FD, FF])
    test("backdoor -> extract pair -> use A as syscall8's continuation", payload)
    
    print("\n=== Test 4: Use the PAIR ITSELF as syscall 8's argument ===\n")
    
    backdoor_pair_as_arg = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(9), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), encode_string("PAIR-SC8-LEFT!\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("PAIR-SC8-RIGHT\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD-RIGHT\n")), nil))
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_pair_as_arg) + bytes([FD, FF])
    test("backdoor -> extract pair -> syscall8(pair)", payload)
    
    print("\n=== Test 5: Use Var(253) (from echo) as argument to other syscalls ===\n")
    
    echo253_to_various = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(7), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), encode_string("NAME-LEFT\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("NAME-RIGHT\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-RIGHT\n")), nil))
        )
    )
    
    print("echo(Var(251)) -> name(Var(253)):")
    payload = bytes([0x0E, 251, FD]) + encode_term(echo253_to_various) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Test 6: Double echo - shift twice ===\n")
    
    double_echo_sc8 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(15), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
                                        App(
                                            App(Var(11), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(8), encode_string("DOUBLE-SC8-LEFT!\n")), nil))
                                                    ),
                                                    Lam(App(App(Var(8), encode_string("DOUBLE-SC8-RIGHT\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("INNER-ECHO-RIGHT\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("OUTER-ECHO-RIGHT\n")), nil))
        )
    )
    
    print("echo(Var(249)) -> echo(Var(251)) -> syscall8(Var(253)):")
    payload = bytes([0x0E, 249, FD]) + encode_term(double_echo_sc8) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Test 7: Use syscall 8 AS A CONTINUATION (not as the main call) ===\n")
    
    use_sc8_as_cont = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(15), Var(0)),
                        Var(9)
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("OUTER-RIGHT\n")), nil))
        )
    )
    
    print("echo(Var(0)) -> echo(Var(2)) with syscall8 as continuation:")
    payload = bytes([0x0E, 0x00, FD]) + encode_term(use_sc8_as_cont) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Test 8: Chain backdoor -> echo -> syscall8 ===\n")
    
    backdoor_echo_sc8 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(15), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
                                        App(
                                            App(Var(11), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(8), encode_string("CHAIN-SC8-LEFT!\n")), nil))
                                                    ),
                                                    Lam(App(App(Var(8), encode_string("CHAIN-SC8-RIGHT\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("ECHO-RIGHT\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD-RIGHT\n")), nil))
        )
    )
    
    print("backdoor(nil) -> echo(pair) -> syscall8(pair+2):")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_echo_sc8) + bytes([FD, FF])
    test("  result", payload)


if __name__ == "__main__":
    main()
