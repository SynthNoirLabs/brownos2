#!/usr/bin/env python3
"""
Var(253) seems to allow continuation when applied to syscall 8's result.
Let's investigate what's happening.

Key observation: "Var(253) result -> then write" prints "AFTER"
This means the computation continues after Var(253) is applied!
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
        result = "(empty)"
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
    print("VAR(253) BEHAVIOR ANALYSIS")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print("\n=== What does Var(253) DO when applied to syscall 8's result? ===\n")
    
    apply_253_print_result = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(Var(1), Var(0)),
                                Lam(
                                    App(
                                        App(Var(7), Var(0)),
                                        Lam(
                                            App(
                                                App(Var(0),
                                                    Lam(App(App(Var(8), Var(0)), nil))
                                                ),
                                                nil
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("syscall8 nil -> (Var(253) result) -> quote -> write:")
    payload = bytes([0x0E, 251, FD]) + encode_term(apply_253_print_result) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Try: (Var(253) (syscall8 result)) with different continuations ===\n")
    
    apply_253_then_branch = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(Var(1), Var(0)),
                                Lam(
                                    App(
                                        App(Var(0),
                                            Lam(App(App(Var(8), encode_string("INNER-L\n")), nil))
                                        ),
                                        Lam(App(App(Var(8), encode_string("INNER-R\n")), nil))
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("(Var(253) sc8Result) -> branch L/R:")
    payload = bytes([0x0E, 251, FD]) + encode_term(apply_253_then_branch) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== What if Var(253) transforms the Either somehow? ===\n")
    
    apply_253_twice = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(App(App(Var(6), encode_string("FIRST-L\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("FIRST-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("Apply (Var(253) sc8Result) as Either:")
    payload = bytes([0x0E, 251, FD]) + encode_term(apply_253_twice) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Use Var(253) to UNLOCK syscall 8? ===\n")
    print("Hypothesis: Var(253) applied to sc8Result might be privileged context")
    
    unlock_attempt = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                Var(1),
                                App(
                                    App(Var(12), Var(0)),
                                    Lam(
                                        App(
                                            App(Var(0),
                                                Lam(App(App(Var(8), encode_string("SC8-L!\n")), nil))
                                            ),
                                            Lam(App(App(Var(8), encode_string("SC8-R\n")), nil))
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("Var(253) (syscall8 nil (λsc8r. branch)) -- nested:")
    payload = bytes([0x0E, 251, FD]) + encode_term(unlock_attempt) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Use backdoor pair + Var(253) ===\n")
    
    backdoor_253_combo = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(16), Var(251)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
                                        App(
                                            App(Var(0), Var(3)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(8), encode_string("COMBO-L\n")), nil))
                                                    ),
                                                    Lam(App(App(Var(8), encode_string("COMBO-R\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("ECHO-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD-R\n")), nil))
        )
    )
    
    print("backdoor -> echo(Var(251)) -> (Var(253) pair):")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_253_combo) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Direct: What does Var(253) evaluate to? ===\n")
    
    just_var253_with_qd = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(5), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(5), Var(0)), nil))
                                ),
                                nil
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("echo(Var(251)) -> quote(Var(253)):")
    payload = bytes([0x0E, 251, FD]) + encode_term(just_var253_with_qd) + bytes([FD, FF])
    test("  result (expect Encoding failed)", payload)


if __name__ == "__main__":
    main()
