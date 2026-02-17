#!/usr/bin/env python3
"""
Key insight from Oracle: syscall 8 might check the CONTINUATION, not the argument.

Try using Var(253-255) (manufactured via echo) AS THE CONTINUATION:
  ((syscall8 arg) Var(253))

Also try using the backdoor pair components as continuations.
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
    elif b"Permission" in resp:
        result = f"Permission denied (len={len(resp)})"
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
    print("CONTINUATION AS THE KEY")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print("\n=== Use echo-manufactured Var(253) AS THE CONTINUATION ===\n")
    print("""
Pattern: 
  echo(Var(251)) -> Left(Var(253))
  Extract Var(253)
  Use as: ((syscall8 arg) Var(253))
""")
    
    echo_var253_as_cont = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Var(0)
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("echo(Var(251)) -> extract Var(253) -> use as syscall8's continuation:")
    payload = bytes([0x0E, 251, FD]) + encode_term(echo_var253_as_cont) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Use Var(254) as continuation ===\n")
    
    echo_var254_as_cont = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Var(0)
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("echo(Var(252)) -> extract Var(254) -> use as syscall8's continuation:")
    payload = bytes([0x0E, 252, FD]) + encode_term(echo_var254_as_cont) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Use backdoor pair's B combinator as continuation ===\n")
    print("""
Backdoor gives: Left(pair) where pair = λs.s A B
  A = λab.bb
  B = λab.ab

Extract B and use as syscall8's continuation:
  pair (λA.λB. ((syscall8 nil) B))
""")
    
    backdoor_B_as_cont = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        Var(0),
                        Lam(Lam(
                            App(
                                App(Var(11), nil),
                                Var(0)
                            )
                        ))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD-R\n")), nil))
        )
    )
    
    print("backdoor -> extract pair -> (pair (λA.λB. syscall8 nil B)):")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_B_as_cont) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Use backdoor pair's A combinator as continuation ===\n")
    
    backdoor_A_as_cont = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        Var(0),
                        Lam(Lam(
                            App(
                                App(Var(11), nil),
                                Var(1)
                            )
                        ))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD-R\n")), nil))
        )
    )
    
    print("backdoor -> extract pair -> (pair (λA.λB. syscall8 nil A)):")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_A_as_cont) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Use the PAIR ITSELF as continuation ===\n")
    
    backdoor_pair_as_cont = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Var(0)
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD-R\n")), nil))
        )
    )
    
    print("backdoor -> extract pair -> ((syscall8 nil) pair):")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_pair_as_cont) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Echo the pair, then use ECHOED pair as continuation ===\n")
    
    backdoor_echo_pair_as_cont = Lam(
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
                                            App(Var(12), nil),
                                            Var(0)
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
    
    print("backdoor -> echo(pair) -> ((syscall8 nil) echoPair):")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_echo_pair_as_cont) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Apply Var(253) to get a continuation, then use that ===\n")
    print("What if Var(253) is a function that PRODUCES the privileged continuation?")
    
    apply_var253 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        App(Var(0), nil)
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("echo(Var(251)) -> extract Var(253) -> ((syscall8 nil) (Var(253) nil)):")
    payload = bytes([0x0E, 251, FD]) + encode_term(apply_var253) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Apply Var(253) to the backdoor pair ===\n")
    
    backdoor_then_echo_combine = Lam(
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
                                            App(Var(12), nil),
                                            App(Var(0), Var(3))
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("E-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD-R\n")), nil))
        )
    )
    
    print("backdoor -> echo(Var(251)) -> ((syscall8 nil) (Var(253) pair)):")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_then_echo_combine) + bytes([FD, FF])
    test("  result", payload)


if __name__ == "__main__":
    main()
