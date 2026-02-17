#!/usr/bin/env python3
"""
The backdoor pair contains special combinators.
Maybe they're meant to be used with syscall8 or the key in a specific way.

Backdoor pair:
  A = λa.λb. b b (self-apply second)
  B = λa.λb. a b (apply first to second)
  pair = λs. s A B

What if we use these combinators creatively?
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
PORT = 61221

FD, FE, FF = 0xFD, 0xFE, 0xFF


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


def test(desc: str, payload: bytes):
    resp = query(payload)
    if not resp:
        result = "(empty)"
    else:
        try:
            text = resp.decode('utf-8', 'replace')
            result = f"OUTPUT: {repr(text[:300])}"
        except:
            result = f"hex: {resp.hex()[:300]}"
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
    print("BACKDOOR COMBINATOR MAGIC")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    # Extract A and B from backdoor, use them with syscall8/key
    
    print("\n=== Extract A from backdoor, use with syscall8 ===\n")
    
    # pair true = A (fst)
    # pair false = B (snd)
    true_term = Lam(Lam(Var(1)))
    false_term = Lam(Lam(Var(0)))
    
    # Get A, use as syscall8 arg
    use_A = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(16), nil),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
                                        # pair at d3
                                        # Get A = pair true
                                        App(
                                            App(Var(0), true_term),
                                            Lam(
                                                # A at d4, key at d2
                                                App(
                                                    App(Var(14), Var(0)),
                                                    Lam(
                                                        App(
                                                            App(
                                                                App(Var(3), Var(0)),
                                                                Lam(
                                                                    App(
                                                                        App(Var(0), identity),
                                                                        Lam(
                                                                            App(
                                                                                App(Var(12),
                                                                                    Lam(Lam(App(App(Var(1), Var(2)), nil)))
                                                                                ),
                                                                                nil
                                                                            )
                                                                        )
                                                                    )
                                                                )
                                                            ),
                                                            Lam(App(App(Var(10), encode_string("A-R\n")), nil))
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("BD-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("syscall8(A) -> (key result) -> inner -> write:")
    payload = bytes([0x0E, 251, FD]) + encode_term(use_A) + bytes([FD, FF])
    resp = test("  A", payload)
    if resp and len(resp) <= 10:
        print(f"  RAW BYTES: {list(resp)}")
    
    # Get B, use as syscall8 arg
    use_B = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(16), nil),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
                                        App(
                                            App(Var(0), false_term),
                                            Lam(
                                                App(
                                                    App(Var(14), Var(0)),
                                                    Lam(
                                                        App(
                                                            App(
                                                                App(Var(3), Var(0)),
                                                                Lam(
                                                                    App(
                                                                        App(Var(0), identity),
                                                                        Lam(
                                                                            App(
                                                                                App(Var(12),
                                                                                    Lam(Lam(App(App(Var(1), Var(2)), nil)))
                                                                                ),
                                                                                nil
                                                                            )
                                                                        )
                                                                    )
                                                                )
                                                            ),
                                                            Lam(App(App(Var(10), encode_string("B-R\n")), nil))
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("BD-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("\nsyscall8(B) -> (key result) -> inner -> write:")
    payload = bytes([0x0E, 251, FD]) + encode_term(use_B) + bytes([FD, FF])
    resp = test("  B", payload)
    if resp and len(resp) <= 10:
        print(f"  RAW BYTES: {list(resp)}")
    
    # What if we apply A or B to the key?
    print("\n=== Apply backdoor combinators TO the key ===\n")
    
    # (A key x) = x x (self-apply x after absorbing key)
    # (B key x) = key x (apply key to x)
    
    A_to_key = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(16), nil),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
                                        App(
                                            App(Var(0), true_term),
                                            Lam(
                                                # A at d4, key at d2
                                                # (A key) = λb. b b (absorbs key, returns self-applier)
                                                App(
                                                    App(App(Var(0), Var(2)), nil),
                                                    Lam(App(App(Var(10), encode_string("AK\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("BD-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("((A key) nil) cont:")
    payload = bytes([0x0E, 251, FD]) + encode_term(A_to_key) + bytes([FD, FF])
    test("  result", payload)
    
    # What about using the key as the "selector" for the pair?
    # (pair key) = key A B
    
    print("\n=== Use key as pair selector ===\n")
    
    key_selects = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(16), nil),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
                                        # pair at d3, key at d1
                                        # (pair key) = key A B
                                        # Since key=Var(253) behaves specially...
                                        App(
                                            App(Var(0), Var(2)),
                                            Lam(
                                                # result at d4
                                                App(
                                                    App(Var(8), Var(0)),
                                                    Lam(
                                                        App(
                                                            App(Var(0),
                                                                Lam(App(App(Var(11), Var(0)), nil))
                                                            ),
                                                            Lam(App(App(Var(11), encode_string("QF\n")), nil))
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("BD-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("(pair key) -> quote result:")
    payload = bytes([0x0E, 251, FD]) + encode_term(key_selects) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # Final idea: what if the "answer" is related to the COMBINATION
    # of error code 6 and byte 1? Like 6+1=7, or 61, or...
    
    print("\n=== Try answer candidates based on 6 and 1 ===\n")
    print("Error code: 6, Inner byte: 1")
    print("Possible answers: '61', '16', '7', '5' (6-1), etc.")
    print("(These would need to be tested on WeChall)")


if __name__ == "__main__":
    main()
