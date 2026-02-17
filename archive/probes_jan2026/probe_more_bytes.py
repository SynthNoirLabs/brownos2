#!/usr/bin/env python3
"""
Byte 1 isn't the answer. Let's try to get MORE bytes.

Hypotheses:
1. The outer payload might be a LIST, not just Right(byte1)
2. Different syscall8 args might give different bytes
3. Chaining transforms might reveal more
4. The backdoor pair might be the key to getting full answer
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
    print("SEARCHING FOR MORE BYTES / THE REAL ANSWER")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    # Maybe the outer is a LIST and we need to iterate?
    # cons(h, t) = λc.λn. c h t
    # So (list consHandler nilHandler) calls consHandler with head and tail
    
    print("\n=== Try treating outer as a LIST ===\n")
    
    outer_as_list = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(
                                        # outer at d4
                                        # If it's cons(h, t), call with handler that takes 2 args
                                        App(
                                            App(Var(0),
                                                Lam(Lam(
                                                    # h=Var(1), t=Var(0) at d6
                                                    # Write "CONS:" then quote head
                                                    App(
                                                        App(Var(10), encode_string("CONS:")),
                                                        Lam(
                                                            App(
                                                                App(Var(13), Var(3)),
                                                                Lam(
                                                                    App(
                                                                        App(Var(0),
                                                                            Lam(App(App(Var(16), Var(0)), nil))
                                                                        ),
                                                                        Lam(App(App(Var(16), encode_string(":HQF")), nil))
                                                                    )
                                                                )
                                                            )
                                                        )
                                                    )
                                                ))
                                            ),
                                            Lam(
                                                # nil/Right handler
                                                App(App(Var(8), encode_string("NIL/RIGHT\n")), nil)
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("TRANSFORM-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("If outer is cons(h,t), get CONS:head. If nil/Right, get NIL/RIGHT:")
    payload = bytes([0x0E, 251, FD]) + encode_term(outer_as_list) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # What if we use BACKDOOR to get the full answer?
    print("\n=== Backdoor + Key combination ===\n")
    
    # backdoor returns Left(pair)
    # Maybe: (key (pair something)) gives the answer?
    
    bd_key_combo = Lam(
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
                                        # Apply key to pair
                                        App(
                                            App(
                                                App(Var(2), Var(0)),
                                                Lam(
                                                    App(
                                                        App(Var(0), identity),
                                                        Lam(
                                                            App(
                                                                App(Var(10),
                                                                    Lam(Lam(App(App(Var(1), Var(2)), Lam(Lam(Var(0))))))
                                                                ),
                                                                nil
                                                            )
                                                        )
                                                    )
                                                )
                                            ),
                                            Lam(App(App(Var(8), encode_string("KP-R\n")), nil))
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
    
    print("(key backdoor_pair) -> extract inner -> write:")
    payload = bytes([0x0E, 251, FD]) + encode_term(bd_key_combo) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW: {resp}")
    
    # What if pair APPLIED TO key gives the answer?
    print("\n=== Pair applied to key ===\n")
    
    pair_to_key = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(16), nil),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
                                        # pair at d3, key (from echo) at d1
                                        # pair = λs. s A B
                                        # (pair key) = key A B
                                        App(
                                            App(Var(0), Var(2)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(
                                                            App(
                                                                App(Var(0), identity),
                                                                Lam(
                                                                    App(
                                                                        App(Var(12),
                                                                            Lam(Lam(App(App(Var(1), Var(2)), Lam(Lam(Var(0))))))
                                                                        ),
                                                                        nil
                                                                    )
                                                                )
                                                            )
                                                        )
                                                    ),
                                                    Lam(App(App(Var(10), encode_string("PK-R\n")), nil))
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
    
    print("(pair key) -> result -> extract -> write:")
    payload = bytes([0x0E, 251, FD]) + encode_term(pair_to_key) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW: {resp}")
    
    # What about using echo with different values?
    print("\n=== Different echo values ===\n")
    
    for echo_val in [250, 252, 253]:
        echo_diff = Lam(
            App(
                App(Var(0),
                    Lam(
                        App(
                            App(Var(10), nil),
                            Lam(
                                App(
                                    App(
                                        App(Var(1), Var(0)),
                                        Lam(
                                            App(
                                                App(Var(0), identity),
                                                Lam(
                                                    App(
                                                        App(Var(7),
                                                            Lam(Lam(App(App(Var(1), Var(2)), Lam(Lam(Var(0))))))
                                                        ),
                                                        nil
                                                    )
                                                )
                                            )
                                        )
                                    ),
                                    Lam(App(App(Var(5), encode_string("R\n")), nil))
                                )
                            )
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("E\n")), nil))
            )
        )
        
        print(f"echo({echo_val}) -> syscall8 -> transform -> inner byte:")
        payload = bytes([0x0E, echo_val, FD]) + encode_term(echo_diff) + bytes([FD, FF])
        resp = test(f"  {echo_val}", payload)
        if resp and len(resp) == 1:
            print(f"  BYTE VALUE: {resp[0]}")


if __name__ == "__main__":
    main()
