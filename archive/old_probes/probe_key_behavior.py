#!/usr/bin/env python3
"""
Key (Var(253)) triggers BOTH Left AND Right paths when used as Either!
This is very unusual. Let's understand what Var(253) actually is.

Var(253) = 0xFD = Application marker
Maybe in the runtime, this has special meaning?
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
    elif b"Encoding failed" in resp:
        result = "Encoding failed!"
    elif b"Invalid term" in resp:
        result = "Invalid term!"
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
    print("UNDERSTANDING VAR(253) BEHAVIOR")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    # What if (key x L R) returns BOTH (L something) AND (R something)?
    # This would explain why both handlers run.
    
    # Let's check: does key alone (without val) also do this?
    
    key_as_either = Lam(
        App(
            App(Var(0),
                Lam(
                    # key=Var(0) at d1, apply as Either
                    App(
                        App(Var(0),
                            Lam(App(App(Var(5), encode_string("KL\n")), nil))
                        ),
                        Lam(App(App(Var(5), encode_string("KR\n")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("\n1. (key L R) directly - key as Either:")
    payload = bytes([0x0E, 251, FD]) + encode_term(key_as_either) + bytes([FD, FF])
    test("  result", payload)
    
    # What about (key nil)?
    key_applied_nil = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(App(Var(0), nil),
                            Lam(App(App(Var(6), encode_string("KN-L\n")), nil))
                        ),
                        Lam(App(App(Var(6), encode_string("KN-R\n")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("\n2. ((key nil) L R):")
    payload = bytes([0x0E, 251, FD]) + encode_term(key_applied_nil) + bytes([FD, FF])
    test("  result", payload)
    
    # What if key is some kind of Y combinator or fixed point?
    # Let's see: (key k) where k is some continuation
    
    key_with_cont = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(0), Lam(Var(0))),
                        Lam(App(App(Var(5), encode_string("KC\n")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("\n3. (key id cont):")
    payload = bytes([0x0E, 251, FD]) + encode_term(key_with_cont) + bytes([FD, FF])
    test("  result", payload)
    
    # Key discovery: if (key val L R) prints both L and R,
    # maybe we're supposed to read the COMBINATION of outputs?
    
    # Let me try: instead of Either handlers, use simpler printing
    key_val_simple = Lam(
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
                                                # Apply (key val) and print results
                                                App(
                                                    App(
                                                        App(Var(3), Var(0)),
                                                        Lam(
                                                            # Left handler gets payload
                                                            App(
                                                                App(Var(9), Var(0)),
                                                                Lam(
                                                                    App(
                                                                        App(Var(0),
                                                                            Lam(App(App(Var(12), Var(0)), nil))
                                                                        ),
                                                                        Lam(App(App(Var(12), encode_string("LQF")), nil))
                                                                    )
                                                                )
                                                            )
                                                        )
                                                    ),
                                                    Lam(
                                                        App(
                                                            App(Var(9), Var(0)),
                                                            Lam(
                                                                App(
                                                                    App(Var(0),
                                                                        Lam(App(App(Var(12), Var(0)), nil))
                                                                    ),
                                                                    Lam(App(App(Var(12), encode_string("RQF")), nil))
                                                                )
                                                            )
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("X\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("\n4. (key val) -> quote both L and R payloads:")
    payload = bytes([0x0E, 251, FD]) + encode_term(key_val_simple) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # Actually, let me just see what the sc8 result is when transformed
    # without extracting - just see if we get useful raw output
    
    print("\n5. Try using syscall 0x2A to get answer directly:")
    
    # Syscall 42 (0x2A) at depth 1 = Var(43)
    sc42_key = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(43), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), Var(0)), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("42F\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("syscall42(key):")
    payload = bytes([0x0E, 251, FD]) + encode_term(sc42_key) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # What about combining backdoor with key?
    print("\n6. Backdoor then syscall42 with key:")
    
    bd_sc42 = Lam(
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
                                            App(Var(47), Var(2)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(9), Var(0)), nil))
                                                    ),
                                                    Lam(App(App(Var(9), encode_string("42F\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("BF\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("backdoor -> syscall42(key):")
    payload = bytes([0x0E, 251, FD]) + encode_term(bd_sc42) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")


if __name__ == "__main__":
    main()
