#!/usr/bin/env python3
"""
What if the key (Var(253)) is meant to be used as a CONTINUATION?

Normal syscall CPS: ((syscall arg) continuation)
What if: ((syscall8 arg) key) does something special?

The key from echo is Var(253), which is outside normal range.
When used as continuation, it might interact with the VM differently.
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
    raise TypeError(f"Unknown term type: {type(term)}")


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


nil = Lam(Lam(Var(0)))
identity = Lam(Var(0))
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def make_church(n):
    expr = Var(0)
    for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_string(s: str):
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


def test_key_as_syscall8_continuation():
    """
    Get key from echo, then use it as continuation for syscall8.
    ((syscall8 nil) key)
    """
    print("\n=== Use key as syscall8 continuation ===")
    
    # echo(251) -> Left(key)
    # Inside Left handler, key is at Var(0)
    # We want to build: ((syscall8 nil) key)
    # syscall8 = 0x08, under 2 Lams (echo cont, Left handler) = Var(10)
    
    test_term = Lam(  # echo continuation
        App(
            App(Var(0),  # Either from echo
                Lam(  # Left handler - key at Var(0)
                    # Build ((syscall8 nil) key)
                    App(
                        App(Var(10), nil),  # (syscall8 nil)
                        Var(0)  # key as continuation!
                    )
                )
            ),
            Lam(  # Right handler
                App(App(Var(4), encode_string("ER")), nil)
            )
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  ((syscall8 nil) key): {resp} (hex: {resp.hex() if resp else 'empty'})")
    
    # Also try quoting the result
    test_term2 = Lam(
        App(
            App(Var(0),
                Lam(  # key at Var(0)
                    # Quote the result of ((syscall8 nil) key)
                    App(
                        App(Var(6),  # quote
                            App(
                                App(Var(10), nil),
                                Var(0)  # key
                            )
                        ),
                        Lam(  # quote continuation
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), Var(0)), nil))  # write Left payload
                                ),
                                Lam(App(App(Var(6), encode_string("QF")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term2) + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  quote(((syscall8 nil) key)): {resp[:50] if resp else 'empty'} len={len(resp)}")


def test_key_as_continuation_for_other_syscalls():
    """
    Try using key as continuation for various syscalls.
    """
    print("\n=== Use key as continuation for other syscalls ===")
    
    syscalls = [
        (0x01, "error string", make_church(0)),
        (0x04, "quote", nil),
        (0x05, "readdir", make_church(0)),
        (0x06, "name", make_church(0)),
        (0x07, "readfile", make_church(11)),
        (0xC9, "backdoor", nil),
    ]
    
    for syscall_num, desc, arg in syscalls:
        test_term = Lam(
            App(
                App(Var(0),
                    Lam(  # key
                        # ((syscall arg) key)
                        App(
                            App(Var(syscall_num + 2), arg),
                            Var(0)  # key
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("E")), nil))
            )
        )
        
        payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
        resp = query(payload, timeout_s=3)
        print(f"  (({desc}) key): {resp[:30] if resp else 'empty'}")
        time.sleep(0.3)


def test_syscall8_with_key_in_arg():
    """
    What if syscall8's argument should contain the key somehow?
    Like: syscall8(pair(key, something))
    """
    print("\n=== syscall8 with key in argument ===")
    
    # Make pair: λf. f a b
    def make_pair(a, b):
        return Lam(App(App(Var(0), a), b))
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # key
                    # syscall8(pair(key, nil))
                    App(
                        App(Var(10), make_pair(Var(0), nil)),
                        Lam(  # syscall8 result
                            App(
                                App(Var(0),
                                    Lam(
                                        App(
                                            App(Var(8), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(10), Var(0)), nil))
                                                    ),
                                                    Lam(App(App(Var(10), encode_string("QF")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(
                                    # Right - write error code
                                    App(App(Var(7), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  syscall8(pair(key, nil)): {resp}")


def test_apply_key_to_QD():
    """
    What if (key QD) does something?
    QD is the quick debug continuation.
    """
    print("\n=== Apply key to QD ===")
    
    # Build: (key QD)
    # QD is not directly encodable as a term, but we can try
    
    # Actually, let's see what happens if we quote (key (some term))
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # key
                    # Try: (key identity)
                    App(
                        App(Var(6),  # quote
                            App(Var(0), identity)  # (key identity)
                        ),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(8), Var(0)), nil))
                                ),
                                Lam(App(App(Var(8), encode_string("QF")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  quote(key identity): {resp[:50] if resp else 'empty'}")
    
    if resp and resp != b'ER' and resp != b'QF':
        print(f"  Full: {resp.hex()}")


def test_raw_byte_253_as_continuation():
    """
    What if we directly use byte 253 (without going through echo)?
    This would be Var(253) directly in the source.
    """
    print("\n=== Direct Var(253) as continuation (no echo) ===")
    
    # Build: ((syscall8 nil) Var(253))
    # But Var(253) = 0xFD which is the App marker!
    # This won't parse correctly...
    
    # We can try building it as raw bytes
    # syscall8(nil) = 08 [nil] FD = 08 00 FE FE FD
    # Then apply to Var(253)... but 253 = FD = App marker
    
    # The only way to get Var(253) is through echo!
    print("  Cannot encode Var(253) directly - it's the App marker (FD)")
    print("  Must use echo to manufacture it at runtime")


def main():
    print("=" * 70)
    print("KEY AS CONTINUATION TESTS")
    print("=" * 70)
    
    test_key_as_syscall8_continuation()
    time.sleep(0.3)
    
    test_key_as_continuation_for_other_syscalls()
    time.sleep(0.3)
    
    test_syscall8_with_key_in_arg()
    time.sleep(0.3)
    
    test_apply_key_to_QD()
    time.sleep(0.3)
    
    test_raw_byte_253_as_continuation()


if __name__ == "__main__":
    main()
