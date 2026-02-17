#!/usr/bin/env python3
"""
Investigate the empty responses - are they timeouts or actual empty?
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
    raise TypeError(f"Unknown term type: {type(term)}")


def query_timed(payload: bytes, timeout_s: float = 5.0) -> tuple:
    """Return (response, actual_time_taken)"""
    start = time.time()
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except:
                pass
            sock.settimeout(timeout_s)
            out = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out += chunk
                except socket.timeout:
                    break
            elapsed = time.time() - start
            return out, elapsed
    except Exception as e:
        elapsed = time.time() - start
        return f"ERROR: {e}".encode(), elapsed


nil = Lam(Lam(Var(0)))


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


def test_timing():
    """
    Compare timing of different operations.
    """
    print("=" * 70)
    print("TIMING ANALYSIS")
    print("=" * 70)
    
    # Quick baseline: simple echo
    print("\n  Baseline (echo 0):")
    payload = bytes([0x0E, 0, FD]) + QD + bytes([FD, FF])
    resp, elapsed = query_timed(payload, timeout_s=10)
    print(f"    Response: {resp[:30]}, Time: {elapsed:.2f}s")
    
    # Known slow: syscall8
    print("\n  syscall8(nil):")
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    resp, elapsed = query_timed(payload, timeout_s=10)
    print(f"    Response: {resp[:30]}, Time: {elapsed:.2f}s")
    
    # The interesting case: (key syscall8)
    print("\n  (key syscall8) branch test:")
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # Left: key at Var(0)
                    App(
                        App(App(Var(0), Var(9)),  # (key syscall8)
                            Lam(App(App(Var(6), encode_string("L")), nil))),
                        Lam(App(App(Var(6), encode_string("R")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp, elapsed = query_timed(payload, timeout_s=10)
    print(f"    Response: {resp[:30]}, Time: {elapsed:.2f}s")
    
    # Another interesting case: syscall8(key)
    print("\n  syscall8(key):")
    test_term2 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(9), Var(0)),  # syscall8(key)
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), encode_string("L")), nil))),
                                Lam(App(App(Var(6), encode_string("R")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term2) + bytes([FD, FF])
    resp, elapsed = query_timed(payload, timeout_s=10)
    print(f"    Response: {resp[:30]}, Time: {elapsed:.2f}s")
    
    # Try with much longer timeout
    print("\n  (key syscall8) with 30s timeout:")
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp, elapsed = query_timed(payload, timeout_s=30)
    print(f"    Response: {resp[:30]}, Time: {elapsed:.2f}s")


def test_key_as_syscall():
    """
    What if key IS a syscall?
    ((key arg) cont) as a syscall pattern?
    """
    print("\n" + "=" * 70)
    print("KEY AS SYSCALL PATTERN")
    print("=" * 70)
    
    # Normal syscall pattern: ((syscall arg) cont)
    # If key is like a syscall: ((key arg) cont)
    
    # We know: (key nil) -> Left(something)
    # So key behaves like a syscall that returns Left
    
    # What args make it return different things?
    args = [
        ("nil", nil),
        ("identity", Lam(Var(0))),
        ("true", Lam(Lam(Var(1)))),  # λxy.x
        ("false", Lam(Lam(Var(0)))),  # λxy.y
        ("church0", Lam(Lam(Var(0)))),  # Same as false
    ]
    
    for name, arg in args:
        test_term = Lam(
            App(
                App(Var(0),
                    Lam(  # Left: key at Var(0)
                        App(
                            App(App(Var(0), arg),  # (key arg)
                                Lam(  # Left handler
                                    App(App(Var(5), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                )
                            ),
                            Lam(App(App(Var(5), encode_string("R")), nil))
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("E")), nil))
            )
        )
        
        payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
        resp, elapsed = query_timed(payload, timeout_s=5)
        
        status = f"{resp} ({elapsed:.1f}s)" if resp else f"empty ({elapsed:.1f}s)"
        print(f"  (key {name}) payload as byte: {status}")
        time.sleep(0.2)


def test_key_with_backdoor():
    """
    What if we need to combine key with backdoor?
    """
    print("\n" + "=" * 70)
    print("KEY + BACKDOOR COMBINATIONS")
    print("=" * 70)
    
    # Get key, get backdoor pair, try combinations
    
    # First: (key backdoor_pair)
    print("\n  Getting backdoor pair, then (key pair):")
    
    # This is complex - we need to chain syscalls
    # backdoor(nil) -> Left(pair)
    # Then in continuation: (key pair)
    
    # Actually let's just do: echo(251) -> key, then backdoor(nil) -> pair
    # But we need to use both...
    
    # Simpler: (key Var(201)) where Var(201) = backdoor syscall
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # Left: key at Var(0)
                    App(
                        App(App(Var(0), Var(202)),  # (key backdoor) - backdoor is at 201, +1 = 202
                            Lam(
                                App(App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("R")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp, elapsed = query_timed(payload, timeout_s=5)
    print(f"    (key backdoor_ref): {resp} ({elapsed:.1f}s)")


def main():
    test_timing()
    time.sleep(0.3)
    
    test_key_as_syscall()
    time.sleep(0.3)
    
    test_key_with_backdoor()


if __name__ == "__main__":
    main()
