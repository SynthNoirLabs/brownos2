#!/usr/bin/env python3
"""
ORACLE INSIGHT: We get byte 1 because we always feed Right(6) to the key.
The key (Var(253)) is likely a lookup/PRF that returns different bytes for different inputs!

Plan: Apply key to Right(0), Right(1), Right(2), ... and collect the bytes.
These might spell out the answer!
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


def make_church(n):
    """Make Church numeral for byte value n (9 lambdas, bits encoded)"""
    expr = Var(0)
    for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def make_right(payload):
    """Scott Right: λl.λr. r payload"""
    return Lam(Lam(App(Var(0), payload)))


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


def test_input(n):
    """
    Apply key to Right(ChurchN) and extract the inner byte.
    Returns the byte value or None if failed.
    """
    church_n = make_church(n)
    right_n = make_right(church_n)
    
    # echo(251) -> Left(key)
    # (key Right(ChurchN)) -> hopefully Left(outer) where outer=Right(inner)
    # Extract inner and write as single byte [inner]
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(
                    # depth 2: key=Var(0), write=Var(4)
                    App(
                        App(
                            App(Var(0), right_n),
                            Lam(
                                # depth 3: outer=Var(0), key=Var(1), write=Var(5)
                                App(
                                    App(Var(0), identity),
                                    Lam(
                                        # depth 4: inner=Var(0), write=Var(6)
                                        App(
                                            App(Var(6),
                                                Lam(Lam(App(App(Var(1), Var(2)), nil)))
                                            ),
                                            nil
                                        )
                                    )
                                )
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
    resp = query(payload)
    
    if resp and len(resp) == 1 and resp not in [b'R', b'E']:
        return resp[0]
    return None


def main():
    print("=" * 70)
    print("VARYING THE ORACLE INPUT")
    print("=" * 70)
    
    print("\nApplying key to Right(Church_N) for N = 0..32")
    print("Collecting output bytes...\n")
    
    results = []
    
    for n in range(33):
        byte_val = test_input(n)
        if byte_val is not None:
            results.append((n, byte_val))
            char = chr(byte_val) if 32 <= byte_val < 127 else f"\\x{byte_val:02x}"
            print(f"  Right({n:2d}) -> byte {byte_val:3d} = {char}")
        else:
            print(f"  Right({n:2d}) -> (failed)")
        time.sleep(0.15)
    
    if results:
        print("\n" + "=" * 70)
        print("COLLECTED BYTES:")
        byte_vals = [b for _, b in results]
        print(f"  Raw: {byte_vals}")
        try:
            as_string = bytes(byte_vals).decode('utf-8', errors='replace')
            print(f"  As string: {repr(as_string)}")
        except:
            pass
        
        printables = [chr(b) if 32 <= b < 127 else '?' for b in byte_vals]
        print(f"  Printable chars: {''.join(printables)}")


if __name__ == "__main__":
    main()
