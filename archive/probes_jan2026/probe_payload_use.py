#!/usr/bin/env python3
"""
Instead of trying to serialize/write the payload from (key nil),
let's try to USE it directly.
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


def make_church(n):
    expr = Var(0)
    for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def test_readfile_with_payload():
    """
    Use the payload from (key nil) as a file ID for readfile.
    
    readfile(fileID) returns the file content.
    If payload is Church 1, it might read file ID 1.
    """
    print("=" * 70)
    print("READFILE WITH PAYLOAD")
    print("=" * 70)
    
    # Get key, apply to nil, use payload as fileID
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # Left: key at Var(0)
                    App(
                        App(App(Var(0), nil),  # (key nil)
                            Lam(  # Left: payload at Var(0)
                                # readfile(payload) - readfile is at Var(8) (syscall 7+1=8)
                                App(
                                    App(Var(8), Var(0)),  # readfile(payload)
                                    Lam(
                                        App(
                                            App(Var(0),
                                                Lam(App(App(Var(8), Var(0)), nil))),  # Left: write
                                            Lam(App(App(Var(8), encode_string("RF")), nil))  # Right
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("KR")), nil))  # key Right
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  readfile(payload): {resp[:100]}")


def test_readdir_with_payload():
    """
    Use payload as directory ID.
    """
    print("\n" + "=" * 70)
    print("READDIR WITH PAYLOAD")
    print("=" * 70)
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(App(Var(0), nil),
                            Lam(
                                # readdir(payload) - readdir is at Var(6) (syscall 5+1=6)
                                App(
                                    App(Var(6), Var(0)),
                                    Lam(
                                        App(
                                            App(Var(0),
                                                Lam(App(App(Var(8), encode_string("OK")), nil))),
                                            Lam(App(App(Var(8), encode_string("RD")), nil))
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("KR")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  readdir(payload): {resp}")


def test_name_with_payload():
    """
    Use payload as file/dir ID for name().
    """
    print("\n" + "=" * 70)
    print("NAME WITH PAYLOAD")
    print("=" * 70)
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(App(Var(0), nil),
                            Lam(
                                # name(payload) - name is at Var(7) (syscall 6+1=7)
                                App(
                                    App(Var(7), Var(0)),
                                    Lam(
                                        App(
                                            App(Var(0),
                                                Lam(App(App(Var(8), Var(0)), nil))),  # Left: write name
                                            Lam(App(App(Var(8), encode_string("NM")), nil))
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("KR")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  name(payload): {resp}")


def test_apply_payload_to_many():
    """
    Apply the payload to various things and see what happens.
    If payload is Church 1, then (payload f x) = f(x).
    """
    print("\n" + "=" * 70)
    print("APPLY PAYLOAD TO THINGS")
    print("=" * 70)
    
    # If payload is Church 1 = λf.λx. f x
    # Then (((payload f) x) anything) should give f(x)
    
    # Test: ((payload identity) "A") should give "A"
    print("\n  Testing ((payload identity) A):")
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(App(Var(0), nil),
                            Lam(
                                # ((payload identity) "hello")
                                # payload at Var(0), identity = λx.x
                                App(
                                    App(
                                        App(Var(0), Lam(Var(0))),  # (payload identity)
                                        encode_string("hello")
                                    ),
                                    Lam(  # continuation for result
                                        App(App(Var(6), Var(0)), nil)  # write result
                                    )
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("KR")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"    Result: {resp}")
    
    # Simpler test: (payload true false) should give true if payload is Church 1
    print("\n  Testing ((payload true) false):")
    
    true_ = Lam(Lam(Var(1)))  # λxy.x
    false_ = Lam(Lam(Var(0)))  # λxy.y
    
    test_term2 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(App(Var(0), nil),
                            Lam(
                                # ((payload true) false)
                                App(
                                    App(App(Var(0), true_), false_),
                                    Lam(
                                        # Test if result is true or false
                                        App(
                                            App(Var(0), encode_string("TRUE")),
                                            encode_string("FALSE")
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("KR")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    # Hmm, this gets complex. Let me try differently:
    # Just write the result after applying
    
    test_term3 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(App(Var(0), nil),
                            Lam(
                                # Just write: ((payload true) false)
                                App(
                                    App(Var(5),  # write
                                        App(App(Var(0), Lam(Lam(Var(1)))), Lam(Lam(Var(0))))  # ((payload true) false)
                                    ),
                                    nil
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("KR")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term3) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"    write(((payload true) false)): {resp}")


def test_simple_write_const():
    """
    Just write a constant to verify the handler structure is correct.
    """
    print("\n" + "=" * 70)
    print("SANITY CHECK: WRITE CONSTANT")
    print("=" * 70)
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(App(Var(0), nil),
                            Lam(
                                # Just write "OK" - ignore payload
                                App(App(Var(5), encode_string("OK")), nil)
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("KR")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  Should print 'OK': {resp}")


def main():
    test_simple_write_const()
    time.sleep(0.3)
    
    test_readfile_with_payload()
    time.sleep(0.3)
    
    test_readdir_with_payload()
    time.sleep(0.3)
    
    test_name_with_payload()
    time.sleep(0.3)
    
    test_apply_payload_to_many()


if __name__ == "__main__":
    main()
