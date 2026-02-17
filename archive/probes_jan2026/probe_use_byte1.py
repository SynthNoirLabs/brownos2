#!/usr/bin/env python3
"""
Use the byte 1 we extract from (key nil) with syscall 8.

We know:
- (key nil) -> Left(something)
- `something` writes as byte 1
- `something` can't be quoted

What if we use this `something` with syscall 8?
Or what if we need to USE byte 1 somehow?
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


def test_syscall8_with_key_result():
    """
    Get the Left payload from (key nil), pass it to syscall 8.
    """
    print("=" * 70)
    print("SYSCALL 8 WITH KEY RESULT")
    print("=" * 70)
    
    # echo(251) -> Left(key)
    # (key nil) -> Left(something)
    # syscall8(something)
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # Left: key at Var(0)
                    App(
                        App(App(Var(0), nil),  # (key nil)
                            Lam(  # Left: `something` at Var(0)
                                # syscall8(something) - syscall8 is at Var(9+1)=Var(10)
                                App(
                                    App(Var(10), Var(0)),  # syscall8(something)
                                    Lam(
                                        App(
                                            App(Var(0),
                                                Lam(App(App(Var(8), Var(0)), nil))),  # Left: write
                                            Lam(App(App(Var(8), encode_string("PD")), nil))  # Right
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
    print(f"  syscall8((key nil) payload): {resp}")


def test_syscall8_with_key_directly():
    """
    Pass the key itself (not (key nil)) to syscall 8.
    """
    print("\n" + "=" * 70)
    print("SYSCALL 8 WITH KEY DIRECTLY")
    print("=" * 70)
    
    # echo(251) -> Left(key)
    # syscall8(key)
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # Left: key at Var(0)
                    # syscall8(key) - syscall8 is at Var(9)
                    App(
                        App(Var(9), Var(0)),  # syscall8(key)
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), Var(0)), nil))),
                                Lam(App(App(Var(6), encode_string("PD")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  syscall8(key): {resp}")


def test_apply_something_to_syscall8():
    """
    Apply `something` (the Left payload from (key nil)) TO syscall 8.
    """
    print("\n" + "=" * 70)
    print("APPLY SOMETHING TO SYSCALL 8")
    print("=" * 70)
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # Left: key at Var(0)
                    App(
                        App(App(Var(0), nil),  # (key nil)
                            Lam(  # Left: `something` at Var(0)
                                # (something syscall8) - syscall8 is at Var(10)
                                App(
                                    App(Var(0), Var(10)),  # (something syscall8)
                                    Lam(
                                        App(
                                            App(Var(0),
                                                Lam(App(App(Var(8), Var(0)), nil))),
                                            Lam(App(App(Var(8), encode_string("R")), nil))
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
    print(f"  ((key nil) payload applied to syscall8): {resp}")


def test_apply_key_to_syscall8():
    """
    Apply key directly to syscall 8.
    (key syscall8)
    """
    print("\n" + "=" * 70)
    print("APPLY KEY TO SYSCALL 8")
    print("=" * 70)
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # Left: key at Var(0)
                    # (key syscall8) - syscall8 is at Var(9)
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
    resp = query(payload, timeout_s=5)
    print(f"  (key syscall8) branch: {resp}")


def test_key_syscall8_extract():
    """
    If (key syscall8) returns Left, extract and use the payload.
    """
    print("\n" + "=" * 70)
    print("(KEY SYSCALL8) -> EXTRACT -> USE")
    print("=" * 70)
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # Left: key at Var(0)
                    App(
                        App(App(Var(0), Var(9)),  # (key syscall8)
                            Lam(  # Left: payload at Var(0)
                                # Write payload as byte
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
    resp = query(payload, timeout_s=5)
    print(f"  (key syscall8) Left payload: {resp}")
    if resp and len(resp) == 1:
        print(f"  Byte value: {resp[0]}")


def test_chain_key_syscall8_syscall8():
    """
    Chain: (key syscall8) -> extract -> use with syscall8 again
    """
    print("\n" + "=" * 70)
    print("CHAIN: (KEY SYSCALL8) -> SYSCALL8")
    print("=" * 70)
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # Left: key at Var(0)
                    App(
                        App(App(Var(0), Var(9)),  # (key syscall8) - inner syscall8
                            Lam(  # Left: payload1 at Var(0)
                                # syscall8(payload1)
                                App(
                                    App(Var(11), Var(0)),  # syscall8(payload1)
                                    Lam(
                                        App(
                                            App(Var(0),
                                                Lam(App(App(Var(8), Var(0)), nil))),
                                            Lam(App(App(Var(8), encode_string("PD")), nil))
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
    print(f"  syscall8((key syscall8) payload): {resp}")


def main():
    test_syscall8_with_key_result()
    time.sleep(0.3)
    
    test_syscall8_with_key_directly()
    time.sleep(0.3)
    
    test_apply_something_to_syscall8()
    time.sleep(0.3)
    
    test_apply_key_to_syscall8()
    time.sleep(0.3)
    
    test_key_syscall8_extract()
    time.sleep(0.3)
    
    test_chain_key_syscall8_syscall8()


if __name__ == "__main__":
    main()
