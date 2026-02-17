#!/usr/bin/env python3
"""
Use the QD (Quick Debug) pattern from solve_brownos_answer.py
combined with the key transform.

QD = 0500fd000500fd03fdfefd02fdfefdfe
This is a continuation that quotes the result and writes it.
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
    print("USING QD PATTERN WITH KEY")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    # QD expects to be the continuation of a syscall.
    # syscall arg QD -> QD receives the result, quotes it, writes it
    
    # Standard: syscall8 nil QD
    print("\n1. Standard: syscall8(nil) with QD continuation:")
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # What about: echo(251) then syscall8 then QD?
    # We need to get the key first, then use it
    
    # Actually, let's try a completely raw approach:
    # Just send the bytes for: echo 251 syscall8 nil key-transform QD
    
    print("\n2. Echo then transform the syscall8 result:")
    # echo(251) (λechoResult. syscall8 nil (λsc8Result. (echoResult (λkey. ...))))
    # This is getting complex. Let me try a simpler wire format.
    
    # Raw bytes approach:
    # 0E = echo
    # FB = 251 (Var to echo)
    # FD = App (echo 251)
    # Then continuation...
    
    # Actually, the working probe was:
    # echo(Var(251)) with continuation that extracts key and applies to sc8
    
    # Let's verify: what is our working chain?
    # 1. echo(251) -> Left(key) where key=Var(253)
    # 2. syscall8(nil) -> Right(6)
    # 3. (key Right(6)) -> Left(outer) where outer=Right(Church1)
    
    # The issue is that outer=Right(Church1) and Church1 = byte value 1
    # This is not the full answer. Maybe we need to access the data differently.
    
    print("\n3. Let's just verify what outer is using QD:")
    
    # Extract outer and use QD to print it
    extract_outer_qd = Lam(
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
                                            App(Var(6), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(9), Var(0)), nil))
                                                    ),
                                                    Lam(App(App(Var(9), encode_string("QF\n")), nil))
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
    
    print("quote(outer) directly:")
    payload = bytes([0x0E, 251, FD]) + encode_term(extract_outer_qd) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # What if we don't use key at all? Just transform sc8Result directly?
    print("\n4. sc8Result as-is (Right(6)), quote the error code:")
    
    sc8_direct_qd = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), encode_string("L\n")), nil))
                                ),
                                Lam(
                                    App(
                                        App(Var(7), Var(0)),
                                        Lam(
                                            App(
                                                App(Var(0),
                                                    Lam(App(App(Var(10), Var(0)), nil))
                                                ),
                                                Lam(App(App(Var(10), encode_string("QF\n")), nil))
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("syscall8(nil) -> Right(errCode) -> quote(errCode):")
    payload = bytes([0x0E, 251, FD]) + encode_term(sc8_direct_qd) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # Aha! Maybe the key (Var(253)) is actually MEANT to quote things?
    # Since it's 0xFD which is the App marker...
    
    print("\n5. What if we apply the key to a simple term and see what happens?")
    
    key_apply_simple = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(6), App(Var(0), encode_string("test"))),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(8), Var(0)), nil))
                                ),
                                Lam(App(App(Var(8), encode_string("QF\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E\n")), nil))
        )
    )
    
    print("quote(key 'test'):")
    payload = bytes([0x0E, 251, FD]) + encode_term(key_apply_simple) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")


if __name__ == "__main__":
    main()
