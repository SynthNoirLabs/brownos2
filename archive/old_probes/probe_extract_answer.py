#!/usr/bin/env python3
"""
VAR(253) TRANSFORMS SYSCALL 8's Right(6) INTO Left!

Now we need to EXTRACT what's in that Left payload.
The structure is: ((Var(253) sc8Result) leftHandler rightHandler)
We want: leftHandler to receive the payload and write it.
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
    elif b"Encoding failed" in resp:
        result = "Encoding failed!"
    elif b"Invalid term" in resp:
        result = "Invalid term!"
    else:
        try:
            text = resp.decode('utf-8', 'replace')
            result = f"OUTPUT: {repr(text[:200])}"
        except:
            result = f"hex: {resp.hex()[:200]}"
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
    print("EXTRACTING THE ANSWER FROM (Var(253) sc8Result)")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print("\n=== Extract Left payload and WRITE it as bytes ===\n")
    print("""
Structure:
  echo(Var(251)) -> Left(Var(253))
  Extract Var(253) as 'key'
  syscall8 nil -> Right(6)
  (key Right(6)) -> Left(payload)
  Extract payload and write it
""")
    
    extract_and_write = Lam(
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
                                        App(App(Var(5), Var(0)), nil)
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("STILL-RIGHT\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-RIGHT\n")), nil))
        )
    )
    
    print("(Var(253) sc8Result) -> Left(payload) -> write(payload):")
    payload = bytes([0x0E, 251, FD]) + encode_term(extract_and_write) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW BYTES: {resp}")
        print(f"  HEX: {resp.hex()}")
    
    print("\n=== Try QUOTING the payload first ===\n")
    
    extract_quote_write = Lam(
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
                                            App(Var(7), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(8), Var(0)), nil))
                                                    ),
                                                    Lam(App(App(Var(8), encode_string("QUOTE-RIGHT\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("STILL-RIGHT\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-RIGHT\n")), nil))
        )
    )
    
    print("(Var(253) sc8Result) -> Left(payload) -> quote(payload) -> write:")
    payload = bytes([0x0E, 251, FD]) + encode_term(extract_quote_write) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW: {resp}")
    
    print("\n=== Maybe the payload is a string already - decode it ===\n")
    
    print("Let me try with the backdoor pair as syscall8's argument:")
    
    backdoor_extract = Lam(
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
                                            App(Var(12), Var(2)),
                                            Lam(
                                                App(
                                                    App(
                                                        App(Var(1), Var(0)),
                                                        Lam(App(App(Var(7), Var(0)), nil))
                                                    ),
                                                    Lam(App(App(Var(7), encode_string("STR\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("ER\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BR\n")), nil))
        )
    )
    
    print("backdoor -> echo(251) -> syscall8(pair) -> (Var(253) result) -> write payload:")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_extract) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  RAW: {resp}")
    
    print("\n=== What IS the payload? Let's use it as an Either itself ===\n")
    
    payload_as_either = Lam(
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
                                            App(Var(0),
                                                Lam(App(App(Var(7), encode_string("PL-L\n")), nil))
                                            ),
                                            Lam(App(App(Var(7), encode_string("PL-R\n")), nil))
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("STILL-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("(Var(253) sc8Result) -> Left(payload) -> treat payload as Either:")
    payload = bytes([0x0E, 251, FD]) + encode_term(payload_as_either) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Apply payload to nil and see what happens ===\n")
    
    apply_payload = Lam(
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
                                            App(Var(0), nil),
                                            Lam(App(App(Var(6), encode_string("APPLIED\n")), nil))
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("STILL-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("(Var(253) sc8Result) -> Left(payload) -> (payload nil) -> write:")
    payload = bytes([0x0E, 251, FD]) + encode_term(apply_payload) + bytes([FD, FF])
    test("  result", payload)


if __name__ == "__main__":
    main()
