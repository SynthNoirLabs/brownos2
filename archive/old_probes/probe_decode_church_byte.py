#!/usr/bin/env python3
"""
The inner value is a Church-encoded byte!
Quoted form: 0100fdfefefefefefefefefeff
Decoded: λλλλλλλλλ. (Var(1) Var(0)) = Church byte for value 1

Let's decode it properly to see what the actual value is.
Also need to check if there are MORE bytes - maybe it's a list!
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
    print("DECODE THE CHURCH BYTE")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    identity = Lam(Var(0))
    
    print("\nQuoted inner value: 0100fdfefefefefefefefefeff")
    print("Parsing: Var(1) Var(0) App, then 9x Lam, then End")
    print("= λλλλλλλλλ. (Var(1) Var(0))")
    print("")
    print("In Church encoding, Var(i) where i=1-8 represents bit positions")
    print("Var(1) = bit 0 (value 1)")
    print("Var(0) = accumulator")
    print("So (Var(1) Var(0)) = apply bit0 = value 1")
    print("")
    
    print("The inner value is Church numeral for 1!")
    print("But wait - maybe THIS is the first byte of a STRING.")
    print("The outer structure might be Right(1), meaning the password char!")
    print("")
    
    print("Let's check if outer payload is a LIST (cons cell):")
    
    try_as_list = Lam(
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
                                        # outer at depth 4, try as cons cell: (outer (λh.λt. ...) nil)
                                        App(
                                            App(Var(0),  
                                                Lam(Lam(  # head=0, tail=1
                                                    App(
                                                        App(Var(10), Var(1)),  # quote(head)
                                                        Lam(
                                                            App(
                                                                App(Var(0),
                                                                    Lam(App(App(Var(12), Var(0)), nil))
                                                                ),
                                                                Lam(App(App(Var(12), encode_string("QF\n")), nil))
                                                            )
                                                        )
                                                    )
                                                ))
                                            ),
                                            nil
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
    
    print("1. Treat outer as cons cell, quote head:")
    payload = bytes([0x0E, 251, FD]) + encode_term(try_as_list) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # Let's decode the Church byte we found
    # Build a decoder: apply to bit-extractor functions
    
    # The Church byte encoding is:
    # byte n = λb7.λb6.λb5.λb4.λb3.λb2.λb1.λb0.λacc. (b_i acc) for each set bit i
    # To decode: apply to (λx.x+128) (λx.x+64) ... (λx.x+1) 0
    
    # But we can't do arithmetic! Instead, decode by passing bits to a printer
    
    print("\n2. Decode Church byte by bit testing:")
    print("Church byte: λb7...b0.λacc. ... if bit i set: (bi acc)")
    print("Pass functions that mark each bit:")
    
    # Actually, let's check the actual bits by applying specific extractors
    decode_byte_val = Lam(
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
                                                # val is the Church byte
                                                # Apply it to 8 identity functions + base
                                                App(
                                                    App(
                                                        App(
                                                            App(
                                                                App(
                                                                    App(
                                                                        App(
                                                                            App(
                                                                                App(Var(0),  # the Church byte
                                                                                    Lam(Lam(App(Var(1), App(Var(1), Var(0)))))  # bit7: double
                                                                                ),
                                                                                Lam(Lam(App(Var(1), App(Var(1), Var(0)))))  # bit6
                                                                            ),
                                                                            Lam(Lam(App(Var(1), App(Var(1), Var(0)))))  # bit5
                                                                        ),
                                                                        Lam(Lam(App(Var(1), App(Var(1), Var(0)))))  # bit4
                                                                    ),
                                                                    Lam(Lam(App(Var(1), App(Var(1), Var(0)))))  # bit3
                                                                ),
                                                                Lam(Lam(App(Var(1), App(Var(1), Var(0)))))  # bit2
                                                            ),
                                                            Lam(Lam(App(Var(1), App(Var(1), Var(0)))))  # bit1
                                                        ),
                                                        Lam(Lam(App(Var(1), App(Var(1), Var(0)))))  # bit0: succ
                                                    ),
                                                    Lam(Var(0))  # zero
                                                ),
                                                Lam(
                                                    App(
                                                        App(Var(9), Var(0)),
                                                        Lam(
                                                            App(
                                                                App(Var(0),
                                                                    Lam(App(App(Var(11), Var(0)), nil))
                                                                ),
                                                                Lam(App(App(Var(11), encode_string("QN\n")), nil))
                                                            )
                                                        )
                                                    )
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
    
    print("Apply Church byte to successor functions and quote result:")
    payload = bytes([0x0E, 251, FD]) + encode_term(decode_byte_val) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # Actually the simplest way: just write the byte directly using syscall 2
    # If val is a Church byte, we need to convert it to wire format
    # Let's try using syscall 42 (0x2A) which might output directly
    
    print("\n3. Maybe there's a list? Check if outer has a 'tail':")
    
    check_tail = Lam(
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
                                        # Apply outer to handlers that check structure
                                        App(
                                            App(Var(0), 
                                                Lam(App(App(Var(7), encode_string("L\n")), nil))  # Left handler
                                            ),
                                            Lam(  # Right handler gets the value
                                                # What if we pass TWO handlers? (cons case)
                                                App(App(Var(7), encode_string("X\n")), nil)
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
    
    print("(outer L R) directly:")
    payload = bytes([0x0E, 251, FD]) + encode_term(check_tail) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n4. Use syscall 42 (0x2A) to output the answer:")
    
    # Syscall 42 at depth n = Var(42+n)
    use_syscall42 = Lam(
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
                                                # val = Church byte
                                                # syscall42 at depth 5 = Var(47)
                                                App(
                                                    App(Var(47), Var(0)),
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
    
    print("syscall42(val):")
    payload = bytes([0x0E, 251, FD]) + encode_term(use_syscall42) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")


if __name__ == "__main__":
    main()
