#!/usr/bin/env python3
"""
Verify the exact pattern that gave us LEFT.
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
            result = f"OUTPUT: {repr(text[:100])}"
        except:
            result = f"hex: {resp.hex()[:100]}"
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
    print("VERIFY THE EXACT PATTERN THAT GAVE LEFT")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print("\n=== This is the EXACT pattern from probe_var253_behavior.py ===\n")
    
    apply_253_twice = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(App(App(Var(6), encode_string("FIRST-L\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("FIRST-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("Apply (Var(253) sc8Result) as Either:")
    payload = bytes([0x0E, 251, FD]) + encode_term(apply_253_twice) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Let me trace through the de Bruijn indices ===\n")
    print("""
Structure at depth 0: echo(Var(251)) cont
  cont = λechoResult.       -- depth 1
    echoResult              -- V0 at depth 1
      (λpayload.            -- depth 2, leftHandler for echo
        syscall8 nil cont2  -- syscall8 = V8+2 = V10
        cont2 = λsc8Result. -- depth 3
          (V1 V0)           -- V1=payload=Var(253), V0=sc8Result
            (λx. write ...)  -- leftHandler2  
            (λx. write ...)  -- rightHandler2
      )
      (λx. write ECHO-R)    -- depth 2, rightHandler for echo
""")
    
    print("So the structure is: ((Var(253) sc8Result) leftHandler rightHandler)")
    print("If this prints FIRST-L, it means (Var(253) sc8Result) acts as Left!")
    
    print("\n=== Test variations ===\n")
    
    print("Test 1: Baseline - just branch on sc8Result directly:")
    baseline = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    Var(0),
                                    Lam(App(App(Var(6), encode_string("SC8-L\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("SC8-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(baseline) + bytes([FD, FF])
    test("  sc8Result directly", payload)
    
    print("\nTest 2: (Var(253) sc8Result) as Either:")
    payload = bytes([0x0E, 251, FD]) + encode_term(apply_253_twice) + bytes([FD, FF])
    test("  (Var(253) sc8Result)", payload)
    
    print("\nTest 3: Try with different arguments to syscall8:")
    
    for arg_desc, arg in [("nil", nil), ("Var(0)", Var(0))]:
        test_pattern = Lam(
            App(
                App(Var(0),
                    Lam(
                        App(
                            App(Var(10), arg),
                            Lam(
                                App(
                                    App(
                                        App(Var(1), Var(0)),
                                        Lam(App(App(Var(6), encode_string("L\n")), nil))
                                    ),
                                    Lam(App(App(Var(6), encode_string("R\n")), nil))
                                )
                            )
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("ER\n")), nil))
            )
        )
        
        payload = bytes([0x0E, 251, FD]) + encode_term(test_pattern) + bytes([FD, FF])
        test(f"  syscall8({arg_desc})", payload)
        time.sleep(0.2)
    
    print("\n=== What if we use the backdoor pair with Var(253)? ===\n")
    
    backdoor_with_253 = Lam(
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
                                                        Lam(App(App(Var(8), encode_string("BD-SC8-L\n")), nil))
                                                    ),
                                                    Lam(App(App(Var(8), encode_string("BD-SC8-R\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("ECHO-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD-R\n")), nil))
        )
    )
    
    print("backdoor -> echo(251) -> syscall8(pair) -> (Var(253) result):")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_with_253) + bytes([FD, FF])
    test("  result", payload)


if __name__ == "__main__":
    main()
