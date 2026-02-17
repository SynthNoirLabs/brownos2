#!/usr/bin/env python3
"""
Add tracing to find where the nested Either extraction fails.
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
    print("TRACING: Where does the nested extraction fail?")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print("\n=== Step by step with trace outputs ===\n")
    
    # First, verify the original pattern still works
    verify_basic = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(
                                    App(Var(1), Var(0)),
                                    Lam(App(App(Var(6), encode_string("GOT-L\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("GOT-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ECHO-R\n")), nil))
        )
    )
    
    print("1. Basic verify - (Var(253) sc8Result) -> L or R?")
    payload = bytes([0x0E, 251, FD]) + encode_term(verify_basic) + bytes([FD, FF])
    test("  result", payload)
    
    # OK so we confirmed payload = Left(something) where something behaves as Right
    # Let's trace deeper with explicit writes at each step
    
    trace_outer = Lam(
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
                                        # Print "A" to show we got to outer Left
                                        App(
                                            App(Var(5), encode_string("A")),
                                            Lam(
                                                # Now treat outer payload as Either
                                                App(
                                                    App(Var(1),
                                                        Lam(App(App(Var(8), encode_string("B")), nil))
                                                    ),
                                                    Lam(App(App(Var(8), encode_string("C")), nil))
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
            Lam(App(App(Var(4), encode_string("Y\n")), nil))
        )
    )
    
    print("\n2. Trace: A=got outer Left, B=inner Left, C=inner Right, X=outer Right:")
    payload = bytes([0x0E, 251, FD]) + encode_term(trace_outer) + bytes([FD, FF])
    test("  result", payload)
    
    # What if payload is NOT an Either but something else?
    # Let's try applying it to different things
    
    print("\n=== What is the outer payload? ===\n")
    
    # Apply outer payload to identity
    identity = Lam(Var(0))
    
    apply_to_id = Lam(
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
                                        # outer payload - apply to identity and identity
                                        App(
                                            App(Var(0), identity),
                                            Lam(App(App(Var(7), encode_string("D\n")), nil))
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("X\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("Y\n")), nil))
        )
    )
    
    print("3. (outerPayload identity) k:")
    payload = bytes([0x0E, 251, FD]) + encode_term(apply_to_id) + bytes([FD, FF])
    test("  result", payload)
    
    # Try quoting the outer payload directly
    quote_outer = Lam(
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
                                        # Quote the outer payload
                                        App(
                                            App(Var(7), Var(0)),
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
                                Lam(App(App(Var(5), encode_string("X\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("Y\n")), nil))
        )
    )
    
    print("\n4. Quote the outer payload directly:")
    payload = bytes([0x0E, 251, FD]) + encode_term(quote_outer) + bytes([FD, FF])
    resp = test("  result", payload)
    if resp:
        print(f"  HEX: {resp.hex()}")
    
    # The original probe said QUOTE-RIGHT (quote returned Right)
    # But that was quoting the INNER payload
    # The quote returning Right means encoding failed
    # This suggests the payload contains unserializable bytes (253/254/255)!
    
    print("\n=== HYPOTHESIS: Payload contains unserializable Var(253/254/255) ===\n")
    print("This would cause quote to fail (Right) and write to produce nothing!")
    
    # Can we "evaluate" the payload somehow to get something printable?
    # Maybe the payload IS a continuation or function we need to call?
    
    # What if payload is the ANSWER wrapped in lambda?
    # e.g., payload = λk. k "answer"
    
    call_with_write = Lam(
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
                                        # Call payload with write as continuation
                                        App(Var(0), 
                                            Lam(App(App(Var(7), Var(0)), nil))
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("X\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("Y\n")), nil))
        )
    )
    
    print("5. (payload (λx. write(x) nil)):")
    payload = bytes([0x0E, 251, FD]) + encode_term(call_with_write) + bytes([FD, FF])
    test("  result", payload)


if __name__ == "__main__":
    main()
