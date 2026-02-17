#!/usr/bin/env python3
"""
Investigate what happens when we apply Var(253) to things.

Finding: ((Var253 syscall8) cont) -> Right branch fires
This means (Var253 syscall8) reduces to something that's an Either!
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
identity = Lam(Var(0))


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


def test_var253_applied_extract_payload():
    """
    ((Var253 X) cont) fires Right branch.
    Let's extract what's in the Right.
    """
    print("=" * 70)
    print("EXTRACT PAYLOAD FROM (Var253 X)")
    print("=" * 70)
    
    # Different X values to apply Var(253) to
    targets = [
        ("nil", nil),
        ("identity", identity),
        ("syscall8 (Var(8))", Var(8)),  # Actually Var(9) in context
        ("echo (Var(14))", Var(14)),  # Actually Var(15) in context
    ]
    
    for name, target in targets:
        # We need to construct this carefully with correct de Bruijn indices
        # echo(251) puts us in context with 1 extra lambda
        # So syscall8=Var(9), echo=Var(15), write=Var(3)
        
        # If target is a Var, we need to adjust for the context
        if isinstance(target, Var):
            adjusted = Var(target.i + 1)  # +1 for the Left handler lambda
        else:
            adjusted = target
        
        test_term = Lam(
            App(
                App(Var(0),  # echo result
                    Lam(  # Left: Var(253) at Var(0)
                        App(
                            App(Var(0), adjusted),  # (Var253 target)
                            Lam(  # Either handler
                                App(
                                    App(Var(0),
                                        Lam(  # Left
                                            App(App(Var(6), encode_string("L:")), nil)
                                        )
                                    ),
                                    Lam(  # Right - write the payload
                                        # Var(0) is the Right payload
                                        # Try to write it as a byte
                                        App(App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
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
        print(f"  (Var253 {name}): {resp}")
        time.sleep(0.2)


def test_var253_quote_result():
    """
    Quote the result of (Var253 X) to see its structure.
    """
    print("\n" + "=" * 70)
    print("QUOTE (Var253 X) RESULTS")
    print("=" * 70)
    
    # Get Var(253), apply it to nil, quote the Right payload
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # Left: Var(253) at Var(0)
                    App(
                        App(Var(0), nil),  # (Var253 nil)
                        Lam(  # Either handler
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), encode_string("L:")), nil))
                                ),
                                Lam(  # Right - quote the payload
                                    App(
                                        App(Var(6), Var(0)),  # quote(payload)
                                        Lam(
                                            App(App(Var(0),
                                                Lam(App(App(Var(8), Var(0)), nil))),
                                                Lam(App(App(Var(8), encode_string("QF")), nil)))
                                        )
                                    )
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
    print(f"  quote(Right payload from (Var253 nil)): {resp.hex() if resp and resp not in [b'L:', b'QF', b'ER'] else resp}")


def test_var253_to_various():
    """
    Apply Var(253) to various things and see what Either branch fires.
    """
    print("\n" + "=" * 70)
    print("VAR(253) APPLIED TO VARIOUS TERMS")
    print("=" * 70)
    
    # In context of echo's Left handler, we have:
    # Var(0) = Var(253), write = Var(3), quote = Var(5), etc.
    
    targets = [
        ("0 (inside lambda)", 0),
        ("1", 1),
        ("2", 2),
        ("8 (syscall8 in caller)", 8),
        ("9 (syscall8 adjusted)", 9),
        ("14 (echo in caller)", 14),
        ("251 (magic?)", 251),
        ("252", 252),
    ]
    
    for name, var_idx in targets:
        test_term = Lam(
            App(
                App(Var(0),  # echo result
                    Lam(  # Left: Var(253) at Var(0)
                        App(
                            App(Var(0), Var(var_idx)),  # (Var253 Var(var_idx))
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
        
        payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
        resp = query(payload, timeout_s=2)
        print(f"  (Var253 Var({name})): {resp}")
        time.sleep(0.1)


def test_var253_double_application():
    """
    What if we apply Var(253) twice?
    ((Var253 X) Y) -> ???
    """
    print("\n" + "=" * 70)
    print("DOUBLE APPLICATION: ((Var253 X) Y)")
    print("=" * 70)
    
    # (Var253 nil) gives Right(something)
    # What if we then apply that result to something else?
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # Left: Var(253) at Var(0)
                    # ((Var253 nil) identity)
                    App(
                        App(App(Var(0), nil), identity),  # ((Var253 nil) identity)
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
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  ((Var253 nil) identity): {resp}")
    
    # Try: ((Var253 nil) nil)
    test_term2 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(App(Var(0), nil), nil),
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
    resp = query(payload, timeout_s=3)
    print(f"  ((Var253 nil) nil): {resp}")


def main():
    test_var253_applied_extract_payload()
    time.sleep(0.3)
    
    test_var253_quote_result()
    time.sleep(0.3)
    
    test_var253_to_various()
    time.sleep(0.3)
    
    test_var253_double_application()


if __name__ == "__main__":
    main()
