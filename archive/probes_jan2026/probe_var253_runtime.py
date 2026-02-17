#!/usr/bin/env python3
"""
What if we need to USE Var(253) at runtime?

Echo manufactures Var(253) from Var(251).
Maybe we need to:
1. Get Var(253) via echo
2. Apply it to something
3. Use the result with syscall 8

The key insight: Var(253) is the App marker (0xFD) in wire format.
At runtime, it's a free variable that doesn't reduce.

What happens if we APPLY Var(253) to things?
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


def test_apply_var253_to_syscall8():
    """
    Get Var(253) via echo, then apply it TO syscall 8.
    
    Pattern: echo(251) -> Left(Var(253))
    Then: (Var(253) syscall8)
    
    If Var(253) is the App marker, what happens when we apply it?
    """
    print("=" * 70)
    print("APPLY VAR(253) TO SYSCALL 8")
    print("=" * 70)
    
    # echo(251) -> continuation handles Left(Var(253))
    # In continuation: (Var(253) syscall8) with some arg and cont
    
    test_term = Lam(
        App(
            App(Var(0),  # echoResult (Either)
                Lam(  # Left handler: Var(0) = Var(253)
                    # Inside 1 extra lambda, syscall8 = Var(9)
                    # Apply: (Var(253) syscall8)
                    # But wait, we need Var(0) which is the echoed value (Var(253))
                    # So we do: ((Var(0) Var(9)) cont)
                    App(
                        App(Var(0), Var(9)),  # (Var253 syscall8)
                        Lam(  # result handler
                            App(App(Var(0), 
                                Lam(App(App(Var(6), Var(0)), nil))),  # Left: write
                                Lam(App(App(Var(6), encode_string("R")), nil)))  # Right
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))  # Right handler for echo
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  ((Var253 syscall8) cont): {resp}")
    

def test_apply_syscall8_to_var253():
    """
    Apply syscall8 TO Var(253).
    
    Pattern: echo(251) -> Left(Var(253))
    Then: (syscall8 Var(253))
    """
    print("\n" + "=" * 70)
    print("APPLY SYSCALL 8 TO VAR(253)")
    print("=" * 70)
    
    test_term = Lam(
        App(
            App(Var(0),  # echoResult
                Lam(  # Left: val at Var(0) is Var(253)
                    App(
                        App(Var(9), Var(0)),  # (syscall8 Var(253))
                        Lam(
                            App(App(Var(0),
                                Lam(App(App(Var(6), Var(0)), nil))),  # Left
                                Lam(App(App(Var(6), encode_string("PD")), nil)))  # Right: perm denied
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  (syscall8 Var(253)): {resp}")


def test_apply_var253_to_nil():
    """
    Apply Var(253) to nil and see what happens.
    """
    print("\n" + "=" * 70)
    print("APPLY VAR(253) TO NIL")
    print("=" * 70)
    
    # echo(251) -> Left(Var(253))
    # Then: (Var(253) nil) and quote the result
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # Left: Var(0) = Var(253)
                    App(
                        App(Var(5), App(Var(0), nil)),  # quote((Var(253) nil))
                        Lam(
                            App(App(Var(0),
                                Lam(App(App(Var(6), Var(0)), nil))),
                                Lam(App(App(Var(6), encode_string("QF")), nil)))
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  quote((Var(253) nil)): {resp.hex() if resp and resp not in [b'QF', b'ER'] else resp}")


def test_chain_echo_twice():
    """
    echo(251) -> Var(253)
    echo(Var(253)) -> Var(255)?
    
    If Var(255) is the End marker (0xFF), what happens?
    """
    print("\n" + "=" * 70)
    print("CHAIN ECHO TWICE: echo(echo(251))")
    print("=" * 70)
    
    # We need to: echo(251) -> get Var(253) -> echo(Var(253)) -> Var(255)?
    
    test_term = Lam(
        App(
            App(Var(0),  # first echo result
                Lam(  # Left: val = Var(253)
                    # Now echo this value
                    App(
                        App(Var(16), Var(0)),  # (echo Var(253)) - echo is at Var(14+2)
                        Lam(  # second echo result handler
                            App(
                                App(Var(0),  # Either
                                    Lam(  # Left: should be Var(255)?
                                        App(
                                            App(Var(7), App(Var(0), nil)),  # quote(result nil)
                                            Lam(
                                                App(App(Var(0),
                                                    Lam(App(App(Var(8), Var(0)), nil))),
                                                    Lam(App(App(Var(8), encode_string("QF")), nil)))
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(7), encode_string("E2")), nil))  # echo2 Right
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E1")), nil))  # echo1 Right
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  echo(echo(251)) quote: {resp.hex() if resp and len(resp) > 5 else resp}")


def test_backdoor_then_echo_then_syscall8():
    """
    What if the sequence matters?
    backdoor -> echo -> syscall8 in a specific order
    """
    print("\n" + "=" * 70)
    print("BACKDOOR -> ECHO -> SYSCALL8 SEQUENCE")
    print("=" * 70)
    
    # backdoor(nil) -> pair
    # echo(pair) -> shifted pair
    # syscall8(shifted pair)
    
    test_term = Lam(
        App(
            App(Var(0),  # backdoor result (Either)
                Lam(  # Left: pair
                    # Echo the pair
                    App(
                        App(Var(16), Var(0)),  # (echo pair) - echo at 14+2
                        Lam(  # echo result handler
                            App(
                                App(Var(0),  # Either
                                    Lam(  # Left: shifted pair
                                        # syscall8(shifted pair)
                                        App(
                                            App(Var(12), Var(0)),  # syscall8 at 8+4
                                            Lam(
                                                App(App(Var(0),
                                                    Lam(App(App(Var(8), Var(0)), nil))),
                                                    Lam(App(App(Var(8), encode_string("PD")), nil)))
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(7), encode_string("E2")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD")), nil))  # backdoor Right
        )
    )
    
    # backdoor(nil)
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  syscall8(echo(backdoor(nil))): {resp}")


def test_use_var253_as_continuation():
    """
    What if Var(253) should be the CONTINUATION, not the argument?
    """
    print("\n" + "=" * 70)
    print("VAR(253) AS CONTINUATION TO SYSCALL 8")
    print("=" * 70)
    
    # Get Var(253), then: (syscall8 nil) with Var(253) as continuation
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # Left: Var(253) at Var(0)
                    # (syscall8 nil) with Var(0) as continuation
                    App(
                        App(Var(9), nil),  # (syscall8 nil)
                        Var(0)  # Var(253) as continuation!
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  ((syscall8 nil) Var(253)): {resp}")


def main():
    test_apply_var253_to_syscall8()
    time.sleep(0.3)
    
    test_apply_syscall8_to_var253()
    time.sleep(0.3)
    
    test_apply_var253_to_nil()
    time.sleep(0.3)
    
    test_chain_echo_twice()
    time.sleep(0.3)
    
    test_backdoor_then_echo_then_syscall8()
    time.sleep(0.3)
    
    test_use_var253_as_continuation()


if __name__ == "__main__":
    main()
