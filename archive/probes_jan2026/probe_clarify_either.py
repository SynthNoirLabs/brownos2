#!/usr/bin/env python3
"""
Clarify the Either handling.

Earlier I had conflicting results:
1. (Var253 nil) with standard Either handler -> LEFT
2. (Var253 X) with custom handler -> RIGHT

The difference might be in the handler structure.

Either = λl.λr. l payload  (Left)
Either = λl.λr. r payload  (Right)

Pattern: (Either LeftHandler RightHandler)

So the result should be:
- For Left(x): LeftHandler x
- For Right(x): RightHandler x
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


def test_echo_result_structure():
    """
    echo(251) returns an Either.
    Let's verify its structure.
    """
    print("=" * 70)
    print("ECHO RESULT STRUCTURE")
    print("=" * 70)
    
    # echo(251) -> Either
    # Apply to handlers: (echoResult LeftHandler RightHandler)
    
    test_term = Lam(
        App(
            App(Var(0),  # echoResult
                Lam(App(App(Var(4), encode_string("LEFT")), nil))),  # LeftHandler
            Lam(App(App(Var(4), encode_string("RIGHT")), nil))  # RightHandler
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  echo(251) branch: {resp}")


def test_key_application_carefully():
    """
    Get the key (Left payload), then apply it to nil.
    The result should be another Either.
    """
    print("\n" + "=" * 70)
    print("KEY APPLICATION CAREFULLY")
    print("=" * 70)
    
    # echo(251) -> Left(key)
    # Extract key, then: (key nil)
    # Result of (key nil) should be an Either (or something else?)
    
    # Pattern 1: Simple - (key nil) treated as Either
    print("\n  Pattern 1: ((key nil) L R)")
    test_term = Lam(
        App(
            App(Var(0),  # echoResult
                Lam(  # Left: key at Var(0)
                    App(
                        App(App(Var(0), nil), 
                            Lam(App(App(Var(5), encode_string("L1")), nil))),
                        Lam(App(App(Var(5), encode_string("R1")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"    Result: {resp}")
    
    # Pattern 2: What if (key nil) is NOT an Either but just a value?
    # Let's try to write it directly
    print("\n  Pattern 2: write((key nil))")
    test_term2 = Lam(
        App(
            App(Var(0),
                Lam(  # Left: key at Var(0)
                    # write((key nil)) - but we need to convert to string first
                    # Let's try quote((key nil)) to see its structure
                    App(
                        App(Var(5), App(Var(0), nil)),  # quote((key nil))
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), Var(0)), nil))),  # Left: write quoted
                                Lam(App(App(Var(6), encode_string("QF")), nil))  # Right: quote failed
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term2) + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"    quote((key nil)): {resp.hex() if resp and resp not in [b'QF', b'ER'] else resp}")


def test_nested_either():
    """
    What if (key nil) returns Left(something), and that something is ALSO an Either?
    
    Pattern: (key nil) -> Left(inner_either)
    inner_either -> Left(final) or Right(final)
    """
    print("\n" + "=" * 70)
    print("NESTED EITHER TEST")
    print("=" * 70)
    
    # ((key nil) OuterLeft OuterRight)
    # If OuterLeft fires, it receives `inner_either`
    # Then we test: (inner_either InnerLeft InnerRight)
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # Left: key at Var(0)
                    # Outer Either pattern
                    App(
                        App(App(Var(0), nil),  # (key nil)
                            Lam(  # OuterLeft: Var(0) = payload
                                # Is payload an Either? Let's test
                                App(
                                    App(Var(0),  # payload as Either
                                        Lam(App(App(Var(7), encode_string("LL")), nil))),  # LeftLeft
                                    Lam(App(App(Var(7), encode_string("LR")), nil))  # LeftRight
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("R_")), nil))  # OuterRight
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  Nested Either test: {resp}")
    
    # So if we get "LL" or "LR", the payload IS an Either!


def test_triple_nested():
    """
    What if there are 3 levels of nesting?
    (key nil) -> Left(Either1)
    Either1 -> Left(Either2)
    Either2 -> Left(finalValue)
    """
    print("\n" + "=" * 70)
    print("TRIPLE NESTED EITHER")
    print("=" * 70)
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # Left: key at Var(0)
                    App(
                        App(App(Var(0), nil),  # (key nil) = Either1
                            Lam(  # Either1 Left
                                App(
                                    App(Var(0),  # Either2
                                        Lam(  # Either2 Left
                                            App(
                                                App(Var(0),  # Either3
                                                    Lam(  # Either3 Left
                                                        App(App(Var(11), encode_string("LLL")), nil)
                                                    )
                                                ),
                                                Lam(App(App(Var(11), encode_string("LLR")), nil))
                                            )
                                        )
                                    ),
                                    Lam(App(App(Var(9), encode_string("LR_")), nil))
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("R__")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ERR")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  Triple nested: {resp}")


def test_extract_inner_value():
    """
    Extract the innermost value from the nested structure.
    """
    print("\n" + "=" * 70)
    print("EXTRACT INNERMOST VALUE")
    print("=" * 70)
    
    # If we have Left(Left(Left(x))), we need to unwrap 3 times
    # Then write x as a byte
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # Left: key at Var(0)
                    App(
                        App(App(Var(0), nil),  # (key nil) = Either1
                            Lam(  # Either1 Left: payload1 at Var(0)
                                App(
                                    App(Var(0),  # payload1 as Either2
                                        Lam(  # Either2 Left: payload2 at Var(0)
                                            # Write payload2 as a single byte
                                            # Using Lam(Lam(App(App(Var(1), Var(2)), nil)))
                                            App(
                                                App(Var(8), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                                nil
                                            )
                                        )
                                    ),
                                    Lam(App(App(Var(7), encode_string("LR")), nil))
                                )
                            )
                        ),
                        Lam(App(App(Var(5), encode_string("R_")), nil))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=3)
    print(f"  Inner value (2 levels): {resp}")
    if resp and len(resp) == 1:
        print(f"  Byte value: {resp[0]}")


def main():
    test_echo_result_structure()
    time.sleep(0.3)
    
    test_key_application_carefully()
    time.sleep(0.3)
    
    test_nested_either()
    time.sleep(0.3)
    
    test_triple_nested()
    time.sleep(0.3)
    
    test_extract_inner_value()


if __name__ == "__main__":
    main()
