#!/usr/bin/env python3
"""
Test stateful hypothesis: Does calling the key multiple times return different bytes?

Theory: The key (Var(253)) might be a stateful oracle that returns successive bytes
of the answer on each call.

We'll build a term that:
1. Gets the key from echo(251)
2. Calls it multiple times
3. Collects the bytes
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


def make_church(n):
    expr = Var(0)
    for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def make_right(payload):
    return Lam(Lam(App(Var(0), payload)))


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


def extract_one_byte(key_var, sc8_result_var, write_var, continuation):
    """
    Given key at key_var, syscall8 result at sc8_result_var,
    apply key to sc8_result, extract byte, write it, then call continuation.
    
    Result structure: (key sc8Result) -> Left(Right(ChurchByte))
    """
    return App(
        App(
            App(key_var, sc8_result_var),  # (key sc8Result)
            Lam(  # Left handler - unwrap outer to get Right(ChurchByte)
                App(
                    App(Var(0), identity),  # unwrap Right
                    Lam(  # inner = ChurchByte at Var(0)
                        # Write single byte list
                        App(
                            App(write_var, Lam(Lam(App(App(Var(1), Var(2)), nil)))),  # [Var(2) = byte]
                            continuation
                        )
                    )
                )
            )
        ),
        Lam(continuation)  # Right handler - shouldn't happen
    )


def test_single_connection_multiple_calls():
    """
    Approach 1: Multiple separate connections, see if each gives same byte.
    """
    print("\n=== Test 1: Multiple separate connections ===")
    results = []
    for i in range(5):
        # Same payload each time
        test_term = Lam(
            App(
                App(Var(0),  # echoResult
                    Lam(  # key = Var(0)
                        App(
                            App(Var(10), nil),  # syscall8(nil)
                            Lam(  # sc8Result = Var(0)
                                App(
                                    App(App(Var(1), Var(0)),  # (key sc8Result)
                                        Lam(
                                            App(
                                                App(Var(0), identity),
                                                Lam(
                                                    App(App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                                )
                                            )
                                        )
                                    ),
                                    Lam(App(App(Var(5), encode_string("R")), nil))
                                )
                            )
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("E")), nil))
            )
        )
        
        payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
        resp = query(payload)
        results.append(resp)
        print(f"  Connection {i+1}: {resp}")
        time.sleep(0.3)
    
    if all(r == results[0] for r in results):
        print(f"  All same: {results[0]}")
    else:
        print(f"  Different results!")


def test_call_key_twice_same_connection():
    """
    Approach 2: Within same lambda term, call key twice and see both results.
    Write byte1 then byte2.
    """
    print("\n=== Test 2: Call key twice in same term (write both bytes) ===")
    
    # Build term that calls key twice on same sc8Result
    test_term = Lam(
        App(
            App(Var(0),  # echoResult
                Lam(  # key = Var(0)
                    App(
                        App(Var(10), nil),  # syscall8(nil)
                        Lam(  # sc8Result = Var(0), key = Var(1)
                            # First call: (key sc8Result)
                            App(
                                App(App(Var(1), Var(0)),
                                    Lam(  # Left - outer
                                        App(
                                            App(Var(0), identity),
                                            Lam(  # byte1 = Var(0)
                                                # Write byte1
                                                App(
                                                    App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                                    # Then call key AGAIN
                                                    App(
                                                        App(App(Var(3), Var(2)),  # (key sc8Result) again
                                                            Lam(  # Left - outer
                                                                App(
                                                                    App(Var(0), identity),
                                                                    Lam(  # byte2 = Var(0)
                                                                        # Write byte2
                                                                        App(
                                                                            App(Var(8), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                                                            nil
                                                                        )
                                                                    )
                                                                )
                                                            )
                                                        ),
                                                        Lam(App(App(Var(7), encode_string("R2")), nil))
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("R1")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  Result: {resp} (hex: {resp.hex() if resp else 'empty'})")
    if len(resp) == 2:
        print(f"  Bytes: {resp[0]}, {resp[1]}")


def test_call_key_with_different_sc8_results():
    """
    Approach 3: Get two different syscall8 results and apply key to each.
    """
    print("\n=== Test 3: Call syscall8 twice, apply key to each result ===")
    
    # Build term: echo -> key -> syscall8 -> result1 -> syscall8 -> result2
    # Then (key result1), (key result2)
    test_term = Lam(
        App(
            App(Var(0),  # echoResult  
                Lam(  # key = Var(0)
                    App(
                        App(Var(10), nil),  # first syscall8(nil)
                        Lam(  # sc8Result1 = Var(0), key = Var(1)
                            # Apply key to result1
                            App(
                                App(App(Var(1), Var(0)),
                                    Lam(  # Left
                                        App(
                                            App(Var(0), identity),
                                            Lam(  # byte1 at Var(0)
                                                # Write byte1
                                                App(
                                                    App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                                    # Now do second syscall8
                                                    App(
                                                        App(Var(14), nil),  # second syscall8
                                                        Lam(  # sc8Result2 at Var(0)
                                                            App(
                                                                App(App(Var(4), Var(0)),  # (key sc8Result2)
                                                                    Lam(
                                                                        App(
                                                                            App(Var(0), identity),
                                                                            Lam(  # byte2
                                                                                App(App(Var(10), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                                                            )
                                                                        )
                                                                    )
                                                                ),
                                                                Lam(App(App(Var(9), encode_string("R2")), nil))
                                                            )
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(5), encode_string("R1")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("E")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  Result: {resp} (hex: {resp.hex() if resp else 'empty'})")


def test_different_echo_values():
    """
    Approach 4: Use different echo values to get different keys.
    """
    print("\n=== Test 4: Different echo values give different keys? ===")
    
    for echo_input in [250, 251, 252, 253]:
        test_term = Lam(
            App(
                App(Var(0),
                    Lam(  # key
                        App(
                            App(Var(10), nil),
                            Lam(  # sc8Result
                                App(
                                    App(App(Var(1), Var(0)),
                                        Lam(
                                            App(
                                                App(Var(0), identity),
                                                Lam(
                                                    App(App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                                )
                                            )
                                        )
                                    ),
                                    Lam(App(App(Var(5), encode_string("R")), nil))
                                )
                            )
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("E")), nil))
            )
        )
        
        payload = bytes([0x0E, echo_input, FD]) + encode_term(test_term) + bytes([FD, FF])
        resp = query(payload)
        print(f"  echo({echo_input}) -> key -> byte: {resp}")
        time.sleep(0.3)


def test_use_both_backdoor_combinators():
    """
    Approach 5: Get backdoor combinators A and B, see if they help sequence.
    A = λab.bb (self-application)
    B = λab.ab (normal application)
    """
    print("\n=== Test 5: Use backdoor combinators for sequencing ===")
    
    # Get backdoor first, then echo
    # backdoor -> Left(pair(A, B))
    # Then use B to sequence: B write1 write2 = write1 write2
    
    test_term = Lam(
        App(
            App(Var(0),  # backdoor result
                Lam(  # pair = Var(0) at binding site
                    # Extract A = fst pair, B = snd pair
                    App(
                        App(Var(0), Lam(Lam(Var(1)))),  # fst to get A
                        Lam(  # A = Var(0)
                            App(
                                App(Var(1), Lam(Lam(Var(0)))),  # snd to get B
                                Lam(  # B = Var(0), A = Var(1), pair = Var(2)
                                    # Now get the key via echo
                                    App(
                                        App(Var(17), nil),  # echo(nil) to get key?
                                        Lam(  # echo result
                                            App(
                                                App(Var(0),
                                                    Lam(  # key from Left
                                                        # syscall8
                                                        App(
                                                            App(Var(13), nil),
                                                            Lam(  # sc8Result
                                                                App(
                                                                    App(App(Var(1), Var(0)),
                                                                        Lam(
                                                                            App(
                                                                                App(Var(0), identity),
                                                                                Lam(
                                                                                    App(App(Var(8), Lam(Lam(App(App(Var(1), Var(2)), nil)))), nil)
                                                                                )
                                                                            )
                                                                        )
                                                                    ),
                                                                    Lam(App(App(Var(7), encode_string("R")), nil))
                                                                )
                                                            )
                                                        )
                                                    )
                                                ),
                                                Lam(App(App(Var(6), encode_string("ER")), nil))
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BR")), nil))  # backdoor Right - shouldn't happen
        )
    )
    
    payload = bytes([0xC9, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload)
    print(f"  backdoor -> echo(nil) -> key -> byte: {resp}")


def main():
    print("=" * 70)
    print("TESTING STATEFUL KEY HYPOTHESIS")
    print("=" * 70)
    print("Theory: Var(253) might return successive answer bytes on each call")
    
    test_single_connection_multiple_calls()
    time.sleep(0.5)
    
    test_call_key_twice_same_connection()
    time.sleep(0.5)
    
    test_call_key_with_different_sc8_results()
    time.sleep(0.5)
    
    test_different_echo_values()
    time.sleep(0.5)
    
    test_use_both_backdoor_combinators()


if __name__ == "__main__":
    main()
