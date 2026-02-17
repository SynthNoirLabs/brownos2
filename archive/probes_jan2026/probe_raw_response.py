#!/usr/bin/env python3
"""
Look at raw responses more carefully.

What if syscall 8 with the right input gives a DIFFERENT output
that we're not properly detecting?
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


def query_raw(payload: bytes, timeout_s: float = 5.0) -> bytes:
    """Get raw response without any processing."""
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


def test_syscall8_raw():
    """
    Send syscall8 with various inputs and look at raw responses.
    """
    print("=" * 70)
    print("SYSCALL 8 RAW RESPONSES")
    print("=" * 70)
    
    # Standard syscall8(nil) with QD
    print("\n  syscall8(nil) via QD:")
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query_raw(payload)
    print(f"    Raw hex: {resp.hex()}")
    print(f"    Length: {len(resp)}")
    
    # What about syscall8 with NO continuation (just see if it outputs anything)
    print("\n  syscall8(nil) with identity continuation:")
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(identity) + bytes([FD, FF])
    resp = query_raw(payload)
    print(f"    Raw hex: {resp.hex() if resp else 'empty'}")
    
    # syscall8 with nil continuation
    print("\n  syscall8(nil) with nil continuation:")
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(nil) + bytes([FD, FF])
    resp = query_raw(payload)
    print(f"    Raw hex: {resp.hex() if resp else 'empty'}")
    
    # syscall8 with key (from echo)
    print("\n  echo(251) -> syscall8(key) via handler:")
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # Left: key
                    App(
                        App(Var(9), Var(0)),  # syscall8(key)
                        Lam(Var(0))  # just return result, no printing
                    )
                )
            ),
            Lam(Var(0))
        )
    )
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query_raw(payload)
    print(f"    Raw hex: {resp.hex() if resp else 'empty'}")


def test_key_extraction_raw():
    """
    Get the key, apply it, look at raw output.
    """
    print("\n" + "=" * 70)
    print("KEY EXTRACTION RAW")
    print("=" * 70)
    
    # The working pattern: ((inner identity) handler) where handler writes as byte
    # Let's see what the raw term looks like before any decoding
    
    print("\n  quote(inner) where inner = Left payload from (key nil):")
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # key
                    App(
                        App(App(Var(0), nil),  # (key nil)
                            Lam(  # Left: inner
                                # quote(inner)
                                App(
                                    App(Var(6), Var(0)),
                                    Lam(
                                        App(
                                            App(Var(0),
                                                Lam(  # Left: quoted
                                                    # write quoted
                                                    App(App(Var(8), Var(0)), nil)
                                                )
                                            ),
                                            Lam(  # Right: quote failed
                                                App(App(Var(8), Var(0)), nil)  # write the error
                                            )
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(Var(0))
                    )
                )
            ),
            Lam(Var(0))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query_raw(payload)
    print(f"    Raw hex: {resp.hex() if resp else 'empty'}")
    
    # What about quote((inner identity))?
    print("\n  quote((inner identity)):")
    test_term2 = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(App(Var(0), nil),
                            Lam(
                                App(
                                    App(Var(6), App(Var(0), identity)),  # quote((inner identity))
                                    Lam(
                                        App(
                                            App(Var(0),
                                                Lam(App(App(Var(8), Var(0)), nil))),
                                            Lam(App(App(Var(8), Var(0)), nil))
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(Var(0))
                    )
                )
            ),
            Lam(Var(0))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term2) + bytes([FD, FF])
    resp = query_raw(payload)
    print(f"    Raw hex: {resp.hex() if resp else 'empty'}")


def test_different_outputs():
    """
    Try writing different things to see what works.
    """
    print("\n" + "=" * 70)
    print("DIFFERENT OUTPUT PATTERNS")
    print("=" * 70)
    
    # Write byte 1 directly
    print("\n  Direct write byte 1:")
    byte1 = Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(App(Var(1), Var(0)))))))))))
    cons_byte1 = Lam(Lam(App(App(Var(1), byte1), nil)))
    payload = bytes([0x02]) + encode_term(cons_byte1) + bytes([FD]) + encode_term(nil) + bytes([FD, FF])
    resp = query_raw(payload)
    print(f"    Raw: {resp}")
    
    # Write via QD
    print("\n  QD applied to Church 1:")
    church1 = Lam(Lam(App(Var(1), Var(0))))
    payload = encode_term(App(QD, church1)) + bytes([FF])
    # Wait, can't do this easily. Let me use proper syscall pattern
    
    # Simpler: just verify QD works
    print("\n  QD applied to nil:")
    payload = QD + encode_term(nil) + bytes([FD, FF])
    resp = query_raw(payload)
    print(f"    Raw hex: {resp.hex()}")


def test_answer_candidates():
    """
    Based on all findings, try some potential answers.
    """
    print("\n" + "=" * 70)
    print("POTENTIAL ANSWER PATTERNS")
    print("=" * 70)
    
    # We know: (payload identity) -> writes byte 1
    # Maybe the answer is hidden in how we extract it?
    
    # Try: multiple extractions in sequence
    print("\n  Multiple byte extractions:")
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # key
                    # Extract 3 times and write each
                    App(
                        App(App(Var(0), nil),  # (key nil)
                            Lam(  # inner1
                                App(
                                    App(Var(0), identity),  # (inner1 identity)
                                    Lam(  # byte1
                                        App(
                                            App(Var(6), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                            # Continue to second extraction
                                            App(
                                                App(App(Var(4), nil),  # (key nil) again
                                                    Lam(
                                                        App(
                                                            App(Var(0), identity),
                                                            Lam(
                                                                App(
                                                                    App(Var(10), Lam(Lam(App(App(Var(1), Var(2)), nil)))),
                                                                    nil
                                                                )
                                                            )
                                                        )
                                                    )
                                                ),
                                                Lam(nil)
                                            )
                                        )
                                    )
                                )
                            )
                        ),
                        Lam(nil)
                    )
                )
            ),
            Lam(nil)
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query_raw(payload)
    print(f"    Multiple extraction: {resp}")
    if resp:
        print(f"    Bytes: {[b for b in resp]}")


def main():
    test_syscall8_raw()
    time.sleep(0.3)
    
    test_key_extraction_raw()
    time.sleep(0.3)
    
    test_different_outputs()
    time.sleep(0.3)
    
    test_answer_candidates()


if __name__ == "__main__":
    main()
