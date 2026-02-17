#!/usr/bin/env python3
"""
Probes based on Oracle/Metis analysis session (Jan 2026).

KEY INSIGHTS:
1. echo(253) should manufacture Var(255) = 0xFF (end marker)
2. Need to capture ALL bytes, not just FF-terminated
3. Try backdoor combinators A/B as continuations
4. "3 leafs" = minimal solution
5. Empty responses might indicate success

The "3 leafs" hint suggests the solution is EXTREMELY minimal.
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
    """Capture ALL bytes without waiting for FF termination."""
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
                    # DON'T break on FF - capture everything
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


def encode_int(n: int):
    """Encode integer as 9-lambda additive bitset."""
    expr = Var(0)
    remaining = n
    for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        while remaining >= weight:
            expr = App(Var(idx), expr)
            remaining -= weight
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def test_echo_253():
    """
    CRITICAL: echo(253) should manufacture Var(255) = 0xFF (end marker).
    
    echo shifts by +2, so:
    - echo(251) -> Var(253) = 0xFD (App)
    - echo(253) -> Var(255) = 0xFF (End)
    
    What happens when Var(255) exists at runtime?
    """
    print("=" * 70)
    print("TEST 1: echo(253) -> Var(255) = 0xFF (END MARKER)")
    print("=" * 70)
    
    # Direct: echo(253) with QD continuation
    payload = bytes([0x0E, 253, FD]) + QD + bytes([FD, FF])
    resp = query_raw(payload, timeout_s=5)
    print(f"  echo(253) raw response: {resp.hex() if resp else 'EMPTY'}")
    print(f"  As text: {resp!r}")
    
    # If we got "Encoding failed!", that confirms Var(255) was created
    # but couldn't be serialized


def test_echo_252():
    """
    echo(252) -> Var(254) = 0xFE (Lambda marker)
    """
    print("\n" + "=" * 70)
    print("TEST 2: echo(252) -> Var(254) = 0xFE (LAMBDA MARKER)")
    print("=" * 70)
    
    payload = bytes([0x0E, 252, FD]) + QD + bytes([FD, FF])
    resp = query_raw(payload, timeout_s=5)
    print(f"  echo(252) raw response: {resp.hex() if resp else 'EMPTY'}")
    print(f"  As text: {resp!r}")


def test_double_echo_to_255():
    """
    Chain echo to reach Var(255):
    echo(251) -> Var(253)
    echo(Var(253)) -> Var(255)?
    
    But wait - echo takes an argument, not a Var index.
    We need to echo the integer 253, which gives us Var(255).
    """
    print("\n" + "=" * 70)
    print("TEST 3: echo(INT_253) -> Var(255)")
    print("=" * 70)
    
    # echo takes an argument term. If we pass the integer encoding of 253,
    # what do we get back?
    int_253 = encode_int(253)
    payload = bytes([0x0E]) + encode_term(int_253) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query_raw(payload, timeout_s=5)
    print(f"  echo(INT_253) raw: {resp.hex() if resp else 'EMPTY'}")
    print(f"  As text: {resp!r}")


def test_backdoor_A_as_continuation():
    """
    Backdoor gives us A = λab.bb (self-application) and B = λab.ab (normal apply).
    
    What if A or B should be the CONTINUATION for syscall 8?
    """
    print("\n" + "=" * 70)
    print("TEST 4: Backdoor A as continuation for syscall 8")
    print("=" * 70)
    
    # A = λab.bb
    A = Lam(Lam(App(Var(0), Var(0))))
    # B = λab.ab
    B = Lam(Lam(App(Var(1), Var(0))))
    
    # (syscall8 nil) with A as continuation
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(A) + bytes([FD, FF])
    resp = query_raw(payload, timeout_s=5)
    print(f"  ((syscall8 nil) A): {resp.hex() if resp else 'EMPTY'}")
    print(f"  As text: {resp!r}")
    
    time.sleep(0.3)
    
    # (syscall8 nil) with B as continuation
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(B) + bytes([FD, FF])
    resp = query_raw(payload, timeout_s=5)
    print(f"  ((syscall8 nil) B): {resp.hex() if resp else 'EMPTY'}")
    print(f"  As text: {resp!r}")


def test_minimal_3_leaf():
    """
    "My record is 3 leafs IIRC"
    
    If "leaf" = Var node, the minimal terms with exactly 3 Vars:
    
    With 2 Apps (leftmost):  ((V0 V1) V2)
    With 2 Apps (rightmost): (V0 (V1 V2))
    With 1 App + 1 Lam:      λ.((V0 V1) V2)
    
    What if we send these DIRECTLY as payloads?
    """
    print("\n" + "=" * 70)
    print("TEST 5: Minimal 3-leaf terms as raw payloads")
    print("=" * 70)
    
    # ((V0 V0) V0) = 00 00 FD 00 FD
    term1 = bytes([0x00, 0x00, FD, 0x00, FD, FF])
    resp = query_raw(term1, timeout_s=3)
    print(f"  ((V0 V0) V0): {resp.hex() if resp else 'EMPTY'}")
    
    time.sleep(0.2)
    
    # (V0 (V0 V0)) = 00 00 00 FD FD
    term2 = bytes([0x00, 0x00, 0x00, FD, FD, FF])
    resp = query_raw(term2, timeout_s=3)
    print(f"  (V0 (V0 V0)): {resp.hex() if resp else 'EMPTY'}")
    
    time.sleep(0.2)
    
    # λ.((V0 V0) V0) = 00 00 FD 00 FD FE
    term3 = bytes([0x00, 0x00, FD, 0x00, FD, FE, FF])
    resp = query_raw(term3, timeout_s=3)
    print(f"  λ.((V0 V0) V0): {resp.hex() if resp else 'EMPTY'}")
    
    time.sleep(0.2)
    
    # What about using syscall indices?
    # ((V8 V8) V8) - syscall 8 three times?
    term4 = bytes([0x08, 0x08, FD, 0x08, FD, FF])
    resp = query_raw(term4, timeout_s=3)
    print(f"  ((V8 V8) V8): {resp.hex() if resp else 'EMPTY'}")


def test_minimal_with_special_bytes():
    """
    "combining special bytes froze my system"
    
    What if the answer involves FD/FE in specific positions?
    """
    print("\n" + "=" * 70)
    print("TEST 6: Terms involving Var(251), Var(252) - near special bytes")
    print("=" * 70)
    
    # ((V251 V251) V251) - using echo's input
    term1 = bytes([251, 251, FD, 251, FD, FF])
    resp = query_raw(term1, timeout_s=3)
    print(f"  ((V251 V251) V251): {resp.hex() if resp else 'EMPTY'}")
    
    time.sleep(0.2)
    
    # ((V252 V252) V252) - one below FD
    term2 = bytes([252, 252, FD, 252, FD, FF])
    resp = query_raw(term2, timeout_s=3)
    print(f"  ((V252 V252) V252): {resp.hex() if resp else 'EMPTY'}")
    
    time.sleep(0.2)
    
    # ((V8 nil) QD) with minimal payload
    # But wait - "3 leafs" might mean the SOLUTION term has 3 vars
    # Not the entire program
    
    # What if we do ((V201 nil) QD) = backdoor call as 3-leaf?
    # 201 = 0xC9
    term3 = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query_raw(term3, timeout_s=3)
    print(f"  ((backdoor nil) QD) - standard: {resp.hex() if resp else 'EMPTY'}")


def test_call_255_as_syscall():
    """
    What if there's a hidden syscall at index 255?
    Since 255 = 0xFF is the end marker, we can't encode Var(255) directly.
    But what if echo shifts us there?
    """
    print("\n" + "=" * 70)
    print("TEST 7: Try to invoke syscall 253, 254 via unusual encoding")
    print("=" * 70)
    
    # This is interesting: what happens if we try to call syscall at very high indices?
    # We know 202-252 all return "Not implemented"
    # But 253-255 are wire format markers
    
    # Let's try syscall 250, 251 to compare
    for idx in [250, 251, 252]:
        payload = bytes([idx]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
        resp = query_raw(payload, timeout_s=3)
        print(f"  syscall({idx}): {resp.hex() if resp else 'EMPTY'}")
        time.sleep(0.2)


def test_raw_output_patterns():
    """
    Metis suggested: check for ANY bytes in empty responses.
    
    Let's look at what we get from various "empty" responses.
    """
    print("\n" + "=" * 70)
    print("TEST 8: Raw output analysis from 'empty' responses")
    print("=" * 70)
    
    # Get echo result with key as continuation
    # This previously gave "empty" response
    
    test_term = Lam(
        App(
            App(Var(0),  # echo result
                Lam(  # Left: Var(253) at Var(0)
                    App(
                        App(Var(9), nil),  # (syscall8 nil)
                        Var(0)  # Var(253) as continuation
                    )
                )
            ),
            identity  # Right handler (shouldn't fire)
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query_raw(payload, timeout_s=8)
    print(f"  ((syscall8 nil) Var(253)) raw bytes: {resp.hex() if resp else 'TOTALLY EMPTY'}")
    print(f"  Length: {len(resp) if resp else 0}")
    if resp:
        print(f"  Each byte: {[f'{b:02x}' for b in resp]}")


def test_write_without_quote():
    """
    Maybe the answer bypasses quote entirely - direct write of something?
    """
    print("\n" + "=" * 70)
    print("TEST 9: Direct write syscall without quote")
    print("=" * 70)
    
    # write(byte_list) -> writes bytes directly
    # What if we write the key directly?
    
    # First, a known working write
    test_bytes = encode_string("TEST")
    payload = bytes([0x02]) + encode_term(test_bytes) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query_raw(payload, timeout_s=3)
    print(f"  write('TEST'): {resp!r}")


def main():
    print("METIS INSIGHTS PROBE - January 2026")
    print("=" * 70)
    
    test_echo_253()
    time.sleep(0.3)
    
    test_echo_252()
    time.sleep(0.3)
    
    test_double_echo_to_255()
    time.sleep(0.3)
    
    test_backdoor_A_as_continuation()
    time.sleep(0.3)
    
    test_minimal_3_leaf()
    time.sleep(0.3)
    
    test_minimal_with_special_bytes()
    time.sleep(0.3)
    
    test_call_255_as_syscall()
    time.sleep(0.3)
    
    test_raw_output_patterns()
    time.sleep(0.3)
    
    test_write_without_quote()
    
    print("\n" + "=" * 70)
    print("DONE")
    print("=" * 70)


if __name__ == "__main__":
    main()
