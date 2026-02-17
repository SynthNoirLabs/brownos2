#!/usr/bin/env python3
"""
Comprehensive BrownOS probing script - tests all identified attack vectors.

Based on Oracle analysis, we're testing:
1. 3-byte payloads (x FE FF patterns)  
2. Hunting for eval/unquote syscall
3. Serialization hypothesis verification
4. Malformed FD/FE/FF payloads
5. Syscall range 202-252
6. All 16 minimal 2-lambda 3-leaf terms
"""

from __future__ import annotations
import socket
import time
from dataclasses import dataclass
from typing import Optional

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD  # application
FE = 0xFE  # lambda
FF = 0xFF  # end-of-code marker

# Quick Debug continuation
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


def recv_all(sock: socket.socket, timeout_s: float = 3.0) -> bytes:
    sock.settimeout(timeout_s)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    return out


def query(payload: bytes, retries: int = 3, timeout_s: float = 3.0) -> tuple[bytes, float]:
    """Returns (response, elapsed_time)"""
    delay = 0.2
    last_err: Exception | None = None
    for _ in range(retries):
        try:
            start = time.time()
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                result = recv_all(sock, timeout_s=timeout_s)
                elapsed = time.time() - start
                return result, elapsed
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed to query {HOST}:{PORT}") from last_err


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported term: {type(term)}")


def parse_term(data: bytes) -> object:
    stack: list[object] = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            if len(stack) < 2:
                raise ValueError("Stack underflow on FD")
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            if len(stack) < 1:
                raise ValueError("Stack underflow on FE")
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    if len(stack) != 1:
        raise ValueError(f"Invalid parse: stack size {len(stack)}")
    return stack[0]


def format_response(data: bytes) -> str:
    """Pretty-print response"""
    if not data:
        return "(empty)"
    if b"Invalid term!" in data:
        return "Invalid term!"
    if b"Encoding failed!" in data:
        return "Encoding failed!"
    if b"Term too big!" in data:
        return "Term too big!"
    # Try to decode as text
    try:
        text = data.decode('utf-8', errors='replace')
        if text.isprintable() or '\n' in text:
            return repr(text[:100])
    except:
        pass
    return data[:50].hex() + ("..." if len(data) > 50 else "")


def nil() -> object:
    """Scott nil = λλ.0"""
    return Lam(Lam(Var(0)))


def encode_byte_term(n: int) -> object:
    """Encode integer as 9-lambda bitset term"""
    expr: object = Var(0)
    for idx, weight in ((1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)):
        if n & weight:
            expr = App(Var(idx), expr)
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_bytes_list(bs: bytes) -> object:
    """Encode bytes as Scott list of byte-terms"""
    cur: object = nil()
    for b in reversed(bs):
        cur = Lam(Lam(App(App(Var(1), encode_byte_term(b)), cur)))
    return cur


# ============================================================================
# TEST SUITE 1: 3-byte payloads (x FE FF)
# ============================================================================
def test_3byte_payloads():
    print("\n" + "="*60)
    print("TEST 1: 3-byte payloads (x FE FF = λ.Var(x))")
    print("="*60)
    
    # Key indices to test
    indices = [
        (0, "identity λ.0"),
        (1, "outer scope λ.1"),
        (2, "λ.2"),
        (8, "syscall 8 ref?"),
        (14, "echo syscall ref?"),
        (42, "syscall 0x2A ref?"),
        (201, "backdoor ref?"),
        (250, "boundary -3"),
        (251, "echo seed"),
        (252, "boundary -1"),
    ]
    
    for idx, desc in indices:
        payload = bytes([idx, FE, FF])
        try:
            resp, elapsed = query(payload, timeout_s=2.0)
            print(f"  {idx:3d} ({desc:20s}): {format_response(resp)} [{elapsed:.2f}s]")
        except Exception as e:
            print(f"  {idx:3d} ({desc:20s}): ERROR: {e}")
        time.sleep(0.3)


# ============================================================================
# TEST SUITE 2: Hunt for eval/unquote syscall
# ============================================================================
def test_eval_syscall_hunt():
    print("\n" + "="*60)
    print("TEST 2: Hunt for eval/unquote syscall")
    print("="*60)
    print("Looking for syscall that takes bytes and returns term...")
    
    # Encode a simple term as bytes: identity λ.0 = 00 FE
    identity_bytes = encode_bytes_list(b'\x00\xfe')
    
    # Test syscalls with this bytes argument
    # If any returns something other than Right(1)/Right(2), it might be eval
    for syscall_num in range(0, 253):
        if syscall_num in [0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 42, 201]:
            continue  # Skip known syscalls
        
        payload = bytes([syscall_num]) + encode_term(identity_bytes) + bytes([FD]) + QD + bytes([FD, FF])
        try:
            resp, elapsed = query(payload, timeout_s=2.0)
            # Check if response is different from "Not implemented" Right(1)
            if resp and b'\x00\xfe\xfe' not in resp[:10]:  # Right(1) has a specific pattern
                print(f"  Syscall {syscall_num}: {format_response(resp)}")
        except:
            pass
        time.sleep(0.15)
    
    print("  (Only non-standard responses shown)")


# ============================================================================
# TEST SUITE 3: Serialization hypothesis verification
# ============================================================================
def test_serialization_hypothesis():
    print("\n" + "="*60)
    print("TEST 3: Serialization hypothesis verification")
    print("="*60)
    
    # Continuation that ignores its argument and returns a known constant (nil)
    # K = λx. nil = λx. λc.λn.n = λ.λ.λ.0
    K_nil = Lam(Lam(Lam(Var(0))))
    
    # Test 1: ((syscall8 nil) QD) - should return "Permission denied"
    payload1 = bytes([0x08]) + encode_term(nil()) + bytes([FD]) + QD + bytes([FD, FF])
    resp1, t1 = query(payload1)
    print(f"  ((syscall8 nil) QD):     {format_response(resp1)} [{t1:.2f}s]")
    
    # Test 2: ((syscall8 nil) K_nil) - forces serializable output
    # If empty, it's NOT serialization failure
    payload2 = bytes([0x08]) + encode_term(nil()) + bytes([FD]) + encode_term(K_nil) + bytes([FD, FF])
    resp2, t2 = query(payload2)
    print(f"  ((syscall8 nil) K_nil):  {format_response(resp2)} [{t2:.2f}s]")
    
    # Test 3: Make Var(253) via echo, use as continuation
    # echo(Var(251)) → Left(Var(253))
    # We need to extract Var(253) from the Either and use it
    # For now, just test echo directly
    payload3 = bytes([0x0E, 251, FD]) + QD + bytes([FD, FF])
    resp3, t3 = query(payload3)
    print(f"  echo(Var(251)) via QD:   {format_response(resp3)} [{t3:.2f}s]")
    
    # Test 4: Try to print the echo result without QD
    # Use write syscall directly on the echo result
    # ((echo Var(251)) (λresult. ((write (quote result)) QD)))
    # This is complex, skip for now


# ============================================================================
# TEST SUITE 4: Malformed FD/FE/FF payloads
# ============================================================================
def test_malformed_payloads():
    print("\n" + "="*60)
    print("TEST 4: Malformed FD/FE/FF payloads")
    print("="*60)
    
    payloads = [
        (bytes([FD, FF]), "FD FF"),
        (bytes([FE, FF]), "FE FF"),
        (bytes([FD, FE, FF]), "FD FE FF"),
        (bytes([FE, FD, FF]), "FE FD FF"),
        (bytes([FD, FD, FF]), "FD FD FF"),
        (bytes([FE, FE, FF]), "FE FE FF"),
        (bytes([FD, FD, FD, FF]), "FD FD FD FF"),
        (bytes([FE, FE, FE, FF]), "FE FE FE FF"),
        (bytes([0x00, FD, FF]), "00 FD FF"),
        (bytes([0x00, 0x00, FD, FF]), "00 00 FD FF"),
        (bytes([0x00, 0x00, FD, FE, FF]), "00 00 FD FE FF (ω)"),
        (bytes([251, 252, FD, FE, FF]), "FB FC FD FE FF (λ.(251 252))"),
        (bytes([252, 251, FD, FE, FF]), "FC FB FD FE FF (λ.(252 251))"),
        (bytes([FD, 0x00, FF]), "FD 00 FF"),
        (bytes([FE, 0x00, FF]), "FE 00 FF"),
    ]
    
    for payload, desc in payloads:
        try:
            resp, elapsed = query(payload, timeout_s=2.0)
            print(f"  {desc:25s}: {format_response(resp)} [{elapsed:.2f}s]")
        except Exception as e:
            print(f"  {desc:25s}: ERROR: {e}")
        time.sleep(0.3)


# ============================================================================
# TEST SUITE 5: Syscall range 202-252
# ============================================================================
def test_syscall_range():
    print("\n" + "="*60)
    print("TEST 5: Syscall range 202-252 with nil argument")
    print("="*60)
    
    interesting = []
    for syscall_num in range(202, 253):
        payload = bytes([syscall_num]) + encode_term(nil()) + bytes([FD]) + QD + bytes([FD, FF])
        try:
            resp, elapsed = query(payload, timeout_s=2.0)
            # Check for non-standard responses
            if resp and b'\x00\xfe' in resp[:5]:
                # Likely Right(1) "Not implemented"
                pass
            elif resp:
                interesting.append((syscall_num, resp, elapsed))
                print(f"  Syscall {syscall_num}: {format_response(resp)} [{elapsed:.2f}s]")
        except Exception as e:
            interesting.append((syscall_num, str(e), 0))
        time.sleep(0.15)
    
    if not interesting:
        print("  All returned 'Not implemented' (Right(1))")
    else:
        print(f"\n  Found {len(interesting)} interesting responses")


# ============================================================================
# TEST SUITE 6: All 16 minimal 2-lambda 3-leaf terms as syscall 8 arguments
# ============================================================================
def test_3leaf_terms():
    print("\n" + "="*60)
    print("TEST 6: All 16 minimal 2-lambda 3-leaf terms as syscall 8 args")
    print("="*60)
    
    # All possible 3-leaf terms with 2 lambdas
    # Left shape: ((x y) z) encoded as x y FD z FD FE FE
    # Right shape: (x (y z)) encoded as x y z FD FD FE FE
    
    terms = []
    
    # Left-associated: ((x y) z)
    for x in [0, 1]:
        for y in [0, 1]:
            for z in [0, 1]:
                enc = bytes([x, y, FD, z, FD, FE, FE, FF])
                desc = f"λλ.(({x} {y}) {z})"
                terms.append((enc, desc))
    
    # Right-associated: (x (y z))
    for x in [0, 1]:
        for y in [0, 1]:
            for z in [0, 1]:
                enc = bytes([x, y, z, FD, FD, FE, FE, FF])
                desc = f"λλ.({x} ({y} {z}))"
                terms.append((enc, desc))
    
    for enc, desc in terms:
        # Use this term as syscall 8's argument
        # ((syscall8 term) QD)
        payload = bytes([0x08]) + enc[:-1] + bytes([FD]) + QD + bytes([FD, FF])  # Remove FF, add FD QD FD FF
        try:
            resp, elapsed = query(payload, timeout_s=2.0)
            status = format_response(resp)
            # Check if it's NOT the usual Permission denied
            if b"Permission denied" not in resp and status != "Invalid term!":
                print(f"  {desc:20s}: {status} [{elapsed:.2f}s] ***INTERESTING***")
            else:
                print(f"  {desc:20s}: {status} [{elapsed:.2f}s]")
        except Exception as e:
            print(f"  {desc:20s}: ERROR: {e}")
        time.sleep(0.2)


# ============================================================================
# TEST SUITE 7: Direct application of special bytes as syscall arguments
# ============================================================================
def test_special_direct():
    print("\n" + "="*60)
    print("TEST 7: Direct application patterns with special indices")
    print("="*60)
    
    # Try Var(251), Var(252) directly as syscall 8 argument
    for idx in [251, 252]:
        payload = bytes([0x08, idx, FD]) + QD + bytes([FD, FF])
        try:
            resp, elapsed = query(payload, timeout_s=2.0)
            print(f"  syscall8(Var({idx})): {format_response(resp)} [{elapsed:.2f}s]")
        except Exception as e:
            print(f"  syscall8(Var({idx})): ERROR: {e}")
        time.sleep(0.3)
    
    # Try backdoor combinators
    # A = λab.bb = λ.λ.((0 0)) = 00 00 FD FE FE
    A = bytes([0x00, 0x00, FD, FE, FE])
    # B = λab.ab = λ.λ.(1 0) = 01 00 FD FE FE  
    B = bytes([0x01, 0x00, FD, FE, FE])
    
    for term_bytes, name in [(A, "A=λab.bb"), (B, "B=λab.ab")]:
        payload = bytes([0x08]) + term_bytes + bytes([FD]) + QD + bytes([FD, FF])
        try:
            resp, elapsed = query(payload, timeout_s=2.0)
            print(f"  syscall8({name}): {format_response(resp)} [{elapsed:.2f}s]")
        except Exception as e:
            print(f"  syscall8({name}): ERROR: {e}")
        time.sleep(0.3)


# ============================================================================
# TEST SUITE 8: Church numeral and Either eliminator (highlighted by Oracle)
# ============================================================================
def test_oracle_recommended():
    print("\n" + "="*60)
    print("TEST 8: Oracle-recommended terms (Church 2, Either eliminator)")
    print("="*60)
    
    # Church 2 = λλ.1(1 0) = 01 01 00 FD FD FE FE
    church2 = bytes([0x01, 0x01, 0x00, FD, FD, FE, FE])
    
    # Either eliminator = λλλ.(2 1 0) = 02 01 FD 00 FD FE FE FE
    either_elim = bytes([0x02, 0x01, FD, 0x00, FD, FE, FE, FE])
    
    for term_bytes, name in [(church2, "Church2"), (either_elim, "Either-elim")]:
        # As syscall 8 argument
        payload = bytes([0x08]) + term_bytes + bytes([FD]) + QD + bytes([FD, FF])
        try:
            resp, elapsed = query(payload, timeout_s=2.0)
            print(f"  syscall8({name}): {format_response(resp)} [{elapsed:.2f}s]")
        except Exception as e:
            print(f"  syscall8({name}): ERROR: {e}")
        time.sleep(0.3)
    
    # Try applying Church2 and Either-elim to backdoor results
    # First get backdoor pair: ((backdoor nil) identity)
    # This is complex; for now just test direct


# ============================================================================
# MAIN
# ============================================================================
def main():
    print("BrownOS Comprehensive Probe Script")
    print("Based on Oracle analysis - testing all attack vectors")
    print(f"Target: {HOST}:{PORT}")
    
    # Run all test suites
    test_3byte_payloads()
    test_malformed_payloads()
    test_serialization_hypothesis()
    test_3leaf_terms()
    test_special_direct()
    test_oracle_recommended()
    test_syscall_range()
    # test_eval_syscall_hunt()  # This is slow, uncomment if needed
    
    print("\n" + "="*60)
    print("PROBE COMPLETE")
    print("="*60)


if __name__ == "__main__":
    main()
