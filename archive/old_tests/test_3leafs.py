#!/usr/bin/env python3
"""
Test the "3 leafs" hypothesis for BrownOS syscall 8.

Key hypothesis from Oracle:
- "3 leafs" = 3 variable occurrences in the AST
- Double-echo shifts de Bruijn indices by +4 (2x +2), so V249->V253, V250->V254, V251->V255
- These map to "forbidden" bytes FD/FE/FF that can't be sent over the wire
- Syscall 8 may be checking for a capability term containing these impossible-to-forge indices
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass

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


def recv_until_ff(sock: socket.socket, timeout_s: float = 5.0) -> bytes:
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
        if FF in chunk:
            break
    return out


def recv_raw(sock: socket.socket, timeout_s: float = 5.0) -> bytes:
    """Receive all data without FF termination requirement."""
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


def query(payload: bytes, retries: int = 3, timeout_s: float = 5.0) -> bytes:
    delay = 0.3
    last_err: Exception | None = None
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_raw(sock, timeout_s=timeout_s)
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed to query {HOST}:{PORT}") from last_err


def parse_term(data: bytes) -> object:
    stack: list[object] = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    if len(stack) != 1:
        raise ValueError(f"Invalid parse: stack size {len(stack)}")
    return stack[0]


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported term node: {type(term)}")


def term_to_str(term: object, depth: int = 0) -> str:
    """Pretty print a term."""
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{term_to_str(term.body, depth+1)}"
    if isinstance(term, App):
        return f"({term_to_str(term.f, depth)} {term_to_str(term.x, depth)})"
    return str(term)


def call_syscall(syscall_num: int, argument: object) -> bytes:
    """Call a syscall and return raw output (for debugging)."""
    payload = bytes([syscall_num]) + encode_term(argument) + bytes([FD]) + QD + bytes([FD, FF])
    return query(payload)


def call_syscall_parsed(syscall_num: int, argument: object) -> object:
    """Call a syscall and parse the result term."""
    out = call_syscall(syscall_num, argument)
    if FF not in out:
        print(f"  WARNING: No FF in output, raw: {out!r}")
        return None
    return parse_term(out)


def decode_either(term: object) -> tuple[str, object]:
    """Decode Scott Either: Left x = λl.λr. l x, Right y = λl.λr. r y"""
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not an Either")
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var) and body.f.i in (0, 1):
        return ("Left" if body.f.i == 1 else "Right", body.x)
    raise ValueError("Unexpected Either shape")


def encode_nil() -> object:
    """Scott nil = λc.λn. n"""
    return Lam(Lam(Var(0)))


def encode_byte_term(n: int) -> object:
    """Encode a byte as a 9-lambda bitset term."""
    WEIGHTS = [(1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)]
    expr: object = Var(0)
    for idx, weight in WEIGHTS:
        if n & weight:
            expr = App(Var(idx), expr)
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def main():
    print("=" * 60)
    print("BrownOS 3-Leafs Hypothesis Test")
    print("=" * 60)
    
    # Test 1: Verify echo syscall behavior
    print("\n[1] Testing echo syscall (0x0E) on simple variable V249")
    test_var = Var(249)
    print(f"  Input: {term_to_str(test_var)}")
    result = call_syscall_parsed(0x0E, test_var)
    if result:
        print(f"  Output term: {term_to_str(result)}")
        tag, payload = decode_either(result)
        print(f"  Decoded: {tag}({term_to_str(payload)})")
        # Under 2 lambdas, V249 should appear as V251 (shifted by +2)
    
    # Test 2: Double echo and check via quote
    print("\n[2] Testing double-echo: echo(echo(V249))")
    # First echo
    result1 = call_syscall_parsed(0x0E, test_var)
    if result1:
        tag1, pay1 = decode_either(result1)
        print(f"  After 1st echo: {tag1}({term_to_str(pay1)})")
        
        # Second echo - we echo the entire Left(V251) term
        result2 = call_syscall_parsed(0x0E, result1)
        if result2:
            tag2, pay2 = decode_either(result2)
            print(f"  After 2nd echo (outer): {tag2}")
            # Now let's quote this to see what bytes we get
            print(f"\n[3] Quoting the double-echoed result...")
            quote_result = call_syscall_parsed(0x04, result2)
            if quote_result:
                qtag, qpay = decode_either(quote_result)
                print(f"  Quote result: {qtag}")
                # The payload should be a list of bytes
                # Let's print the raw output to see
                raw = call_syscall(0x04, result2)
                print(f"  Raw quote output: {raw.hex()}")
                # Check for FD/FE/FF in the quoted data
                if b'\xfd' in raw or b'\xfe' in raw:
                    print("  *** FOUND forbidden bytes in quoted output! ***")
    
    # Test 3: Build 3-leaf terms and test with syscall 8
    print("\n[4] Testing 3-leaf terms with syscall 8")
    
    # The 3-leaf terms from Oracle analysis
    three_leaf_terms = [
        ("((V249 V250) V251)", App(App(Var(249), Var(250)), Var(251))),
        ("(V249 (V250 V251))", App(Var(249), App(Var(250), Var(251)))),
        ("((V250 V249) V251)", App(App(Var(250), Var(249)), Var(251))),
        ("(V249 (V251 V250))", App(Var(249), App(Var(251), Var(250)))),
    ]
    
    for name, term in three_leaf_terms:
        print(f"\n  Testing base term: {name}")
        print(f"    Encoded bytes: {encode_term(term).hex()}")
        
        # Direct to syscall 8
        result = call_syscall_parsed(0x08, term)
        if result:
            tag, pay = decode_either(result)
            print(f"    Direct to syscall 8: {tag}({term_to_str(pay) if isinstance(pay, (Var, Lam, App)) else '...'})")
        
        # Single echo then syscall 8
        echo1 = call_syscall_parsed(0x0E, term)
        if echo1:
            result = call_syscall_parsed(0x08, echo1)
            if result:
                tag, pay = decode_either(result)
                print(f"    After 1x echo to syscall 8: {tag}(...)")
            
            # Try unwrapping the Left and passing just the payload
            e1tag, e1pay = decode_either(echo1)
            result = call_syscall_parsed(0x08, e1pay)
            if result:
                tag, pay = decode_either(result)
                print(f"    Unwrapped 1x echo to syscall 8: {tag}(...)")
        
        # Double echo then syscall 8
        if echo1:
            echo2 = call_syscall_parsed(0x0E, echo1)
            if echo2:
                result = call_syscall_parsed(0x08, echo2)
                if result:
                    tag, pay = decode_either(result)
                    print(f"    After 2x echo to syscall 8: {tag}(...)")
                
                # Try unwrapping outer Left
                e2tag, e2pay = decode_either(echo2)
                result = call_syscall_parsed(0x08, e2pay)
                if result:
                    tag, pay = decode_either(result)
                    print(f"    Unwrapped 2x echo to syscall 8: {tag}(...)")
    
    # Test 5: Try using the backdoor pair
    print("\n[5] Testing backdoor (syscall 201) + syscall 8 combinations")
    bd_result = call_syscall_parsed(0xC9, encode_nil())
    if bd_result:
        tag, pair = decode_either(bd_result)
        print(f"  Backdoor result: {tag}")
        if tag == "Left":
            # Pair is cons(A, B) where A = λa.λb. b b, B = λa.λb. a b
            # Try passing the pair directly to syscall 8
            result = call_syscall_parsed(0x08, pair)
            if result:
                rtag, rpay = decode_either(result)
                print(f"  Backdoor pair to syscall 8: {rtag}(...)")
            
            # Echo the pair then syscall 8
            echo_pair = call_syscall_parsed(0x0E, pair)
            if echo_pair:
                result = call_syscall_parsed(0x08, echo_pair)
                if result:
                    rtag, rpay = decode_either(result)
                    print(f"  Echoed backdoor pair to syscall 8: {rtag}(...)")
    
    print("\n" + "=" * 60)
    print("Test complete")


if __name__ == "__main__":
    main()
