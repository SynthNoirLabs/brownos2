#!/usr/bin/env python3
"""
Test what the backdoor (syscall 201) actually returns.

Mail says: "Backdoor is ready at syscall 201; start with 00 FE FE."
"""

import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF
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


def encode_term(term):
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported: {type(term)}")


def parse_term(data):
    stack = []
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
        raise ValueError(f"Invalid parse: stack={len(stack)}")
    return stack[0]


def send_raw(payload, timeout=8.0):
    """Send raw payload and return response."""
    with socket.create_connection((HOST, PORT), timeout=timeout) as s:
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)
        s.settimeout(timeout)
        out = b""
        while True:
            try:
                c = s.recv(4096)
                if not c:
                    break
                out += c
            except:
                break
        return out


def test_backdoor():
    """Test syscall 201 (backdoor) with various inputs."""

    print("=" * 80)
    print("TESTING BACKDOOR (SYSCALL 201)")
    print("=" * 80)

    # Test 1: Exact mail instructions - "start with 00 FE FE"
    print("\n[TEST 1] Mail instruction: start with 00 FE FE")
    print("Payload: 0x00 0xFE 0xFE (Var(0) wrapped in 2 lambdas)")

    # This is: λ.λ.Var(0) which is the Church encoding of 0 (false)
    term1 = Lam(Lam(Var(0)))
    payload1 = bytes([201]) + encode_term(term1) + bytes([FD]) + QD + bytes([FD, FF])

    print(f"Full bytecode: {payload1.hex()}")
    result1 = send_raw(payload1)
    print(f"Raw response ({len(result1)} bytes): {result1.hex()}")

    if result1:
        try:
            parsed = parse_term(result1)
            print(f"Parsed term: {parsed}")
        except Exception as e:
            print(f"Parse error: {e}")

    time.sleep(0.4)

    # Test 2: Just the backdoor pair from utils/decode_backdoor.py
    print("\n[TEST 2] Backdoor pair A and B")

    # A = λa.λb.(b b)  - self-apply 2nd arg
    A = Lam(Lam(App(Var(0), Var(0))))

    # B = λa.λb.(a b)  - apply 1st to 2nd
    B = Lam(Lam(App(Var(1), Var(0))))

    print(f"A = {A}")
    print(f"B = {B}")

    # Call backdoor with A
    payload_A = bytes([201]) + encode_term(A) + bytes([FD]) + QD + bytes([FD, FF])
    print(f"\nBackdoor(A) bytecode: {payload_A.hex()}")
    result_A = send_raw(payload_A)
    print(f"Response ({len(result_A)} bytes): {result_A.hex()}")
    if result_A:
        try:
            print(f"Parsed: {parse_term(result_A)}")
        except Exception as e:
            print(f"Parse error: {e}")

    time.sleep(0.4)

    # Call backdoor with B
    payload_B = bytes([201]) + encode_term(B) + bytes([FD]) + QD + bytes([FD, FF])
    print(f"\nBackdoor(B) bytecode: {payload_B.hex()}")
    result_B = send_raw(payload_B)
    print(f"Response ({len(result_B)} bytes): {result_B.hex()}")
    if result_B:
        try:
            print(f"Parsed: {parse_term(result_B)}")
        except Exception as e:
            print(f"Parse error: {e}")

    time.sleep(0.4)

    # Test 3: Apply backdoor to itself (like the decode script does)
    print("\n[TEST 3] Backdoor applied to various globals")

    for g_id in [0, 1, 8, 14, 201, 251, 252]:
        payload = bytes([201]) + bytes([g_id]) + bytes([FD]) + QD + bytes([FD, FF])
        print(f"\nBackdoor(g({g_id})) bytecode: {payload.hex()}")
        result = send_raw(payload)
        print(f"Response ({len(result)} bytes): {result.hex()}")
        if result:
            try:
                print(f"Parsed: {parse_term(result)}")
            except Exception as e:
                print(f"Parse error: {e}")
        time.sleep(0.4)

    # Test 4: What if we pass the literal bytes 00 FE FE as bytecode?
    print("\n[TEST 4] Raw bytes 00 FE FE sent to backdoor")
    # Note: This is actually Lam(Lam(Var(0))) which is test 1
    # But let's be explicit
    payload4 = bytes([201, 0x00, 0xFE, 0xFE, FD]) + QD + bytes([FD, FF])
    print(f"Bytecode: {payload4.hex()}")
    result4 = send_raw(payload4)
    print(f"Response ({len(result4)} bytes): {result4.hex()}")
    if result4:
        try:
            print(f"Parsed: {parse_term(result4)}")
        except Exception as e:
            print(f"Parse error: {e}")


if __name__ == "__main__":
    test_backdoor()
