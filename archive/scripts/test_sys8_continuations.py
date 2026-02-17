#!/usr/bin/env python3
"""
CRITICAL TEST: Use 00 FE FE (Church 0) as CONTINUATION instead of QD.

The mail says "start with 00 FE FE" - what if this means:
Use Church 0 as the continuation for syscall 8?

Normal: sys8(arg)(QD)
Test:   sys8(arg)(Church0)
"""

import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

# QD = Quick Debug continuation
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

# Church 0 = λλVar(0) = 00 FE FE
CHURCH_0 = bytes([0x00, 0xFE, 0xFE])


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


def send_raw(payload, timeout=10.0):
    """Send raw payload and return response."""
    try:
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
                    if FF in c:
                        break
                except:
                    break
            return out
    except Exception as e:
        return b""


print("=" * 80)
print("TESTING SYSCALL 8 WITH DIFFERENT CONTINUATIONS")
print("=" * 80)

# Test 1: sys8 with Church 0 continuation
print("\n[TEST 1] sys8(backdoor_output)(Church 0)")
print("=" * 80)

# Get the backdoor output first
backdoor_common = bytes.fromhex("000200fdfefefefefefefefefefdfefe")  # Without FF

# Payload: 08 <backdoor_output> FD <CHURCH_0> FD FF
#          syscall8(backdoor_output)(Church0)
payload1 = bytes([0x08]) + backdoor_common + bytes([FD]) + CHURCH_0 + bytes([FD, FF])

print(f"Payload: sys8(backdoor_common)(00 FE FE)")
print(f"Bytecode: {payload1.hex()}")
print(f"Length: {len(payload1)} bytes")

result1 = send_raw(payload1)
print(f"\nResponse ({len(result1)} bytes): {result1.hex()}")

if result1:
    if len(result1) > 10:
        print(f"Full: {result1.hex()}")
        print(f"Printable: {repr(result1)}")
    else:
        print(f"Short response: {result1.hex()}")
else:
    print("⚠️  EMPTY or TIMEOUT")

time.sleep(0.5)

# Test 2: sys8 with Church 1, 2, 3...
print("\n[TEST 2] sys8(backdoor_output)(Church N) for N=0..5")
print("=" * 80)

for n in range(6):
    # Church n = λf.λx. f^n(x)
    if n == 0:
        church_n = Lam(Lam(Var(0)))  # λλ0
    else:
        # Build f(f(...(x)))
        inner = Var(0)
        for _ in range(n):
            inner = App(Var(1), inner)
        church_n = Lam(Lam(inner))

    church_bytes = encode_term(church_n)
    payload = (
        bytes([0x08]) + backdoor_common + bytes([FD]) + church_bytes + bytes([FD, FF])
    )

    print(f"\nChurch {n}: {church_bytes.hex()}")
    print(f"Payload: {payload.hex()}")

    result = send_raw(payload)
    print(
        f"Response ({len(result)} bytes): {result.hex()[:80]}{'...' if len(result) > 40 else ''}"
    )

    time.sleep(0.4)

# Test 3: sys8 with NO continuation (see what happens)
print("\n[TEST 3] sys8(backdoor_output) WITH NO CONTINUATION")
print("=" * 80)

payload3 = bytes([0x08]) + backdoor_common + bytes([FD, FF])
print(f"Payload: {payload3.hex()}")

result3 = send_raw(payload3, timeout=5.0)
print(f"Response ({len(result3)} bytes): {result3.hex()}")

time.sleep(0.5)

# Test 4: Use backdoor OUTPUT as continuation for sys8
print("\n[TEST 4] sys8(Church 0)(backdoor_output) - REVERSED!")
print("=" * 80)

payload4 = bytes([0x08]) + CHURCH_0 + bytes([FD]) + backdoor_common + bytes([FD, FF])
print(f"Payload: {payload4.hex()}")

result4 = send_raw(payload4)
print(f"Response ({len(result4)} bytes): {result4.hex()}")

time.sleep(0.5)

# Test 5: CHAIN backdoor then sys8
print("\n[TEST 5] sys8(backdoor(Church 0))(QD) - CHAINED!")
print("=" * 80)

# First get backdoor(Church 0) output
backdoor_special = bytes.fromhex("01010000fdfefefd0100fdfefefdfefefdfefe")  # Without FF

payload5 = bytes([0x08]) + backdoor_special + bytes([FD]) + QD + bytes([FD, FF])
print(f"Payload: {payload5.hex()}")

result5 = send_raw(payload5)
print(f"Response ({len(result5)} bytes): {result5.hex()}")

if result5 and not result5.startswith(bytes([0x01, 0x06])):
    print("⚠️  NOT error 6! Different response!")

time.sleep(0.5)

# Test 6: Try sys8 with IDENTITY continuation
print("\n[TEST 6] sys8(backdoor_output)(IDENTITY)")
print("=" * 80)

# Identity = λx.x = 00 FE
IDENTITY = bytes([0x00, 0xFE])

payload6 = bytes([0x08]) + backdoor_common + bytes([FD]) + IDENTITY + bytes([FD, FF])
print(f"Payload: {payload6.hex()}")

result6 = send_raw(payload6)
print(f"Response ({len(result6)} bytes): {result6.hex()}")

print("\n" + "=" * 80)
print("ANALYSIS")
print("=" * 80)

print("""
Looking for responses that are NOT:
  - Empty (timeout/hang)
  - Right(6) = permission denied
  - Same as QD continuation

If we get DIFFERENT output, the continuation matters!
""")
