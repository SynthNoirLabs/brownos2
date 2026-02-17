#!/usr/bin/env python3
"""
Probe: Minimal payloads and the "3 leafs" interpretation

The author said "My record is 3 leafs IIRC"

What if "3 leafs" means:
1. A term with exactly 3 Var nodes
2. A payload of 3 bytes (plus markers)
3. The ANSWER has 3 characters
4. Something about the structure of the solution

Let's explore minimal interesting payloads.
"""

from __future__ import annotations

import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def query_raw(payload: bytes, timeout_s: float = 5.0) -> bytes:
    delay = 0.2
    for attempt in range(3):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                sock.shutdown(socket.SHUT_WR)
                sock.settimeout(timeout_s)
                out = b""
                while True:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        out += chunk
                    except socket.timeout:
                        break
                return out
        except Exception as e:
            time.sleep(delay)
            delay *= 2
    return b""


def count_vars(payload: bytes) -> int:
    """Count Var nodes in a payload"""
    count = 0
    for b in payload:
        if b < 0xFD:
            count += 1
    return count


def test_minimal_payloads():
    """Test various minimal payloads"""
    print("\n=== TEST: Minimal Payloads ===")

    print("\n1. Single Var (1 leaf):")
    for v in [0, 1, 8, 14, 201]:
        payload = bytes([v, FF])
        resp = query_raw(payload, timeout_s=3)
        print(f"   Var({v}): {resp.hex() if resp else 'EMPTY'}")

    print("\n2. Two Vars in App (2 leaves):")
    # (V0 V1) = 00 01 FD FF
    patterns_2 = [
        (bytes([0x00, 0x01, FD, FF]), "(V0 V1)"),
        (bytes([0x08, 0x00, FD, FF]), "(syscall8 V0)"),
        (bytes([0x0E, 0x00, FD, FF]), "(echo V0)"),
        (bytes([0xC9, 0x00, FD, FF]), "(backdoor V0)"),
    ]
    for payload, desc in patterns_2:
        resp = query_raw(payload, timeout_s=3)
        vars_count = count_vars(payload[:-1])  # exclude FF
        print(f"   {desc} [{vars_count} vars]: {resp.hex() if resp else 'EMPTY'}")

    print("\n3. Three Vars (3 leaves):")
    # ((V0 V1) V2) = 00 01 FD 02 FD FF
    patterns_3 = [
        (bytes([0x08, 0x00, FD, 0x00, FD, FF]), "((8 0) 0)"),
        (bytes([0x08, 0x00, FD, QD[0], FD, FF]), "((8 0) V5)"),  # QD starts with 05
        (bytes([0x08, 0x0E, FD, 0x00, FD, FF]), "((8 echo) 0)"),
        (bytes([0x0E, 0x00, FD, 0x0E, FD, FF]), "((echo 0) echo)"),
        (bytes([0x00, 0x08, FD, 0x00, FD, FF]), "((0 8) 0)"),
        (bytes([0xC9, 0x00, FD, 0x00, FD, FF]), "((backdoor 0) 0)"),
    ]
    for payload, desc in patterns_3:
        resp = query_raw(payload, timeout_s=3)
        print(f"   {desc}: {resp.hex() if resp else 'EMPTY'}")


def test_syscall8_minimal():
    """Minimal syscall8 invocations"""
    print("\n=== TEST: Minimal Syscall8 Calls ===")

    # The standard CPS pattern: ((syscall arg) continuation)
    # Minimal arg: nil = 00 FE FE (3 bytes, 1 var)
    # Minimal continuation: identity = 00 FE (2 bytes, 1 var)

    nil = bytes([0x00, FE, FE])
    identity = bytes([0x00, FE])

    print("\n1. ((syscall8 nil) identity):")
    payload1 = bytes([0x08]) + nil + bytes([FD]) + identity + bytes([FD, FF])
    resp1 = query_raw(payload1)
    print(f"   Payload: {payload1.hex()}")
    print(f"   Response: {resp1.hex() if resp1 else 'EMPTY'}")

    print("\n2. ((syscall8 identity) identity):")
    payload2 = bytes([0x08]) + identity + bytes([FD]) + identity + bytes([FD, FF])
    resp2 = query_raw(payload2)
    print(f"   Payload: {payload2.hex()}")
    print(f"   Response: {resp2.hex() if resp2 else 'EMPTY'}")

    print("\n3. syscall8 with different continuations:")
    for cont_var in [0, 1, 2, 4, 5, 8, 14]:
        # ((syscall8 nil) Var(N))
        payload = bytes([0x08]) + nil + bytes([FD, cont_var, FD, FF])
        resp = query_raw(payload, timeout_s=3)
        status = resp.hex() if resp else "EMPTY"
        print(f"   cont=V{cont_var}: {status[:40]}...")


def test_direct_writes():
    """What if we just need to write something specific?"""
    print("\n=== TEST: Direct Write Patterns ===")

    # Maybe the answer involves using write syscall (0x02) to output something

    nil = bytes([0x00, FE, FE])

    print("\n1. Write empty list:")
    # ((write nil) nil)
    payload1 = bytes([0x02]) + nil + bytes([FD]) + nil + bytes([FD, FF])
    resp1 = query_raw(payload1)
    print(f"   Response: {resp1.hex() if resp1 else 'EMPTY'}")

    # What about writing the result of backdoor?
    print("\n2. Backdoor → extract → write:")
    # This would need complex chaining...


def test_backdoor_minimal():
    """Minimal backdoor interactions"""
    print("\n=== TEST: Minimal Backdoor Calls ===")

    nil = bytes([0x00, FE, FE])
    identity = bytes([0x00, FE])

    print("\n1. ((backdoor nil) identity):")
    payload1 = bytes([0xC9]) + nil + bytes([FD]) + identity + bytes([FD, FF])
    resp1 = query_raw(payload1)
    print(f"   Payload: {payload1.hex()}")
    print(f"   Response: {resp1.hex() if resp1 else 'EMPTY'}")

    print("\n2. ((backdoor nil) QD):")
    payload2 = bytes([0xC9]) + nil + bytes([FD]) + QD + bytes([FD, FF])
    resp2 = query_raw(payload2)
    print(f"   Response hex: {resp2.hex() if resp2 else 'EMPTY'}")
    # This should print the backdoor pair


def test_what_backdoor_returns():
    """Carefully examine what backdoor returns"""
    print("\n=== TEST: Backdoor Return Value ===")

    nil = bytes([0x00, FE, FE])

    print("\n1. Quote the backdoor result:")
    # ((backdoor nil) λleft.((left (λpair.((quote pair) write_cont))) nil))
    # where write_cont = λbytes.((write bytes) nil)

    # Simpler: just use QD
    payload = bytes([0xC9]) + nil + bytes([FD]) + QD + bytes([FD, FF])
    resp = query_raw(payload)
    print(f"   Response: {resp.hex() if resp else 'EMPTY'}")

    if resp:
        # Parse the response
        # Should be Left(pair) where pair = λs.(s A B)
        # QD serializes this
        print(f"   Length: {len(resp)} bytes")

        # Try to interpret: 01 XX FD FE FE FF would be Left(XX)
        # The backdoor pair is more complex


def test_count_leafs_in_solution():
    """What if '3 leafs' means the solution payload has exactly 3 var bytes?"""
    print("\n=== TEST: Solutions with Exactly 3 Vars ===")

    nil = bytes([0x00, FE, FE])

    # Patterns with exactly 3 Var bytes:
    # Remember: lambdas and apps don't count, only 0x00-0xFC bytes

    patterns = [
        # ((V8 (λ.V0)) V0) = 3 vars: 8, 0, 0
        bytes([0x08, 0x00, FE, FD, 0x00, FD, FF]),
        # ((V8 V0) (λ.V0)) = 3 vars: 8, 0, 0
        bytes([0x08, 0x00, FD, 0x00, FE, FD, FF]),
        # (V8 ((V0 V0) ...)) - various
    ]

    for i, payload in enumerate(patterns):
        var_count = count_vars(payload[:-1])
        resp = query_raw(payload, timeout_s=3)
        print(
            f"   Pattern {i + 1} [{var_count} vars]: {resp.hex() if resp else 'EMPTY'}"
        )
        print(f"      Payload: {payload.hex()}")


def main():
    print("=" * 60)
    print("PROBE: Minimal Payloads and '3 Leafs'")
    print("=" * 60)

    test_minimal_payloads()
    test_syscall8_minimal()
    test_backdoor_minimal()
    test_what_backdoor_returns()
    test_count_leafs_in_solution()

    print("\n" + "=" * 60)
    print("PROBE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
