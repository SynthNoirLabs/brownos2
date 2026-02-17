#!/usr/bin/env python3
"""
What if the answer comes from APPLYING the backdoor combinators?

A = λab.bb (self-apply second)
B = λab.ab (apply first to second)

What happens when we apply these to each other or to specific terms?
"""

import socket
import time

HOST = "82.165.133.222"
PORT = 61221

FD, FE, FF = 0xFD, 0xFE, 0xFF
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


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


def test(desc: str, payload: bytes):
    resp = query(payload)
    if not resp:
        result = "(empty/timeout)"
    elif b"Encoding failed" in resp:
        result = "Encoding failed!"
    elif b"Invalid term" in resp:
        result = "Invalid term!"
    elif resp == b'\xff':
        result = "Just FF"
    else:
        try:
            text = resp.decode('utf-8', 'replace')
            if text.isprintable() or '\n' in text:
                result = f"Text: {repr(text[:60])}"
            else:
                result = f"hex: {resp.hex()[:80]}"
        except:
            result = f"hex: {resp.hex()[:80]}"
    print(f"{desc}: {result}")


def main():
    print("=" * 70)
    print("COMBINATOR APPLICATION TESTS")
    print("=" * 70)
    
    nil = bytes([0x00, FE, FE])
    A = bytes([0x00, 0x00, FD, FE, FE])
    B = bytes([0x01, 0x00, FD, FE, FE])
    I = bytes([0x00, FE])
    omega = bytes([0x00, 0x00, FD, FE])
    
    print("\n=== Apply combinators to each other (print result with QD) ===\n")
    
    combos = [
        ("(A A)", A + A + bytes([FD])),
        ("(A B)", A + B + bytes([FD])),
        ("(B A)", B + A + bytes([FD])),
        ("(B B)", B + B + bytes([FD])),
        ("((A A) nil)", A + A + bytes([FD]) + nil + bytes([FD])),
        ("((A B) nil)", A + B + bytes([FD]) + nil + bytes([FD])),
        ("((B A) nil)", B + A + bytes([FD]) + nil + bytes([FD])),
        ("((B B) nil)", B + B + bytes([FD]) + nil + bytes([FD])),
    ]
    
    for desc, term in combos:
        payload = term + bytes([FD]) + QD + bytes([FD, FF])
        test(f"QD({desc})", payload)
        time.sleep(0.15)
    
    print("\n=== Use combinators with write syscall ===\n")
    
    write_combos = [
        ("write (A A)", bytes([0x02]) + A + A + bytes([FD, FD]) + nil + bytes([FD, FF])),
        ("write (B B)", bytes([0x02]) + B + B + bytes([FD, FD]) + nil + bytes([FD, FF])),
    ]
    
    for desc, payload in write_combos:
        test(desc, payload)
        time.sleep(0.15)
    
    print("\n=== Extract pair from backdoor and apply ===\n")
    
    backdoor_extract_apply = bytes([0xC9]) + nil + bytes([FD]) + bytes([
        0x00, FE, FE,
        0x00, 0x00, FD, FE, FE,
        FD,
        0x00, FE, FE,
        0x00, 0x00, FD, FE, FE,
        FD, FD, FE,
        FD
    ]) + bytes([FD]) + QD + bytes([FD, FF])
    test("backdoor -> extract -> apply", backdoor_extract_apply)
    
    print("\n=== Get pair, apply selector to extract A, then print A ===\n")
    
    get_A_cont = bytes([
        0x00, FE,
        FD,
    ])
    
    payload = bytes([0xC9]) + nil + bytes([FD]) + bytes([
        0x00, FE, FE,
        0x00, FE,
        FD, FE,
        FD
    ]) + bytes([FD]) + QD + bytes([FD, FF])
    test("backdoor(nil) -> (pair false I) -> QD", payload)
    
    print("\n=== Use the pair as a continuation directly ===\n")
    
    for syscall in [0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0E, 0x2A, 0xC9]:
        int_0 = bytes([0x00] * 9 + [FE] * 9)
        payload = bytes([syscall]) + nil + bytes([FD])
        
        pair_cont = bytes([
            0x00, FE,
            FD
        ])
        
        payload += pair_cont + bytes([FD, FF])
        test(f"syscall {hex(syscall)}(nil) -> pair projection", payload)
        time.sleep(0.1)
    
    print("\n=== The 'S K I' combinators ===\n")
    
    K = bytes([0x01, FE, FE])
    S = bytes([0x02, 0x00, FD, 0x01, 0x00, FD, FD, FE, FE, FE])
    
    ski_combos = [
        ("K nil", K + nil + bytes([FD])),
        ("K K", K + K + bytes([FD])),
        ("S K K", S + K + bytes([FD]) + K + bytes([FD])),
    ]
    
    for desc, term in ski_combos:
        payload = term + bytes([FD]) + QD + bytes([FD, FF])
        test(f"QD({desc})", payload)
        time.sleep(0.15)


if __name__ == "__main__":
    main()
