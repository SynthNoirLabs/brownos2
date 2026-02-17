#!/usr/bin/env python3
"""
Test untested BrownOS patterns identified by explore agent.
Reports ANY result that is NOT Right(6) or silent.
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass


HOST = "82.165.133.222"
PORT = 61221

FD = 0xFD  # application
FE = 0xFE  # lambda
FF = 0xFF  # end-of-code marker

# Quick Debug continuation from the challenge cheat sheet.
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


def recv_all(sock: socket.socket, timeout_s: float) -> bytes:
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


def query(payload: bytes, retries: int = 3, timeout_s: float = 4.0) -> bytes:
    delay = 0.2
    last_err: Exception | None = None
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s=timeout_s)
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


def decode_either(term: object) -> tuple[str, object]:
    """
    Scott Either:
    Left x  = λl.λr. l x  -> λ.λ.(1 x)
    Right y = λl.λr. r y  -> λ.λ.(0 y)
    """
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not an Either")
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var) and body.f.i in (0, 1):
        return ("Left" if body.f.i == 1 else "Right", body.x)
    raise ValueError("Unexpected Either shape")


def is_right_6(term: object) -> bool:
    """Check if term is Right(Var(6))"""
    try:
        tag, payload = decode_either(term)
        return tag == "Right" and isinstance(payload, Var) and payload.i == 6
    except:
        return False


def test_pattern(name: str, payload: bytes) -> None:
    """Test a pattern and report if result is NOT Right(6) or silent"""
    print(f"\n{'='*60}")
    print(f"Testing: {name}")
    print(f"Payload (hex): {payload.hex()}")
    print(f"Payload (bytes): {list(payload)}")
    
    try:
        result = query(payload, timeout_s=5.0)
        print(f"Response length: {len(result)} bytes")
        print(f"Response (hex): {result.hex()}")
        
        if len(result) == 0:
            print("⚠️  SILENT RESPONSE (empty)")
            return
        
        try:
            term = parse_term(result)
            print(f"Parsed term: {term}")
            
            if is_right_6(term):
                print("✓ Result is Right(6) - expected/boring")
            else:
                print("🔥 INTERESTING: Result is NOT Right(6)!")
                try:
                    tag, payload_inner = decode_either(term)
                    print(f"   Either tag: {tag}")
                    print(f"   Payload: {payload_inner}")
                except Exception as e:
                    print(f"   Could not decode as Either: {e}")
        except Exception as e:
            print(f"⚠️  Parse error: {e}")
            print(f"   Raw bytes: {result[:100]}")
            
    except Exception as e:
        print(f"❌ Query failed: {e}")


def main() -> None:
    print("BrownOS Untested Pattern Probe")
    print(f"Target: {HOST}:{PORT}")
    
    # Pattern 1: Syscall 8 with itself as argument
    # ((0x08 Var(8)) QD)
    print("\n" + "="*60)
    print("PATTERN 1: Syscall 8 with Var(8) as argument")
    pattern1a = bytes([0x08, 0x08, FD]) + QD + bytes([FD, FF])
    test_pattern("((0x08 Var(8)) QD)", pattern1a)
    
    # ((0x08 nil) Var(8))
    # nil = λ.λ.0
    nil = Lam(Lam(Var(0)))
    pattern1b = bytes([0x08]) + encode_term(nil) + bytes([FD, 0x08, FD, FF])
    test_pattern("((0x08 nil) Var(8))", pattern1b)
    
    # Pattern 2: Triple echo before syscall 8
    # echo = syscall 0x0E
    # echo(echo(echo(nil))) then use result with syscall 8
    print("\n" + "="*60)
    print("PATTERN 2: Triple echo before syscall 8")
    
    # Build: ((0x08 (((0x0E nil) (0x0E nil)) (0x0E nil))) QD)
    # Actually: echo(nil) = (0x0E nil FD)
    # echo(echo(nil)) = (0x0E (0x0E nil FD) FD)
    # echo(echo(echo(nil))) = (0x0E (0x0E (0x0E nil FD) FD) FD)
    # Then: (0x08 <triple-echo> FD) QD FD
    
    triple_echo_term = App(Var(0x0E), App(Var(0x0E), App(Var(0x0E), nil)))
    pattern2 = bytes([0x08]) + encode_term(triple_echo_term) + bytes([FD]) + QD + bytes([FD, FF])
    test_pattern("((0x08 echo(echo(echo(nil)))) QD)", pattern2)
    
    # Pattern 3: Syscall 8 with QD as argument
    print("\n" + "="*60)
    print("PATTERN 3: Syscall 8 with QD as argument")
    
    qd_term = parse_term(QD + bytes([FF]))
    pattern3 = bytes([0x08]) + encode_term(qd_term) + bytes([FD]) + QD + bytes([FD, FF])
    test_pattern("((0x08 QD) QD)", pattern3)
    
    # Pattern 4: Program starting with 00 FE FE
    print("\n" + "="*60)
    print("PATTERN 4: Program starting with 00 FE FE")
    
    # Literally: 00 FE FE ... FF
    # This is: λ.λ.Var(0) which is nil
    pattern4a = bytes([0x00, FE, FE, FF])
    test_pattern("00 FE FE FF (nil)", pattern4a)
    
    # Try applying nil to something
    # (nil Var(5)) QD
    pattern4b = bytes([0x00, FE, FE, 0x05, FD]) + QD + bytes([FD, FF])
    test_pattern("((nil Var(5)) QD)", pattern4b)
    
    # Try: (nil QD)
    pattern4c = bytes([0x00, FE, FE]) + QD + bytes([FD, FF])
    test_pattern("(nil QD)", pattern4c)
    
    # Pattern 5: Mixed syscall nesting
    print("\n" + "="*60)
    print("PATTERN 5: Mixed syscall nesting")
    
    # ((0x08 ((0x0E nil) ...)) ...)
    # Build: ((0x08 (0x0E nil)) QD)
    echo_nil = App(Var(0x0E), nil)
    pattern5a = bytes([0x08]) + encode_term(echo_nil) + bytes([FD]) + QD + bytes([FD, FF])
    test_pattern("((0x08 (0x0E nil)) QD)", pattern5a)
    
    # Try: ((0x0E ((0x08 nil) QD)) QD)
    syscall8_nil = App(Var(0x08), nil)
    syscall8_nil_qd = App(syscall8_nil, parse_term(QD + bytes([FF])))
    pattern5b = bytes([0x0E]) + encode_term(syscall8_nil_qd) + bytes([FD]) + QD + bytes([FD, FF])
    test_pattern("((0x0E ((0x08 nil) QD)) QD)", pattern5b)
    
    # Additional interesting patterns
    print("\n" + "="*60)
    print("BONUS PATTERNS")
    
    # Syscall 8 with Var(0)
    pattern_bonus1 = bytes([0x08, 0x00, FD]) + QD + bytes([FD, FF])
    test_pattern("((0x08 Var(0)) QD)", pattern_bonus1)
    
    # Syscall 8 with Var(255)
    pattern_bonus2 = bytes([0x08, 0xFF - 1, FD]) + QD + bytes([FD, FF])  # 0xFE is lambda, so use 0xFC
    test_pattern("((0x08 Var(252)) QD)", pattern_bonus2)
    
    # Double application of syscall 8
    # (((0x08 nil) nil) QD)
    pattern_bonus3 = bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    test_pattern("(((0x08 nil) nil) QD)", pattern_bonus3)
    
    print("\n" + "="*60)
    print("Testing complete!")


if __name__ == "__main__":
    main()
