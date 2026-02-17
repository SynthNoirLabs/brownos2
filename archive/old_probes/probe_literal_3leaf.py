#!/usr/bin/env python3
"""
LITERAL 3 LEAF SOLUTION ATTEMPT

Author: "My record is 3 leafs IIRC"

What if the ENTIRE payload has exactly 3 Var nodes?

Pattern: ((Var(a) Var(b)) Var(c)) + FF
This is: syscall_a(arg_b, cont_c)

Or with lambdas for structure but only 3 Vars total.

Key insight: We need to find a,b,c such that this produces the flag!
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


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError


def count_vars(term: object) -> int:
    if isinstance(term, Var):
        return 1
    if isinstance(term, Lam):
        return count_vars(term.body)
    if isinstance(term, App):
        return count_vars(term.f) + count_vars(term.x)
    return 0


def query(payload: bytes, timeout_s: float = 4.0) -> bytes:
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
                if FF in chunk:
                    break
            except socket.timeout:
                break
        return out


def test(desc: str, payload: bytes, show_hex: bool = True) -> str:
    try:
        resp = query(payload)
        if not resp:
            result = "(empty)"
        elif b"Encoding failed" in resp:
            result = "Encoding failed!"
        elif b"Invalid term" in resp:
            result = "Invalid term!"
        elif resp.hex().startswith("01"):
            result = f"Left! len={len(resp)}"
            if show_hex:
                result += f" hex={resp.hex()[:60]}"
        else:
            result = resp.hex()[:60] if show_hex else f"Right/other len={len(resp)}"
        print(f"{desc}: {result}")
        return result
    except Exception as e:
        print(f"{desc}: ERROR - {e}")
        return f"ERROR: {e}"


def main():
    print("=" * 70)
    print("LITERAL 3-LEAF PATTERNS")
    print("=" * 70)
    
    print("\n=== Pattern: ((Var(a) Var(b)) Var(c)) ===\n")
    print("Syscall CPS: (syscall arg) cont\n")
    
    interesting = [
        (201, "backdoor"),
        (14, "echo"),
        (8, "syscall8"),
        (7, "readfile"),
        (5, "readdir"),
        (4, "quote"),
        (2, "write"),
        (1, "errstr"),
        (42, "towel"),
    ]
    
    print("Testing: ((backdoor X) Y) for various X, Y:\n")
    
    for b, b_name in interesting[:6]:
        for c, c_name in interesting[:6]:
            term = App(App(Var(201), Var(b)), Var(c))
            vars_count = count_vars(term)
            payload = encode_term(term) + bytes([FF])
            test(f"((backdoor {b_name}) {c_name}) [{vars_count}v]", payload, show_hex=False)
        time.sleep(0.1)
    
    print("\n=== Pattern: ((echo X) Y) ===\n")
    
    for b in [0, 1, 8, 14, 201, 251, 252]:
        for c in [0, 1, 2, 4, 8, 14, 201]:
            term = App(App(Var(14), Var(b)), Var(c))
            payload = encode_term(term) + bytes([FF])
            result = test(f"((echo Var({b})) Var({c}))", payload, show_hex=False)
            if "Left" in result:
                print(f"  ^^^ SUCCESS!")
        time.sleep(0.1)
    
    print("\n=== Pattern: ((syscall8 X) Y) - direct call ===\n")
    
    for b in [0, 1, 8, 14, 201]:
        for c in [0, 1, 2, 4, 8, 14, 201]:
            term = App(App(Var(8), Var(b)), Var(c))
            payload = encode_term(term) + bytes([FF])
            result = test(f"((syscall8 Var({b})) Var({c}))", payload, show_hex=False)
            if "Left" in result:
                print(f"  ^^^ SUCCESS!")
        time.sleep(0.1)
    
    print("\n=== Pattern: λ.((Var(a) Var(b)) Var(c)) - with 1 lambda ===\n")
    
    for a, a_name in [(201, "backdoor"), (14, "echo"), (8, "syscall8")]:
        for b in [0, 1]:
            term = Lam(App(App(Var(a), Var(b)), Var(0)))
            vars_count = count_vars(term)
            payload = encode_term(term) + bytes([FF])
            test(f"λ.(({a_name} V{b}) V0) [{vars_count}v]", payload, show_hex=False)
    
    print("\n=== Minimal nil pattern: λλ.V0 (nil itself) ===\n")
    
    nil = Lam(Lam(Var(0)))
    print(f"nil = λλ.V0 has {count_vars(nil)} var(s)")
    
    term = App(App(Var(201), nil), nil)
    vars_count = count_vars(term)
    payload = encode_term(term) + bytes([FF])
    test(f"((backdoor nil) nil) [{vars_count}v]", payload)
    
    term = App(App(Var(201), nil), Var(8))
    vars_count = count_vars(term)
    payload = encode_term(term) + bytes([FF])
    test(f"((backdoor nil) syscall8) [{vars_count}v]", payload)
    
    term = App(App(Var(201), nil), Var(14))
    vars_count = count_vars(term)
    payload = encode_term(term) + bytes([FF])
    test(f"((backdoor nil) echo) [{vars_count}v]", payload)
    
    print("\n=== What if 3 leafs means raw byte count? ===\n")
    
    raw_3byte = [
        ("C9 00 FF", bytes([0xC9, 0x00, FF])),
        ("C9 08 FF", bytes([0xC9, 0x08, FF])),
        ("0E 00 FF", bytes([0x0E, 0x00, FF])),
        ("08 00 FF", bytes([0x08, 0x00, FF])),
        ("00 C9 FF", bytes([0x00, 0xC9, FF])),
        ("08 C9 FF", bytes([0x08, 0xC9, FF])),
    ]
    
    for desc, payload in raw_3byte:
        test(desc, payload)


if __name__ == "__main__":
    main()
