#!/usr/bin/env python3
"""
Author hint: "My record is 3 leafs IIRC"

In lambda calculus, "leafs" = variables (Var nodes).
The minimal 3-leaf terms that could be answers:

Pattern 1: ((V_a V_b) V_c) - three vars, two apps
Pattern 2: (V_a (V_b V_c)) - three vars, two apps  
Pattern 3: λ.((V_a V_b) V_c) - three vars under lambda

For syscall semantics ((syscall arg) cont):
- syscall = Var(n) for some n
- arg = Var(m) 
- cont = Var(k) or some continuation

What if the answer is:
((8 backdoor_result) QD) - but backdoor_result is a single Var?

Or what about using the backdoor pair's A and B components directly?
A = λab.bb (self-apply second)
B = λab.ab (apply first to second)

These create specific combinators. What if (A B) or (B A) produces something useful?
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


def query(payload: bytes, timeout_s: float = 3.0) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except:
            pass
        sock.settimeout(timeout_s)
        out = b""
        while True:
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


def test(desc: str, payload: bytes) -> None:
    try:
        resp = query(payload)
        if not resp:
            print(f"{desc}: (empty)")
        elif b"Encoding failed" in resp:
            print(f"{desc}: Encoding failed!")
        elif b"Invalid term" in resp:
            print(f"{desc}: Invalid term!")
        elif resp.hex().startswith("01"):
            print(f"{desc}: Left! len={len(resp)}")
        else:
            print(f"{desc}: {resp.hex()[:60]}")
    except Exception as e:
        print(f"{desc}: ERROR - {e}")
    time.sleep(0.15)


def main():
    print("=== 3-Leaf Minimal Terms ===\n")
    
    nil = Lam(Lam(Var(0)))
    
    print("1. Minimal 3-var patterns with syscalls:\n")
    print("   Pattern: ((syscall_a syscall_b) syscall_c)\n")
    
    interesting_globals = [
        (1, "errstr"),
        (2, "write"),
        (4, "quote"),
        (5, "readdir"),
        (6, "name"),
        (7, "readfile"),
        (8, "syscall8"),
        (14, "echo"),
        (42, "towel"),
        (201, "backdoor"),
    ]
    
    for a, a_name in interesting_globals[:5]:
        for b, b_name in interesting_globals[:5]:
            for c, c_name in [(201, "backdoor")]:
                term = App(App(Var(a), Var(b)), Var(c))
                vars_count = count_vars(term)
                payload = encode_term(term) + bytes([FF])
                test(f"(({a_name} {b_name}) {c_name}) [{vars_count}v]", payload)
    
    print("\n2. Use QD with 3-leaf syscall patterns:\n")
    
    for a in [1, 4, 5, 6, 7, 8, 14, 42, 201]:
        for b in [0, 1, 8, 201]:
            term = App(App(Var(a), Var(b)), nil)
            vars_count = count_vars(term)
            payload = encode_term(term) + QD + bytes([FD, FF])
            if vars_count <= 4:
                test(f"((Var({a}) Var({b})) nil) + QD [{vars_count}v]", payload)
    
    print("\n3. Backdoor with minimal continuation:\n")
    
    continuations = [
        ("Var(0)", Var(0)),
        ("Var(1)", Var(1)),
        ("Var(2)", Var(2)),
        ("Var(4)", Var(4)),
        ("Var(8)", Var(8)),
        ("I = λ.V0", Lam(Var(0))),
    ]
    
    for name, cont in continuations:
        payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(cont) + bytes([FD, FF])
        test(f"backdoor(nil) {name}", payload)
    
    print("\n4. Echo then pass to syscall (minimal):\n")
    
    for i in [0, 1, 4, 5, 6, 7, 8, 201, 251, 252]:
        cont = Var(8)
        payload = bytes([0x0E]) + bytes([i]) + bytes([FD]) + encode_term(cont) + bytes([FD, FF])
        test(f"echo(Var({i})) then Var(8)", payload)
    
    print("\n5. Three-leaf with echo:\n")
    
    for a in [0, 1, 8, 201]:
        for b in [0, 1, 8, 14]:
            term = App(App(Var(14), Var(a)), Var(b))
            payload = encode_term(term) + bytes([FF])
            test(f"((echo Var({a})) Var({b}))", payload)


if __name__ == "__main__":
    main()
