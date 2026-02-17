#!/usr/bin/env python3
"""
Extract and use backdoor pair components correctly.

The pair is: λ.λ.((V1 λ.λ.(V0 V0)) λ.λ.(V1 V0))

This is a Scott pair: λs. s A B where s is the selector
- Strip 1 lambda to get: λ.((V1 λ.λ.(V0 V0)) λ.λ.(V1 V0))
  This is: λ.((V1 A) B) where V1 is 's' (shifted by 1 for the selector's lambda)

Wait - there's 2 lambdas, so it's: λs.λ?. ((s A) B)
That's weird. Let me re-analyze.

Actually looking at it:
- outer term is: λ.λ.((V1 A) B)
- V1 refers to the first parameter (s)
- So this IS pair = λs.λdummy. s A B

To extract A and B, we need to apply selectors:
- pair (λa.λb.a) nil → A
- pair (λa.λb.b) nil → B
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


def term_to_str(term: object, depth=0) -> str:
    if depth > 20:
        return "..."
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{term_to_str(term.body, depth+1)}"
    if isinstance(term, App):
        return f"({term_to_str(term.f, depth+1)} {term_to_str(term.x, depth+1)})"
    return "?"


def query(payload: bytes, timeout_s: float = 5.0) -> bytes:
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


def parse_term(data: bytes) -> object:
    stack = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x, f = stack.pop(), stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            stack.append(Lam(stack.pop()))
        else:
            stack.append(Var(b))
    return stack[0] if len(stack) == 1 else None


def decode_either(term):
    if isinstance(term, Lam) and isinstance(term.body, Lam):
        body = term.body.body
        if isinstance(body, App) and isinstance(body.f, Var):
            return ("Left" if body.f.i == 1 else "Right", body.x)
    return None, None


def main():
    print("=== Backdoor Pair Extraction ===\n")
    
    nil = Lam(Lam(Var(0)))
    fst = Lam(Lam(Var(1)))
    snd = Lam(Lam(Var(0)))
    
    print("Get the backdoor pair:")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    term = parse_term(resp)
    tag, pair = decode_either(term)
    print(f"Pair: {term_to_str(pair)}")
    
    print("\n=== Extract A using fst selector ===")
    
    extract_fst = Lam(
        App(
            App(Var(0), fst),
            nil
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(extract_fst) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    print(f"Response: {resp.hex()}")
    
    if resp:
        a_term = parse_term(resp)
        print(f"A (raw): {term_to_str(a_term)}")
        a_tag, a_payload = decode_either(a_term)
        if a_tag == "Left":
            print(f"A (unwrapped): {term_to_str(a_payload)}")
    time.sleep(0.2)
    
    print("\n=== Extract B using snd selector ===")
    
    extract_snd = Lam(
        App(
            App(Var(0), snd),
            nil
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(extract_snd) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    print(f"Response: {resp.hex()}")
    
    if resp:
        b_term = parse_term(resp)
        print(f"B (raw): {term_to_str(b_term)}")
        b_tag, b_payload = decode_either(b_term)
        if b_tag == "Left":
            print(f"B (unwrapped): {term_to_str(b_payload)}")
    time.sleep(0.2)
    
    print("\n=== Use extracted components with syscall 8 ===")
    
    syscall8 = Var(8)
    
    extract_fst_sc8 = Lam(
        App(
            App(
                App(Var(0), fst),
                nil
            ),
            syscall8
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(extract_fst_sc8) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    print(f"A applied to syscall8: {resp.hex()[:60] if resp else '(empty)'}")
    time.sleep(0.2)
    
    print("\n=== Chain: backdoor → extract A → apply to syscall 8 → QD ===")
    
    chain_a_to_sc8 = Lam(
        App(
            App(Var(0), fst),
            Lam(
                App(
                    App(syscall8, Var(0)),
                    Lam(Lam(Var(0)))
                )
            )
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(chain_a_to_sc8) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    print(f"backdoor → A → syscall8(A): {resp.hex()[:60] if resp else '(empty)'}")
    time.sleep(0.2)
    
    print("\n=== The key insight: pair applied to selector ===")
    print("pair = λs.λd. s A B")
    print("pair fst nil = fst A B = A")
    print("pair snd nil = snd A B = B")
    print()
    print("What if we apply the pair to syscall8 directly?")
    print("pair syscall8 = λd. syscall8 A B")
    print("(pair syscall8) nil = syscall8 A B = (syscall8 A) B")
    print()
    print("This means syscall8 gets A as argument and B as continuation!")
    
    apply_pair_to_sc8 = Lam(
        App(
            App(Var(0), syscall8),
            nil
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(apply_pair_to_sc8) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    print(f"\n(pair syscall8) nil: {resp.hex()[:80] if resp else '(empty)'}")


if __name__ == "__main__":
    main()
