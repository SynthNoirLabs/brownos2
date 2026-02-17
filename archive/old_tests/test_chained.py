#!/usr/bin/env python3
"""
Test chaining echo result directly to syscall 8 within a single program.

Key insight: We can't serialize the echoed term (Encoding failed!), but we
CAN use it internally within the VM by chaining syscalls in a single program.

Program structure:
  echo(base_term, λresult. syscall8(result, QD))

This way the echoed term is passed directly to syscall 8 without serialization.
"""
from __future__ import annotations

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


def recv_raw(sock: socket.socket, timeout_s: float = 5.0) -> bytes:
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
    raise RuntimeError(f"Failed to query") from last_err


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


def term_str(term: object) -> str:
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{term_str(term.body)}"
    if isinstance(term, App):
        return f"({term_str(term.f)} {term_str(term.x)})"
    return str(term)


def decode_either(term: object) -> tuple[str, object]:
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not an Either")
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var) and body.f.i in (0, 1):
        return ("Left" if body.f.i == 1 else "Right", body.x)
    raise ValueError("Unexpected Either shape")


def decode_byte_term(term: object) -> int:
    WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}
    cur = term
    for _ in range(9):
        if not isinstance(cur, Lam):
            raise ValueError("Not enough lambdas")
        cur = cur.body
    def eval_bits(e):
        if isinstance(e, Var):
            return WEIGHTS.get(e.i, 0)
        if isinstance(e, App) and isinstance(e.f, Var):
            return WEIGHTS.get(e.f.i, 0) + eval_bits(e.x)
        return 0
    return eval_bits(cur)


def main():
    print("=" * 60)
    print("BrownOS Chained Syscall Test")
    print("=" * 60)
    
    # Build a program that chains echo → syscall 8 internally
    # Structure: ((echo base_term) (λresult. ((syscall8 result) QD)))
    #
    # In de Bruijn with syscalls as globals:
    # - syscall 8 is Var(8) at top level
    # - echo is Var(14) at top level (0x0E)
    # - Inside the lambda for result, we're under 1 binder, so:
    #   - syscall 8 becomes Var(9)
    #   - result is Var(0)
    #   - QD needs to be shifted by +1 under this lambda
    #
    # Actually, let's build this manually in raw bytes for precision.
    
    print("\n[1] Building chained program: echo(V249) → syscall8")
    
    # First, let's understand the structure:
    # We want: ((0x0E V249) (λx. ((0x08 x) QD)))
    #
    # The continuation λx. ((0x08 x) QD) needs careful construction.
    # Under the lambda, syscall 8 is at index 9 (8+1), and QD references
    # indices shifted by +1.
    #
    # But actually, for syscall CPS, we need to be more careful.
    # Let's try a simpler approach: manually construct the chained program.
    
    # Program: ((0x0E V249) (λecho_result. ((0x08 (unwrap echo_result)) QD)))
    #
    # But unwrapping is complex. Let's first try without unwrapping.
    
    # Simpler: echo returns Left(x), let's pass that directly to syscall 8
    # and see what happens.
    
    # Build: ((0x0E V249) (λr. ((0x08 r) QD)))
    # In bytes:
    # - 0x0E = echo syscall
    # - F9 = V249
    # - FD = App(0x0E, F9)
    # - continuation = λr. ((0x08 r) QD)
    #   Under λ, 0x08 becomes 0x09, and QD indices shift by +1
    
    # Let's compute shifted QD
    qd_parsed = parse_term(QD + b'\xff')
    print(f"  QD parsed: {term_str(qd_parsed)}")
    
    # Shift QD by +1 for use under one lambda
    def shift_term(t, amount):
        if isinstance(t, Var):
            return Var(t.i + amount)
        if isinstance(t, Lam):
            return Lam(shift_term(t.body, amount))
        if isinstance(t, App):
            return App(shift_term(t.f, amount), shift_term(t.x, amount))
        return t
    
    qd_shifted1 = shift_term(qd_parsed, 1)
    print(f"  QD shifted +1: {term_str(qd_shifted1)}")
    
    # Build continuation: λr. ((0x09 r) QD_shifted)
    # r is Var(0) under the lambda
    cont = Lam(App(App(Var(9), Var(0)), qd_shifted1))
    print(f"  Continuation: {term_str(cont)}")
    
    # Build full program: ((0x0E V249) cont) FF
    prog = App(App(Var(0x0E), Var(249)), cont)
    payload = encode_term(prog) + bytes([FF])
    print(f"  Full payload: {payload.hex()}")
    
    # Send it
    out = query(payload)
    print(f"  Raw output: {out!r}")
    if FF in out:
        result = parse_term(out)
        print(f"  Parsed: {term_str(result)}")
        try:
            tag, pay = decode_either(result)
            print(f"  Decoded: {tag}")
            if tag == "Right":
                err_code = decode_byte_term(pay)
                print(f"    Error code: {err_code}")
        except Exception as e:
            print(f"  Decode error: {e}")
    
    # Test 2: Double echo then syscall 8
    print("\n[2] Building chained: echo(echo(V249)) → syscall8")
    
    # ((0x0E V249) (λr1. ((0x0E r1) (λr2. ((0x08 r2) QD_shifted2)))))
    # Under 2 lambdas, syscall indices shift by +2, QD shifts by +2
    
    qd_shifted2 = shift_term(qd_parsed, 2)
    inner_cont = Lam(App(App(Var(10), Var(0)), qd_shifted2))  # syscall 8 at index 8+2=10
    outer_cont = Lam(App(App(Var(15), Var(0)), inner_cont))   # echo at index 14+1=15
    prog2 = App(App(Var(0x0E), Var(249)), outer_cont)
    payload2 = encode_term(prog2) + bytes([FF])
    print(f"  Full payload: {payload2.hex()}")
    
    out2 = query(payload2)
    print(f"  Raw output: {out2!r}")
    if FF in out2:
        result2 = parse_term(out2)
        print(f"  Parsed: {term_str(result2)}")
        try:
            tag, pay = decode_either(result2)
            print(f"  Decoded: {tag}")
            if tag == "Right":
                err_code = decode_byte_term(pay)
                print(f"    Error code: {err_code}")
        except Exception as e:
            print(f"  Decode error: {e}")
    
    # Test 3: Try with 3-leaf term
    print("\n[3] Building chained: echo(echo((V249 V250) V251)) → syscall8")
    
    three_leaf = App(App(Var(249), Var(250)), Var(251))
    inner_cont3 = Lam(App(App(Var(10), Var(0)), qd_shifted2))
    outer_cont3 = Lam(App(App(Var(15), Var(0)), inner_cont3))
    prog3 = App(App(Var(0x0E), three_leaf), outer_cont3)
    payload3 = encode_term(prog3) + bytes([FF])
    print(f"  Full payload: {payload3.hex()}")
    
    out3 = query(payload3)
    print(f"  Raw output: {out3!r}")
    if FF in out3:
        result3 = parse_term(out3)
        print(f"  Parsed: {term_str(result3)}")
        try:
            tag, pay = decode_either(result3)
            print(f"  Decoded: {tag}")
            if tag == "Right":
                err_code = decode_byte_term(pay)
                print(f"    Error code: {err_code}")
            else:
                print(f"    SUCCESS! Payload: {term_str(pay)}")
        except Exception as e:
            print(f"  Decode error: {e}")
    
    # Test 4: Unwrap the Left from echo before passing to syscall 8
    print("\n[4] Building: echo(V251) → unwrap Left → syscall8")
    
    # To unwrap Left(x), we apply it to (λx.x) and (λx.x) or similar
    # Left x = λl.λr. l x
    # (Left x) id discard = id x = x
    #
    # Actually simpler: (Left x) (λa.a) anything = (λa.a) x = x
    #
    # So: ((echo_result) identity discard)
    # In de Bruijn, identity = λ.0 = Lam(Var(0))
    
    # Build: ((0x0E V251) (λer. ((0x08 ((er (λ.0)) anything)) QD)))
    # Under 1 lambda: syscall 8 at 9, er at 0
    # identity under that lambda: Lam(Var(0)) but inside the inner app, 
    # we need to be careful about scoping
    
    identity = Lam(Var(0))
    discard = Var(0)  # Just reuse er for discard since id(x) = x
    
    # ((er identity) discard) = (((Var(0) identity) discard)
    # Under 1 lambda for er: identity stays as Lam(Var(0))
    unwrap = App(App(Var(0), identity), discard)
    
    # Full program: ((0x0E V251) (λer. ((0x08 unwrap) QD_shifted1)))
    cont4 = Lam(App(App(Var(9), unwrap), qd_shifted1))
    prog4 = App(App(Var(0x0E), Var(251)), cont4)
    payload4 = encode_term(prog4) + bytes([FF])
    print(f"  Full payload: {payload4.hex()}")
    
    out4 = query(payload4)
    print(f"  Raw output: {out4!r}")
    if FF in out4:
        result4 = parse_term(out4)
        print(f"  Parsed: {term_str(result4)}")
        try:
            tag, pay = decode_either(result4)
            print(f"  Decoded: {tag}")
            if tag == "Right":
                err_code = decode_byte_term(pay)
                print(f"    Error code: {err_code}")
        except Exception as e:
            print(f"  Decode error: {e}")
    
    print("\n" + "=" * 60)
    print("Test complete")


if __name__ == "__main__":
    main()
