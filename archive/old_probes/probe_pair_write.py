#!/usr/bin/env python3
"""
What if applying the backdoor pair to write produces the flag?

pair write nil = write A B = write(A, continuation=B)

A and B aren't byte lists, but maybe the error message IS the flag?
Or maybe there's special handling?
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
        return f"ERROR: {e}".encode()


def test(desc: str, payload: bytes) -> None:
    resp = query(payload)
    if not resp:
        print(f"{desc}: (empty)")
    else:
        try:
            text = resp.decode('utf-8', 'replace')
            if len(text) < 200:
                print(f"{desc}: {text!r}")
            else:
                print(f"{desc}: len={len(resp)} hex={resp.hex()[:80]}")
        except:
            print(f"{desc}: hex={resp.hex()[:80]}")
    time.sleep(0.2)


def main():
    print("=" * 70)
    print("PAIR + WRITE COMBINATIONS")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    write = Var(2)
    quote = Var(4)
    
    print("\n=== backdoor(nil) >>= λpair. (pair write) nil ===\n")
    
    cont = Lam(App(App(Var(0), write), nil))
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(cont) + bytes([FD, FF])
    test("backdoor >> pair write nil", payload)
    
    print("\n=== backdoor(nil) >>= λpair. pair (λA.λB. write A B) nil ===\n")
    
    cont = Lam(App(App(Var(0), Lam(Lam(App(App(write, Var(1)), Var(0))))), nil))
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(cont) + bytes([FD, FF])
    test("backdoor >> pair selector(write A B) nil", payload)
    
    print("\n=== backdoor(nil) >>= λpair. pair quote nil >>= write ===\n")
    
    quote_then_write = Lam(
        App(
            App(Var(0), Lam(Lam(App(App(quote, Var(1)), Lam(
                App(App(Var(0), Lam(App(App(write, Var(0)), nil))), nil)
            ))))),
            nil
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(quote_then_write) + bytes([FD, FF])
    test("backdoor >> pair (λAB. quote A >>= write) nil", payload)
    
    print("\n=== Try errstr with various codes ===\n")
    
    for code in range(8):
        def encode_int(n):
            expr = Var(0)
            for idx, weight in ((1, 1), (2, 2), (3, 4), (4, 8)):
                if n & weight:
                    expr = App(Var(idx), expr)
            term = expr
            for _ in range(9):
                term = Lam(term)
            return term
        
        int_term = encode_int(code)
        payload = bytes([0x01]) + encode_term(int_term) + bytes([FD]) + QD + bytes([FD, FF])
        resp = query(payload)
        if resp and FF in resp:
            from solve_brownos_answer import parse_term, decode_either, decode_bytes_list
            try:
                term = parse_term(resp)
                tag, p = decode_either(term)
                if tag == "Left":
                    text = decode_bytes_list(p).decode('utf-8', 'replace')
                    print(f"errstr({code}): {text!r}")
            except:
                print(f"errstr({code}): {resp.hex()[:60]}")
        time.sleep(0.1)
    
    print("\n=== Try combinations that might reveal hidden messages ===\n")
    
    A = Lam(Lam(App(Var(0), Var(0))))
    B = Lam(Lam(App(Var(1), Var(0))))
    
    payload = bytes([0x01]) + encode_term(A) + bytes([FD]) + QD + bytes([FD, FF])
    test("errstr(A)", payload)
    
    payload = bytes([0x01]) + encode_term(B) + bytes([FD]) + QD + bytes([FD, FF])
    test("errstr(B)", payload)
    
    print("\n=== What does quote return for A and B? ===\n")
    
    payload = bytes([0x04]) + encode_term(A) + bytes([FD]) + QD + bytes([FD, FF])
    test("quote(A)", payload)
    
    payload = bytes([0x04]) + encode_term(B) + bytes([FD]) + QD + bytes([FD, FF])
    test("quote(B)", payload)


if __name__ == "__main__":
    main()
