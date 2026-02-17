#!/usr/bin/env python3
"""
The pair mechanism reaches syscall 8 differently!

pair syscall8 = syscall8 A B = (syscall8 A) B

A is the argument, B is the continuation.
We got Right(2) = Invalid argument.

What if we construct different pairs that feed syscall8 the right argument?
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
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


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported: {type(term)}")


def query(payload: bytes, timeout_s: float = 5.0) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
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


def test(desc: str, payload: bytes) -> None:
    try:
        resp = query(payload)
        resp_str = resp.hex() if resp else "(empty)"
        if b"Encoding failed" in resp:
            resp_str = "Encoding failed!"
        elif b"Invalid term" in resp:
            resp_str = "Invalid term!"
        elif b"Term too big" in resp:
            resp_str = "Term too big!"
        else:
            from solve_brownos_answer import parse_term, decode_either, decode_byte_term
            try:
                term = parse_term(resp)
                tag, p = decode_either(term)
                try:
                    code = decode_byte_term(p)
                    resp_str = f"{tag}({code}) - {['OK', 'NoSyscall', 'InvalidArg', 'UnknownId', 'NotDir', 'NotFile', 'PermDenied'][code]}"
                except:
                    resp_str = f"{tag}(...) raw={resp.hex()[:50]}"
            except:
                resp_str = resp.hex()[:60]
        print(f"{desc:65} -> {resp_str}")
    except Exception as e:
        print(f"{desc:65} -> ERROR: {e}")
    time.sleep(0.15)


def main():
    print("=== Pair mechanism with syscall 8 ===\n")
    
    nil = Lam(Lam(Var(0)))
    I = Lam(Var(0))
    K = Lam(Lam(Var(1)))
    syscall8 = Var(8)
    
    def make_pair(fst, snd):
        return Lam(App(App(Var(0), fst), snd))
    
    print("Construct custom pairs and apply to syscall8:\n")
    
    pairs = [
        ("pair(nil, nil) syscall8", make_pair(nil, nil)),
        ("pair(nil, QD_term) syscall8", make_pair(nil, Lam(Lam(Var(0))))),
        ("pair(I, I) syscall8", make_pair(I, I)),
        ("pair(K, K) syscall8", make_pair(K, K)),
        
        ("pair(Var0, nil) syscall8", make_pair(Var(0), nil)),
        ("pair(Var1, nil) syscall8", make_pair(Var(1), nil)),
        ("pair(Var8, nil) syscall8", make_pair(Var(8), nil)),
        
        ("pair(nil, I) syscall8", make_pair(nil, I)),
        ("pair(nil, K) syscall8", make_pair(nil, K)),
    ]
    
    for desc, pair in pairs:
        payload = encode_term(App(pair, syscall8)) + QD + bytes([FD, FF])
        test(desc, payload)
    
    print("\n=== Use backdoor pair but wrap syscall8 ===\n")
    
    wrap_cont = Lam(
        App(
            App(Var(0), Lam(App(syscall8, Var(0)))),
            Lam(Lam(Var(0)))
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(wrap_cont) + bytes([FD]) + QD + bytes([FD, FF])
    test("backdoor >>= \\p. p (\\x.syscall8 x) nil", payload)
    
    print("\n=== Apply backdoor pair to (syscall8 arg) for various args ===\n")
    
    args = [nil, I, K, Var(0), Var(1), Var(8), Var(201)]
    for arg in args:
        wrap = Lam(App(Var(0), App(syscall8, arg)))
        payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(wrap) + bytes([FD]) + QD + bytes([FD, FF])
        test(f"backdoor >>= \\p. p (syscall8 {arg})", payload)
    
    print("\n=== Chain: backdoor pair + echo ===\n")
    
    echo = Var(0x0E)
    wrap_echo = Lam(App(Var(0), echo))
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(wrap_echo) + bytes([FD]) + QD + bytes([FD, FF])
    test("backdoor >>= \\p. p echo", payload)
    
    wrap_echo_sc8 = Lam(
        App(
            App(Var(0), echo),
            Lam(
                App(
                    Var(0),
                    syscall8
                )
            )
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(wrap_echo_sc8) + bytes([FD]) + QD + bytes([FD, FF])
    test("backdoor >>= \\p. p echo (\\r. r syscall8)", payload)


if __name__ == "__main__":
    main()
