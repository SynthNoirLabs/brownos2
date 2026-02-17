#!/usr/bin/env python3
"""
What if the solution uses write (Var(2)) to output the flag directly?

The backdoor pair when applied to write might produce output!
pair = λs.λd. s A B
pair write nil = write A B = write(A, continuation=B)

Or: backdoor returns pair, we extract something and write it.
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


def test(desc: str, payload: bytes) -> None:
    try:
        resp = query(payload)
        if not resp:
            print(f"{desc}: (empty)")
        else:
            try:
                text = resp.decode('utf-8', 'replace')
                if text.isprintable() or '\n' in text:
                    print(f"{desc}: TEXT={text!r}")
                else:
                    print(f"{desc}: hex={resp.hex()[:80]}")
            except:
                print(f"{desc}: hex={resp.hex()[:80]}")
    except Exception as e:
        print(f"{desc}: ERROR - {e}")
    time.sleep(0.2)


def main():
    print("=" * 70)
    print("DIRECT WRITE OUTPUT TESTS")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    write = Var(2)
    quote = Var(4)
    echo = Var(0x0E)
    backdoor = Var(201)
    syscall8 = Var(8)
    
    print("\n=== Backdoor with write as continuation ===\n")
    
    cont_write_pair = Lam(
        App(
            App(Var(0), write),
            nil
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(cont_write_pair) + bytes([FD, FF])
    test("backdoor(nil) >>= λpair. (pair write) nil", payload)
    
    cont_apply_pair = Lam(
        App(
            App(Var(0), Lam(Lam(
                App(App(write, Var(1)), Var(0))
            ))),
            nil
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(cont_apply_pair) + bytes([FD, FF])
    test("backdoor(nil) >>= λpair. pair (λA.λB. write A B) nil", payload)
    
    print("\n=== Quote the backdoor pair and write it ===\n")
    
    quote_then_write = Lam(
        App(
            App(quote, Var(0)),
            Lam(
                App(
                    App(Var(0), Lam(
                        App(App(write, Var(0)), nil)
                    )),
                    nil
                )
            )
        )
    )
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(quote_then_write) + bytes([FD, FF])
    test("backdoor(nil) >>= quote >>= extract >>= write", payload)
    
    print("\n=== Echo + quote + write ===\n")
    
    for i in [0, 1, 8, 14, 201, 251, 252]:
        echo_quote_write = Lam(
            App(
                App(quote, Var(0)),
                Lam(
                    App(
                        App(Var(0), Lam(
                            App(App(write, Var(0)), nil)
                        )),
                        nil
                    )
                )
            )
        )
        payload = bytes([0x0E, i, FD]) + encode_term(echo_quote_write) + bytes([FD, FF])
        test(f"echo(Var({i})) >>= quote >>= extract >>= write", payload)
    
    print("\n=== Direct patterns with write ===\n")
    
    term = App(App(write, backdoor), nil)
    payload = encode_term(term) + bytes([FF])
    test("write(backdoor, nil)", payload)
    
    term = App(App(write, echo), nil)
    payload = encode_term(term) + bytes([FF])
    test("write(echo, nil)", payload)
    
    term = App(App(write, syscall8), nil)
    payload = encode_term(term) + bytes([FF])
    test("write(syscall8, nil)", payload)
    
    print("\n=== What does QD output for minimal terms? ===\n")
    
    payload = encode_term(nil) + QD + bytes([FD, FF])
    test("nil + QD", payload)
    
    payload = encode_term(Var(0)) + QD + bytes([FD, FF])
    test("Var(0) + QD", payload)
    
    payload = encode_term(backdoor) + QD + bytes([FD, FF])
    test("Var(201) + QD", payload)
    
    print("\n=== Minimal: just output via write with constants ===\n")
    

    
    print("\n=== Try syscall 8 with backdoor bypass, output via write ===\n")
    
    for dir_id in [0, 1]:
        def encode_int(n):
            expr = Var(0)
            remaining = n
            for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
                while remaining >= weight:
                    expr = App(Var(idx), expr)
                    remaining -= weight
            term = expr
            for _ in range(9):
                term = Lam(term)
            return term
        
        int_term = encode_int(dir_id)
        selector = Lam(Lam(App(App(syscall8, int_term), Var(0))))
        cont = Lam(
            App(
                App(Var(0), selector),
                Lam(
                    App(
                        App(Var(0), Lam(
                            App(
                                App(quote, Var(0)),
                                Lam(
                                    App(
                                        App(Var(0), Lam(
                                            App(App(write, Var(0)), nil)
                                        )),
                                        nil
                                    )
                                )
                            )
                        )),
                        nil
                    )
                )
            )
        )
        
        payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(cont) + bytes([FD, FF])
        test(f"backdoor bypass syscall8({dir_id}) >>= quote >>= write", payload)


if __name__ == "__main__":
    main()
