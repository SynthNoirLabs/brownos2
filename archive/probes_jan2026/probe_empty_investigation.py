#!/usr/bin/env python3
"""
CRITICAL FINDING: ((syscall8 nil) A) and ((syscall8 nil) B) give EMPTY responses.
This is DIFFERENT from "Permission denied" which we normally get.

Empty might mean:
1. VM diverges (infinite loop)
2. Success with no output
3. Write syscall was triggered but wrote nothing
4. Something else entirely

Let's investigate what these combinators actually DO when used as continuations.
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


def encode_term(term) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unknown term type: {type(term)}")


def query_timed(payload: bytes, timeout_s: float = 5.0):
    start = time.time()
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
            elapsed = time.time() - start
            return out, elapsed, None
    except Exception as e:
        elapsed = time.time() - start
        return b"", elapsed, str(e)


nil = Lam(Lam(Var(0)))
identity = Lam(Var(0))


def encode_string(s: str):
    def encode_byte(n):
        expr = Var(0)
        for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
            if n & weight:
                expr = App(Var(idx), expr)
        term = expr
        for _ in range(9):
            term = Lam(term)
        return term
    def cons(h, t):
        return Lam(Lam(App(App(Var(1), h), t)))
    cur = nil
    for b in reversed(s.encode()):
        cur = cons(encode_byte(b), cur)
    return cur


A = Lam(Lam(App(Var(0), Var(0))))
B = Lam(Lam(App(Var(1), Var(0))))


def test_timing_comparison():
    print("=" * 70)
    print("TIMING COMPARISON: Empty vs Normal responses")
    print("=" * 70)
    
    tests = [
        ("Normal: ((syscall42 nil) QD)", bytes([0x2A]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])),
        ("Normal: ((syscall8 nil) QD)", bytes([0x08]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])),
        ("Empty: ((syscall8 nil) A)", bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(A) + bytes([FD, FF])),
        ("Empty: ((syscall8 nil) B)", bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(B) + bytes([FD, FF])),
        ("Empty: ((syscall8 nil) identity)", bytes([0x08]) + encode_term(nil) + bytes([FD]) + encode_term(identity) + bytes([FD, FF])),
    ]
    
    for name, payload in tests:
        resp, elapsed, err = query_timed(payload, timeout_s=8)
        if err:
            print(f"  {name}: ERROR {err} ({elapsed:.2f}s)")
        else:
            status = "EMPTY" if not resp else f"{len(resp)} bytes"
            print(f"  {name}: {status} ({elapsed:.2f}s)")
            if resp and len(resp) < 50:
                print(f"    Raw: {resp.hex()}")
        time.sleep(0.3)


def test_what_A_does():
    print("\n" + "=" * 70)
    print("WHAT DOES A = λab.bb DO AS A CONTINUATION?")
    print("=" * 70)
    
    print("\nA = λa.λb.(b b)")
    print("When syscall returns Right(6), it becomes:")
    print("  (A Right(6)) = λb.(b b)")
    print("  This is a self-application waiting for an argument!")
    print("\nBut CPS should call: (A result)")
    print("  = (λa.λb.(bb) result)")
    print("  = λb.(bb)")
    print("  = Church omega precursor - needs another arg!")


def test_what_B_does():
    print("\n" + "=" * 70)
    print("WHAT DOES B = λab.ab DO AS A CONTINUATION?")
    print("=" * 70)
    
    print("\nB = λa.λb.(a b)")
    print("When syscall returns Right(6), it becomes:")
    print("  (B Right(6)) = λb.(Right(6) b)")
    print("  This applies Right(6) to whatever b is!")
    print("\nIf Right(6) = λl.λr.(r 6), then:")
    print("  (Right(6) b) = λr.(r 6)")
    print("  We eliminated the Left handler and kept Right!")


def test_chain_with_write():
    print("\n" + "=" * 70)
    print("CHAIN: syscall8 with A/B then write")
    print("=" * 70)
    
    chain_A = App(
        App(Var(8), nil),
        Lam(
            App(
                App(Var(0), identity),
                Lam(
                    App(App(Var(4), encode_string("WORKED")), nil)
                )
            )
        )
    )
    
    payload = encode_term(chain_A) + bytes([FF])
    resp, elapsed, err = query_timed(payload, timeout_s=5)
    print(f"  Chain with write after A: {resp!r} ({elapsed:.2f}s)")


def test_syscall8_all_args_with_A():
    print("\n" + "=" * 70)
    print("SYSCALL 8 WITH VARIOUS ARGS, A AS CONTINUATION")
    print("=" * 70)
    
    args_to_test = [
        ("nil", nil),
        ("identity", identity),
        ("A itself", A),
        ("B", B),
        ("0", Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(Var(0))))))))))),
    ]
    
    for name, arg in args_to_test:
        payload = bytes([0x08]) + encode_term(arg) + bytes([FD]) + encode_term(A) + bytes([FD, FF])
        resp, elapsed, err = query_timed(payload, timeout_s=5)
        status = "EMPTY" if not resp else f"{resp.hex()[:40]}..."
        print(f"  ((syscall8 {name}) A): {status} ({elapsed:.2f}s)")
        time.sleep(0.3)


def test_backdoor_result_as_arg_with_A():
    print("\n" + "=" * 70)
    print("BACKDOOR RESULT AS ARG TO SYSCALL8, A AS CONTINUATION")
    print("=" * 70)
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(9), Var(0)),
                        A
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD")), nil))
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(test_term) + bytes([FD, FF])
    resp, elapsed, err = query_timed(payload, timeout_s=5)
    print(f"  ((syscall8 backdoor_result) A): {'EMPTY' if not resp else resp.hex()[:50]} ({elapsed:.2f}s)")


def test_echo_then_syscall8_with_A():
    print("\n" + "=" * 70)
    print("ECHO(251) -> VAR(253) -> SYSCALL8 WITH A")
    print("=" * 70)
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(9), Var(0)),
                        A
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp, elapsed, err = query_timed(payload, timeout_s=5)
    print(f"  ((syscall8 Var(253)) A): {'EMPTY' if not resp else resp.hex()[:50]} ({elapsed:.2f}s)")


def test_combined_approach():
    print("\n" + "=" * 70)
    print("COMBINED: backdoor -> extract A/B -> use with syscall8")
    print("=" * 70)
    
    backdoor_handler = Lam(
        App(
            App(Var(0), identity),
            Lam(
                App(App(Var(4), encode_string("PR")), nil)
            )
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_handler) + bytes([FD, FF])
    resp, elapsed, err = query_timed(payload, timeout_s=5)
    print(f"  (backdoor(nil) identity): {resp!r} ({elapsed:.2f}s)")


def test_omega_divergence():
    print("\n" + "=" * 70)
    print("OMEGA (Ω) DIVERGENCE TEST")
    print("=" * 70)
    
    omega = App(Lam(App(Var(0), Var(0))), Lam(App(Var(0), Var(0))))
    
    payload = encode_term(omega) + bytes([FF])
    resp, elapsed, err = query_timed(payload, timeout_s=3)
    print(f"  Omega: {'EMPTY' if not resp else resp.hex()[:30]} ({elapsed:.2f}s)")
    print(f"  (Timeout suggests divergence)")


def main():
    test_timing_comparison()
    time.sleep(0.5)
    
    test_what_A_does()
    test_what_B_does()
    
    test_chain_with_write()
    time.sleep(0.5)
    
    test_syscall8_all_args_with_A()
    time.sleep(0.5)
    
    test_backdoor_result_as_arg_with_A()
    time.sleep(0.5)
    
    test_echo_then_syscall8_with_A()
    time.sleep(0.5)
    
    test_combined_approach()
    time.sleep(0.5)
    
    test_omega_divergence()
    
    print("\n" + "=" * 70)
    print("INVESTIGATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
