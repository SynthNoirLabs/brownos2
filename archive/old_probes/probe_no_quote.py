#!/usr/bin/env python3
"""
Oracle insight: STOP USING QD (which calls quote).
Build continuations that use write directly without quoting.

Strategy:
1. For Right(code) results: call errorString(code) -> write the error string
2. For Left(bytes) results: write the bytes directly  
3. Never call syscall 0x04 (quote)

B combinator = λf.λg.λx. f(g x) = "3 leafs" (vars f, g, x each used once)
In de Bruijn: λ.λ.λ. (V2 (V1 V0))
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


def encode_term(term) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unknown term: {term}")


def query(payload: bytes, timeout_s: float = 8.0) -> bytes:
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
    else:
        try:
            text = resp.decode('utf-8', 'replace')
            result = f"OUTPUT: {repr(text[:80])}"
        except:
            result = f"hex: {resp.hex()[:80]}"
    print(f"{desc}: {result}")
    return resp


def main():
    print("=" * 70)
    print("NO-QUOTE CONTINUATION TESTS")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    write = Var(2)
    errorString = Var(1)
    syscall8 = Var(8)
    echo = Var(0x0E)
    backdoor = Var(0xC9)
    
    print("\n=== Build a continuation that handles Either without quote ===\n")
    print("either_handler = λresult. result (λbytes. write bytes nil) (λcode. errorString code (λstr. write str nil))")
    print()
    
    either_handler = Lam(
        App(
            App(
                Var(0),
                Lam(
                    App(App(write, Var(0)), nil)
                )
            ),
            Lam(
                App(
                    App(errorString, Var(0)),
                    Lam(
                        App(App(write, Var(0)), nil)
                    )
                )
            )
        )
    )
    
    print("Testing either_handler with known syscalls...\n")
    
    test_syscalls = [
        ("errorString(0)", Var(1), Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(Var(0))))))))))),
        ("syscall 0x2A", Var(0x2A), nil),
    ]
    
    for desc, syscall, arg in test_syscalls:
        payload = encode_term(syscall) + encode_term(arg) + bytes([FD]) + encode_term(either_handler) + bytes([FD, FF])
        test(desc, payload)
        time.sleep(0.2)
    
    print("\n=== Test syscall 8 with no-quote handler ===\n")
    
    payload = encode_term(syscall8) + encode_term(nil) + bytes([FD]) + encode_term(either_handler) + bytes([FD, FF])
    test("syscall8(nil) with either_handler", payload)
    
    print("\n=== Echo + syscall 8 with no-quote handler ===\n")
    
    for base in [251, 252, 250]:
        echo_extract_sc8 = Lam(
            App(
                App(
                    Var(0),
                    Lam(
                        App(
                            App(syscall8, Var(0)),
                            either_handler
                        )
                    )
                ),
                nil
            )
        )
        
        payload = bytes([0x0E, base, FD]) + encode_term(echo_extract_sc8) + bytes([FD, FF])
        test(f"echo(Var({base})) -> extract -> syscall8 -> either_handler", payload)
        time.sleep(0.3)
    
    print("\n=== Backdoor + echo + syscall 8 chain ===\n")
    
    backdoor_echo_sc8 = Lam(
        App(
            App(echo, Var(0)),
            Lam(
                App(
                    App(
                        Var(0),
                        Lam(
                            App(
                                App(syscall8, Var(0)),
                                either_handler
                            )
                        )
                    ),
                    nil
                )
            )
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_echo_sc8) + bytes([FD, FF])
    test("backdoor -> echo(pair) -> extract -> syscall8", payload)
    
    print("\n=== The B combinator (3 leafs): λfgx. f(gx) ===\n")
    
    B_comb = Lam(Lam(Lam(App(Var(2), App(Var(1), Var(0))))))
    print(f"B = {B_comb}")
    print(f"Encoded: {encode_term(B_comb).hex()}")
    
    payload = encode_term(syscall8) + encode_term(B_comb) + bytes([FD]) + encode_term(either_handler) + bytes([FD, FF])
    test("syscall8(B) with either_handler", payload)
    
    payload = encode_term(syscall8) + encode_term(nil) + bytes([FD]) + encode_term(B_comb) + bytes([FD, FF])
    test("syscall8(nil) with B as continuation", payload)
    
    print("\n=== Use B to compose echo and syscall8 ===\n")
    
    B_syscall8_echo = App(App(B_comb, syscall8), echo)
    print(f"B syscall8 echo = {B_syscall8_echo}")
    
    payload = encode_term(B_syscall8_echo) + encode_term(nil) + bytes([FD]) + encode_term(either_handler) + bytes([FD, FF])
    test("(B syscall8 echo) nil", payload)
    
    print("\n=== Try syscall 8 inside backdoor's execution context ===\n")
    
    sc8_in_backdoor_ctx = Lam(
        App(
            App(syscall8, Var(0)),
            Lam(
                App(
                    App(
                        Var(0),
                        Lam(App(App(write, Var(0)), nil))
                    ),
                    Lam(
                        App(
                            App(errorString, Var(0)),
                            Lam(App(App(write, Var(0)), nil))
                        )
                    )
                )
            )
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(sc8_in_backdoor_ctx) + bytes([FD, FF])
    test("backdoor(nil) then syscall8(pair) in same ctx", payload)
    
    print("\n=== Minimal 3-leaf terms with syscall 8 ===\n")
    
    three_leaf_patterns = [
        ("λ.λ.λ.(V2 (V1 V0))", Lam(Lam(Lam(App(Var(2), App(Var(1), Var(0))))))),
        ("λ.λ.λ.(V0 (V1 V2))", Lam(Lam(Lam(App(Var(0), App(Var(1), Var(2))))))),
        ("λ.λ.λ.((V2 V1) V0)", Lam(Lam(Lam(App(App(Var(2), Var(1)), Var(0)))))),
        ("λ.λ.λ.((V0 V1) V2)", Lam(Lam(Lam(App(App(Var(0), Var(1)), Var(2)))))),
    ]
    
    for desc, term in three_leaf_patterns:
        payload = encode_term(syscall8) + encode_term(term) + bytes([FD]) + encode_term(either_handler) + bytes([FD, FF])
        test(f"syscall8({desc})", payload)
        time.sleep(0.2)
    
    print("\n=== Use echo output as THE CONTINUATION (not argument) ===\n")
    
    for base in [251, 252]:
        use_echo_as_cont = Lam(
            App(
                App(
                    Var(0),
                    Lam(
                        App(
                            App(syscall8, nil),
                            Var(0)
                        )
                    )
                ),
                nil
            )
        )
        
        payload = bytes([0x0E, base, FD]) + encode_term(use_echo_as_cont) + bytes([FD, FF])
        test(f"echo(Var({base})) -> use as syscall8's continuation", payload)
        time.sleep(0.3)


if __name__ == "__main__":
    main()
