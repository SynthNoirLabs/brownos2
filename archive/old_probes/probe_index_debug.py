#!/usr/bin/env python3
"""
Debug de Bruijn indices for nested syscalls.

At top level:
  Var(1) = errorString
  Var(2) = write
  Var(4) = quote
  Var(8) = syscall8
  Var(14) = echo (0x0E)
  Var(201) = backdoor (0xC9)

Inside N lambdas, all these shift by +N.
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
            result = f"OUTPUT: {repr(text[:100])}"
        except:
            result = f"hex: {resp.hex()[:100]}"
    print(f"{desc}: {result}")
    return resp


def encode_string(s: str):
    nil = Lam(Lam(Var(0)))
    
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


def main():
    print("=" * 70)
    print("DE BRUIJN INDEX DEBUG")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print("\n=== Reference: syscall indices at different depths ===\n")
    print("depth=0: echo=14, write=2")
    print("depth=1: echo=15, write=3") 
    print("depth=2: echo=16, write=4")
    print("depth=3: echo=17, write=5")
    
    print("\n=== Test echo at depth 0 ===\n")
    
    payload = bytes([0x0E]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    test("echo(nil) at depth 0", payload)
    
    print("\n=== Test calling echo from inside a lambda ===\n")
    
    echo_at_depth_1 = Lam(
        App(
            App(Var(15), nil),
            Lam(
                App(
                    App(Var(0),
                        Lam(App(App(Var(5), encode_string("LEFT\n")), nil))
                    ),
                    Lam(App(App(Var(5), encode_string("RIGHT\n")), nil))
                )
            )
        )
    )
    
    payload = encode_term(echo_at_depth_1) + encode_term(nil) + bytes([FD, FF])
    test("(λ_. echo nil ...) nil", payload)
    
    print("\n=== Backdoor chain with explicit depth tracking ===\n")
    print("""
Structure:
  backdoor(nil) cont1  -- depth 0 for backdoor call
  
  cont1 = λbdResult.    -- depth 1
    bdResult            -- Either from backdoor
      (λpair.           -- depth 2, leftHandler
        echo(pair)      -- echo = Var(14+2) = Var(16)
          (λechoResult. -- depth 3
            ...
          )
      )
      (λerr. ...)       -- depth 2, rightHandler
""")
    
    backdoor_chain = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(16), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), encode_string("ECHO-LEFT\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("ECHO-RIGHT\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD-RIGHT\n")), nil))
        )
    )
    
    print("backdoor -> echo(pair) with echo=Var(16) at depth 2:")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(backdoor_chain) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Try different echo indices ===\n")
    
    for echo_idx in [15, 16, 17]:
        test_chain = Lam(
            App(
                App(Var(0),
                    Lam(
                        App(
                            App(Var(echo_idx), Var(0)),
                            Lam(
                                App(
                                    App(Var(0),
                                        Lam(App(App(Var(6), encode_string(f"L{echo_idx}\n")), nil))
                                    ),
                                    Lam(App(App(Var(6), encode_string(f"R{echo_idx}\n")), nil))
                                )
                            )
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("BD-R\n")), nil))
            )
        )
        
        payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(test_chain) + bytes([FD, FF])
        test(f"  echo=Var({echo_idx})", payload)
        time.sleep(0.2)
    
    print("\n=== Check if pair is being passed correctly ===\n")
    
    print_pair = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(5), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), Var(0)), nil))
                                ),
                                nil
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD-RIGHT\n")), nil))
        )
    )
    
    print("backdoor -> extract pair -> quote(pair) -> write:")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(print_pair) + bytes([FD, FF])
    test("  result (shows pair bytes)", payload)


if __name__ == "__main__":
    main()
