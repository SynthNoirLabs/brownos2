#!/usr/bin/env python3
"""
Full chain: backdoor -> echo -> syscall8

Now with correct de Bruijn indices!

Depths:
  depth 0: backdoor call
  depth 1: bdResult (Either)
  depth 2: pair (from Left)
  depth 3: echoResult (Either)
  depth 4: echoPair (from Left)
  depth 5+: more nesting...

Syscall indices:
  echo = 14, at depth N: 14+N
  syscall8 = 8, at depth N: 8+N
  write = 2, at depth N: 2+N
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
    print("FULL CHAIN: BACKDOOR -> ECHO -> SYSCALL8")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print("\n=== Chain structure ===\n")
    print("""
backdoor nil (λbdResult.           -- depth 1
  bdResult 
    (λpair.                        -- depth 2: echo=16
      echo pair (λechoResult.      -- depth 3
        echoResult
          (λechoPair.              -- depth 4: syscall8=12, write=6
            syscall8 echoPair (λsc8Result.  -- depth 5
              sc8Result
                (λdata. write data nil)     -- depth 6: write=8
                (λerr. write "SC8-R" nil)   -- depth 6: write=8
            )
          )
          (λerr. write "ECHO-R" nil)  -- depth 4: write=6
      )
    )
    (λerr. write "BD-R" nil)       -- depth 2: write=4
)
""")
    
    full_chain = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(16), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
                                        App(
                                            App(Var(12), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(8), encode_string("SC8-LEFT!\n")), nil))
                                                    ),
                                                    Lam(App(App(Var(8), encode_string("SC8-RIGHT\n")), nil))
                                                )
                                            )
                                        )
                                    )
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
    
    print("Full chain result:")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(full_chain) + bytes([FD, FF])
    test("  backdoor -> echo -> syscall8", payload)
    
    print("\n=== Same chain, but use the ECHOED pair for syscall8 ===\n")
    print("""
After echo, the pair is shifted by +2.
So what was (λs.s A B) becomes (λs.s A' B') where A' and B' have
shifted internal indices.

This might be the key - the shifted pair might trigger something!
""")
    
    print("The above test already passes echoPair to syscall8.")
    print("Let's verify echo really shifts indices:\n")
    
    verify_shift = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(16), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
                                        App(
                                            App(Var(7), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(App(App(Var(8), Var(0)), nil))
                                                    ),
                                                    nil
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("Q-ECHO-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("Q-BD-R\n")), nil))
        )
    )
    
    print("backdoor -> echo(pair) -> quote(echoPair):")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(verify_shift) + bytes([FD, FF])
    test("  result (should show shifted pair bytes)", payload)
    
    print("\n=== Double echo chain ===\n")
    print("echo(echo(pair)) shifts indices twice!")
    
    double_echo_chain = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(16), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(
                                        App(
                                            App(Var(18), Var(0)),
                                            Lam(
                                                App(
                                                    App(Var(0),
                                                        Lam(
                                                            App(
                                                                App(Var(14), Var(0)),
                                                                Lam(
                                                                    App(
                                                                        App(Var(0),
                                                                            Lam(App(App(Var(10), encode_string("DBL-SC8-L\n")), nil))
                                                                        ),
                                                                        Lam(App(App(Var(10), encode_string("DBL-SC8-R\n")), nil))
                                                                    )
                                                                )
                                                            )
                                                        )
                                                    ),
                                                    Lam(App(App(Var(8), encode_string("E2-R\n")), nil))
                                                )
                                            )
                                        )
                                    )
                                ),
                                Lam(App(App(Var(6), encode_string("E1-R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD-R\n")), nil))
        )
    )
    
    print("backdoor -> echo -> echo -> syscall8:")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(double_echo_chain) + bytes([FD, FF])
    test("  result", payload)
    
    print("\n=== Use pair's A or B combinator as syscall8's continuation ===\n")
    
    use_pair_elements = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(
                            Var(0),
                            Lam(
                                Lam(
                                    App(
                                        App(Var(11), nil),
                                        Var(0)
                                    )
                                )
                            )
                        ),
                        Lam(
                            Lam(
                                App(
                                    App(Var(11), nil),
                                    Var(1)
                                )
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD-R\n")), nil))
        )
    )
    
    print("backdoor -> (pair (λA.λB. syscall8 nil B) (λA.λB. syscall8 nil A)):")
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(use_pair_elements) + bytes([FD, FF])
    test("  result", payload)


if __name__ == "__main__":
    main()
