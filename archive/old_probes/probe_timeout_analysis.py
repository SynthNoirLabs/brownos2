#!/usr/bin/env python3
"""
Analyze the TIMEOUT behavior when using special terms.

Key observation: When we use Var(253-255) as continuation, we get TIMEOUT
instead of "Permission denied". This suggests syscall 8 is doing something
different in this case.

Let's:
1. Confirm which patterns cause timeout vs Permission denied
2. Try variations that might produce actual output
3. Check if there's any observable side effect
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
    raise TypeError


def query(payload: bytes, timeout_s: float = 3.0) -> tuple:
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
                    if FF in chunk:
                        break
                except socket.timeout:
                    break
            elapsed = time.time() - start
            return out, elapsed, "ok"
    except socket.timeout:
        return b"", time.time() - start, "timeout"
    except Exception as e:
        return str(e).encode(), time.time() - start, "error"


def classify(resp: bytes, elapsed: float, status: str) -> str:
    if status == "timeout":
        return f"TIMEOUT ({elapsed:.1f}s)"
    if not resp:
        return f"EMPTY ({elapsed:.1f}s)"
    if b"Permission" in resp:
        return f"PERM_DENIED ({elapsed:.1f}s)"
    if b"Encoding failed" in resp:
        return f"ENCODE_FAIL ({elapsed:.1f}s)"
    if b"Invalid term" in resp:
        return f"INVALID ({elapsed:.1f}s)"
    return f"DATA:{resp.hex()[:30]} ({elapsed:.1f}s)"


def test(desc: str, payload: bytes, timeout_s: float = 3.0) -> str:
    resp, elapsed, status = query(payload, timeout_s)
    result = classify(resp, elapsed, status)
    print(f"{desc}: {result}")
    return result


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
    print("TIMEOUT VS PERMISSION DENIED ANALYSIS")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
    
    print("\n=== Baseline: syscall 8 with QD continuation ===\n")
    
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    test("syscall8(nil) with QD", payload)
    
    print("\n=== Compare: Var(253) as argument vs as continuation ===\n")
    
    echo_var253_as_arg = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), encode_string("L\n")), nil))
                                ),
                                Lam(App(App(Var(6), encode_string("R\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER\n")), nil))
        )
    )
    
    print("echo(Var(251)) -> syscall8(Var(253)) -> print handler:")
    payload = bytes([0x0E, 251, FD]) + encode_term(echo_var253_as_arg) + bytes([FD, FF])
    test("  Var(253) as ARGUMENT", payload)
    
    echo_var253_as_cont = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Var(0)
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER\n")), nil))
        )
    )
    
    print("echo(Var(251)) -> ((syscall8 nil) Var(253)):")
    payload = bytes([0x0E, 251, FD]) + encode_term(echo_var253_as_cont) + bytes([FD, FF])
    test("  Var(253) as CONTINUATION", payload)
    
    print("\n=== What happens if we wrap the continuation call? ===\n")
    
    wrap_var253_cont = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(App(Var(1), Var(0)))
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER\n")), nil))
        )
    )
    
    print("echo(Var(251)) -> syscall8 nil (λresult. Var(253) result):")
    payload = bytes([0x0E, 251, FD]) + encode_term(wrap_var253_cont) + bytes([FD, FF])
    test("  Var(253) applied to result", payload)
    
    print("\n=== Check if syscall 8 makes state changes ===\n")
    
    int_46 = Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(
        App(Var(5), App(Var(4), App(Var(3), App(Var(2), App(Var(1), Var(0))))))
    )))))))))
    
    read_log_before = bytes([0x07]) + encode_term(int_46) + bytes([FD]) + QD + bytes([FD, FF])
    
    print("Read access.log before syscall8:")
    resp1, _, _ = query(read_log_before)
    print(f"  First bytes: {resp1[:50].hex() if resp1 else 'empty'}")
    
    time.sleep(0.5)
    
    print("Call syscall8 with timeout-inducing pattern:")
    payload = bytes([0x0E, 251, FD]) + encode_term(echo_var253_as_cont) + bytes([FD, FF])
    query(payload, timeout_s=2.0)
    
    time.sleep(0.5)
    
    print("Read access.log after syscall8:")
    resp2, _, _ = query(read_log_before)
    print(f"  First bytes: {resp2[:50].hex() if resp2 else 'empty'}")
    
    if resp1 and resp2 and resp1 != resp2:
        print("  LOG CHANGED!")
    else:
        print("  Log unchanged (or error)")
    
    print("\n=== Try different special vars as continuation ===\n")
    
    for base in [249, 250, 251, 252]:
        expected_var = base + 2
        
        test_cont = Lam(
            App(
                App(Var(0),
                    Lam(
                        App(
                            App(Var(10), nil),
                            Var(0)
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("ER\n")), nil))
            )
        )
        
        payload = bytes([0x0E, base, FD]) + encode_term(test_cont) + bytes([FD, FF])
        test(f"Var({expected_var}) as cont", payload)
        time.sleep(0.2)
    
    print("\n=== Try applying Var(253) to syscall 8's result ===\n")
    
    apply_to_result = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(Var(1), Var(0))
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER\n")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(apply_to_result) + bytes([FD, FF])
    test("syscall8 -> (λresult. Var(253) result)", payload)
    
    print("\n=== Try using write after Var(253) application ===\n")
    
    apply_then_write = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(10), nil),
                        Lam(
                            App(
                                App(Var(1), Var(0)),
                                Lam(App(App(Var(6), encode_string("AFTER\n")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER\n")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(apply_then_write) + bytes([FD, FF])
    test("Var(253) result -> then write", payload)


if __name__ == "__main__":
    main()
