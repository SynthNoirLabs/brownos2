#!/usr/bin/env python3
"""
ALTERNATIVE HYPOTHESIS: The answer might NOT come from syscall 8!

"3 leafs" might mean:
1. The answer is obtainable with a 3-Var term
2. The answer is somewhere in the filesystem we already have
3. The answer is in the backdoor output
4. The answer involves combining A and B in a specific way

Let's explore paths that DON'T involve syscall 8.
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


nil = Lam(Lam(Var(0)))
identity = Lam(Var(0))
A = Lam(Lam(App(Var(0), Var(0))))
B = Lam(Lam(App(Var(1), Var(0))))


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


def encode_int(n: int):
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


def test_backdoor_combinators():
    print("=" * 70)
    print("EXPLORE BACKDOOR COMBINATORS A AND B")
    print("=" * 70)
    
    print("\nA = λab.bb (self-application)")
    print("B = λab.ab (normal apply)")
    print("\nLet's see what (A B), (B A), (A A), (B B) produce:")
    
    combinations = [
        ("(A B)", App(A, B)),
        ("(B A)", App(B, A)),
        ("(A A)", App(A, A)),
        ("(B B)", App(B, B)),
        ("((A B) nil)", App(App(A, B), nil)),
        ("((B A) nil)", App(App(B, A), nil)),
        ("((A B) identity)", App(App(A, B), identity)),
        ("((B A) identity)", App(App(B, A), identity)),
    ]
    
    for name, term in combinations:
        payload = bytes([0x04]) + encode_term(term) + bytes([FD]) + QD + bytes([FD, FF])
        resp = query(payload, timeout_s=3)
        print(f"  quote({name}): {resp.hex()[:60] if resp else 'EMPTY'}")
        time.sleep(0.2)


def test_minimal_3var_syscalls():
    print("\n" + "=" * 70)
    print("MINIMAL 3-VAR SYSCALL TERMS")
    print("=" * 70)
    
    print("\n'3 leafs' might mean the smallest working syscall:")
    
    terms_3_var = [
        ("((0x2A nil) QD)", bytes([0x2A]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])),
        ("((0xC9 nil) QD)", bytes([0xC9]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])),
        ("((0x0E 251) QD)", bytes([0x0E, 251, FD]) + QD + bytes([FD, FF])),
    ]
    
    for name, payload in terms_3_var:
        resp = query(payload, timeout_s=3)
        print(f"  {name}: {resp[:50]!r}")
        time.sleep(0.2)


def test_write_special_sequences():
    print("\n" + "=" * 70)
    print("WRITE SPECIAL BYTE SEQUENCES")
    print("=" * 70)
    
    print("\nWhat if the flag is obtained by WRITING specific bytes?")
    
    def make_byte_list(bs):
        cur = nil
        for b in reversed(bs):
            cur = Lam(Lam(App(App(Var(1), encode_int(b)), cur)))
        return cur
    
    sequences = [
        ("FD FE FF", [0xFD, 0xFE, 0xFF]),
        ("00 FE FE", [0x00, 0xFE, 0xFE]),
        ("C9 00 FE FE", [0xC9, 0x00, 0xFE, 0xFE]),
        ("Just 0xFF", [0xFF]),
        ("0xFD 0xFD 0xFD", [0xFD, 0xFD, 0xFD]),
    ]
    
    for name, bs in sequences:
        byte_list = make_byte_list(bs)
        payload = bytes([0x02]) + encode_term(byte_list) + bytes([FD]) + QD + bytes([FD, FF])
        resp = query(payload, timeout_s=3)
        print(f"  write({name}): {resp!r}")
        time.sleep(0.2)


def test_read_hidden_files():
    print("\n" + "=" * 70)
    print("CHECK FOR HIDDEN FILES")
    print("=" * 70)
    
    print("\nMaybe there are file IDs we haven't checked?")
    
    handler = Lam(
        App(
            App(Var(0),
                Lam(App(App(Var(4), Var(0)), nil))),
            Lam(App(App(Var(4), encode_string("NF")), nil))
        )
    )
    
    file_ids = [100, 128, 200, 255, 257, 258, 300, 500, 512, 1000]
    
    for fid in file_ids:
        payload = bytes([0x07]) + encode_term(encode_int(fid)) + bytes([FD]) + encode_term(handler) + bytes([FD, FF])
        resp = query(payload, timeout_s=2)
        if resp and b'NF' not in resp:
            print(f"  readfile(id {fid}): {resp[:50]!r}")
        time.sleep(0.1)
    
    print("\n  (Only showing files that exist)")


def test_quote_backdoor_pair():
    print("\n" + "=" * 70)
    print("QUOTE THE BACKDOOR PAIR STRUCTURE")
    print("=" * 70)
    
    print("\nLet's see exactly what the backdoor returns:")
    
    handler = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(5), Var(0)),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), Var(0)), nil))),
                                Lam(App(App(Var(6), encode_string("QF")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD")), nil))
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(handler) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  quote(backdoor result): {resp.hex() if resp else 'EMPTY'}")
    
    if resp and resp != b'QF' and resp != b'BD':
        print(f"  Parsed length: {len(resp)} bytes")
        for i, b in enumerate(resp[:30]):
            print(f"    [{i}] 0x{b:02X} = {b}")


def test_extract_backdoor_components():
    print("\n" + "=" * 70)
    print("EXTRACT AND QUOTE BACKDOOR COMPONENTS")
    print("=" * 70)
    
    true_selector = Lam(Lam(Var(1)))
    false_selector = Lam(Lam(Var(0)))
    
    for name, selector in [("first (A)", true_selector), ("second (B)", false_selector)]:
        handler = Lam(
            App(
                App(Var(0),
                    Lam(
                        App(
                            App(Var(5), App(Var(0), selector)),
                            Lam(
                                App(
                                    App(Var(0),
                                        Lam(App(App(Var(6), Var(0)), nil))),
                                    Lam(App(App(Var(6), encode_string("QF")), nil))
                                )
                            )
                        )
                    )
                ),
                Lam(App(App(Var(4), encode_string("BD")), nil))
            )
        )
        
        payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(handler) + bytes([FD, FF])
        resp = query(payload, timeout_s=5)
        print(f"  quote({name}): {resp.hex() if resp else 'EMPTY'}")
        time.sleep(0.3)


def test_Y_combinator_with_backdoor():
    print("\n" + "=" * 70)
    print("Y COMBINATOR WITH BACKDOOR")
    print("=" * 70)
    
    print("\nA = λab.bb can be used to build omega/Y...")
    print("What if (A A) or similar produces something useful?")
    
    handler = Lam(
        App(
            App(Var(0),
                Lam(
                    App(
                        App(Var(5), App(App(Var(0), true_selector := Lam(Lam(Var(1)))), App(Var(0), true_selector))),
                        Lam(
                            App(
                                App(Var(0),
                                    Lam(App(App(Var(6), Var(0)), nil))),
                                Lam(App(App(Var(6), encode_string("QF")), nil))
                            )
                        )
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("BD")), nil))
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(handler) + bytes([FD, FF])
    resp = query(payload, timeout_s=5)
    print(f"  quote((A A)): {resp.hex()[:60] if resp else 'EMPTY'}")


def test_direct_answer_candidates():
    print("\n" + "=" * 70)
    print("POTENTIAL ANSWER CANDIDATES")
    print("=" * 70)
    
    print("\nBased on all we know, the answer might be:")
    candidates = [
        "A",
        "B", 
        "AB",
        "BA",
        "λab.bb",
        "λab.ab",
        "0x01",
        "01",
        "fd",
        "FE",
        "Var253",
        "echo",
        "key",
        "3leaf",
        "00FEFE",
        "omega",
        "backdoor201",
        "syscall201",
    ]
    
    print("  Candidates to try on WeChall:")
    for c in candidates:
        print(f"    - {c}")


def main():
    test_backdoor_combinators()
    time.sleep(0.3)
    
    test_minimal_3var_syscalls()
    time.sleep(0.3)
    
    test_write_special_sequences()
    time.sleep(0.3)
    
    test_read_hidden_files()
    time.sleep(0.3)
    
    test_quote_backdoor_pair()
    time.sleep(0.3)
    
    test_extract_backdoor_components()
    time.sleep(0.3)
    
    test_Y_combinator_with_backdoor()
    time.sleep(0.3)
    
    test_direct_answer_candidates()
    
    print("\n" + "=" * 70)
    print("ALTERNATIVE PATHS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
