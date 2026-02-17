#!/usr/bin/env python3
"""
Generate potential answer candidates based on what we've discovered.

The WeChall answer might be:
1. Something hidden in the filesystem we haven't found
2. A decoded value from syscall 8 (if we can make it work)
3. A combination of things we already know
4. The result of correctly using the backdoor
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


def parse_term(data: bytes) -> object:
    stack = []
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
    return stack[0] if len(stack) == 1 else None


def decode_either(term):
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        return None, None
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var):
        if body.f.i == 1:
            return "Left", body.x
        elif body.f.i == 0:
            return "Right", body.x
    return None, None


def strip_lams(term, n):
    cur = term
    for _ in range(n):
        if not isinstance(cur, Lam):
            return None
        cur = cur.body
    return cur


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def eval_bitset(expr):
    if isinstance(expr, Var):
        return WEIGHTS.get(expr.i, 0)
    if isinstance(expr, App) and isinstance(expr.f, Var):
        return WEIGHTS.get(expr.f.i, 0) + eval_bitset(expr.x)
    return 0


def decode_byte_term(term):
    body = strip_lams(term, 9)
    if body is None:
        return None
    return eval_bitset(body)


def uncons_scott_list(term):
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        return None
    body = term.body.body
    if isinstance(body, Var) and body.i == 0:
        return None
    if isinstance(body, App) and isinstance(body.f, App):
        if isinstance(body.f.f, Var) and body.f.f.i == 1:
            return body.f.x, body.x
    return None


def decode_bytes_list(term):
    out = []
    cur = term
    for _ in range(100000):
        res = uncons_scott_list(cur)
        if res is None:
            return bytes(out)
        head, cur = res
        b = decode_byte_term(head)
        if b is None:
            break
        out.append(b)
    return bytes(out)


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


def call_syscall(num, arg):
    payload = bytes([num]) + encode_term(arg) + bytes([FD]) + QD + bytes([FD, FF])
    return query(payload)


def main():
    print("=" * 70)
    print("TESTING ANSWER CANDIDATES")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    
    print("\n=== Call backdoor and examine pair more carefully ===\n")
    
    resp = call_syscall(0xC9, nil)
    print(f"Backdoor raw response: {resp.hex()[:100]}")
    
    term = parse_term(resp)
    if term:
        tag, payload = decode_either(term)
        print(f"Tag: {tag}")
        if tag == "Left":
            print(f"Payload type: {type(payload).__name__}")
            if isinstance(payload, Lam):
                print("Payload is a lambda (the pair)")
                body = payload.body
                print(f"  Body type: {type(body).__name__}")
                
                if isinstance(body, App) and isinstance(body.f, App):
                    inner = body.f
                    print(f"  Has App(App(...)) structure")
                    if isinstance(inner.f, Var):
                        print(f"  Selector: Var({inner.f.i})")
                    A = inner.x
                    B = body.x
                    print(f"  A (first element): {type(A).__name__}")
                    print(f"  B (second element): {type(B).__name__}")
                    
                    print("\n  Trying to decode A and B as terms...")
                    if isinstance(A, Lam) and isinstance(A.body, Lam):
                        inner_A = A.body.body
                        print(f"    A = λλ.{inner_A}")
                    if isinstance(B, Lam) and isinstance(B.body, Lam):
                        inner_B = B.body.body
                        print(f"    B = λλ.{inner_B}")
    
    print("\n=== Try different syscall 8 argument patterns ===\n")
    
    backdoor_resp = call_syscall(0xC9, nil)
    backdoor_term = parse_term(backdoor_resp)
    
    if backdoor_term:
        _, pair = decode_either(backdoor_term)
        
        if pair and isinstance(pair, Lam):
            test_cases = [
                ("syscall8(pair)", pair),
            ]
            
            for desc, arg in test_cases:
                payload = bytes([0x08]) + encode_term(arg) + bytes([FD]) + QD + bytes([FD, FF])
                resp = query(payload)
                if resp:
                    print(f"{desc}: {resp.hex()[:60]}")
                else:
                    print(f"{desc}: (empty)")
                time.sleep(0.2)
    
    print("\n=== Check file IDs we might have missed ===\n")
    
    interesting_ids = [42, 201, 8, 14, 0xC9, 255, 254, 253]
    
    for fid in interesting_ids:
        arg = encode_int(fid)
        
        name_resp = call_syscall(0x06, arg)
        name_term = parse_term(name_resp)
        if name_term:
            tag, payload = decode_either(name_term)
            if tag == "Left":
                name = decode_bytes_list(payload)
                print(f"name({fid}): {name}")
            else:
                print(f"name({fid}): Right (not found)")
        
        time.sleep(0.15)
    
    print("\n=== Check for hidden content in specific files ===\n")
    
    file_ids_to_check = [
        (11, "/etc/passwd"),
        (65, ".history"),
        (88, "dloser mail"),
        (46, "access.log"),
    ]
    
    for fid, desc in file_ids_to_check:
        arg = encode_int(fid)
        resp = call_syscall(0x07, arg)
        term = parse_term(resp)
        if term:
            tag, payload = decode_either(term)
            if tag == "Left":
                content = decode_bytes_list(payload)
                print(f"File {fid} ({desc}):")
                print(f"  Length: {len(content)} bytes")
                print(f"  Content: {content[:200]}")
                print()
        time.sleep(0.2)
    
    print("\n=== Try calling syscall 8 from inside backdoor continuation ===\n")
    
    syscall8_from_backdoor = Lam(
        App(
            App(Var(8), Var(0)),
            Lam(Lam(Var(0)))
        )
    )
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(syscall8_from_backdoor) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    print(f"backdoor -> syscall8(result): {resp.hex()[:60] if resp else '(empty)'}")


if __name__ == "__main__":
    main()
