#!/usr/bin/env python3
"""
Syscall 8 returns Left for directories via backdoor bypass.
Decode the directory listings and compare to regular readdir.
Also scan for HIDDEN directories that only syscall 8 can see.
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
WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


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


def encode_int_proper(n: int) -> object:
    expr: object = Var(0)
    remaining = n
    weights = [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]
    for idx, weight in weights:
        while remaining >= weight:
            expr = App(Var(idx), expr)
            remaining -= weight
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


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


def parse_term(data: bytes) -> object:
    stack: list[object] = []
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
    if len(stack) != 1:
        raise ValueError(f"Invalid parse: stack size {len(stack)}")
    return stack[0]


def strip_lams(term: object, n: int) -> object:
    cur = term
    for _ in range(n):
        if not isinstance(cur, Lam):
            raise ValueError("Not enough leading lambdas")
        cur = cur.body
    return cur


def eval_bitset_expr(expr: object) -> int:
    if isinstance(expr, Var):
        return WEIGHTS.get(expr.i, 0)
    if isinstance(expr, App):
        if isinstance(expr.f, Var):
            return WEIGHTS.get(expr.f.i, 0) + eval_bitset_expr(expr.x)
    raise ValueError(f"Unexpected expr: {type(expr)}")


def decode_int(term: object) -> int:
    body = strip_lams(term, 9)
    return eval_bitset_expr(body)


def decode_either(term: object) -> tuple[str, object]:
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not an Either")
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var):
        if body.f.i == 1:
            return ("Left", body.x)
        if body.f.i == 0:
            return ("Right", body.x)
    raise ValueError("Unexpected Either shape")


def decode_dirlist_3way(term: object) -> list[tuple[str, int]]:
    """Decode 3-way directory listing: dir/file/nil nodes."""
    entries = []
    cur = term
    for _ in range(1000):
        if not isinstance(cur, Lam):
            break
        cur2 = cur.body
        if not isinstance(cur2, Lam):
            break
        cur3 = cur2.body
        if not isinstance(cur3, Lam):
            break
        body = cur3.body
        
        if isinstance(body, Var) and body.i == 0:
            return entries
        
        if isinstance(body, App) and isinstance(body.f, App):
            if isinstance(body.f.f, Var):
                selector = body.f.f.i
                id_term = body.f.x
                rest = body.x
                
                try:
                    file_id = decode_int(id_term)
                    entry_type = "dir" if selector == 2 else "file"
                    entries.append((entry_type, file_id))
                except:
                    entries.append(("?", -1))
                
                cur = rest
                continue
        
        break
    
    return entries


def syscall8_bypass(n: int) -> bytes:
    """Call syscall 8 with integer n via backdoor bypass."""
    nil = Lam(Lam(Var(0)))
    syscall8 = Var(8)
    int_term = encode_int_proper(n)
    selector = Lam(Lam(App(App(syscall8, int_term), Var(0))))
    cont = Lam(App(App(Var(0), selector), nil))
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(cont) + bytes([FD]) + QD + bytes([FD, FF])
    return query(payload)


def syscall5_readdir(n: int) -> bytes:
    """Call regular readdir (syscall 5)."""
    payload = bytes([0x05]) + encode_term(encode_int_proper(n)) + bytes([FD]) + QD + bytes([FD, FF])
    return query(payload)


def main():
    print("=" * 70)
    print("SYSCALL 8 DIRECTORY LISTING DECODE & COMPARE")
    print("=" * 70)
    
    print("\n=== Compare root directory (id 0) ===\n")
    
    resp_sc5 = syscall5_readdir(0)
    resp_sc8 = syscall8_bypass(0)
    
    print(f"Syscall 5 response length: {len(resp_sc5)}")
    print(f"Syscall 8 response length: {len(resp_sc8)}")
    print(f"Same response? {resp_sc5 == resp_sc8}")
    
    try:
        term_sc5 = parse_term(resp_sc5)
        tag5, payload5 = decode_either(term_sc5)
        entries5 = decode_dirlist_3way(payload5)
        print(f"\nSyscall 5 entries: {entries5}")
    except Exception as e:
        print(f"Syscall 5 decode error: {e}")
    
    try:
        term_sc8 = parse_term(resp_sc8)
        tag8, payload8 = decode_either(term_sc8)
        entries8 = decode_dirlist_3way(payload8)
        print(f"Syscall 8 entries: {entries8}")
    except Exception as e:
        print(f"Syscall 8 decode error: {e}")
    
    print("\n=== Scan for hidden directories (IDs not in regular tree) ===\n")
    
    known_dirs = {0, 1, 2, 3, 4, 5, 6, 9, 22, 25, 39, 43, 50}
    
    hidden_dirs = []
    for n in range(100):
        if n in known_dirs:
            continue
        try:
            resp = syscall8_bypass(n)
            hex_resp = resp.hex()
            if "000300" in hex_resp:
                continue
            if hex_resp.startswith("01") or "Left" in str(resp):
                hidden_dirs.append(n)
                print(f"ID {n}: Left (hidden directory?) - len={len(resp)}")
        except:
            pass
        time.sleep(0.1)
    
    if hidden_dirs:
        print(f"\nFound potential hidden directories: {hidden_dirs}")
    else:
        print("\nNo hidden directories found in 0-99 range")
    
    print("\n=== Test higher ID ranges ===\n")
    
    for n in [100, 200, 300, 400, 500, 1000, 2000]:
        try:
            resp = syscall8_bypass(n)
            hex_resp = resp.hex()
            if "000300" not in hex_resp:
                print(f"ID {n}: {resp.hex()[:60]}")
        except Exception as e:
            print(f"ID {n}: ERROR - {e}")
        time.sleep(0.15)


if __name__ == "__main__":
    main()
