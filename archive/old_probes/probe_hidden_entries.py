#!/usr/bin/env python3
"""
Compare syscall 5 vs syscall 8 for ALL directories.
Look for any HIDDEN entries that only syscall 8 reveals.
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
PORT = 61221

FD, FE, FF = 0xFD, 0xFE, 0xFF
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
    raise TypeError


def encode_int(n: int) -> object:
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


def query(payload: bytes, timeout_s: float = 4.0) -> bytes:
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
        return out


def parse_term(data: bytes) -> object:
    stack = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x, f = stack.pop(), stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            stack.append(Lam(stack.pop()))
        else:
            stack.append(Var(b))
    return stack[0] if len(stack) == 1 else None


def decode_either(term):
    if isinstance(term, Lam) and isinstance(term.body, Lam):
        body = term.body.body
        if isinstance(body, App) and isinstance(body.f, Var):
            return ("Left" if body.f.i == 1 else "Right", body.x)
    return None, None


def strip_lams(term, n):
    cur = term
    for _ in range(n):
        if isinstance(cur, Lam):
            cur = cur.body
        else:
            return None
    return cur


def eval_bitset(expr):
    if isinstance(expr, Var):
        return WEIGHTS.get(expr.i, 0)
    if isinstance(expr, App) and isinstance(expr.f, Var):
        return WEIGHTS.get(expr.f.i, 0) + eval_bitset(expr.x)
    return 0


def decode_int(term):
    body = strip_lams(term, 9)
    return eval_bitset(body) if body else None


def decode_3way_dirlist(term):
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
                    entry_type = "dir" if selector == 2 else "file" if selector == 1 else "?"
                    entries.append((entry_type, file_id))
                except:
                    entries.append(("?", -1))
                
                cur = rest
                continue
        
        break
    
    return entries


def readdir_sc5(dir_id: int) -> list:
    payload = bytes([0x05]) + encode_term(encode_int(dir_id)) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    if not resp:
        return []
    term = parse_term(resp)
    tag, payload_term = decode_either(term)
    if tag == "Left":
        return decode_3way_dirlist(payload_term)
    return []


def readdir_sc8(dir_id: int) -> list:
    nil = Lam(Lam(Var(0)))
    syscall8 = Var(8)
    int_term = encode_int(dir_id)
    
    selector = Lam(Lam(App(App(syscall8, int_term), Var(0))))
    cont = Lam(App(App(Var(0), selector), nil))
    
    payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(cont) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    if not resp:
        return []
    term = parse_term(resp)
    tag, payload_term = decode_either(term)
    if tag == "Left":
        return decode_3way_dirlist(payload_term)
    return []


def main():
    print("=== Compare Syscall 5 vs Syscall 8 for all directories ===\n")
    
    all_dirs = [0, 1, 2, 3, 4, 5, 6, 9, 22, 25, 39, 43, 50]
    
    for dir_id in all_dirs:
        sc5 = readdir_sc5(dir_id)
        time.sleep(0.15)
        sc8 = readdir_sc8(dir_id)
        time.sleep(0.15)
        
        if sc5 == sc8:
            print(f"Dir {dir_id}: SAME ({len(sc5)} entries)")
        else:
            print(f"Dir {dir_id}: DIFFERENT!")
            print(f"  SC5: {sc5}")
            print(f"  SC8: {sc8}")
            
            sc5_ids = set(e[1] for e in sc5)
            sc8_ids = set(e[1] for e in sc8)
            
            only_sc5 = sc5_ids - sc8_ids
            only_sc8 = sc8_ids - sc5_ids
            
            if only_sc5:
                print(f"  Only in SC5: {only_sc5}")
            if only_sc8:
                print(f"  Only in SC8: {only_sc8}")


if __name__ == "__main__":
    main()
