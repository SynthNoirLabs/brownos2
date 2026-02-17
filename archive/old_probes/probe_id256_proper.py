#!/usr/bin/env python3
"""Test ID 256 with proper encoding."""

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


def query(payload: bytes, timeout_s: float = 3.0) -> bytes:
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


def decode_byte_term(term):
    body = strip_lams(term, 9)
    return eval_bitset(body) if body else None


def decode_either(term):
    if isinstance(term, Lam) and isinstance(term.body, Lam):
        body = term.body.body
        if isinstance(body, App) and isinstance(body.f, Var):
            return ("Left" if body.f.i == 1 else "Right", body.x)
    return None, None


def uncons_list(term):
    if isinstance(term, Lam) and isinstance(term.body, Lam):
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
        res = uncons_list(cur)
        if res is None:
            return bytes(out)
        head, cur = res
        b = decode_byte_term(head)
        if b is not None:
            out.append(b)
    return bytes(out)


def main():
    print("=== ID 256 with proper encoding ===\n")
    
    print("1. name(256):")
    payload = bytes([0x06]) + encode_term(encode_int_proper(256)) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    tag, p = decode_either(parse_term(resp))
    if tag == "Left":
        name = decode_bytes_list(p)
        print(f"   Name: {name.decode('utf-8', 'replace')!r}")
    else:
        print(f"   Error: {tag}")
        try:
            code = decode_byte_term(p)
            print(f"   Error code: {code}")
        except:
            pass
    time.sleep(0.2)
    
    print("\n2. readfile(256):")
    payload = bytes([0x07]) + encode_term(encode_int_proper(256)) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    tag, p = decode_either(parse_term(resp))
    if tag == "Left":
        content = decode_bytes_list(p)
        print(f"   Content: {content.decode('utf-8', 'replace')!r}")
    else:
        print(f"   Error: {tag}")
        try:
            code = decode_byte_term(p)
            codes = {0: "Exception", 1: "NotImpl", 2: "InvalidArg", 3: "UnknownId", 4: "NotDir", 5: "NotFile", 6: "PermDenied"}
            print(f"   Error code: {code} = {codes.get(code, '?')}")
        except:
            pass
    time.sleep(0.2)
    
    print("\n3. readdir(256):")
    payload = bytes([0x05]) + encode_term(encode_int_proper(256)) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    tag, p = decode_either(parse_term(resp))
    if tag == "Left":
        print(f"   Success (directory listing)")
    else:
        try:
            code = decode_byte_term(p)
            codes = {0: "Exception", 1: "NotImpl", 2: "InvalidArg", 3: "UnknownId", 4: "NotDir", 5: "NotFile", 6: "PermDenied"}
            print(f"   Error code: {code} = {codes.get(code, '?')}")
        except:
            pass
    time.sleep(0.2)
    
    print("\n4. Scan nearby IDs (250-260):")
    for n in range(250, 261):
        payload = bytes([0x06]) + encode_term(encode_int_proper(n)) + bytes([FD]) + QD + bytes([FD, FF])
        resp = query(payload)
        tag, p = decode_either(parse_term(resp))
        if tag == "Left":
            name = decode_bytes_list(p).decode('utf-8', 'replace')
            print(f"   ID {n}: {name!r}")
        else:
            print(f"   ID {n}: (unknown)")
        time.sleep(0.1)


if __name__ == "__main__":
    main()
