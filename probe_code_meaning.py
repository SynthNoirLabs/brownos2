#!/usr/bin/env python3
import socket
import time
import sys
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD  # application
FE = 0xFE  # lambda
FF = 0xFF  # end-of-code marker

# Quick Debug (QD) from the challenge cheat sheet
QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

@dataclass(frozen=True)
class Var:
    i: int
    def __repr__(self): return f"V{self.i}"

@dataclass(frozen=True)
class Lam:
    body: object
    def __repr__(self): return f"λ.{self.body}"

@dataclass(frozen=True)
class App:
    f: object
    x: object
    def __repr__(self): return f"({self.f} {self.x})"

def parse_term(data: bytes) -> object:
    stack = []
    for b in data:
        if b == FF: break
        if b == FD:
            if len(stack) < 2: return None
            x = stack.pop(); f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            if len(stack) < 1: return None
            stack.append(Lam(stack.pop()))
        else:
            stack.append(Var(b))
    return stack[0] if len(stack) == 1 else None

def decode_int(term: object) -> int:
    cur = term
    for _ in range(9):
        if not isinstance(cur, Lam): return None
        cur = cur.body
    val = 0
    weights = {0:0, 1:1, 2:2, 3:4, 4:8, 5:16, 6:32, 7:64, 8:128}
    while isinstance(cur, App):
        if not isinstance(cur.f, Var): return None
        val += weights.get(cur.f.i, 0)
        cur = cur.x
    if isinstance(cur, Var):
        val += weights.get(cur.i, 0)
    return val

def decode_either(term: object):
    if not isinstance(term, Lam) or not isinstance(term.body, Lam): return None
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var):
        return ("Left" if body.f.i == 1 else "Right", body.x)
    return None

def decode_list(term: object):
    # λc.λn. n or λc.λn. c h t
    out = []
    cur = term
    while True:
        if not isinstance(cur, Lam) or not isinstance(cur.body, Lam): break
        body = cur.body.body
        if isinstance(body, Var) and body.i == 0: break # nil
        if isinstance(body, App) and isinstance(body.f, App) and isinstance(body.f.f, Var) and body.f.f.i == 1:
            out.append(body.f.x)
            cur = body.x
        else: break
    return out

def decode_3way_list(term: object):
    # λd.λf.λn. n or d id rest or f id rest
    items = []
    cur = term
    while True:
        if not isinstance(cur, Lam) or not isinstance(cur.body, Lam) or not isinstance(cur.body.body, Lam): break
        body = cur.body.body.body
        if isinstance(body, Var) and body.i == 0: break
        if isinstance(body, App) and isinstance(body.f, App) and isinstance(body.f.f, Var):
            type_var = body.f.f.i # 2 for dir, 1 for file
            entry_id = decode_int(body.f.x)
            items.append((type_var, entry_id))
            cur = body.x
        else: break
    return items

def classify_result(res_bytes: bytes) -> str:
    if not res_bytes: return "(EMPTY)"
    if b"Encoding failed!" in res_bytes: return "Encoding failed!"

    term = parse_term(res_bytes)
    if not term: return f"Hex: {res_bytes.hex()[:20]}..."

    # Try decoding as Either
    e = decode_either(term)
    if e:
        tag, val = e
        if tag == "Right":
            err_code = decode_int(val)
            return f"Right(Error:{err_code})" if err_code is not None else f"Right(Term:{val})"

        # Left branch - try various decoders
        # 1. Byte List (String)
        blist = decode_list(val)
        if blist:
            try:
                chars = [decode_int(b) for b in blist]
                if all(32 <= c <= 126 for c in chars):
                    return f"Left(String:'{''.join(chr(c) for c in chars)}')"
                return f"Left(Bytes:{chars[:5]}...)"
            except: pass

        # 2. 3-way List (readdir)
        dirlist = decode_3way_list(val)
        if dirlist:
            return f"Left(DirList:{dirlist})"

        # 3. Int
        v_int = decode_int(val)
        if v_int is not None:
            return f"Left(Int:{v_int})"

        return f"Left(Term:{val})"

    # Try decoding as direct Int
    i = decode_int(term)
    if i is not None: return f"Int:{i}"

    # Default to string representation
    s = str(term)
    return s[:100] + "..." if len(s) > 100 else s

def query(payload: bytes, timeout_s: float = 8.0) -> bytes:
    for _ in range(3):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                sock.shutdown(socket.SHUT_WR)
                out = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk: break
                    out += chunk
                    if FF in out: break
                if out: return out
        except Exception:
            time.sleep(1)
    return b""

def encode_byte_term(n: int) -> bytes:
    expr = bytes([0])
    for i in range(8):
        if n & (1 << i):
            expr += bytes([i+1, FD])
    for _ in range(9):
        expr += bytes([FE])
    return expr

def main():
    syscalls = [1, 2, 4, 5, 6, 7, 8, 14, 42, 201]

    # Define arguments
    args = [
        ("V0", bytes([0])),
        ("nil", bytes([0, FE, FE])),
        ("int0", encode_byte_term(0)),
        ("int1", encode_byte_term(1)),
        ("int2", encode_byte_term(2)),
    ]

    print(f"{'Syscall':<8} | {'Arg':<6} | {'Classification / Result'}")
    print("-" * 80)

    for sc in syscalls:
        for name, arg_bytes in args:
            # Construct: App(App(Var(sc), arg), QD)
            payload = bytes([sc]) + arg_bytes + bytes([FD]) + QD_BYTES + bytes([FD, FF])

            res = query(payload)
            classification = classify_result(res)

            print(f"{sc:02}       | {name:<6} | {classification}")
            time.sleep(0.2)

if __name__ == "__main__":
    main()
