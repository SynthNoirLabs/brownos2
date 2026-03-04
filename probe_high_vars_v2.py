#!/usr/bin/env python3
"""
probe_high_vars_v2.py — Systematic scan of high vars and combinations.
"""

import socket
import time
from dataclasses import dataclass
from solve_brownos_answer import (
    App,
    Lam,
    Var,
    encode_term,
)

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE
FF = 0xFF

QD_raw = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

@dataclass(frozen=True)
class NVar: name: str
@dataclass(frozen=True)
class NGlob: index: int
@dataclass(frozen=True)
class NLam: param: str; body: object
@dataclass(frozen=True)
class NApp: f: object; x: object
@dataclass(frozen=True)
class NConst: term: object

def shift_db(term, delta, cutoff=0):
    if isinstance(term, Var): return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam): return Lam(shift_db(term.body, delta, cutoff + 1))
    if isinstance(term, App): return App(shift_db(term.f, delta, cutoff), shift_db(term.x, delta, cutoff))
    return term

def to_db(term, env=()):
    if isinstance(term, NVar): return Var(env.index(term.name))
    if isinstance(term, NGlob): return Var(term.index + len(env))
    if isinstance(term, NLam): return Lam(to_db(term.body, (term.param,) + env))
    if isinstance(term, NApp): return App(to_db(term.f, env), to_db(term.x, env))
    if isinstance(term, NConst): return shift_db(term.term, len(env))
    raise TypeError(f"Unsupported: {type(term)}")

def g(i): return NGlob(i)
def v(name): return NVar(name)
def lam(param, body): return NLam(param, body)
def app(f, x): return NApp(f, x)
def apps(*terms):
    out = terms[0]
    for t in terms[1:]: out = app(out, t)
    return out

def parse_qd():
    stack = []
    for b in QD_raw:
        if b == FD:
            x = stack.pop(); f = stack.pop(); stack.append(App(f, x))
        elif b == FE: stack.append(Lam(stack.pop()))
        else: stack.append(Var(b))
    return stack[0]

QD = NConst(parse_qd())
NIL = NConst(Lam(Lam(Var(0))))
E = lam("x", lam("k", app(v("k"), lam("l", lam("r", app(v("l"), v("x")))))))

def query(payload, timeout_s=5.0):
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            out = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                out += chunk
                if FF in chunk: break
            return out
    except Exception as e: return f"ERROR: {e}".encode()

def classify(out):
    if not out: return "EMPTY"
    if b"Permission denied" in out: return "Permission denied"
    if b"Invalid term!" in out: return "Invalid term!"
    if b"Encoding failed!" in out: return "Encoding failed!"
    if b"Invalid argument" in out: return "Invalid argument"
    return out.hex()

def main():
    print(f"{'Probe':<40} | {'Result'}")
    print("-" * 60)

    # 1. Call Var(253..255) with argument and QD
    for i in [250, 251, 252]:
        target = i + 3
        # Var(target) NIL QD
        probe = app(app(E, g(i)),
                    lam("lx", apps(v("lx"),
                                   lam("f", lam("r", apps(v("f"), NIL, QD))),
                                   NIL, NIL)))
        payload = encode_term(to_db(probe)) + bytes([FF])
        res = query(payload)
        print(f"Var({target}) NIL QD        | {classify(res)}")

    # 2. backdoor(nil) Var(253) QD
    # (Var(253) pair) QD
    for i in [250, 251, 252]:
        target = i + 3
        probe = app(app(E, g(i)),
                    lam("lx", apps(v("lx"),
                                   lam("f", lam("r", apps(app(app(g(201), NIL), v("f")), QD))),
                                   NIL, NIL)))
        payload = encode_term(to_db(probe)) + bytes([FF])
        res = query(payload)
        print(f"backdoor(nil) Var({target}) QD | {classify(res)}")

    # 3. sys8(A, B) using backdoor
    probe = apps(g(201), NIL,
                 lam("lx", apps(v("lx"),
                                lam("p", lam("r", apps(v("p"), g(8)))), # p 8 = 8 A B
                                NIL)),
                 QD) # Continuation for 8 A B
    payload = encode_term(to_db(probe)) + bytes([FF])
    res = query(payload)
    print(f"sys8 A B (backdoor)      | {classify(res)}")

    # 4. sys8(B, A) using backdoor
    # We need a way to flip the pair.
    # pair A B (λa.λb. pair b a)
    flip = lam("a", lam("b", apps(lam("h", lam("t", lam("s", apps(v("s"), v("h"), v("t"))))), v("b"), v("a"))))
    probe = apps(g(201), NIL,
                 lam("lx", apps(v("lx"),
                                lam("p", lam("r", apps(apps(v("p"), flip), g(8)))),
                                NIL)),
                 QD)
    payload = encode_term(to_db(probe)) + bytes([FF])
    res = query(payload)
    print(f"sys8 B A (backdoor)      | {classify(res)}")

if __name__ == "__main__":
    main()
