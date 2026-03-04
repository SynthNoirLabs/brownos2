#!/usr/bin/env python3
"""
probe_pair_applied_v2.py — Focused tests for X(A)(B) and variants.
A = lam a b. b b
B = lam a b. a b
"""

from __future__ import annotations
import socket
import time
from dataclasses import dataclass
from solve_brownos_answer import App, Lam, Var, encode_term

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

NIL = NConst(Lam(Lam(Var(0))))
def parse_qd():
    stack = []
    for b in QD_raw:
        if b == FD: x = stack.pop(); f = stack.pop(); stack.append(App(f, x))
        elif b == FE: stack.append(Lam(stack.pop()))
        else: stack.append(Var(b))
    return stack[0]
QD = NConst(parse_qd())

def query(payload):
    try:
        with socket.create_connection((HOST, PORT), timeout=5.0) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            out = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                out += chunk
                if FF in chunk: break
            return out
    except: return b"ERROR"

def build_payload(term): return encode_term(to_db(term)) + bytes([FF])

def classify(out):
    if not out: return "EMPTY"
    if b"Permission denied" in out: return "Permission denied"
    if b"Invalid argument" in out: return "Invalid argument"
    if b"Not implemented" in out: return "Not implemented"
    if out == b"ERROR": return "ERROR"
    return f"HEX:{out[:64].hex()}"

def main():
    # A = lam a b. b b
    A = lam("a", lam("b", app(v("b"), v("b"))))
    # B = lam a b. a b
    B = lam("a", lam("b", app(v("a"), v("b"))))

    syscalls = [1, 2, 4, 5, 6, 7, 8, 14, 42, 201]

    print("Testing X(A)(QD) directly:")
    for x in syscalls:
        term = apps(g(x), A, QD)
        c = classify(query(build_payload(term)))
        print(f"  {x:<3}: {c}")

    print("\nTesting ( (X A B) QD ) (Applying result of XAB to QD):")
    for x in syscalls:
        term = app(apps(g(x), A, B), QD)
        c = classify(query(build_payload(term)))
        print(f"  {x:<3}: {c}")

    print("\nTesting X(B)(QD) directly:")
    for x in syscalls:
        term = apps(g(x), B, QD)
        c = classify(query(build_payload(term)))
        print(f"  {x:<3}: {c}")

    print("\nTesting X(A)(A) directly:")
    for x in syscalls:
        term = apps(g(x), A, A)
        c = classify(query(build_payload(term)))
        print(f"  {x:<3}: {c}")

if __name__ == "__main__":
    main()
