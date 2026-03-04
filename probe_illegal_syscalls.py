#!/usr/bin/env python3
"""
probe_illegal_syscalls.py — Call Var(253..255) using pure-lambda echo trick.
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

# ---------------------------------------------------------------------------
# Named-term DSL
# ---------------------------------------------------------------------------
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

# E = λx. λk. k (λl. λr. l x)
E = lam("x", lam("k", app(v("k"), lam("l", lam("r", app(v("l"), v("x")))))))

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------
def main():
    # Construct Var(253) = E(Var(250)) inside Left
    # Construct Var(254) = E(Var(251)) inside Left
    # Construct Var(255) = E(Var(252)) inside Left

    print(f"{'Probe':<40} | {'Result'}")
    print("-" * 60)

    for i in range(240, 253):
        # E(Var(i)) -> λk. k (Left Var(i+3))
        # lx = Left Var(i+3) = λl.λr. l Var(i+3)
        # lx (λf. λr. apps(g(4), v("f"), QD)) NIL
        #   -> (λf. λr. apps(g(4), v("f"), QD)) Var(i+3)
        #   -> λr. apps(g(4), Var(i+3), QD)
        # Apply to NIL to get: apps(g(4), Var(i+3), QD)

        probe = app(app(E, g(i)),
                    lam("lx", apps(v("lx"),
                                   lam("f", lam("r", apps(g(4), v("f"), QD))),
                                   NIL,
                                   NIL)))

        payload = encode_term(to_db(probe)) + bytes([FF])
        res = query(payload)
        print(f"Quote target of E({i})   | {classify(res)}")

if __name__ == "__main__":
    main()
