#!/usr/bin/env python3
"""
probe_pair_applied.py — Tests backdoor(nil)(lam(p, app(p, X)))(lam(_, nil))
for all active syscalls X in {1,2,4,5,6,7,8,14,42,201}.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    encode_byte_term,
    encode_bytes_list,
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
class NVar:
    name: str

@dataclass(frozen=True)
class NGlob:
    index: int

@dataclass(frozen=True)
class NLam:
    param: str
    body: object

@dataclass(frozen=True)
class NApp:
    f: object
    x: object

@dataclass(frozen=True)
class NConst:
    term: object

def shift_db(term, delta, cutoff=0):
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_db(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_db(term.f, delta, cutoff), shift_db(term.x, delta, cutoff))
    return term

def to_db(term, env=()):
    if isinstance(term, NVar):
        return Var(env.index(term.name))
    if isinstance(term, NGlob):
        return Var(term.index + len(env))
    if isinstance(term, NLam):
        return Lam(to_db(term.body, (term.param,) + env))
    if isinstance(term, NApp):
        return App(to_db(term.f, env), to_db(term.x, env))
    if isinstance(term, NConst):
        return shift_db(term.term, len(env))
    raise TypeError(f"Unsupported: {type(term)}")

def g(i):
    return NGlob(i)

def v(name):
    return NVar(name)

def lam(param, body):
    return NLam(param, body)

def app(f, x):
    return NApp(f, x)

def apps(*terms):
    out = terms[0]
    for t in terms[1:]:
        out = app(out, t)
    return out

NIL = NConst(Lam(Lam(Var(0))))

def parse_qd():
    stack = []
    for b in QD_raw:
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            stack.append(Lam(stack.pop()))
        else:
            stack.append(Var(b))
    return stack[0]

QD = NConst(parse_qd())

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
def recv_all(sock, timeout_s=10.0):
    sock.settimeout(timeout_s)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    return out

def query(payload, timeout_s=10.0):
    delay = 0.3
    for _ in range(4):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s=timeout_s)
        except Exception:
            time.sleep(delay)
            delay = min(delay * 2, 2.0)
    return b"ERROR"

def build_payload(term):
    return encode_term(to_db(term)) + bytes([FF])

def classify(out):
    if not out:
        return "EMPTY"
    known = [
        "Invalid term!",
        "Encoding failed!",
        "Term too big!",
        "Permission denied",
        "Not implemented",
        "Invalid argument",
        "Unexpected exception",
        "Oh, go choke",
    ]
    for t in known:
        if out.startswith(t.encode("ascii")):
            return f"TEXT:{t!r}"
    return f"HEX:{out[:120].hex()}"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    syscalls = [1, 2, 4, 5, 6, 7, 8, 14, 42, 201]

    print(f"{'Syscall':<10} {'Result'}")
    print("-" * 40)

    for x in syscalls:
        # backdoor(nil) (lam res. res (lam p. p X) (lam _. nil))
        # res = Either Left(pair) Right(err)
        # res (lam p. p X) (lam _. NIL) -> (lam p. p X) (pair) -> pair X -> X A B
        term = apps(
            g(201),
            NIL,
            lam("res", apps(v("res"), lam("p", app(v("p"), g(x))), lam("_", NIL)))
        )
        payload = build_payload(term)
        out = query(payload)
        c = classify(out)
        print(f"{x:<10} {c}")

    print("\n--- testing with QD wrapper ---")
    for x in syscalls:
        # backdoor(nil) (lam res. res (lam p. QD (p X)) (lam _. nil))
        # -> QD (pair X) -> QD (X A B)
        term = apps(
            g(201),
            NIL,
            lam("res", apps(v("res"), lam("p", app(QD, app(v("p"), g(x)))), lam("_", NIL)))
        )
        payload = build_payload(term)
        out = query(payload)
        c = classify(out)
        print(f"{x:<10} {c}")

    print("\n--- testing backdoor(nil) (lam p. QD (p X)) (lam _. nil) ---")
    # This is what I should have done in the first place if I thought backdoor was CPS.
    # But it is CPS! backdoor arg cont.
    for x in syscalls:
        term = apps(
            g(201),
            NIL,
            lam("p", app(QD, app(v("p"), g(x)))),
            lam("_", NIL)
        )
        payload = build_payload(term)
        out = query(payload)
        c = classify(out)
        print(f"{x:<10} {c}")

if __name__ == "__main__":
    main()
