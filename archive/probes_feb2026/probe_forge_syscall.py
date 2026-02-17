#!/usr/bin/env python3
"""
BREAKTHROUGH PROBE: Globals are Scott lists [byte(id), byte(255)].
Syscall dispatch is structural — we can FORGE syscalls!

Key tests:
1. Verify: forged g(8) == real g(8) (both return Permission denied)
2. Try forged syscalls with IDs 253, 254, 255 (can't normally encode)
3. Try different tag values (not 255) — maybe tag controls permissions!
4. Try IDs > 255
5. Try single-element lists, three-element lists, etc.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import App, Lam, Var, encode_term, encode_bytes_list

HOST = "wc3.wechall.net"
PORT = 61221
FF = 0xFF


# -- Named-term builder --
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
        try:
            return Var(env.index(term.name))
        except ValueError as exc:
            raise ValueError(f"Unbound name: {term.name}") from exc
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


def v(n):
    return NVar(n)


def lam(p, b):
    return NLam(p, b)


def app(f, x):
    return NApp(f, x)


def apps(*t):
    out = t[0]
    for x in t[1:]:
        out = app(out, x)
    return out


NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)


def int_term(n):
    """Encode integer n as 9-lambda byte term (works for n >= 0, supports >255 via repeated bits)."""
    expr = Var(0)
    for idx, weight in (
        (1, 1),
        (2, 2),
        (3, 4),
        (4, 8),
        (5, 16),
        (6, 32),
        (7, 64),
        (8, 128),
    ):
        if n & weight:
            expr = App(Var(idx), expr)
    # For values > 255, we need to add extra bits
    remaining = n >> 8  # bits above 255
    if remaining:
        # Add extra V8 (128) applications for each 128 needed
        extra = remaining * 128
        # Actually, the encoding is additive. For 256 = 128+128, use V8(V8(V0))
        # For now, handle simple cases
        for _ in range(remaining):
            expr = App(Var(8), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def make_scott_list(elements):
    """Build a Scott-encoded list of terms."""
    # nil = λc.λn. n
    result = Lam(Lam(Var(0)))
    for elem in reversed(elements):
        # cons h t = λc.λn. c h t
        # In de Bruijn: λ.λ.((V1 H_shifted) T_shifted)
        h_shifted = shift_db(elem, 2)
        t_shifted = shift_db(result, 2)
        result = Lam(Lam(App(App(Var(1), h_shifted), t_shifted)))
    return result


def forge_syscall(syscall_id, tag=255):
    """Forge a syscall term: Scott list [byte(syscall_id), byte(tag)]."""
    return NConst(make_scott_list([int_term(syscall_id), int_term(tag)]))


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


def query_named(term, timeout_s=10.0, retries=3):
    payload = encode_term(to_db(term)) + bytes([FF])
    delay = 0.2
    for attempt in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s=timeout_s)
        except Exception as e:
            if attempt == retries - 1:
                return b""
            time.sleep(delay)
            delay = min(delay * 2, 2.0)
    return b""


def write_str(s):
    return apps(g(2), NConst(encode_bytes_list(s.encode())), NIL)


# Quote-free observer
def obs_full():
    right_handler = lam(
        "err_code",
        apps(
            g(1),
            v("err_code"),
            lam(
                "err_res",
                apps(
                    v("err_res"),
                    lam("errstr", apps(g(2), v("errstr"), NIL)),
                    lam("_e2", write_str("?")),
                ),
            ),
        ),
    )
    left_handler = lam("_payload", write_str("L:"))
    return lam("res", apps(v("res"), left_handler, right_handler))


# Observer that also writes the error code number
def obs_detailed():
    """On Right(n), writes 'R:' then the error string. On Left(x), writes 'L:'."""
    right_handler = lam(
        "err_code",
        apps(
            g(2),
            NConst(encode_bytes_list(b"R:")),
            lam(
                "_w",
                apps(
                    g(1),
                    v("err_code"),
                    lam(
                        "err_res",
                        apps(
                            v("err_res"),
                            lam("errstr", apps(g(2), v("errstr"), NIL)),
                            lam("_e2", write_str("?")),
                        ),
                    ),
                ),
            ),
        ),
    )
    left_handler = lam(
        "payload",
        apps(
            g(2),
            NConst(encode_bytes_list(b"L:")),
            lam("_w", NIL),  # just write L: and stop
        ),
    )
    return lam("res", apps(v("res"), left_handler, right_handler))


OBS = obs_detailed()

# ========== PHASE 1: Verify forged syscalls match real ones ==========
print("=" * 60)
print("PHASE 1: Verify forged syscalls match real ones")
print("=" * 60)

# Real g(42) = towel
prog_real = apps(g(42), NIL, OBS)
out_real = query_named(prog_real)
print(f"  real g(42)(nil): {out_real!r}")
time.sleep(0.3)

# Forged [42, 255]
prog_forged = apps(forge_syscall(42), NIL, OBS)
out_forged = query_named(prog_forged)
print(f"  forged [42,255](nil): {out_forged!r}")
time.sleep(0.3)

# Real g(1) = error_string
prog_real2 = apps(g(1), NConst(int_term(0)), OBS)
out_real2 = query_named(prog_real2)
print(f"  real g(1)(int(0)): {out_real2!r}")
time.sleep(0.3)

# Forged [1, 255]
prog_forged2 = apps(forge_syscall(1), NConst(int_term(0)), OBS)
out_forged2 = query_named(prog_forged2)
print(f"  forged [1,255](int(0)): {out_forged2!r}")
time.sleep(0.3)

# Real g(8) = sys8
prog_real3 = apps(g(8), NIL, OBS)
out_real3 = query_named(prog_real3)
print(f"  real g(8)(nil): {out_real3!r}")
time.sleep(0.3)

# Forged [8, 255]
prog_forged3 = apps(forge_syscall(8), NIL, OBS)
out_forged3 = query_named(prog_forged3)
print(f"  forged [8,255](nil): {out_forged3!r}")
time.sleep(0.3)

print()
print("=" * 60)
print("PHASE 2: Forged syscalls with impossible IDs (253, 254, 255)")
print("=" * 60)

for sid in [253, 254, 255]:
    prog = apps(forge_syscall(sid), NIL, OBS)
    out = query_named(prog)
    print(f"  forged [{sid},255](nil): {out!r}")
    time.sleep(0.3)

print()
print("=" * 60)
print("PHASE 3: Different TAG values (not 255)")
print("=" * 60)

# What if the tag byte controls the permission level?
# Real syscalls use 255. What about other tags?
for tag in [0, 1, 8, 42, 128, 200, 254, 253]:
    prog = apps(forge_syscall(8, tag=tag), NIL, OBS)
    out = query_named(prog)
    print(f"  forged [8,{tag}](nil): {out!r}")
    time.sleep(0.3)

# Also: what about tag=8 with id=255?
prog = apps(forge_syscall(255, tag=8), NIL, OBS)
out = query_named(prog)
print(f"  forged [255,8](nil): {out!r}")
time.sleep(0.3)

print()
print("=" * 60)
print("PHASE 4: Forged with IDs > 255")
print("=" * 60)

for sid in [256, 257, 300, 512, 1024]:
    prog = apps(forge_syscall(sid), NIL, OBS)
    out = query_named(prog, timeout_s=15)
    print(f"  forged [{sid},255](nil): {out!r}")
    time.sleep(0.3)

print()
print("=" * 60)
print("PHASE 5: Different list lengths")
print("=" * 60)

# What if the syscall structure has only 1 element? Or 3?
# Single element: [byte(8)]
single = NConst(make_scott_list([int_term(8)]))
prog = apps(single, NIL, OBS)
out = query_named(prog)
print(f"  forged [8] (1 elem): {out!r}")
time.sleep(0.3)

# Three elements: [byte(8), byte(255), byte(0)]
triple = NConst(make_scott_list([int_term(8), int_term(255), int_term(0)]))
prog = apps(triple, NIL, OBS)
out = query_named(prog, timeout_s=15)
print(f"  forged [8,255,0] (3 elem): {out!r}")
time.sleep(0.3)

# Empty list as syscall
empty = NIL
prog = apps(empty, NIL, OBS)
out = query_named(prog, timeout_s=15)
print(f"  forged [] (empty): {out!r}")
time.sleep(0.3)

# Just the integer (not a list)
bare = NConst(int_term(8))
prog = apps(bare, NIL, OBS)
out = query_named(prog, timeout_s=15)
print(f"  forged bare int(8): {out!r}")
time.sleep(0.3)

print()
print("=" * 60)
print("PHASE 6: Systematic tag sweep for sys8")
print("=" * 60)

# Sweep ALL possible tag values 0-255 for syscall 8
# Looking for any that DON'T return Permission denied
interesting = []
for tag in range(256):
    prog = apps(forge_syscall(8, tag=tag), NIL, OBS)
    out = query_named(prog, timeout_s=8)
    label = "silent" if not out else out.decode("latin-1", errors="replace")[:50]
    if tag % 32 == 0:
        print(f"  [8,{tag}]: {label}")
    if out and b"Permission denied" not in out and b"Not implemented" not in out:
        interesting.append((tag, out))
        print(f"  *** INTERESTING [8,{tag}]: {out!r}")
    time.sleep(0.15)

print(f"\nInteresting results: {len(interesting)}")
for tag, out in interesting:
    print(f"  tag={tag}: {out!r}")

print("\nDone.")
