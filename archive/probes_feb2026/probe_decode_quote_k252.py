#!/usr/bin/env python3
"""
Quick analysis: decode what quote(K(g(252))) actually returns,
and explore the pair(sys8) silence + other new leads.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    encode_term,
    encode_bytes_list,
    parse_term,
    QD,
    FF,
    FD,
    FE,
)

HOST = "wc3.wechall.net"
PORT = 61221


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
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


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


def write_marker(ch):
    return apps(g(2), NConst(encode_bytes_list(ch.encode())), NIL)


# OBS: quote-free observer
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
                    lam("_e2", write_marker("?")),
                ),
            ),
        ),
    )
    left_handler = lam("_payload", write_str("L:"))
    return lam("res", apps(v("res"), left_handler, right_handler))


# OBS that writes "L" then also writes the payload via quote
def obs_with_quote():
    left_handler = lam(
        "payload",
        apps(
            g(2),
            NConst(encode_bytes_list(b"L:")),
            lam(
                "_w",
                apps(
                    g(4),
                    v("payload"),
                    lam(
                        "qres",
                        apps(
                            v("qres"),
                            lam("qbytes", apps(g(2), v("qbytes"), NIL)),
                            lam("_qe", write_str("QF")),
                        ),
                    ),
                ),
            ),
        ),
    )
    right_handler = lam(
        "err_code",
        apps(
            g(1),
            v("err_code"),
            lam(
                "err_res",
                apps(
                    v("err_res"),
                    lam(
                        "errstr",
                        apps(
                            g(2),
                            NConst(encode_bytes_list(b"R:")),
                            lam("_w2", apps(g(2), v("errstr"), NIL)),
                        ),
                    ),
                    lam("_e2", write_marker("?")),
                ),
            ),
        ),
    )
    return lam("res", apps(v("res"), left_handler, right_handler))


def pretty_term(t, depth=0):
    if isinstance(t, Var):
        return f"V{t.i}"
    if isinstance(t, Lam):
        return f"λ.{pretty_term(t.body, depth + 1)}"
    if isinstance(t, App):
        return f"({pretty_term(t.f, depth)} {pretty_term(t.x, depth)})"
    return str(t)


print("=" * 60)
print("ANALYSIS 1: What does K(g(N)) actually reduce to?")
print("=" * 60)

# Use QD to see what K(g(252)) looks like after evaluation
# QD prints the byte encoding of the term
for idx in [250, 251, 252]:
    K_comb = NConst(Lam(Lam(Var(1))))
    # Build raw payload: K g(idx) QD FD FD (with FF)
    # Actually use named terms for correctness
    prog = apps(K_comb, g(idx))
    # Now pass this to QD
    db_term = to_db(prog)
    payload = encode_term(db_term) + QD + bytes([FD, FF])

    out = b""
    try:
        with socket.create_connection((HOST, PORT), timeout=10) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            out = recv_all(sock, timeout_s=10)
    except Exception as e:
        print(f"  K(g({idx})) QD: error {e}")
        continue

    print(f"  K(g({idx})) QD output: {out.hex() if out else 'empty'}")
    if out and out[-1:] == bytes([0xFF]):
        try:
            parsed = parse_term(out)
            print(f"    parsed: {pretty_term(parsed)}")
        except Exception as e:
            print(f"    parse error: {e}")
    elif out:
        print(f"    raw text: {out!r}")
    time.sleep(0.3)

print()

# Now test: what does K(g(252))(nil) reduce to via QD?
print("=" * 60)
print("ANALYSIS 2: What does K(g(252))(nil) reduce to?")
print("=" * 60)

K_comb = NConst(Lam(Lam(Var(1))))
prog = apps(K_comb, g(252), NIL)
db_term = to_db(prog)
payload = encode_term(db_term) + QD + bytes([FD, FF])

out = b""
try:
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        out = recv_all(sock, timeout_s=10)
except Exception as e:
    print(f"  error: {e}")

print(f"  K(g(252))(nil) QD: {out.hex() if out else 'empty'}")
if out and out[-1:] == bytes([0xFF]):
    try:
        parsed = parse_term(out)
        print(f"  parsed: {pretty_term(parsed)}")
    except Exception as e:
        print(f"  parse error: {e}")
elif out:
    print(f"  raw text: {out!r}")
time.sleep(0.3)

print()
print("=" * 60)
print("ANALYSIS 3: Pair(sys8) detailed observation")
print("=" * 60)

# pair(sys8) = sys8(A)(B)
# A = λa.λb.bb = the fst component of backdoor pair
# B = λa.λb.ab = the snd component
# sys8(A) calls sys8 with arg=A, continuation = B
# sys8 always returns Right(6), so B(Right(6))
# B = λa.λb.ab, so B(Right(6)) = λb.Right(6)(b)
# Right(6) = λl.λr.(r int(6))
# Right(6)(b) = (λl.λr.(r int(6)))(b) = λr.(r int(6))
# So B(Right(6)) = λb.(λr.(r int(6))) — a lambda!
# This is "partially applied Right" — still waiting for the r handler
# We then try to discriminate this with our observer, but it's one lambda short

# Let's observe more carefully with write markers at EVERY step
# Actually let's just print the raw output of pair(sys8) with different observers

# First: use QD directly on pair(sys8) result
# The result should be λb.(something)
prog = apps(
    g(201),
    NIL,
    lam(
        "bd_res",
        apps(
            v("bd_res"),
            lam(
                "pair",
                # pair(sys8) gives us the result
                # Then pass to QD for observation
                apps(v("pair"), g(8)),  # This is sys8(A, B) → B(Right(6)) → λb.partial
            ),
            lam("bd_err", write_str("BE")),
        ),
    ),
)
# Apply QD to the whole thing
db_term = to_db(prog)
payload = encode_term(db_term) + QD + bytes([FD, FF])
out = b""
try:
    with socket.create_connection((HOST, PORT), timeout=15) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        out = recv_all(sock, timeout_s=15)
except Exception as e:
    print(f"  error: {e}")

print(f"  pair(sys8) QD: {out.hex() if out else 'empty'}")
if out and out[-1:] == bytes([0xFF]):
    try:
        parsed = parse_term(out)
        print(f"  parsed: {pretty_term(parsed)}")
    except Exception as e:
        print(f"  parse error: {e}")
elif out:
    print(f"  raw: {out!r}")
time.sleep(0.3)

# Also: what if we apply pair(sys8) to TWO arguments (to complete the partial application)?
# pair(sys8)(left_handler)(right_handler) — should give us the error!
prog2 = apps(
    g(201),
    NIL,
    lam(
        "bd_res",
        apps(
            v("bd_res"),
            lam(
                "pair",
                apps(
                    apps(v("pair"), g(8)),  # pair(sys8) = B(Right(6)) = λb.partial
                    lam("left_val", write_str("SUCCESS!")),  # left handler
                    lam(
                        "right_val",  # right handler
                        apps(
                            g(1),
                            v("right_val"),
                            lam(
                                "err_res",
                                apps(
                                    v("err_res"),
                                    lam("errstr", apps(g(2), v("errstr"), NIL)),
                                    lam("_", write_str("?")),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            lam("bd_err", write_str("BE")),
        ),
    ),
)
out2 = query_named(prog2, timeout_s=15)
print(f"  pair(sys8)(left_h)(right_h): {out2!r}")
time.sleep(0.3)

print()
print("=" * 60)
print("ANALYSIS 4: What does quote actually do with Var > 252?")
print("=" * 60)

# The VM might handle large variable indices with a multi-byte encoding
# or might just silently wrap them. Let's see:
# quote(g(250)) vs quote(K(g(252))) vs quote(identity) for comparison

for label, term in [
    ("identity", lam("x", v("x"))),
    ("g(250)", g(250)),
    ("g(252)", g(252)),
    ("K=λλ.V1", NConst(Lam(Lam(Var(1))))),
]:
    obs = obs_with_quote()
    prog = apps(g(4), term, obs)
    out = query_named(prog)
    print(f"  quote({label}): {out!r}")
    time.sleep(0.2)

# Now the KEY test: quote(K(g(252))) — what does it actually output?
# We already got hex output. Let's get it cleanly.
obs = obs_with_quote()
K_comb = NConst(Lam(Lam(Var(1))))
prog = apps(g(4), apps(K_comb, g(252)), obs)
out = query_named(prog, timeout_s=15)
print(f"\n  quote(K(g(252))) full: {out!r}")
print(f"  hex: {out.hex()}")

# Does it start with L: (Left)?
if out.startswith(b"L:"):
    term_bytes = out[2:]
    print(f"  After 'L:' prefix: {term_bytes.hex()}")
    if term_bytes and term_bytes[-1] == 0xFF:
        try:
            parsed = parse_term(term_bytes)
            print(f"  Parsed term: {pretty_term(parsed)}")
        except Exception as e:
            print(f"  Parse error: {e}")
elif out.startswith(b"R:"):
    print(f"  Right (error): {out[2:]!r}")
time.sleep(0.3)

# Compare with K(g(251))
prog2 = apps(g(4), apps(K_comb, g(251)), obs)
out2 = query_named(prog2, timeout_s=15)
print(f"\n  quote(K(g(251))) full: {out2!r}")
if out2.startswith(b"L:"):
    term_bytes2 = out2[2:]
    if term_bytes2 and term_bytes2[-1] == 0xFF:
        try:
            parsed2 = parse_term(term_bytes2)
            print(f"  Parsed term: {pretty_term(parsed2)}")
        except Exception as e:
            print(f"  Parse error: {e}")

print()
print("=" * 60)
print("ANALYSIS 5: Do globals have internal structure?")
print("=" * 60)

# What does quote(g(N)) return for various N?
# This tells us if globals are atoms or compound terms
for gidx in [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
    obs = obs_with_quote()
    prog = apps(g(4), g(gidx), obs)
    out = query_named(prog)
    if out.startswith(b"L:"):
        term_part = out[2:]
        print(f"  quote(g({gidx})): bytes_after_L = {term_part.hex()}")
    elif out.startswith(b"R:"):
        print(f"  quote(g({gidx})): Right error: {out[2:]!r}")
    else:
        print(f"  quote(g({gidx})): {out!r}")
    time.sleep(0.2)

print("\nDone.")
