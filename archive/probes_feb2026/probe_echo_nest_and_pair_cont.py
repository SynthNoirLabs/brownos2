#!/usr/bin/env python3
"""
Probe: Nested echo (double/triple shift) + backdoor pair as continuation for sys8.

Key hypotheses:
  H1: Nested echo creates deeper shift (+4, +6) that hits Var(255)
  H2: Backdoor pair as CONTINUATION for sys8 (not argument)
  H3: Pass backdoor pair component as sys8 argument AND use other as continuation
  H4: Use echo to create a "kernel token" that only the backdoor can produce
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import App, Lam, Var, encode_term, encode_bytes_list

HOST = "wc3.wechall.net"
PORT = 61221
FF = 0xFF


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


def query_named(term, timeout_s=12.0, retries=3):
    payload = encode_term(to_db(term)) + bytes([FF])
    if len(payload) > 1800:
        print(f"    WARNING: payload size {len(payload)} bytes, approaching limit!")
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
def obs():
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
    left_handler = lam(
        "payload",
        apps(
            g(2),
            NConst(encode_bytes_list(b"LEFT!")),
            lam(
                "_w",
                # Also try to write a quote of the payload
                apps(
                    g(4),
                    v("payload"),
                    lam(
                        "qr",
                        apps(
                            v("qr"),
                            lam("qbytes", apps(g(2), v("qbytes"), NIL)),
                            lam("_qe", write_str("QF")),
                        ),
                    ),
                ),
            ),
        ),
    )
    return lam("res", apps(v("res"), left_handler, right_handler))


OBS = obs()

print("=" * 60)
print("PHASE 1: Nested echo → sys8 (without unwrapping)")
print("=" * 60)

# Test 1: echo(g(251)) → raw Left → sys8(raw_left)
# echo(g(251)) → Left(Var(253_shifted)) where inside Left: Var(253)
# Pass raw Left to sys8
prog1 = apps(
    g(14),
    g(251),
    lam(
        "echo1",  # echo1 = Left(shifted_251)
        apps(g(8), v("echo1"), OBS),
    ),
)
out1 = query_named(prog1)
print(f"  echo(g(251))→sys8(raw): {out1!r}")
time.sleep(0.3)

# Test 2: echo(g(252)) → raw Left → sys8(raw_left)
prog2 = apps(g(14), g(252), lam("echo1", apps(g(8), v("echo1"), OBS)))
out2 = query_named(prog2)
print(f"  echo(g(252))→sys8(raw): {out2!r}")
time.sleep(0.3)

# Test 3: NESTED echo — echo(echo(g(249))) → double Left → +4 shift → Var(253)
# echo(g(249)) → Left1(Var(251_shifted))
# echo(Left1) → Left2(shifted_Left1) — now inner has +4 total shift
prog3 = apps(
    g(14),
    g(249),
    lam("echo1", apps(g(14), v("echo1"), lam("echo2", apps(g(8), v("echo2"), OBS)))),
)
out3 = query_named(prog3)
print(f"  echo(echo(g(249)))→sys8(raw): {out3!r}")
time.sleep(0.3)

# Test 4: Triple echo — echo(echo(echo(g(247)))) → +6 shift
prog4 = apps(
    g(14),
    g(247),
    lam(
        "e1",
        apps(
            g(14),
            v("e1"),
            lam("e2", apps(g(14), v("e2"), lam("e3", apps(g(8), v("e3"), OBS)))),
        ),
    ),
)
out4 = query_named(prog4)
print(f"  echo^3(g(247))→sys8(raw): {out4!r}")
time.sleep(0.3)

# Test 5: echo(g(250)) nested to hit exactly 253
# echo(g(250)) → Left(... Var(252)...) — shifted by +2 inside Left
# echo of that → Left(Left(... Var(254)...)) — another +2
prog5 = apps(
    g(14), g(250), lam("e1", apps(g(14), v("e1"), lam("e2", apps(g(8), v("e2"), OBS))))
)
out5 = query_named(prog5)
print(f"  echo(echo(g(250)))→sys8(raw): {out5!r}")
time.sleep(0.3)

print()
print("=" * 60)
print("PHASE 2: Backdoor pair as CONTINUATION for sys8")
print("=" * 60)

# The pair from backdoor is: λsel. sel A B
# If pair is used as continuation: sys8(arg, pair) → pair(result) = result(A)(B)
# For Right(6): Right(6)(A)(B) = (λl.λr.r(int6))(A)(B) = B(int6)
# B = λa.λb.ab, so B(int6) = λb.int6(b)
# int6 is a 9-lambda byte term, so int6(b) reduces... but int6 expects 9 args
# So it's really: (λ^9.body)(b) → λ^8.body[b/V0] = still a function

# For Left(x): Left(x)(A)(B) = A(x)
# A = λa.λb.bb, so A(x) = λb.bb — ignores x!
# Then we need to apply this to something to see the result

# Test A: sys8(nil) with pair as continuation, then apply result to OBS
prog_a = apps(
    g(201),
    NIL,
    lam(
        "bd_res",
        apps(
            v("bd_res"),
            lam(
                "pair",
                # sys8(nil, pair) → pair(Right(6)) → Right(6)(A)(B) = B(int6) = λb.int6(b)
                # Then observe this result
                apps(g(8), NIL, v("pair")),
            ),
            lam("bd_err", write_str("BE")),
        ),
    ),
)
# Apply OBS to the whole expression
# Actually, in CPS, sys8(nil, pair) is the end of the chain.
# pair(result) produces something, but nothing observes it.
# We need a different approach.

# Let's make pair's A and B components write markers
# Actually, pair(result) = result(A)(B).
# For Right(6): B(int(6))... this goes nowhere useful.
# For Left(x): A(x) = λb.bb — also not useful for observation.

# Better: use pair as continuation, but wrap it to observe
prog_a2 = apps(
    g(201),
    NIL,
    lam(
        "bd_res",
        apps(
            v("bd_res"),
            lam(
                "pair",
                apps(
                    g(8),
                    NIL,
                    lam(
                        "sys8_res",
                        # sys8 returned sys8_res (which is Right(6))
                        # Now apply pair to sys8_res
                        apps(v("pair"), v("sys8_res")),
                    ),
                ),
            ),
            lam("bd_err", write_str("BE")),
        ),
    ),
)
out_a2 = query_named(prog_a2, timeout_s=15)
print(f"  A2: sys8(nil)→pair(result): {out_a2!r}")
time.sleep(0.3)

# Test B: Use pair component A as argument to sys8
# A = fst of pair = pair(true) where true = λa.λb.a
# B = snd of pair = pair(false) where false = λa.λb.b
K_true = lam("a", lam("b", v("a")))
K_false = lam("a", lam("b", v("b")))

# sys8(A, OBS) — already tested, but let me also try A applied to B as argument
prog_b = apps(
    g(201),
    NIL,
    lam(
        "bd_res",
        apps(
            v("bd_res"),
            lam(
                "pair",
                apps(
                    g(8),
                    # arg = A(B) = omega = λx.xx
                    # This will DIVERGE when evaluated!
                    # BUT: maybe sys8 doesn't evaluate its arg before checking?
                    # Skip this, it'll timeout.
                    # Instead: arg = pair itself
                    v("pair"),
                    # continuation = pair
                    v("pair"),
                ),
            ),
            lam("bd_err", write_str("BE")),
        ),
    ),
)
out_b = query_named(prog_b, timeout_s=15)
print(f"  B: sys8(pair, pair): {out_b!r}")
time.sleep(0.3)

# Test C: sys8 with A as continuation (not OBS)
# A = λa.λb.bb
# If sys8(nil, A): A(Right(6)) = (λa.λb.bb)(Right(6)) = λb.bb
# Then what? λb.bb is just a function waiting for an arg. Nothing writes.
# We need to observe it. Let's chain: sys8(nil, A) → result → write something
prog_c = apps(
    g(201),
    NIL,
    lam(
        "bd_res",
        apps(
            v("bd_res"),
            lam(
                "pair",
                apps(
                    g(8),
                    NIL,
                    # continuation: λresult. write("PRE") then [pair applied to result]
                    lam(
                        "sys8r",
                        apps(
                            g(2),
                            NConst(encode_bytes_list(b"PRE|")),
                            lam(
                                "_w",
                                # Now apply pair components creatively
                                # pair(sys8r) = sys8r(A)(B)
                                # If sys8r is Right(6): (λl.λr.r(int6))(A)(B) = B(int6) = λb.int6(b)
                                # If sys8r is Left(x): (λl.λr.l(x))(A)(B) = A(x) = λb.bb
                                apps(v("pair"), v("sys8r")),
                            ),
                        ),
                    ),
                ),
            ),
            lam("bd_err", write_str("BE")),
        ),
    ),
)
out_c = query_named(prog_c, timeout_s=15)
print(f"  C: sys8(nil)→PRE|→pair(result): {out_c!r}")
time.sleep(0.3)

print()
print("=" * 60)
print("PHASE 3: Use echo to CREATE the backdoor pair, then feed to sys8")
print("=" * 60)

# What if we echo the backdoor pair and the echo-wrapped version is what sys8 needs?
prog_d = apps(
    g(201),
    NIL,
    lam(
        "bd_res",
        apps(
            v("bd_res"),
            lam(
                "pair",
                # echo(pair) → Left(shifted_pair)
                apps(
                    g(14),
                    v("pair"),
                    lam("echoed_pair", apps(g(8), v("echoed_pair"), OBS)),
                ),
            ),
            lam("bd_err", write_str("BE")),
        ),
    ),
)
out_d = query_named(prog_d)
print(f"  D: echo(backdoor_pair)→sys8(echoed): {out_d!r}")
time.sleep(0.3)

# Echo the WHOLE backdoor result (Left(pair)) without unwrapping
# echo(backdoor_result) → Left(Left(pair_shifted))
prog_e = apps(
    g(201),
    NIL,
    lam(
        "bd_raw",  # this is Left(pair)
        apps(g(14), v("bd_raw"), lam("echoed", apps(g(8), v("echoed"), OBS))),
    ),
)
out_e = query_named(prog_e)
print(f"  E: echo(Left(pair))→sys8(echoed): {out_e!r}")
time.sleep(0.3)

print()
print("=" * 60)
print("PHASE 4: Completely different — sys8 with its OWN GLOBAL as argument")
print("=" * 60)

# What if sys8 needs to receive ITSELF?
# sys8(g(8), OBS) — "I am syscall 8, here is my ID"
prog_f = apps(g(8), g(8), OBS)
out_f = query_named(prog_f)
print(f"  F: sys8(g(8)): {out_f!r}")
time.sleep(0.3)

# sys8 with the integer 8
prog_g = apps(g(8), NConst(int_term(8)), OBS)
out_g = query_named(prog_g)
print(f"  G: sys8(int(8)): {out_g!r}")
time.sleep(0.3)

# sys8 with the byte list encoding of "8" → [0x08, 0xFF] (which is what quote returns for g(8))
prog_h = apps(g(8), NConst(encode_bytes_list(bytes([8, 0xFF]))), OBS)
out_h = query_named(prog_h)
print(f"  H: sys8([0x08, 0xFF]): {out_h!r}")
time.sleep(0.3)

# sys8 with just byte [8]
prog_i = apps(g(8), NConst(encode_bytes_list(bytes([8]))), OBS)
out_i = query_named(prog_i)
print(f"  I: sys8([0x08]): {out_i!r}")
time.sleep(0.3)

print()
print("=" * 60)
print("PHASE 5: What if sys8's arg must be a PROGRAM (byte list)?")
print("=" * 60)

# What if sys8 is like an eval() — it takes bytecode and executes it?
# The argument should be a byte list encoding a program.
# If we give it the bytes for a simple program like "towel"...
# towel = g(42) nil QD → bytes: 2A 00FE FE FD QD FD FF
# As a byte list: [0x2A, 0x00, 0xFE, 0xFE, 0xFD, <QD bytes>, 0xFD, 0xFF]

# Actually, let's try something simpler: the byte encoding of "write('hello')"
# or even just a simple term

# First: sys8 with byte list [0xFF] (just end marker)
prog_j = apps(g(8), NConst(encode_bytes_list(bytes([0xFF]))), OBS)
out_j = query_named(prog_j)
print(f"  J: sys8([0xFF]): {out_j!r}")
time.sleep(0.3)

# sys8 with byte list encoding of nil: [0x00, 0xFE, 0xFE, 0xFF]
prog_k = apps(g(8), NConst(encode_bytes_list(bytes([0x00, 0xFE, 0xFE, 0xFF]))), OBS)
out_k = query_named(prog_k)
print(f"  K: sys8(bytes_of_nil): {out_k!r}")
time.sleep(0.3)

# sys8 with the byte list encoding of sys8 itself: [0x08, 0xFF]
prog_l = apps(g(8), NConst(encode_bytes_list(bytes([0x08, 0xFF]))), OBS)
out_l = query_named(prog_l)
print(f"  L: sys8([0x08, 0xFF] = 'sys8' bytecode): {out_l!r}")
time.sleep(0.3)

# sys8 with the encoded QD continuation
qd_bytes = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
prog_m = apps(g(8), NConst(encode_bytes_list(qd_bytes)), OBS)
out_m = query_named(prog_m)
print(f"  M: sys8(QD_bytes): {out_m!r}")
time.sleep(0.3)

# sys8 with the full cheat sheet first example: QD + 2A 00FEFE FD + QD + FD FF
# This is "towel output via QD"
full_prog_bytes = (
    bytes([0x2A])
    + bytes([0x00, 0xFE, 0xFE])
    + bytes([0xFD])
    + qd_bytes
    + bytes([0xFD, 0xFF])
)
prog_n = apps(g(8), NConst(encode_bytes_list(full_prog_bytes)), OBS)
out_n = query_named(prog_n)
print(f"  N: sys8(full_towel_program_bytes): {out_n!r}")
time.sleep(0.3)

print()
print("=" * 60)
print("PHASE 6: Use READFILE to get sys8's own bytecode, feed it to sys8")
print("=" * 60)

# readfile(8) → this is /bin/solution
# We know readfile(8) returns Right (error) — BUT what error code?
prog_rf = apps(
    g(7),
    NConst(int_term(8)),
    lam(
        "res",
        apps(
            v("res"),
            lam("content", write_str("GOT_CONTENT!")),
            lam(
                "err",
                apps(
                    g(1),
                    v("err"),
                    lam(
                        "err_str_res",
                        apps(
                            v("err_str_res"),
                            lam("s", apps(g(2), v("s"), NIL)),
                            lam("_", write_str("??")),
                        ),
                    ),
                ),
            ),
        ),
    ),
)
out_rf = query_named(prog_rf)
print(f"  readfile(8): {out_rf!r}")
time.sleep(0.3)

# Also check: name(8) — what's the name of entry 8?
prog_name = apps(
    g(6),
    NConst(int_term(8)),
    lam(
        "res",
        apps(
            v("res"),
            lam("name_bytes", apps(g(2), v("name_bytes"), NIL)),
            lam("err", write_str("NAME_ERR")),
        ),
    ),
)
out_name = query_named(prog_name)
print(f"  name(8): {out_name!r}")
time.sleep(0.3)

print("\nDone.")
