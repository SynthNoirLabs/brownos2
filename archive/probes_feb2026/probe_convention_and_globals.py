#!/usr/bin/env python3
"""
Probe: Varied calling conventions for sys8 + exploring non-implemented globals.

Key tests:
1. sys8 with swapped argument order (continuation first, then arg)
2. sys8 with 3+ arguments
3. sys8 with syscall globals as continuation (g(2), g(4), etc.)
4. sys8 bare application (no continuation)
5. Non-implemented globals with different arities
6. sys8 with results from other syscalls as unforgeable tokens
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import App, Lam, Var, encode_term, encode_bytes_list, QD, FF

HOST = "wc3.wechall.net"
PORT = 61221


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


def query_named(term, timeout_s=10.0, retries=2):
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


def query_raw(payload_bytes, timeout_s=10.0, retries=2):
    """Send raw bytes (must include FF terminator)."""
    delay = 0.2
    for attempt in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload_bytes)
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


def obs():
    """Quote-free observer: Left→'L:', Right→error string"""
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
    left_handler = lam("_payload", write_str("LEFT!"))
    return lam("res", apps(v("res"), left_handler, right_handler))


OBS = obs()

# ========== PHASE 1: Varied calling conventions for sys8 ==========
print("=" * 60)
print("PHASE 1: Varied calling conventions for sys8")
print("=" * 60)

# Standard: sys8(nil, OBS) = ((g(8) nil) OBS) — known: Permission denied
# Already confirmed many times. Skip.

# Test A: What if sys8 expects: ((g(8) continuation) arg)?
# i.e., sys8(OBS, nil) — swapped order
prog_a = apps(g(8), OBS, NIL)
out_a = query_named(prog_a)
print(f"  A: sys8(OBS, nil) [swapped]: {out_a!r}")
time.sleep(0.3)

# Test B: sys8 with 3 arguments: sys8(arg1, arg2, continuation)
prog_b = apps(g(8), NIL, NIL, OBS)
out_b = query_named(prog_b)
print(f"  B: sys8(nil, nil, OBS) [3 args]: {out_b!r}")
time.sleep(0.3)

# Test C: sys8 with 4 arguments
prog_c = apps(g(8), NIL, NIL, NIL, OBS)
out_c = query_named(prog_c)
print(f"  C: sys8(nil, nil, nil, OBS) [4 args]: {out_c!r}")
time.sleep(0.3)

# Test D: sys8 bare (just g(8) alone, observed with QD)
# Apply QD to g(8):  g(8) QD FD FF
db_d = to_db(g(8))
payload_d = encode_term(db_d) + QD + bytes([0xFD, 0xFF])
out_d = query_raw(payload_d)
print(f"  D: g(8) QD [bare]: {out_d.hex() if out_d else 'empty'}")
time.sleep(0.3)

# Test E: sys8 with just one arg and no continuation, observed outside
# g(8)(nil) → this should be a partially applied function
# Apply QD: g(8)(nil) QD
prog_e = apps(g(8), NIL)
db_e = to_db(prog_e)
payload_e = encode_term(db_e) + QD + bytes([0xFD, 0xFF])
out_e = query_raw(payload_e)
print(f"  E: g(8)(nil) QD [partial]: {out_e.hex() if out_e else 'empty'}")
time.sleep(0.3)

# Test F: g(2) (write) as continuation for sys8
# sys8(nil, g(2)): if sys8 returns Left(bytes), g(2)(Left(bytes)) = write(Left_term)
# If sys8 returns Right(6), g(2)(Right(6)) = write(Right_term)
# Either way, write will try to output the Either as bytes... which won't work as expected
# But might produce interesting output!
prog_f = apps(g(8), NIL, g(2))
out_f = query_named(prog_f, timeout_s=15)
print(f"  F: sys8(nil, g(2)=write): {out_f!r}")
time.sleep(0.3)

# Test G: g(4) (quote) as continuation
# sys8(nil, g(4)): quote(Right(6)) → Left(bytes_encoding_of_Right6)
# This is interesting — it quotes the RESULT of sys8
prog_g = apps(g(8), NIL, g(4))
out_g = query_named(prog_g, timeout_s=15)
print(f"  G: sys8(nil, g(4)=quote): {out_g!r}")
time.sleep(0.3)

# Test H: g(14) (echo) as continuation
# sys8(nil, g(14)): echo(Right(6)) → Left(Right(6))
prog_h = apps(g(8), NIL, g(14))
out_h = query_named(prog_h, timeout_s=15)
print(f"  H: sys8(nil, g(14)=echo): {out_h!r}")
time.sleep(0.3)

# Test I: g(1) (error_string) as continuation
# sys8(nil, g(1)): error_string(Right(6)) → ???
# error_string expects an integer, not an Either. Might get InvalidArg
prog_i = apps(g(8), NIL, g(1))
out_i = query_named(prog_i, timeout_s=15)
print(f"  I: sys8(nil, g(1)=error_str): {out_i!r}")
time.sleep(0.3)

# Test J: g(8) as its OWN continuation
# sys8(nil, g(8)): sys8(Right(6)) → sys8 with Either as arg
prog_j = apps(g(8), NIL, g(8))
out_j = query_named(prog_j, timeout_s=15)
print(f"  J: sys8(nil, g(8)=self): {out_j!r}")
time.sleep(0.3)

# Test K: g(42) (towel) as continuation
prog_k = apps(g(8), NIL, g(42))
out_k = query_named(prog_k, timeout_s=15)
print(f"  K: sys8(nil, g(42)=towel): {out_k!r}")
time.sleep(0.3)

# Test L: g(201) (backdoor) as continuation
# sys8(nil, g(201)): backdoor(Right(6)) → expects nil, so InvalidArg
prog_l = apps(g(8), NIL, g(201))
out_l = query_named(prog_l, timeout_s=15)
print(f"  L: sys8(nil, g(201)=backdoor): {out_l!r}")
time.sleep(0.3)

# Test M: sys8 with g(0) as continuation (diverges)
# sys8(nil, g(0)): g(0)(Right(6)) → diverges (already known g(0) diverges for all)
# But what if sys8 produces a SIDE EFFECT before calling continuation?
# We'd see output before the diverge!
prog_m_prefix = apps(
    g(2), NConst(encode_bytes_list(b"PRE|")), lam("_", apps(g(8), NIL, g(0)))
)
out_m = query_named(prog_m_prefix, timeout_s=15)
print(f"  M: PRE|→sys8(nil, g(0)=diverge): {out_m!r}")
time.sleep(0.3)

print()
print("=" * 60)
print("PHASE 2: Non-implemented globals with different arities")
print("=" * 60)

# Test g(9), g(10), g(11), g(12), g(13) with 0, 1, 2, 3 args
# These are "Not implemented" as syscalls — but what if they do something with more/fewer args?
for gidx in [3, 9, 10, 11, 12, 13, 15, 16, 17, 18, 19, 20]:
    # 0 args: just g(i) observed with QD
    db0 = to_db(g(gidx))
    payload0 = encode_term(db0) + QD + bytes([0xFD, 0xFF])
    out0 = query_raw(payload0, timeout_s=8)

    # 1 arg: g(i)(nil) with OBS
    out1 = query_named(apps(g(gidx), NIL, OBS), timeout_s=8)

    # 2 args: g(i)(nil, nil) with OBS
    out2 = query_named(apps(g(gidx), NIL, NIL, OBS), timeout_s=8)

    label0 = out0.hex()[:20] if out0 else "empty"
    label1 = out1.decode("latin-1", errors="replace")[:30] if out1 else "empty"
    label2 = out2.decode("latin-1", errors="replace")[:30] if out2 else "empty"

    print(f"  g({gidx:3d}): 0args={label0}  1arg={label1}  2args={label2}")
    time.sleep(0.2)

print()
print("=" * 60)
print("PHASE 3: sys8 with unforgeable tokens from other syscalls")
print("=" * 60)

# Get towel output (a string) and feed to sys8
prog_t = apps(
    g(42),
    NIL,
    lam(
        "towel_res",
        apps(
            v("towel_res"),
            lam("towel_str", apps(g(8), v("towel_str"), OBS)),
            lam("towel_err", write_str("TE")),
        ),
    ),
)
out_t = query_named(prog_t)
print(f"  sys8(towel_string): {out_t!r}")
time.sleep(0.3)

# Get name(0) = "/" and feed to sys8
prog_n = apps(
    g(6),
    NConst(int_term(0)),
    lam(
        "name_res",
        apps(
            v("name_res"),
            lam("name_str", apps(g(8), v("name_str"), OBS)),
            lam("name_err", write_str("NE")),
        ),
    ),
)
out_n = query_named(prog_n)
print(f"  sys8(name('/'))): {out_n!r}")
time.sleep(0.3)

# Get readdir(0) = directory listing and feed to sys8
prog_rd = apps(
    g(5),
    NConst(int_term(0)),
    lam(
        "rd_res",
        apps(
            v("rd_res"),
            lam("dir_list", apps(g(8), v("dir_list"), OBS)),
            lam("rd_err", write_str("RE")),
        ),
    ),
)
out_rd = query_named(prog_rd)
print(f"  sys8(readdir(0)): {out_rd!r}")
time.sleep(0.3)

# Get error_string(6) = "Permission denied" and feed back to sys8
prog_es = apps(
    g(1),
    NConst(int_term(6)),
    lam(
        "es_res",
        apps(
            v("es_res"),
            lam("errstr", apps(g(8), v("errstr"), OBS)),
            lam("es_err", write_str("EE")),
        ),
    ),
)
out_es = query_named(prog_es)
print(f"  sys8(error_string(6)): {out_es!r}")
time.sleep(0.3)

# Get readfile(11) = /etc/passwd content and feed to sys8
prog_pw = apps(
    g(7),
    NConst(int_term(11)),
    lam(
        "pw_res",
        apps(
            v("pw_res"),
            lam("pw_bytes", apps(g(8), v("pw_bytes"), OBS)),
            lam("pw_err", write_str("PE")),
        ),
    ),
)
out_pw = query_named(prog_pw)
print(f"  sys8(passwd_content): {out_pw!r}")
time.sleep(0.3)

# Get readfile(88) = mail spool and feed to sys8
prog_mail = apps(
    g(7),
    NConst(int_term(88)),
    lam(
        "ml_res",
        apps(
            v("ml_res"),
            lam("ml_bytes", apps(g(8), v("ml_bytes"), OBS)),
            lam("ml_err", write_str("ME")),
        ),
    ),
)
out_mail = query_named(prog_mail)
print(f"  sys8(mail_content): {out_mail!r}")
time.sleep(0.3)

# Get access.log and feed to sys8
prog_al = apps(
    g(7),
    NConst(int_term(46)),
    lam(
        "al_res",
        apps(
            v("al_res"),
            lam("al_bytes", apps(g(8), v("al_bytes"), OBS)),
            lam("al_err", write_str("AE")),
        ),
    ),
)
out_al = query_named(prog_al)
print(f"  sys8(access_log): {out_al!r}")
time.sleep(0.3)

# Get .history content and feed to sys8
prog_hist = apps(
    g(7),
    NConst(int_term(65)),
    lam(
        "h_res",
        apps(
            v("h_res"),
            lam("h_bytes", apps(g(8), v("h_bytes"), OBS)),
            lam("h_err", write_str("HE")),
        ),
    ),
)
out_hist = query_named(prog_hist)
print(f"  sys8(.history): {out_hist!r}")
time.sleep(0.3)

print()
print("=" * 60)
print("PHASE 4: sys8 with the RAW Either results (not unwrapped)")
print("=" * 60)

# What if sys8 needs to receive the ENTIRE Either from another syscall?
# towel returns Left(string) — pass that whole Either to sys8
prog_rt = apps(g(42), NIL, lam("towel_either", apps(g(8), v("towel_either"), OBS)))
out_rt = query_named(prog_rt)
print(f"  sys8(towel_raw_either): {out_rt!r}")
time.sleep(0.3)

# error_string raw
prog_res = apps(
    g(1), NConst(int_term(0)), lam("es_either", apps(g(8), v("es_either"), OBS))
)
out_res = query_named(prog_res)
print(f"  sys8(error_string_raw_either): {out_res!r}")
time.sleep(0.3)

# backdoor raw
prog_rbd = apps(g(201), NIL, lam("bd_either", apps(g(8), v("bd_either"), OBS)))
out_rbd = query_named(prog_rbd)
print(f"  sys8(backdoor_raw_either): {out_rbd!r}")
time.sleep(0.3)

# quote raw
prog_rq = apps(g(4), NIL, lam("q_either", apps(g(8), v("q_either"), OBS)))
out_rq = query_named(prog_rq)
print(f"  sys8(quote_raw_either): {out_rq!r}")
time.sleep(0.3)

# echo raw
prog_re = apps(g(14), NIL, lam("e_either", apps(g(8), v("e_either"), OBS)))
out_re = query_named(prog_re)
print(f"  sys8(echo_raw_either): {out_re!r}")
time.sleep(0.3)

print("\nDone.")
