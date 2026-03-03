#!/usr/bin/env python3
"""
probe_stub_typed.py — Sweep stub globals with typed real-world inputs.

Prior sweeps used only {nil, int0, int1} as arguments.
This sweep routes typed values (strings, dirs, pairs, bytecode)
through the CPS adapter C_g = λr. r(g)(K*) into each stub global.

The 11 known-active globals: 0,1,2,4,5,6,7,8,14,42,201
All other globals 3..252 (excl. known) = stubs, returned Right(1) = "Not implemented"

Decision rule: ANY response other than Right(1)/EMPTY/parse-errors = NOVEL.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE
FF = 0xFF
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

KNOWN_ACTIVE = {0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201}
# All stubs: 0..252 minus known-active
STUBS = [g for g in range(253) if g not in KNOWN_ACTIVE]


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


def encode_term(t):
    if isinstance(t, Var):
        return bytes([t.i])
    if isinstance(t, Lam):
        return encode_term(t.body) + bytes([FE])
    if isinstance(t, App):
        return encode_term(t.f) + encode_term(t.x) + bytes([FD])
    raise TypeError(f"bad: {type(t)}")


def parse_term(data):
    stack = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    if len(stack) != 1:
        raise ValueError(f"stack={len(stack)}")
    return stack[0]


_last = 0.0


def query(payload, retries=3, timeout_s=5.0):
    global _last
    gap = 0.35
    now = time.time()
    if now - _last < gap:
        time.sleep(gap - (now - _last))
    delay = 0.3
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                sock.settimeout(timeout_s)
                out = b""
                try:
                    while True:
                        c = sock.recv(4096)
                        if not c:
                            break
                        out += c
                        if FF in c:
                            break
                except socket.timeout:
                    pass
                _last = time.time()
                return out
        except Exception as e:
            time.sleep(delay)
            delay *= 2
    return b""


def encode_byte_term(n):
    expr = Var(0)
    for idx, w in ((1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)):
        if n & w:
            expr = App(Var(idx), expr)
    t = expr
    for _ in range(9):
        t = Lam(t)
    return t


def big_int(n):
    expr = Var(0)
    remaining = n
    for idx, w in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        while remaining >= w:
            expr = App(Var(idx), expr)
            remaining -= w
    t = expr
    for _ in range(9):
        t = Lam(t)
    return t


KSTAR = Lam(Lam(Var(0)))
N0 = encode_byte_term(0)
N11 = encode_byte_term(11)
N65 = encode_byte_term(65)
N256 = big_int(256)
N0_dir = encode_byte_term(0)  # root dir id

# Globals
G_NAME = 6
G_READFILE = 7
G_READDIR = 5
G_BACKDOOR = 201
G_QUOTE = 4
G_SYS8 = 8


def make_C_left(g: int) -> object:
    """C_g = λr. r(Var(g+1))(K*)  — routes Left(x) into g(x)(K*)"""
    return Lam(App(App(Var(0), Var(g + 1)), KSTAR))


def make_R_right(g: int) -> object:
    """R_g = λr. r(K*)(Var(g+1))  — routes Right(y) into g(y)(K*)"""
    return Lam(App(App(Var(0), KSTAR), Var(g + 1)))


def make_QD_cont() -> bytes:
    """Returns QD bytes (used as continuation to observe raw result)."""
    return QD


# ── Input producers (each yields (label, bytes)) ──────────────────────────────
def build_input_matrix(stub_g: int) -> list[tuple[str, bytes]]:
    """
    Build the 11-probe typed input matrix for stub global g.
    We use C_g = λr. r(g_shifted)(K*) as the continuation, except for
    the final two which use R_g for Right-type inputs.

    Payloads are raw programs (not QD-wrapped) so we get live output
    if the stub produces output.  Each payload is:
      (((producer arg) C_g) K*)   — Left-routing variant
      (((producer arg) R_g) K*)   — Right-routing variant
    """
    C_g = make_C_left(stub_g)
    R_g = make_R_right(stub_g)

    rows = []

    def add(label: str, producer_g: int, arg: object, adapter: object):
        enc_producer_arg = encode_term(App(Var(producer_g), arg))
        enc_C = encode_term(adapter)
        payload = (
            enc_producer_arg
            + enc_C
            + bytes([FD])
            + encode_term(KSTAR)
            + bytes([FD, FF])
        )
        rows.append((label, payload))

    # Left-producers → C_g
    add("name(/)→Cg", G_NAME, N0_dir, C_g)  # passes string "/"
    add("name(wtf)→Cg", G_NAME, N256, C_g)  # passes string "wtf"
    add("readfile(11)→Cg", G_READFILE, N11, C_g)  # passes /etc/passwd content
    add("readfile(65)→Cg", G_READFILE, N65, C_g)  # passes .history content
    add("readfile(256)→Cg", G_READFILE, N256, C_g)  # passes "Uhm... yeah... no...\n"
    add("readdir(0)→Cg", G_READDIR, N0_dir, C_g)  # passes dir3 (root listing)
    add("backdoor(K*)→Cg", G_BACKDOOR, KSTAR, C_g)  # passes pair(A,B)
    # quote(Var(8)) = bytecode of sys8 — passes bytecode
    add("quote(sys8)→Cg", G_QUOTE, Var(G_SYS8), C_g)

    # Right-producers → R_g
    add("sys8(N0)→Rg", G_SYS8, N0, R_g)  # passes Right(6) = error code 6
    add("readdir(256)→Rg", G_READDIR, N256, R_g)  # passes Right(4) = error code 4

    return rows


# Baseline: test stub with nil (the old sweep's input) for comparison
def build_baseline(stub_g: int) -> list[tuple[str, bytes]]:
    rows = []
    # ((g nil) QD)
    payload = bytes([stub_g]) + encode_term(KSTAR) + bytes([FD]) + QD + bytes([FD, FF])
    rows.append(("g(nil)→QD", payload))
    # ((g int0) QD)
    payload = bytes([stub_g]) + encode_term(N0) + bytes([FD]) + QD + bytes([FD, FF])
    rows.append(("g(N0)→QD", payload))
    return rows


# ── Classify response ──────────────────────────────────────────────────────────

# Right(1) raw bytes from QD (the known "Not implemented" response)
RIGHT1_HEX = "000100fdfefefefefefefefefefdfefeff"


def classify(raw: bytes) -> str:
    if not raw:
        return "EMPTY"
    h = raw.hex()
    if h == RIGHT1_HEX:
        return "RIGHT1"
    if "00030200fdfdfefefefefefefefefefdfefeff" in h:
        return "RIGHT6"
    if "000200fdfefefefefefefefefefdfefeff" in h:
        return "RIGHT2"
    if "000300fdfefefefefefefefefefdfefeff" in h:
        return "RIGHT3"
    if "000400fdfefefefefefefefefefdfefeff" in h:
        return "RIGHT4"
    try:
        text = raw.decode("ascii", errors="replace")
        if "Invalid term" in text:
            return "INVALID"
        if "Encoding failed" in text:
            return "ENC_FAIL"
        if "Term too big" in text:
            return "TOO_BIG"
        if "Permission denied" in text:
            return "PERM_DENIED"
        if "Invalid argument" in text:
            return "INVALID_ARG"
        if "Not implemented" in text:
            return "NOT_IMPL"
        if "Not a directory" in text:
            return "NOT_DIR"
        if "No such file" in text:
            return "NO_FILE"
        printable = all(
            0x20 <= b <= 0x7E or b in (0x0A, 0x0D) for b in raw if b != 0xFF
        )
        if printable and len(raw) < 300:
            return f"TEXT:{raw.replace(bytes([0xFF]), b'').decode('ascii', 'replace').strip()!r}"
    except Exception:
        pass
    if FF in raw:
        return f"TERM:{raw[: raw.index(FF)].hex()[:60]}"
    return f"RAW:{raw[:30].hex()}"


def is_novel(r: str) -> bool:
    boring = {
        "RIGHT1",
        "EMPTY",
        "NOT_IMPL",
        "INVALID",
        "ENC_FAIL",
        "TOO_BIG",
        "INVALID_ARG",
    }
    return r not in boring


# ── Main ──────────────────────────────────────────────────────────────────────


def main():
    print("=" * 70)
    print(f"STUB TYPED-INPUT SWEEP — {len(STUBS)} stubs × 10 typed inputs each")
    print(f"Decision: any non-RIGHT1/EMPTY/error = NOVEL")
    print("=" * 70)

    novels = []
    total = 0
    boring = 0

    # Quick baseline sanity: verify Right(1) for a few known stubs
    print("\n--- Baseline sanity (3,9,10,11,13 should be Right(1)) ---")
    for g in [3, 9, 10, 11, 13]:
        payload = bytes([g]) + encode_term(KSTAR) + bytes([FD]) + QD + bytes([FD, FF])
        raw = query(payload, retries=2)
        print(f"  g={g}: {classify(raw)}")

    print(
        f"\n--- Typed sweep ({len(STUBS)} stubs × 10 probes = {len(STUBS) * 10} tests) ---"
    )

    for g in STUBS:
        matrix = build_input_matrix(g)
        g_novels = []
        for label, payload in matrix:
            raw = query(payload, retries=2)
            result = classify(raw)
            total += 1
            if is_novel(result):
                print(f"  *** NOVEL g=0x{g:02x}={g} [{label}]: {result}")
                print(f"      payload: {payload.hex()}")
                g_novels.append((label, payload.hex(), result))
                novels.append((g, label, payload.hex(), result))
            else:
                boring += 1
            if total % 200 == 0:
                print(f"  [{total}/{len(STUBS) * 10}] g={g} latest={result}")

    print("\n" + "=" * 70)
    print(f"DONE: {total} tests, {boring} boring, {len(novels)} NOVEL")
    print("=" * 70)

    if novels:
        print(f"\n!!! {len(novels)} NOVEL RESULTS !!!")
        for g, label, phex, result in novels:
            print(f"\n  g=0x{g:02x}={g} [{label}]")
            print(f"  payload: {phex}")
            print(f"  result:  {result}")
    else:
        print("\nAll stubs still boring with typed inputs.")
        print("→ Stub-as-gated-primitive hypothesis weakens significantly.")


if __name__ == "__main__":
    main()
