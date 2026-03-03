#!/usr/bin/env python3
"""
probe_3leaf_continuations.py — Systematic 3-leaf continuation sweep.

Focus: Does ANY 3-leaf term T make sys8(N0)(T) return non-Right(6)?

The LLM hypothesis: "3 leafs" hints at the SHAPE of the program, not
a new argument. The existing sweeps tested 3-leaf terms as PROGRAMS
(with QD appended), not as CONTINUATIONS given to producers.

This probe tests all 6 canonical 1-lambda forms as continuations:
  Form 1: λr. ((r a) b)      — C_g family [partially tested, only b=K*]
  Form 2: λr. (r (a b))      — UNTESTED
  Form 3: λr. ((a r) b)      — UNTESTED
  Form 4: λr. (a (r b))      — UNTESTED
  Form 5: λr. ((a b) r)      — Rerr-like [partially tested, only a=K*,b=err_str]
  Form 6: λr. (a (b r))      — UNTESTED

Plus 0-lambda right-assoc: App(Var(a), App(Var(b), Var(c)))  — UNTESTED
And 2-lambda forms.

Strategy:
  Phase 1: sys8(N0)(T) for ALL 6 forms × interesting globals — primary
  Phase 2: echo(N256)(T) as control (to verify T parses correctly)
  Phase 3: Same T with readfile(11) as producer (for Left-handling forms)
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

# Standard Right(6) response bytes (from QD output)
RIGHT6_QD = bytes.fromhex("00030200fdfdfefefefefefefefefefdfefeff")


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


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported: {type(term)}")


def parse_term(data: bytes) -> object:
    stack: list[object] = []
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
        raise ValueError(f"Stack size {len(stack)}")
    return stack[0]


def recv_until_ff(sock: socket.socket, timeout_s: float = 5.0) -> bytes:
    sock.settimeout(timeout_s)
    out = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
            if FF in chunk:
                break
    except socket.timeout:
        pass
    return out


_last_query = 0.0


def query(payload: bytes, retries: int = 3, timeout_s: float = 5.0) -> bytes:
    global _last_query
    gap = 0.35
    now = time.time()
    if now - _last_query < gap:
        time.sleep(gap - (now - _last_query))
    delay = 0.3
    last_err = None
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                result = recv_until_ff(sock, timeout_s=timeout_s)
                _last_query = time.time()
                return result
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed: {last_err}")


def encode_byte_term(n: int) -> object:
    expr: object = Var(0)
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
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def big_int(n: int) -> object:
    expr: object = Var(0)
    remaining = n
    for idx, w in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        while remaining >= w:
            expr = App(Var(idx), expr)
            remaining -= w
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}

N0 = encode_byte_term(0)
N11 = encode_byte_term(11)
N256 = big_int(256)
KSTAR = Lam(Lam(Var(0)))

# ──────────────────────────────────────────────────
# Globals
# ──────────────────────────────────────────────────
G_EXCEPTION = 0
G_ERROR_STRING = 1
G_WRITE = 2
G_QUOTE = 4
G_READDIR = 5
G_NAME = 6
G_READFILE = 7
G_SYS8 = 8
G_ECHO = 14
G_BACKDOOR = 201

GLOBAL_NAMES = {
    0: "exc",
    1: "err_str",
    2: "write",
    4: "quote",
    5: "readdir",
    6: "name",
    7: "readfile",
    8: "sys8",
    14: "echo",
    201: "backdoor",
}

# All "interesting" globals for sweep
# Primary: all known syscalls
INTERESTING_GLOBALS = [0, 1, 2, 4, 5, 6, 7, 8, 14, 201]

# Secondary: extended (for phase 2)
EXTENDED_GLOBALS = list(range(0, 16)) + [42, 201]


# ──────────────────────────────────────────────────
# 3-leaf continuation generators
# ──────────────────────────────────────────────────
# All forms: λr. body  where r = Var(0) inside lambda,
# a = Var(a_glob + 1), b = Var(b_glob + 1)  (shifted by 1 lambda depth)


def form1(a_glob: int, b_glob: int) -> object:
    """λr. ((r a) b) — C_g family"""
    return Lam(App(App(Var(0), Var(a_glob + 1)), Var(b_glob + 1)))


def form2(a_glob: int, b_glob: int) -> object:
    """λr. (r (a b))"""
    return Lam(App(Var(0), App(Var(a_glob + 1), Var(b_glob + 1))))


def form3(a_glob: int, b_glob: int) -> object:
    """λr. ((a r) b) = a(r)(b)"""
    return Lam(App(App(Var(a_glob + 1), Var(0)), Var(b_glob + 1)))


def form4(a_glob: int, b_glob: int) -> object:
    """λr. (a (r b)) = a(r(b))"""
    return Lam(App(Var(a_glob + 1), App(Var(0), Var(b_glob + 1))))


def form5(a_glob: int, b_glob: int) -> object:
    """λr. ((a b) r) = a(b)(r) — Rerr family"""
    return Lam(App(App(Var(a_glob + 1), Var(b_glob + 1)), Var(0)))


def form6(a_glob: int, b_glob: int) -> object:
    """λr. (a (b r)) = a(b(r))"""
    return Lam(App(Var(a_glob + 1), App(Var(b_glob + 1), Var(0))))


# 0-lambda forms (free vars only, as direct terms)
def form0_left(a_glob: int, b_glob: int, c_glob: int) -> object:
    """App(App(Var(a), Var(b)), Var(c)) — left-assoc [extensively tested]"""
    return App(App(Var(a_glob), Var(b_glob)), Var(c_glob))


def form0_right(a_glob: int, b_glob: int, c_glob: int) -> object:
    """App(Var(a), App(Var(b), Var(c))) — right-assoc [UNTESTED as continuation]"""
    return App(Var(a_glob), App(Var(b_glob), Var(c_glob)))


# 2-lambda forms (bound vars: Var(0)=inner, Var(1)=outer)
# Pattern: λa.λb. body  where a=Var(1), b=Var(0)
# Free globals shifted by +2
def form2lam_selector_left(c_glob: int) -> object:
    """λa.λb. a  — K combinator, ignores b, returns a (Left handler)"""
    return Lam(Lam(Var(1)))  # K, but no free globals → not 3-leaf


def form2lam_rr(a_glob: int) -> object:
    """λa.λb. a(b) — B-like with free a, b bound. But a,b bound → only 1 free Var."""
    # λa.λb. Var(a_glob+2)(Var(0)) — uses free global a_glob
    return Lam(
        Lam(App(Var(a_glob + 2), Var(0)))
    )  # 2 leaves: a_glob+2 and Var(0)... only 2 leaves


# Actually 2-lambda with 3 leaves needs more structure:
# λa.λb. ((g a) b) — g is free glob, a,b are bound
def form2lam_gab(g_glob: int) -> object:
    """λa.λb. ((g a) b) — g=free, a=Var(1), b=Var(0). 3 leaves."""
    return Lam(Lam(App(App(Var(g_glob + 2), Var(1)), Var(0))))


# λa.λb. (a (g b)) — g=free, a=Var(1), b=Var(0). 3 leaves.
def form2lam_agb(g_glob: int) -> object:
    """λa.λb. (a (g b))"""
    return Lam(Lam(App(Var(1), App(Var(g_glob + 2), Var(0)))))


# λa.λb. (g (a b)) — g=free, a=Var(1), b=Var(0). 3 leaves.
def form2lam_gab2(g_glob: int) -> object:
    """λa.λb. (g (a b))"""
    return Lam(Lam(App(Var(g_glob + 2), App(Var(1), Var(0)))))


# λa.λb. ((a b) g) — g=free, a=Var(1), b=Var(0). 3 leaves.
def form2lam_abg(g_glob: int) -> object:
    """λa.λb. ((a b) g)"""
    return Lam(Lam(App(App(Var(1), Var(0)), Var(g_glob + 2))))


# λa.λb. (a (b g)) — g=free, a=Var(1), b=Var(0). 3 leaves.
def form2lam_abg2(g_glob: int) -> object:
    """λa.λb. (a (b g))"""
    return Lam(Lam(App(Var(1), App(Var(0), Var(g_glob + 2)))))


# λa.λb. ((b g) a) — g=free, a=Var(1), b=Var(0). 3 leaves.
def form2lam_bga(g_glob: int) -> object:
    """λa.λb. ((b g) a)"""
    return Lam(Lam(App(App(Var(0), Var(g_glob + 2)), Var(1))))


# ──────────────────────────────────────────────────
# Classify response
# ──────────────────────────────────────────────────


def classify(raw: bytes) -> str:
    if not raw:
        return "EMPTY"
    try:
        text = raw.decode("ascii", errors="replace")
        if "Invalid term" in text:
            return "INVALID"
        if "Encoding failed" in text:
            return "ENCODING_FAIL"
        if "Term too big" in text:
            return "TOO_BIG"
        if "Rate limit" in text or "Rate" in text:
            return "RATE_LIMIT"
        if "Permission denied" in text:
            return "PERM_DENIED"
        if "Invalid argument" in text:
            return "INVALID_ARG"
        if "Not implemented" in text:
            return "NOT_IMPL"
        if "No such file" in text:
            return "NO_FILE"
        if "Not a directory" in text:
            return "NOT_DIR"
        # Text output that's not an error message
        printable = all(
            0x20 <= b <= 0x7E or b in (0x0A, 0x0D, 0x09) for b in raw if b != 0xFF
        )
        if printable and len(raw) <= 200:
            clean = raw.replace(bytes([0xFF]), b"").decode("ascii", "replace").strip()
            return f"TEXT:{clean!r}"
    except Exception:
        pass
    # Binary response
    if 0xFF in raw:
        term_hex = raw[: raw.index(0xFF)].hex()
        return f"TERM:{term_hex}"
    return f"RAW:{raw[:40].hex()}"


def is_novel(result: str) -> bool:
    boring = {
        "EMPTY",
        "PERM_DENIED",
        "INVALID_ARG",
        "NOT_IMPL",
        "INVALID",
        "ENCODING_FAIL",
        "TOO_BIG",
        "RATE_LIMIT",
        "NO_FILE",
        "NOT_DIR",
    }
    return result not in boring and not result.startswith("TERM:00030200")


# ──────────────────────────────────────────────────
# Main sweep
# ──────────────────────────────────────────────────


def run_phase(
    label: str, tests: list[tuple[str, bytes]], log_boring: bool = False
) -> list[tuple[str, str, str]]:
    """Run a batch of (name, payload) tests. Return list of novel results."""
    print(f"\n{'=' * 70}")
    print(f"PHASE: {label}  ({len(tests)} tests)")
    print("=" * 70)
    novels = []
    for i, (name, payload) in enumerate(tests):
        try:
            raw = query(payload, retries=2, timeout_s=5.0)
            result = classify(raw)
        except Exception as e:
            result = f"FAILED:{e}"

        novel = is_novel(result)
        if novel:
            print(f"  *** NOVEL [{i + 1:4d}/{len(tests)}] {name}")
            print(f"      payload: {payload.hex()}")
            print(f"      result:  {result}")
            novels.append((name, payload.hex(), result))
        elif log_boring and i % 50 == 0:
            print(f"  [{i + 1:4d}/{len(tests)}] {name}: {result}")

    if not novels:
        print(f"  All {len(tests)} tests boring (PERM_DENIED / EMPTY / errors)")
    return novels


def main():
    print("=" * 70)
    print("3-LEAF CONTINUATION SWEEP")
    print("Core question: does ANY 3-leaf T make sys8(N0)(T) ≠ Right(6)?")
    print("=" * 70)

    all_novels = []

    # ──────────────────────────────────────────────────────────────────
    # PHASE 1: 6 forms × interesting globals as continuations to sys8
    # ──────────────────────────────────────────────────────────────────
    form_fns = [
        ("F1:λr.((r a) b)", form1),
        ("F2:λr.(r (a b))", form2),
        ("F3:λr.((a r) b)", form3),
        ("F4:λr.(a (r b))", form4),
        ("F5:λr.((a b) r)", form5),
        ("F6:λr.(a (b r))", form6),
    ]

    GLOB_NAMES = GLOBAL_NAMES

    for form_label, form_fn in form_fns:
        tests = []
        for a in INTERESTING_GLOBALS:
            for b in INTERESTING_GLOBALS:
                t = form_fn(a, b)
                enc_t = encode_term(t)
                payload = (
                    bytes([G_SYS8])
                    + encode_term(N0)
                    + bytes([FD])
                    + enc_t
                    + bytes([FD, FF])
                )
                a_name = GLOB_NAMES.get(a, str(a))
                b_name = GLOB_NAMES.get(b, str(b))
                tests.append((f"sys8(N0)→{form_label}(a={a_name},b={b_name})", payload))

        novels = run_phase(f"sys8(N0) + {form_label}", tests)
        all_novels.extend(novels)

    # ──────────────────────────────────────────────────────────────────
    # PHASE 2: Same 6 forms but with echo(N256) as producer
    # (control: checks that the form correctly handles Left)
    # ──────────────────────────────────────────────────────────────────
    print("\n\n--- CONTROL: echo(N256) as producer ---")
    control_tests = []
    for form_label, form_fn in form_fns:
        for a in INTERESTING_GLOBALS:
            for b in INTERESTING_GLOBALS:
                t = form_fn(a, b)
                enc_t = encode_term(t)
                payload = (
                    bytes([G_ECHO])
                    + encode_term(N256)
                    + bytes([FD])
                    + enc_t
                    + bytes([FD, FF])
                )
                a_name = GLOB_NAMES.get(a, str(a))
                b_name = GLOB_NAMES.get(b, str(b))
                control_tests.append(
                    (f"echo(N256)→{form_label}(a={a_name},b={b_name})", payload)
                )

    novels = run_phase("echo(N256) + all 6 forms [CONTROL]", control_tests)
    all_novels.extend(novels)

    # ──────────────────────────────────────────────────────────────────
    # PHASE 3: 0-lambda right-assoc form as continuation to sys8
    # App(Var(a), App(Var(b), result)) — sys8 feeds Right(6) as 3rd arg
    # ──────────────────────────────────────────────────────────────────
    print("\n\n--- 0-LAMBDA RIGHT-ASSOC FORMS ---")
    right_assoc_tests = []
    for a in INTERESTING_GLOBALS:
        for b in INTERESTING_GLOBALS:
            # As continuation: App(Var(a), App(Var(b), result))
            # λr. (a (b r)) = form6, already covered above
            # Raw 0-lambda: directly as the tail (not wrapped in lambda)
            # In wire format: sys8(N0)(App(Var(a), App(Var(b), ?)))
            # But this needs to be applied to result, so it IS a continuation
            # The 0-lambda right-assoc form as PROGRAM:
            # App(Var(a), App(Var(b), Var(c))) sent as standalone
            for c in INTERESTING_GLOBALS:
                term = form0_right(a, b, c)
                payload = encode_term(term) + bytes([FF])
                a_name = GLOB_NAMES.get(a, str(a))
                b_name = GLOB_NAMES.get(b, str(b))
                c_name = GLOB_NAMES.get(c, str(c))
                right_assoc_tests.append(
                    (f"rightassoc(a={a_name},b={b_name},c={c_name})", payload)
                )

    novels = run_phase(
        "0-lambda right-assoc programs", right_assoc_tests, log_boring=False
    )
    all_novels.extend(novels)

    # ──────────────────────────────────────────────────────────────────
    # PHASE 4: 2-lambda forms × interesting globals as continuations to sys8
    # ──────────────────────────────────────────────────────────────────
    print("\n\n--- 2-LAMBDA FORMS ---")
    lam2_form_fns = [
        ("2L-gab:λa.λb.((g a) b)", form2lam_gab),
        ("2L-agb:λa.λb.(a (g b))", form2lam_agb),
        ("2L-g(ab):λa.λb.(g (a b))", form2lam_gab2),
        ("2L-(ab)g:λa.λb.((a b) g)", form2lam_abg),
        ("2L-a(bg):λa.λb.(a (b g))", form2lam_abg2),
        ("2L-(bg)a:λa.λb.((b g) a)", form2lam_bga),
    ]

    lam2_tests = []
    for form_label, form_fn in lam2_form_fns:
        for g in INTERESTING_GLOBALS:
            t = form_fn(g)
            enc_t = encode_term(t)
            payload = (
                bytes([G_SYS8])
                + encode_term(N0)
                + bytes([FD])
                + enc_t
                + bytes([FD, FF])
            )
            g_name = GLOB_NAMES.get(g, str(g))
            lam2_tests.append((f"sys8(N0)→{form_label}(g={g_name})", payload))

    novels = run_phase("sys8(N0) + 2-lambda forms", lam2_tests)
    all_novels.extend(novels)

    # ──────────────────────────────────────────────────────────────────
    # PHASE 5: Extended globals sweep for forms 2-4 and 6
    # (F1 and F5 already explored in adapters; F2,F3,F4,F6 are novel)
    # Use extended range 0-15 + 201 for a, keep b as interesting
    # ──────────────────────────────────────────────────────────────────
    print("\n\n--- EXTENDED GLOBALS (F2, F3, F4, F6 with 0-15 + 201) ---")
    novel_forms = [
        ("F2:λr.(r (a b))", form2),
        ("F3:λr.((a r) b)", form3),
        ("F4:λr.(a (r b))", form4),
        ("F6:λr.(a (b r))", form6),
    ]
    extended_tests = []
    for form_label, form_fn in novel_forms:
        for a in EXTENDED_GLOBALS:
            for b in INTERESTING_GLOBALS:
                t = form_fn(a, b)
                enc_t = encode_term(t)
                payload = (
                    bytes([G_SYS8])
                    + encode_term(N0)
                    + bytes([FD])
                    + enc_t
                    + bytes([FD, FF])
                )
                a_name = GLOB_NAMES.get(a, str(a))
                b_name = GLOB_NAMES.get(b, str(b))
                extended_tests.append(
                    (f"sys8(N0)→{form_label}(a={a_name},b={b_name})", payload)
                )

    novels = run_phase("sys8(N0) + Forms 2,3,4,6 extended globals", extended_tests)
    all_novels.extend(novels)

    # ──────────────────────────────────────────────────────────────────
    # PHASE 6: readfile(11) + forms 1-6 (Left-producing)
    # Controls whether Left-handling forms work with a different Left producer
    # ──────────────────────────────────────────────────────────────────
    print("\n\n--- readfile(11) as producer (Left-producing) ---")
    readfile_tests = []
    for form_label, form_fn in form_fns:
        for a in INTERESTING_GLOBALS:
            for b in INTERESTING_GLOBALS:
                t = form_fn(a, b)
                enc_t = encode_term(t)
                payload = (
                    bytes([G_READFILE])
                    + encode_term(N11)
                    + bytes([FD])
                    + enc_t
                    + bytes([FD, FF])
                )
                a_name = GLOB_NAMES.get(a, str(a))
                b_name = GLOB_NAMES.get(b, str(b))
                readfile_tests.append(
                    (f"readfile(11)→{form_label}(a={a_name},b={b_name})", payload)
                )

    novels = run_phase("readfile(11) + all 6 forms", readfile_tests)
    all_novels.extend(novels)

    # ──────────────────────────────────────────────────────────────────
    # FINAL SUMMARY
    # ──────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)

    if all_novels:
        print(f"\n!!! {len(all_novels)} NOVEL RESULTS FOUND !!!")
        for name, phex, result in all_novels:
            print(f"\n  {name}")
            print(f"  payload: {phex}")
            print(f"  result:  {result}")
    else:
        print("\nNo novel results. All tests returned boring (Right(6)/EMPTY/errors).")
        print("→ 3-leaf continuation hypothesis retired.")


if __name__ == "__main__":
    main()
