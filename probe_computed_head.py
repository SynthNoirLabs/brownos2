#!/usr/bin/env python3
"""
probe_computed_head.py — Test function-position provenance hypothesis.

Core question: Does the evaluator's permission gate for sys8 check the
SYNTACTIC head (original Var(8) in source) or the RUNTIME value that
reaches head position after β-reduction?

B combinator = λa.λb. a(b) (from backdoor pair).
B(f)(x) β-reduces to f(x), putting f in head position via reduction.

If sys8 behaves differently when reached via B(sys8)(x) vs Var(8)(x),
the permission check is syntactic. Otherwise it's runtime-based.

Decision matrix:
  P1 pass + P2 Right(6) → runtime identity check (hypothesis dead)
  P1 pass + P2 ≠ Right(6) → BREAKTHROUGH (syntactic bypass found!)
  P1 fail → computed heads don't work at all (hypothesis dead faster)
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
        raise ValueError(f"Invalid parse: stack size {len(stack)}")
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


def query(payload: bytes, retries: int = 3, timeout_s: float = 5.0) -> bytes:
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
                return recv_until_ff(sock, timeout_s=timeout_s)
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


def strip_lams(term, n):
    for _ in range(n):
        if not isinstance(term, Lam):
            raise ValueError("Not enough lambdas")
        term = term.body
    return term


def eval_bitset_expr(expr):
    if isinstance(expr, Var):
        return WEIGHTS[expr.i]
    if isinstance(expr, App):
        return WEIGHTS[expr.f.i] + eval_bitset_expr(expr.x)
    raise ValueError(f"Unexpected: {type(expr)}")


def decode_byte_term(term):
    return eval_bitset_expr(strip_lams(term, 9))


def uncons_scott_list(term):
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not a Scott list node")
    body = term.body.body
    if isinstance(body, Var) and body.i == 0:
        return None
    if (
        isinstance(body, App)
        and isinstance(body.f, App)
        and isinstance(body.f.f, Var)
        and body.f.f.i == 1
    ):
        return body.f.x, body.x
    raise ValueError("Unexpected Scott list shape")


def decode_bytes_list(term):
    out = []
    cur = term
    for _ in range(1_000_000):
        res = uncons_scott_list(cur)
        if res is None:
            return bytes(out)
        head, cur = res
        out.append(decode_byte_term(head))
    raise RuntimeError("List too long")


def decode_either(term):
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not an Either")
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var) and body.f.i in (0, 1):
        return ("Left" if body.f.i == 1 else "Right", body.x)
    raise ValueError("Unexpected Either shape")


# ──────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────

G_ERROR_STRING = 1
G_WRITE = 2
G_QUOTE = 4
G_READDIR = 5
G_NAME = 6
G_READFILE = 7
G_SYS8 = 8
G_ECHO = 14
G_BACKDOOR = 201

KSTAR = Lam(Lam(Var(0)))  # K* = λa.λb.b
I_COMB = Lam(Var(0))  # I = λx.x
K_COMB = Lam(Lam(Var(1)))  # K = λa.λb.a

N0 = encode_byte_term(0)
N6 = encode_byte_term(6)
N256 = big_int(256)

# B combinator from backdoor pair: B = λa.λb. a(b)
B_COMB = Lam(Lam(App(Var(1), Var(0))))

# A combinator from backdoor pair: A = λa.λb. b(b)  (ω-like)
A_COMB = Lam(Lam(App(Var(0), Var(0))))

# Full backdoor pair: pair = λf.λg. f(A)(B)
PAIR = Lam(Lam(App(App(Var(1), A_COMB), B_COMB)))


def make_PS(depth: int) -> object:
    """Build PS = λe. e(λs. write(s)(K*))(K*) at given embedding depth.

    write = global[2]. Inside PS's 2 lambdas + embedding depth:
    write = Var(2 + depth + 2) = Var(4 + depth)
    """
    write_var = Var(G_WRITE + depth + 2)  # depth of embedding + 2 for PS's own lambdas
    left_h = Lam(App(App(write_var, Var(0)), KSTAR))
    return Lam(App(App(Var(0), left_h), KSTAR))


def make_PSE(depth: int) -> object:
    """Build PSE at given embedding depth.

    PSE = λe. e(left_h)(right_h)
    left_h = λs. write(s)(K*)
    right_h = λc. error_string(c)(λr2. r2(λstr. write(str)(K*))(K*))

    At embedding depth d:
      depth 1 (λe): global offsets shift by d
      depth 2 (λs or λc): write=Var(2+d+2), error_string=Var(1+d+2)
      depth 3 (λr2): no new globals needed
      depth 4 (λstr): write=Var(2+d+4)
    """
    # left_h at depth d+2: write = Var(G_WRITE + d + 2)
    left_h = Lam(App(App(Var(G_WRITE + depth + 2), Var(0)), KSTAR))

    # inner_left at depth d+4: write = Var(G_WRITE + d + 4)
    inner_left = Lam(App(App(Var(G_WRITE + depth + 4), Var(0)), KSTAR))

    # inner_unwrap at depth d+3: r2 = Var(0)
    inner_unwrap = Lam(App(App(Var(0), inner_left), KSTAR))

    # right_h at depth d+2: error_string = Var(G_ERROR_STRING + d + 2)
    right_h = Lam(App(App(Var(G_ERROR_STRING + depth + 2), Var(0)), inner_unwrap))

    return Lam(App(App(Var(0), left_h), right_h))


# Top-level PS/PSE (depth=0)
PS = make_PS(0)
PSE = make_PSE(0)


def build_payload(term: object) -> bytes:
    return encode_term(term) + bytes([FF])


def interpret(raw: bytes) -> str:
    if not raw:
        return "EMPTY"
    try:
        text = raw.replace(bytes([0xFF]), b"").decode("ascii", "replace")
        if "Invalid" in text or "Term too big" in text or "Encoding failed" in text:
            return f"ERROR: {text.strip()}"
    except Exception:
        pass
    if all(0x20 <= b <= 0x7E or b in (0x0A, 0x0D, 0x09) for b in raw if b != 0xFF):
        clean = raw.replace(bytes([0xFF]), b"").decode("ascii", "replace")
        return f'TEXT: "{clean}"'
    if 0xFF in raw:
        term_bytes = raw[: raw.index(0xFF)]
        try:
            term = parse_term(raw)
            try:
                tag, pl = decode_either(term)
                if tag == "Left":
                    try:
                        s = decode_bytes_list(pl).decode("utf-8", "replace")
                        return f'Left("{s}")'
                    except Exception:
                        return f"Left(<non-string>) hex={term_bytes.hex()}"
                else:
                    try:
                        code = decode_byte_term(pl)
                        return f"Right({code})"
                    except Exception:
                        return f"Right(<non-int>) hex={term_bytes.hex()}"
            except Exception:
                return f"Term: hex={term_bytes.hex()}"
        except Exception:
            return f"Unparseable: hex={term_bytes.hex()}"
    return f"Raw: {raw[:60].hex()}"


def run_probe(label: str, term: object, delay: float = 0.5) -> str:
    payload = build_payload(term)
    print(f"\n  [{label}]")
    print(f"    hex: {encode_term(term).hex()}ff")
    print(f"    size: {len(payload)}B")
    try:
        raw = query(payload, retries=3, timeout_s=5.0)
        result = interpret(raw)
        print(f"    raw: {raw[:80].hex() if raw else 'EMPTY'}")
        print(f"    → {result}")
        time.sleep(delay)
        return result
    except Exception as e:
        print(f"    → FAILED: {e}")
        time.sleep(delay)
        return f"FAILED: {e}"


def main():
    print("=" * 70)
    print("Computed Head Probe — Function-position provenance")
    print("=" * 70)
    print()
    print("Hypothesis: sys8's permission gate checks the syntactic head,")
    print("not the runtime value. B(sys8)(x) might bypass it.")

    results = {}

    # ──────────────────────────────────────────────────
    # PHASE 1: Controls (known syscalls via B)
    # ──────────────────────────────────────────────────
    print("\n--- Phase 1: Controls (B-computed head with known syscalls) ---")

    # C0: Direct baseline — ((name N256) PS) — no B involved
    results["C0: direct name(N256)→PS"] = run_probe(
        "C0: ((name N256) PS) [direct baseline]", App(App(Var(G_NAME), N256), PS)
    )

    # P1: B-computed name — (((B name) N256) PS)
    # B(name) = λb.name(b), then λb.name(b)(N256) = name(N256)
    results["P1: B(name)(N256)→PS"] = run_probe(
        "P1: (((B name) N256) PS) [computed head control]",
        App(App(App(B_COMB, Var(G_NAME)), N256), PS),
    )

    # C0b: Direct readfile baseline
    results["C0b: direct readfile(N256)→PS"] = run_probe(
        "C0b: ((readfile N256) PS) [direct baseline]",
        App(App(Var(G_READFILE), N256), PS),
    )

    # P1b: B-computed readfile
    results["P1b: B(readfile)(N256)→PS"] = run_probe(
        "P1b: (((B readfile) N256) PS) [computed head control 2]",
        App(App(App(B_COMB, Var(G_READFILE)), N256), PS),
    )

    # P1c: B-computed error_string
    results["P1c: B(err_str)(N6)→PS"] = run_probe(
        "P1c: (((B error_string) N6) PS) [computed head control 3]",
        App(App(App(B_COMB, Var(G_ERROR_STRING)), N6), PS),
    )

    # ──────────────────────────────────────────────────
    # PHASE 2: The critical test — sys8 via B
    # ──────────────────────────────────────────────────
    print("\n--- Phase 2: CRITICAL — sys8 via B-computed head ---")

    # C1: Direct sys8 baseline
    results["C1: direct sys8(N0)→PSE"] = run_probe(
        "C1: ((sys8 N0) PSE) [direct baseline]", App(App(Var(G_SYS8), N0), PSE)
    )

    # P2: B-computed sys8 — THE CRITICAL TEST
    results["P2: B(sys8)(N0)→PSE"] = run_probe(
        "P2: (((B sys8) N0) PSE) [CRITICAL: computed head sys8]",
        App(App(App(B_COMB, Var(G_SYS8)), N0), PSE),
    )

    # P2b: B-computed sys8 with different arg (N256)
    results["P2b: B(sys8)(N256)→PSE"] = run_probe(
        "P2b: (((B sys8) N256) PSE) [computed head, diff arg]",
        App(App(App(B_COMB, Var(G_SYS8)), N256), PSE),
    )

    # P2c: B-computed sys8 with K* (nil) arg
    results["P2c: B(sys8)(K*)→PSE"] = run_probe(
        "P2c: (((B sys8) K*) PSE) [computed head, nil arg]",
        App(App(App(B_COMB, Var(G_SYS8)), KSTAR), PSE),
    )

    # ──────────────────────────────────────────────────
    # PHASE 3: Echo→extract→B pattern (corrected)
    # Uses: echo(fn) → C_id → fn extracted → B(fn)(arg) → cont
    # C_id = λr. r(I)(K*) — extracts Left value via identity
    # ──────────────────────────────────────────────────
    print("\n--- Phase 3: Echo as head producer (corrected) ---")

    # The pattern: echo produces a function, we extract it, then use it.
    # But we can't easily chain echo→extract→B→apply at the top level.
    # Instead, use a hand-built continuation that does all steps:
    #
    # echo(Var(6)) with continuation:
    #   λresult. result(λfn. (((B fn) N256) PS_shifted))(K*)
    #
    # Inside λresult (depth 1): result=V0
    # Inside λfn (depth 2): fn=V0, B needs no shift (closed),
    #   N256 closed, but PS needs depth=2 shift
    #
    # After: result=Left(Var(6)) → λfn.((B fn N256) PS)(Var(6))
    #   = ((B Var(6)) N256) PS = name(N256) → "wtf"

    PS_d2 = make_PS(2)  # PS with write shifted for depth 2

    # λfn. (((B fn) N256) PS_d2)
    inner_handler = Lam(App(App(App(B_COMB, Var(0)), N256), PS_d2))
    # λresult. result(inner_handler)(K*)
    echo_cont_name = Lam(App(App(Var(0), inner_handler), KSTAR))

    # P3: echo(name)→extract→B→name(N256)→PS [corrected]
    results["P3: echo(name)→B→name(N256)"] = run_probe(
        "P3: ((echo name) (λr.r(λfn.((B fn N256) PS))(K*))) [echo→B control]",
        App(App(Var(G_ECHO), Var(G_NAME)), echo_cont_name),
    )

    # P4: echo(sys8)→extract→B→sys8(N0)→PSE [the critical echo version]
    PSE_d2 = make_PSE(2)  # PSE with correct depth shifts
    inner_handler_sys8 = Lam(App(App(App(B_COMB, Var(0)), N0), PSE_d2))
    echo_cont_sys8 = Lam(App(App(Var(0), inner_handler_sys8), KSTAR))

    results["P4: echo(sys8)→B→sys8(N0)"] = run_probe(
        "P4: ((echo sys8) (λr.r(λfn.((B fn N0) PSE))(K*))) [echo→B→sys8]",
        App(App(Var(G_ECHO), Var(G_SYS8)), echo_cont_sys8),
    )

    # ──────────────────────────────────────────────────
    # PHASE 4: Backdoor as combinator source (corrected)
    # Extract B from pair, use it to compute head
    # ──────────────────────────────────────────────────
    print("\n--- Phase 4: Backdoor as combinator source (corrected) ---")

    # Pattern: backdoor(K*) → Left(pair)
    # Extract pair from Left, apply pair(K*) to get B (pair's second component),
    # then B(name)(N256)→PS.
    #
    # Continuation for backdoor:
    #   λresult. result(λpair. ((((pair K*) name_shifted) N256) PS_d2))(K*)
    #
    # Depth analysis:
    #   λresult = depth 1
    #   λpair = depth 2
    #   Inside λpair: pair=V0, K* closed, name=global[6]+2=V8, N256 closed
    #   PS at depth 2 needs make_PS(2)
    #
    # Semantics: pair(K*) = (λf.λg.f(A)(B))(K*) = λg.K*(A)(B) = λg.B
    # Then (λg.B)(Var(8)_at_depth2=name) = B  (K* discards g? no...)
    #
    # Wait: pair(K*)(name) = K*(A)(B)(name)?? No.
    # pair = λf.λg. f(A)(B).  pair(K*) = λg. K*(A)(B) = λg. B.
    # pair(K*)(name) = (λg. B)(name) = B.
    # That gives us B, not B(name). We need another step.
    #
    # Alternative: pair(K)(name).
    # pair(K) = λg. K(A)(B) = λg. A. pair(K)(name) = A = ω.
    # Also not what we want.
    #
    # The pair is λf.λg. f(A)(B). To use B as an applicator:
    # We need: extract B from pair, then apply B(name)(N256).
    # pair(K*)(I) = B(I)... wait, pair(K*) = λg. B, so pair(K*)(I) = B. Correct.
    # But then we need to apply B to name and N256 separately.
    #
    # Full chain in one continuation:
    #   λresult. result(λpair. (((pair K*) I_shifted)(name_shifted)(N256)) PS_d2)(K*)
    # But this doesn't work: pair(K*)(I) = B, then B(name)(N256) = name(N256).
    # Actually: (((pair K*) I) name) = B(name) = λb.name(b)
    # Then (λb.name(b))(N256) = name(N256)
    # Then (name(N256) PS) → "wtf"
    #
    # Hmm, ((pair K*) I) first: pair(K*) = λg.B, (λg.B)(I) = B ✓
    # Then B(name_d2)(N256) = name(N256), with PS_d2 as continuation.
    #
    # Structure: (((((pair K*) I) name_d2) N256) PS_d2)
    # This is App^5 at depth 2.

    name_d2 = Var(G_NAME + 2)  # name at depth 2
    # λpair. ((((((pair K*) I) name_d2) N256) PS_d2)
    inner_p5 = Lam(App(App(App(App(App(Var(0), KSTAR), I_COMB), name_d2), N256), PS_d2))
    bdoor_cont_name = Lam(App(App(Var(0), inner_p5), KSTAR))

    results["P5: bdoor→pair→B→name(N256)"] = run_probe(
        "P5: ((bdoor K*)(λr.r(λp.(((((p K*) I) name) N256) PS))(K*))) [bdoor→B control]",
        App(App(Var(G_BACKDOOR), KSTAR), bdoor_cont_name),
    )

    # P6: Same but targeting sys8
    sys8_d2 = Var(G_SYS8 + 2)  # sys8 at depth 2
    PSE_d2b = make_PSE(2)
    inner_p6 = Lam(App(App(App(App(App(Var(0), KSTAR), I_COMB), sys8_d2), N0), PSE_d2b))
    bdoor_cont_sys8 = Lam(App(App(Var(0), inner_p6), KSTAR))

    results["P6: bdoor→pair→B→sys8(N0)"] = run_probe(
        "P6: ((bdoor K*)(λr.r(λp.(((((p K*) I) sys8) N0) PSE))(K*))) [bdoor→B→sys8]",
        App(App(Var(G_BACKDOOR), KSTAR), bdoor_cont_sys8),
    )

    # ──────────────────────────────────────────────────
    # PHASE 5: Additional computed-head variants
    # ──────────────────────────────────────────────────
    print("\n--- Phase 5: Additional computed-head variants ---")

    # I(sys8) as head: ((I sys8) N0) PSE = sys8(N0)(PSE)
    results["X1: I(sys8)(N0)→PSE"] = run_probe(
        "X1: (((I sys8) N0) PSE) [identity wrapper]",
        App(App(App(I_COMB, Var(G_SYS8)), N0), PSE),
    )

    # K(sys8)(junk) as head: (((K sys8 junk) N0) PSE) = sys8(N0)(PSE)
    results["X2: K(sys8)(junk)(N0)→PSE"] = run_probe(
        "X2: ((((K sys8) K*) N0) PSE) [K-wrapper]",
        App(App(App(App(K_COMB, Var(G_SYS8)), KSTAR), N0), PSE),
    )

    # (λx.x)(sys8) — same as I but written differently
    results["X3: (λx.x)(sys8)(N0)→PSE"] = run_probe(
        "X3: ((((λx.x) sys8) N0) PSE) [explicit lambda wrapper]",
        App(App(App(Lam(Var(0)), Var(G_SYS8)), N0), PSE),
    )

    # A(sys8) = sys8(sys8) — omega-like self-application via A
    # A = λa.λb. b(b). A(sys8) = λb. b(b). Applied to N0: N0(N0). Not useful.
    # Let's try a combinator that does f(x): S combinator variant
    # S K I x = x (standard, but complex)

    # Actually: ((λf.λx.((f x) PSE)) sys8 N0)
    # At depth 2 inside the lambda: f=V1, x=V0, PSE needs depth 2
    # After β: ((sys8 N0) PSE)
    PSE_d2c = make_PSE(2)
    wrapper = Lam(Lam(App(App(Var(1), Var(0)), PSE_d2c)))
    results["X4: (λf.λx.f(x)(PSE))(sys8)(N0)"] = run_probe(
        "X4: ((λf.λx.((f x) PSE)) sys8 N0) [2-lambda wrapper]",
        App(App(wrapper, Var(G_SYS8)), N0),
    )

    # ──────────────────────────────────────────────────
    # SUMMARY
    # ──────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY — Computed Head Hypothesis")
    print("=" * 70)

    # Phase 1
    print("\nPhase 1 (Controls — computed head with known syscalls):")
    for key in [
        "C0: direct name(N256)→PS",
        "P1: B(name)(N256)→PS",
        "C0b: direct readfile(N256)→PS",
        "P1b: B(readfile)(N256)→PS",
        "P1c: B(err_str)(N6)→PS",
    ]:
        print(f"  {key}: {results[key]}")

    # Phase 2
    print("\nPhase 2 (CRITICAL — sys8 via computed head):")
    for key in [
        "C1: direct sys8(N0)→PSE",
        "P2: B(sys8)(N0)→PSE",
        "P2b: B(sys8)(N256)→PSE",
        "P2c: B(sys8)(K*)→PSE",
    ]:
        print(f"  {key}: {results[key]}")

    # Phase 3
    print("\nPhase 3 (Echo as head producer):")
    for key in ["P3: echo(name)→B→name(N256)", "P4: echo(sys8)→B→sys8(N0)"]:
        print(f"  {key}: {results[key]}")

    # Phase 4
    print("\nPhase 4 (Backdoor as combinator source):")
    for key in ["P5: bdoor→pair→B→name(N256)", "P6: bdoor→pair→B→sys8(N0)"]:
        print(f"  {key}: {results[key]}")

    # Phase 5
    print("\nPhase 5 (Additional wrappers):")
    for key in [
        "X1: I(sys8)(N0)→PSE",
        "X2: K(sys8)(junk)(N0)→PSE",
        "X3: (λx.x)(sys8)(N0)→PSE",
        "X4: (λf.λx.f(x)(PSE))(sys8)(N0)",
    ]:
        print(f"  {key}: {results[key]}")

    # Decision
    print("\n--- DECISION ---")
    p1_ok = "wtf" in results.get("P1: B(name)(N256)→PS", "")
    p2_val = results.get("P2: B(sys8)(N0)→PSE", "")
    p2_perm = "Permission denied" in p2_val or "Right(6)" in p2_val

    if not p1_ok:
        print("  P1 FAILED: computed heads don't dispatch syscalls.")
        print("  → Hypothesis DEAD. Evaluator requires direct Var head.")
    elif p1_ok and not p2_perm:
        print("  P1 PASSED + P2 DIFFERS from Right(6)!")
        print("  → POTENTIAL BREAKTHROUGH! Syntactic bypass may work!")
        print(f"  → P2 returned: {p2_val}")
    else:
        print("  P1 PASSED + P2 still Right(6).")
        print("  → Permission check is RUNTIME-based, not syntactic.")
        print("  → Computed head hypothesis retired.")

    return results


if __name__ == "__main__":
    main()
