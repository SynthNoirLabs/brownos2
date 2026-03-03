#!/usr/bin/env python3
"""
probe_cps_adapters.py — Test "tiny CPS adapter" hypothesis from external LLM.

Hypothesis: C_g = λr. r(g)(K*) adapters route Left/Right values between
producer syscalls (echo, backdoor, sys8) and consumer syscalls (write, name,
readfile, quote, error_string).

Key novel tests:
  P4: echo(N256) → Cn → name → PS → should print "wtf"
  P5: echo(N256) → Cr → readfile → PS → should print "Uhm... yeah... no..."
  P8: readdir(N256) → Rerr → error_string → Cw → write
  P9: echo(N256) → C_sys8 → sys8 → PSE (extra: echo→sys8 via adapter)
"""

from __future__ import annotations

import hashlib
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
    """Encode integer n >= 0 using additive weights (supports >255)."""
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
# Syscall globals (at top level, Var(n) = global[n])
# ──────────────────────────────────────────────────
# 0x01 = error_string, 0x02 = write, 0x04 = quote,
# 0x05 = readdir, 0x06 = name, 0x07 = readfile,
# 0x08 = solution(sys8), 0x0E = echo, 0xC9 = backdoor(sys201)

G_ERROR_STRING = 1
G_WRITE = 2
G_QUOTE = 4
G_READDIR = 5
G_NAME = 6
G_READFILE = 7
G_SYS8 = 8
G_ECHO = 14  # 0x0E
G_BACKDOOR = 201  # 0xC9

# ──────────────────────────────────────────────────
# Building blocks
# ──────────────────────────────────────────────────

KSTAR = Lam(Lam(Var(0)))  # K* = λa.λb.b (= nil = false)

N0 = encode_byte_term(0)
N6 = encode_byte_term(6)
N256 = big_int(256)  # 128+128 = App(V8, App(V8, V0)) under 9 lambdas


def make_C_left(global_id: int) -> object:
    """C_g = λr. r(g)(K*) — route Left(x) into consumer syscall g.

    Inside 1 lambda: global[k] = Var(k+1).
    """
    shifted_g = Var(global_id + 1)
    return Lam(App(App(Var(0), shifted_g), KSTAR))


def make_R_right(global_id: int) -> object:
    """R_g = λr. r(K*)(g) — route Right(y) into consumer syscall g.

    Inside 1 lambda: global[k] = Var(k+1).
    """
    shifted_g = Var(global_id + 1)
    return Lam(App(App(Var(0), KSTAR), shifted_g))


# CPS adapters
Cw = make_C_left(G_WRITE)  # λr. r(write)(K*)
Cq = make_C_left(G_QUOTE)  # λr. r(quote)(K*)
Cn = make_C_left(G_NAME)  # λr. r(name)(K*)
Cr = make_C_left(G_READFILE)  # λr. r(readfile)(K*)
C_sys8 = make_C_left(G_SYS8)  # λr. r(sys8)(K*)
Rerr = make_R_right(G_ERROR_STRING)  # λr. r(K*)(error_string)


# PS = λe. e(λs. write(s)(K*))(K*)
# Inside outer λe (depth 1): write = Var(G_WRITE+1) = Var(3)
# Inside inner λs (depth 2): write = Var(G_WRITE+2) = Var(4)
_left_handler_PS = Lam(App(App(Var(G_WRITE + 2), Var(0)), KSTAR))
PS = Lam(App(App(Var(0), _left_handler_PS), KSTAR))


# PSE = λe. e(left_h)(right_h)
# left_h = λs. write(s)(K*)
# right_h = λc. error_string(c)(λr2. r2(λstr. write(str)(K*))(K*))
#
# Depths:
#   outer λe = depth 1
#   left_h λs = depth 2: write=Var(4), s=Var(0)
#   right_h λc = depth 2: error_string=Var(3), c=Var(0)
#   inner_unwrap λr2 = depth 3: r2=Var(0)
#   inner_left λstr = depth 4: write=Var(6), str=Var(0)

_left_h_PSE = Lam(App(App(Var(G_WRITE + 2), Var(0)), KSTAR))  # λs. write(s)(K*)
_inner_left = Lam(App(App(Var(G_WRITE + 4), Var(0)), KSTAR))  # λstr. write(str)(K*)
_inner_unwrap = Lam(App(App(Var(0), _inner_left), KSTAR))  # λr2. r2(inner_left)(K*)
_right_h_PSE = Lam(
    App(App(Var(G_ERROR_STRING + 2), Var(0)), _inner_unwrap)
)  # λc. error_string(c)(inner_unwrap)
PSE = Lam(App(App(Var(0), _left_h_PSE), _right_h_PSE))


# ──────────────────────────────────────────────────
# Verify LLM's hex encodings against our encoder
# ──────────────────────────────────────────────────


def verify_hex():
    """Compare our AST-encoded hex against the LLM's claimed hex."""
    checks = {
        "K*": (KSTAR, "00fefe"),
        "N0": (N0, "00fefefefefefefefefe"),  # 00 + 9x FE = 10 bytes
        "N6": (N6, "030200fdfdFEFEFEFEFEFEFEFEFE".lower()),
        "N256": (N256, "080800fdfdfefefefefefefefefe"),  # big_int(256)
        "Cw": (Cw, "0003fd00fefefdfe"),
        "Cq": (Cq, "0005fd00fefefdfe"),
        "Cn": (Cn, "0007fd00fefefdfe"),
        "Cr": (Cr, "0008fd00fefefdfe"),
        "Rerr": (Rerr, "0000fefefd02fdfe"),
        "PS": (PS, "000400fd00fefefdfefd00fefefdfe"),
    }

    all_ok = True
    for name, (term, expected_hex) in checks.items():
        actual_hex = encode_term(term).hex()
        match = "✅" if actual_hex == expected_hex else "❌"
        if actual_hex != expected_hex:
            all_ok = False
        print(f"  {match} {name}: ours={actual_hex}  llm={expected_hex}")

    return all_ok


# ──────────────────────────────────────────────────
# Payload construction (AST-first, encode second)
# ──────────────────────────────────────────────────


def build_payload(term: object) -> bytes:
    """Encode a term and append FF marker."""
    return encode_term(term) + bytes([FF])


def build_payloads():
    """Build all 8 LLM payloads + extras, from AST."""
    payloads = {}

    # P1: (((error_string N6) Cw) K*)
    # Expected: prints "Permission denied"
    payloads["P1: error_string(N6)→Cw→write"] = App(
        App(App(Var(G_ERROR_STRING), N6), Cw), KSTAR
    )

    # P2: (((name N256) Cw) K*)
    # Expected: prints "wtf"
    payloads["P2: name(N256)→Cw→write"] = App(App(App(Var(G_NAME), N256), Cw), KSTAR)

    # P3: (((readfile N256) Cw) K*)
    # Expected: prints "Uhm... yeah... no..."
    payloads["P3: readfile(N256)→Cw→write"] = App(
        App(App(Var(G_READFILE), N256), Cw), KSTAR
    )

    # P4: (((echo N256) Cn) PS) ← NOVEL: echo as producer → name
    # Expected: prints "wtf"
    payloads["P4: echo(N256)→Cn→name→PS [NOVEL]"] = App(
        App(App(Var(G_ECHO), N256), Cn), PS
    )

    # P5: (((echo N256) Cr) PS) ← NOVEL: echo as producer → readfile
    # Expected: prints "Uhm... yeah... no..."
    payloads["P5: echo(N256)→Cr→readfile→PS [NOVEL]"] = App(
        App(App(Var(G_ECHO), N256), Cr), PS
    )

    # P6: (((backdoor K*) Cq) PS)
    # Expected: prints pair bytecode
    payloads["P6: backdoor(K*)→Cq→quote→PS"] = App(
        App(App(Var(G_BACKDOOR), KSTAR), Cq), PS
    )

    # P7: ((((sys8 N0) Rerr) Cw) K*)
    # Expected: prints "Permission denied" (via Right(6)→error_string)
    payloads["P7: sys8(N0)→Rerr→error_string→Cw→write"] = App(
        App(App(App(Var(G_SYS8), N0), Rerr), Cw), KSTAR
    )

    # P8: ((((readdir N256) Rerr) Cw) K*) ← NOVEL: Right-route
    # Expected: prints "Not a directory" (Right(4)→error_string)
    payloads["P8: readdir(N256)→Rerr→err_str→Cw→write [NOVEL]"] = App(
        App(App(App(Var(G_READDIR), N256), Rerr), Cw), KSTAR
    )

    # P4-PSE: (((echo N256) Cn) PSE) ← LLM's "most informative query"
    # Expected: prints "wtf" or error message
    payloads["P4-PSE: echo(N256)→Cn→name→PSE [MOST INFORMATIVE]"] = App(
        App(App(Var(G_ECHO), N256), Cn), PSE
    )

    # EXTRA P9: (((echo N256) C_sys8) PSE) ← echo→sys8 via adapter
    # Expected: if echo→sys8 unlocks something, we'd see a different result
    payloads["P9: echo(N256)→C_sys8→sys8→PSE [EXTRA]"] = App(
        App(App(Var(G_ECHO), N256), C_sys8), PSE
    )

    # EXTRA P10: echo(N0) → Cn → name → PSE (different arg)
    payloads["P10: echo(N0)→Cn→name→PSE [EXTRA]"] = App(
        App(App(Var(G_ECHO), N0), Cn), PSE
    )

    # EXTRA P11: echo→Cq→quote→PS (echo as producer → quote)
    payloads["P11: echo(N256)→Cq→quote→PS [EXTRA]"] = App(
        App(App(Var(G_ECHO), N256), Cq), PS
    )

    return payloads


# ──────────────────────────────────────────────────
# Run probes
# ──────────────────────────────────────────────────


def interpret_response(raw: bytes, label: str) -> str:
    """Try to interpret the response in multiple ways."""
    if not raw:
        return "EMPTY (no response)"

    # Check for text responses
    try:
        text = raw.decode("ascii", errors="replace")
        if "Invalid" in text or "Term too big" in text or "Encoding failed" in text:
            return f"ERROR: {text.strip()}"
    except Exception:
        pass

    # Check for FF-terminated term
    if FF in raw:
        term_bytes = raw[: raw.index(FF)]
        hex_str = term_bytes.hex()

        # Try to parse as term
        try:
            term = parse_term(raw)
            # Try decode as Either
            try:
                tag, payload = decode_either(term)
                if tag == "Left":
                    try:
                        text = decode_bytes_list(payload).decode("utf-8", "replace")
                        return f'Left("{text}") [written to socket]'
                    except Exception:
                        return f"Left(<non-string>) hex={hex_str}"
                else:
                    try:
                        code = decode_byte_term(payload)
                        return f"Right({code}) hex={hex_str}"
                    except Exception:
                        return f"Right(<non-int>) hex={hex_str}"
            except Exception:
                pass

            return f"Term (not Either): hex={hex_str}"
        except Exception:
            return f"Unparseable: hex={hex_str}"

    return f"Raw (no FF): {raw[:60].hex()}"


def run_all():
    print("=" * 70)
    print("CPS Adapter Probe — Testing tiny adapter hypothesis")
    print("=" * 70)

    # Step 1: Verify hex encodings
    print("\n--- Step 1: Verify LLM hex encodings ---")
    hex_ok = verify_hex()
    if hex_ok:
        print("  All hex encodings MATCH ✅")
    else:
        print("  ⚠️  Some hex encodings MISMATCH — check above")

    # Step 2: Build and verify payloads
    print("\n--- Step 2: Build payloads from AST ---")
    payloads = build_payloads()
    for label, term in payloads.items():
        enc = encode_term(term)
        print(f"  {label}")
        print(f"    size={len(enc) + 1}B  hex={enc.hex()}ff")

    # Step 3: Also verify LLM's compact hex for "most informative query"
    llm_most_informative = "0e080800fdfdfefefefefefefefefefd0007fd00fefefdfefd000400fd00fefefdfefd0300fd000400fd00fefefdfefd00fefefdfefdfefdfefdff"
    our_p4pse_term = payloads["P4-PSE: echo(N256)→Cn→name→PSE [MOST INFORMATIVE]"]
    our_p4pse_hex = encode_term(our_p4pse_term).hex() + "ff"
    print(
        f"\n  LLM 'most informative' hex match: {'✅' if our_p4pse_hex == llm_most_informative else '❌'}"
    )
    if our_p4pse_hex != llm_most_informative:
        print(f"    Ours: {our_p4pse_hex}")
        print(f"    LLM:  {llm_most_informative}")

    # Step 4: Run probes on live server
    print("\n--- Step 3: Running probes on live server ---")
    results = {}
    for label, term in payloads.items():
        payload = build_payload(term)
        print(f"\n  [{label}]")
        print(f"    Sending {len(payload)}B...")
        try:
            raw = query(payload, retries=3, timeout_s=5.0)
            interpretation = interpret_response(raw, label)
            results[label] = (raw, interpretation)
            print(f"    Raw: {raw[:80].hex()}")
            print(f"    → {interpretation}")
        except Exception as e:
            results[label] = (b"", f"FAILED: {e}")
            print(f"    → FAILED: {e}")
        time.sleep(0.5)  # rate limit courtesy

    # Step 5: Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    for label, (raw, interp) in results.items():
        novel = " ★" if "NOVEL" in label or "MOST" in label or "EXTRA" in label else ""
        print(f"  {label}: {interp}{novel}")

    return results


# ──────────────────────────────────────────────────
# Hash candidate testing
# ──────────────────────────────────────────────────


def test_hash_candidates():
    """Test LLM's 5 hash candidates + extras against sha1^56154 target."""
    target = "9252ed65ffac2aa763adb21ef72c0178f1d83286"

    candidates = [
        # LLM's 5 candidates (adapter hex strings)
        "0003fd00fefefdfe",  # Cw hex
        "0007fd00fefefdfe",  # Cn hex
        "0008fd00fefefdfe",  # Cr hex
        "0005fd00fefefdfe",  # Cq hex
        "0000fefefd02fdfe",  # Rerr hex
        # Also try as raw bytes
        bytes.fromhex("0003fd00fefefdfe").decode("latin-1"),
        bytes.fromhex("0007fd00fefefdfe").decode("latin-1"),
        bytes.fromhex("0008fd00fefefdfe").decode("latin-1"),
        bytes.fromhex("0005fd00fefefdfe").decode("latin-1"),
        bytes.fromhex("0000fefefd02fdfe").decode("latin-1"),
        # Other candidates
        "Cw",
        "Cn",
        "Cr",
        "Cq",
        "Rerr",
        "adapter",
        "CPS",
        "continuation",
        "Permission denied",
        "3leafs",
        "3 leafs",
        "three leafs",
    ]

    print("\n--- Hash candidate testing ---")
    print(f"  Target: sha1^56154 = {target}")
    for cand in candidates:
        if isinstance(cand, str):
            h = hashlib.sha1(cand.encode("utf-8")).hexdigest()
        else:
            h = hashlib.sha1(cand).hexdigest()
        # Iterate sha1 56153 more times
        for _ in range(56153):
            h = hashlib.sha1(h.encode("utf-8")).hexdigest()
        match = "✅ MATCH!" if h == target else "❌"
        display = repr(cand) if len(repr(cand)) < 40 else repr(cand)[:37] + "..."
        print(f"  {match} {display} → {h[:16]}...")
        if h == target:
            print(f"\n  🎉 ANSWER FOUND: {cand}")
            return cand

    print("  No matches found.")
    return None


if __name__ == "__main__":
    results = run_all()
    test_hash_candidates()
