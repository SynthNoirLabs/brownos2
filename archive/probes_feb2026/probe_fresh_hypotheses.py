#!/usr/bin/env python3
"""
probe_fresh_hypotheses.py — Test 3 fresh hypothesis categories against BrownOS syscall 8.

Category A: Exception Handler Override (4 tests)
Category B: Read Binary Files / Quote Globals (6 tests)
Category C: 3-Leaf Terms as CONTINUATIONS (10 tests)

Any non-Right(6) result from sys8 is flagged with "!!! BREAKTHROUGH !!!".
"""

from __future__ import annotations

import socket
import time
import traceback
from dataclasses import dataclass

# ── Constants ──────────────────────────────────────────────────────────────────

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD  # application
FE = 0xFE  # lambda
FF = 0xFF  # end-of-code marker

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

SLEEP_BETWEEN = 0.5  # seconds between requests


# ── AST ────────────────────────────────────────────────────────────────────────


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


# ── Encoding / Decoding ───────────────────────────────────────────────────────


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported term: {type(term)}")


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


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def strip_lams(term: object, n: int) -> object:
    cur = term
    for _ in range(n):
        if not isinstance(cur, Lam):
            raise ValueError("Not enough leading lambdas")
        cur = cur.body
    return cur


def eval_bitset_expr(expr: object) -> int:
    if isinstance(expr, Var):
        return WEIGHTS.get(expr.i, -1)
    if isinstance(expr, App):
        if not isinstance(expr.f, Var):
            raise ValueError("Unexpected function position")
        w = WEIGHTS.get(expr.f.i, -1)
        if w < 0:
            raise ValueError(f"Unknown weight for Var({expr.f.i})")
        return w + eval_bitset_expr(expr.x)
    raise ValueError(f"Unexpected expr: {type(expr)}")


def encode_byte_term(n: int) -> object:
    """Encode integer n as 9-lambda additive bitset term."""
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


def encode_bytes_list(bs: bytes) -> object:
    nil: object = Lam(Lam(Var(0)))

    def cons(h: object, t: object) -> object:
        return Lam(Lam(App(App(Var(1), h), t)))

    cur: object = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


def decode_either(term: object) -> tuple[str, object]:
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not an Either")
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var) and body.f.i in (0, 1):
        return ("Left" if body.f.i == 1 else "Right", body.x)
    raise ValueError("Unexpected Either shape")


def decode_byte_term(term: object) -> int:
    body = strip_lams(term, 9)
    return eval_bitset_expr(body)


def decode_bytes_list(term: object) -> bytes:
    out: list[int] = []
    cur = term
    for _ in range(1_000_000):
        if not isinstance(cur, Lam) or not isinstance(cur.body, Lam):
            break
        body = cur.body.body
        if isinstance(body, Var) and body.i == 0:
            return bytes(out)
        if (
            isinstance(body, App)
            and isinstance(body.f, App)
            and isinstance(body.f.f, Var)
            and body.f.f.i == 1
        ):
            head, cur = body.f.x, body.x
            out.append(decode_byte_term(head))
        else:
            break
    return bytes(out)


def term_to_str(term: object, depth: int = 0) -> str:
    """Pretty-print a term (abbreviated beyond depth)."""
    if depth > 6:
        return "..."
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{term_to_str(term.body, depth + 1)}"
    if isinstance(term, App):
        return f"({term_to_str(term.f, depth + 1)} {term_to_str(term.x, depth + 1)})"
    return "?"


# ── Network ───────────────────────────────────────────────────────────────────


def recv_until_ff(sock: socket.socket, timeout_s: float = 5.0) -> bytes:
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
        if FF in chunk:
            break
    return out


def query(payload: bytes, retries: int = 3, timeout_s: float = 5.0) -> bytes:
    delay = 0.3
    last_err: Exception | None = None
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
    raise RuntimeError(f"query failed after retries") from last_err


# ── Helpers ───────────────────────────────────────────────────────────────────

NIL = Lam(Lam(Var(0)))  # Scott nil / false


def g(n: int) -> Var:
    """Global/syscall n — just Var(n) at top level."""
    return Var(n)


def app(f: object, x: object) -> App:
    return App(f, x)


def lam(body: object) -> Lam:
    return Lam(body)


def send_raw_term(term: object, timeout_s: float = 5.0) -> bytes:
    """Encode term, append FF, send, return raw response."""
    payload = encode_term(term) + bytes([FF])
    return query(payload, timeout_s=timeout_s)


def send_raw_bytes(payload_bytes: bytes, timeout_s: float = 5.0) -> bytes:
    """Send pre-built bytes (must already include FF)."""
    return query(payload_bytes, timeout_s=timeout_s)


def analyze_response(raw: bytes, test_label: str, is_sys8: bool = False) -> None:
    """Parse and display response. Flag breakthroughs for sys8 tests."""
    raw_hex = raw.hex()
    print(f"  Raw hex: {raw_hex}")

    if not raw:
        print(f"  Result: EMPTY (no response / timeout)")
        return

    if b"Invalid term" in raw:
        print(f"  Result: Invalid term!")
        return

    if b"Term too big" in raw:
        print(f"  Result: Term too big!")
        return

    if b"Encoding failed" in raw:
        print(f"  Result: Encoding failed!")
        return

    if FF not in raw:
        # Try to decode as ASCII
        try:
            text = raw.decode("utf-8", "replace")
            print(f"  Result: Raw text: {text!r}")
        except Exception:
            print(f"  Result: No FF terminator, raw: {raw_hex}")
        return

    try:
        term = parse_term(raw)
        try:
            tag, payload = decode_either(term)
            if tag == "Right":
                try:
                    err_code = decode_byte_term(payload)
                    print(f"  Result: Right({err_code})")
                    if is_sys8 and err_code != 6:
                        print(
                            f"  !!! BREAKTHROUGH !!! sys8 returned Right({err_code}) instead of Right(6)!"
                        )
                except Exception:
                    print(f"  Result: Right({term_to_str(payload)})")
                    if is_sys8:
                        print(
                            f"  !!! BREAKTHROUGH !!! sys8 returned Right with unusual payload!"
                        )
            else:
                # Left — success!
                if is_sys8:
                    print(f"  !!! BREAKTHROUGH !!! sys8 returned LEFT!")
                    print(f"  Left payload: {term_to_str(payload)}")
                    try:
                        bs = decode_bytes_list(payload)
                        print(f"  Decoded bytes: {bs!r}")
                    except Exception:
                        pass
                else:
                    # Not sys8, just informational
                    try:
                        bs = decode_bytes_list(payload)
                        print(f"  Result: Left(bytes={bs!r})")
                    except Exception:
                        print(f"  Result: Left({term_to_str(payload)})")
        except ValueError:
            print(f"  Result: Non-Either term: {term_to_str(term)}")
            if is_sys8:
                print(f"  !!! BREAKTHROUGH !!! sys8 returned non-Either response!")
    except Exception as e:
        print(f"  Result: Parse error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# CATEGORY A: Exception Handler Override
# ══════════════════════════════════════════════════════════════════════════════


def run_category_a() -> None:
    print("\n" + "=" * 70)
    print("CATEGORY A: Exception Handler Override")
    print("=" * 70)
    print("Hypothesis: g(0) sets an exception handler. Setting one before sys8")
    print("might alter its permission check behavior.\n")

    # ── Test A1 ──────────────────────────────────────────────────────────────
    # ((g(0) (λexc. ((g(2) (quote "ok")) (λ_. nil)))) ((g(8) nil) QD))
    # Set handler that writes "ok", then call sys8(nil)(QD)
    #
    # CPS structure: ((g(0) handler) body)
    # g(0) at top level = Var(0)
    # BUT: inside the handler lambda, indices shift by 1
    # Inside the body position of g(0), we're NOT under extra lambdas from g(0) itself—
    # the body is the second argument.
    #
    # Actually: g(0) takes handler, then the result takes body.
    # ((g(0) handler) body) — handler and body are at the same lambda depth as g(0).
    #
    # handler = λexc. ((g(2) (quote "ok")) (λ_. nil))
    # Inside handler: under 1 lambda, so g(2)=Var(3), g(4)=Var(5)
    # But "quote" is syscall 4, and to do CPS inside a handler is complex.
    # Simpler: handler = λexc. nil (just swallow exception)
    # and separately test with identity handler

    print("--- Test A1: handler=write('ok'), then sys8 ---")
    # Simplified: handler writes a constant string via g(2), then does nothing.
    # Inside handler (1 lam deep): g(2) = Var(3), to write we need CPS:
    # ((Var(3) str_ok) (λ_. nil_shifted))
    # str_ok = encode_bytes_list(b"ok") — but this is complex inside a lambda.
    #
    # Let's build the term structurally:
    # handler = λexc. ((Var(3) str_ok) (λwrite_result. Var(0)_shifted))
    # Too complex with nested byte terms under lambda. Let's use raw bytes approach.
    #
    # Alternative: make handler = λexc. nil  (simplest)
    # body = ((g(8) nil) QD)
    #
    # Full: ((Var(0) (λ. nil)) ((Var(8) nil) QD))
    # = App(App(Var(0), Lam(NIL)), App(App(Var(8), NIL), QD_term))
    #
    # But QD is easier as raw bytes. Let's build the whole thing as bytes.

    # Approach: build term as AST, encode, append QD at the right place.
    # handler_simple = λ. nil = λ. (λ.λ.V0) = Lam(Lam(Lam(Var(0))))
    handler_nil = lam(Lam(Lam(Var(0))))  # λexc. nil (nil = λc.λn. n = λ.λ.V0)

    # body = ((g(8) nil) QD)
    # We'll build this as raw bytes since QD is raw.
    # g(0)(handler) = App(Var(0), handler)
    # (g(0)(handler))(body) = App(App(Var(0), handler), body)
    # body = ((Var(8) nil) QD)
    # = ((Var(8) (Lam(Lam(Var(0))))) QD)

    # Encode: g0_handler part, then body part with QD
    g0_handler = encode_term(App(g(0), handler_nil))
    # body = (Var(8) nil) QD FD = 08 00FEFE FD QD FD
    body_bytes = bytes([0x08]) + encode_term(NIL) + bytes([FD]) + QD + bytes([FD])
    payload_a1 = g0_handler + body_bytes + bytes([FD, FF])
    raw = send_raw_bytes(payload_a1)
    analyze_response(raw, "A1", is_sys8=True)
    time.sleep(SLEEP_BETWEEN)

    # ── Test A2 ──────────────────────────────────────────────────────────────
    print("\n--- Test A2: handler=identity, then sys8 ---")
    handler_id = lam(Var(0))  # λexc. exc
    g0_handler2 = encode_term(App(g(0), handler_id))
    payload_a2 = g0_handler2 + body_bytes + bytes([FD, FF])
    raw = send_raw_bytes(payload_a2)
    analyze_response(raw, "A2", is_sys8=True)
    time.sleep(SLEEP_BETWEEN)

    # ── Test A3 ──────────────────────────────────────────────────────────────
    print(
        "\n--- Test A3: Chained — sys8 → capture error → set as handler → sys8 again ---"
    )
    # This is complex. Build as:
    # ((g(0) (λexc. ((g(8) exc) QD_shifted))) ((g(8) nil) (λr. ((g(0) (λe. ((g(8) e) QD_shifted2))) r))))
    #
    # Simpler chain approach:
    # First sys8(nil) with continuation that takes result, sets it as exception handler,
    # then calls sys8 again.
    #
    # inner_k = λresult. ((g(0) (λe. ((g(8) e) QD))) ((g(8) result) QD))
    #
    # But de Bruijn indices shift! Let's think carefully:
    #
    # At top level: g(8) = Var(8), g(0) = Var(0)
    # inner_k = λ.  (= 1 lam deep)
    #   g(8) = Var(9), g(0) = Var(1), result = Var(0)
    #
    #   body: ((Var(1) handler) ((Var(9) Var(0)) QD_shifted))
    #   handler = λ.  (= 2 lams deep)
    #     g(8) = Var(10), e = Var(0)
    #     handler_body: ((Var(10) Var(0)) QD_shifted2)
    #
    # QD needs to be shifted too... this gets very messy with raw QD bytes.
    #
    # Simpler: just do the full thing as sequential bytes.
    # ((g(8) nil) (λresult. ((g(8) result) QD_at_depth_1)))
    #
    # At depth 1 inside the λresult, g(8) = Var(9), result = Var(0)
    # QD at depth 1: QD references g(4)=Var(5), g(2)=Var(3), g(0)=Var(1) internally.
    # Inside 1 more lambda, those become Var(6), Var(4), Var(2).
    # QD raw = 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
    # The vars in QD that reference globals: the QD term is self-contained,
    # it uses vars 0-5 internally (bound by its own lambdas). So shifting doesn't
    # apply to QD's internal vars — they're all bound within QD itself.
    #
    # Wait: QD = λ.λ. ((Var(5) (Var(0) (Var(5) (Var(0) ...))))
    # QD parsed: let's check.
    # 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
    # Stack trace:
    #   05 → [V5]
    #   00 → [V5, V0]
    #   FD → [App(V5,V0)]
    #   00 → [App(V5,V0), V0]
    #   05 → [App(V5,V0), V0, V5]
    #   00 → [App(V5,V0), V0, V5, V0]
    #   FD → [App(V5,V0), V0, App(V5,V0)]
    #   03 → [App(V5,V0), V0, App(V5,V0), V3]
    #   FD → [App(V5,V0), V0, App(App(V5,V0),V3)]
    #   FE → [App(V5,V0), V0, Lam(App(App(V5,V0),V3))]
    #   FD → [App(V5,V0), App(V0, Lam(App(App(V5,V0),V3)))]
    #   02 → [App(V5,V0), App(V0, Lam(App(App(V5,V0),V3))), V2]
    #   FD → [App(V5,V0), App(App(V0, Lam(App(App(V5,V0),V3))), V2)]
    #   FE → [App(V5,V0), Lam(App(App(V0, Lam(App(App(V5,V0),V3))), V2))]
    #   FD → [App(App(V5,V0), Lam(App(App(V0, Lam(...)),V2)))]
    #   FE → [Lam(App(App(V5,V0), Lam(App(App(V0, Lam(...)),V2))))]
    #
    # QD = Lam(App(App(Var(5), Var(0)), Lam(App(App(Var(0), Lam(App(App(Var(5), Var(0)), Var(3)))), Var(2)))))
    # Under the outer Lam, vars 5, 2, 3 refer to globals (g(4), g(1), g(2) at top level).
    # Actually, QD has 2 lambdas total at front. Inside 2 lambdas:
    # V5 = global 3 (g(4-1)=g(3)? No...)
    #
    # Wait. QD when used as continuation in ((g(N) arg) QD):
    # QD is at top level. It has its own lambdas. When the VM applies QD to the result,
    # it substitutes. QD's free variables (anything ≥ 2 since QD has 2 leading lambdas)
    # refer to the enclosing scope — which is top level.
    #
    # QD parsed properly:
    # After 2 lambdas, free vars ≥ 2 are globals shifted by 2.
    # V5 inside 2 lambdas → global index 5-2 = 3 → g(3)? But we said g(4) = quote...
    # Hmm, actually from the QD description: QD does write(quote(result)).
    # g(2) = write, g(4) = quote.
    # Inside QD's 2 lambdas: g(2) appears as V(2+2)=V4, g(4) as V(4+2)=V6.
    # But we see V5, V3, V2 in the parse. Something doesn't match my manual parse.
    #
    # Regardless, QD works correctly at top level. If we put QD under additional
    # lambdas, its free variable references shift and it breaks.
    #
    # So for chained tests, we need to use QD only at top level.
    # Chain approach: first sys8, continue with a custom observer that
    # passes result to a SECOND sys8, and THAT one uses QD at the right depth.
    #
    # Actually the simplest chain: build the ENTIRE program at top level.
    # ((g(8) nil) (λr. ((g(8) r) QD_needs_to_be_at_depth_1)))
    #
    # QD at depth 1 doesn't work naively. BUT we can use the CPS chain trick:
    # The continuation of the first sys8 does another sys8 call whose continuation
    # is QD — but QD's free vars would be wrong at depth 1.
    #
    # Alternative: skip proper chaining and just do the g(0) wrapping test simply.

    # Simple version: ((g(0) (λ. Var(0))) ((g(8) nil) QD))
    # where g(0) catches exception from sys8, and the handler returns exc itself.
    # Then the OVERALL expression evaluates to the exception (the Right(6)),
    # and QD prints it... but wait, QD is the continuation of sys8, not of g(0).
    #
    # Let's think about this differently:
    # g(0) behavior hypothesis: ((g(0) handler) body) evaluates body; if body throws,
    # calls handler with the exception.
    # So: ((g(0) handler) ((g(8) nil) QD))
    # If sys8 throws an exception (not just returns Right(6) via CPS), handler catches it.
    # If sys8 returns normally via CPS (calling QD with Right(6)), g(0) doesn't intervene.
    #
    # What if sys8 raises a VM exception that g(0) catches?
    # handler = λexc. ((g(2) ((g(4) exc) QD_inner)) QD_outer)
    # This requires QD at multiple depths... too complex.
    #
    # Let's just do a simpler test: chain two sys8 calls in CPS.
    # ((g(8) nil) (λr1. ((g(8) r1) QD)))
    # Here the continuation of first sys8 is λr1. ((g(8) r1) QD)
    # Inside this lambda (depth 1): g(8) = Var(9), r1 = Var(0)
    # QD's free vars would be wrong at depth 1.
    #
    # Use raw bytes with manually shifted QD? Too error-prone.
    #
    # Better approach: just use the CPS chain at the byte level:
    # ((g(8) nil) (λr1. output_r1_then_call_sys8_r1_with_QD))
    #
    # Actually, the simplest chain that DOES work:
    # sys8(nil) → result r1 → sys8(r1) → result r2 → QD(r2)
    # All in CPS: ((g8 nil) (λr1. ((g8 r1) QD)))
    # But QD at depth 1 has wrong free vars.
    #
    # We can embed QD's functionality manually:
    # At depth 1: write = Var(3), quote = Var(5)
    # "QD at depth 1" = λresult. ((Var(3) ((Var(5) result) (λquoted. quoted))) (λ_. done))
    # This is getting complicated. Let me just hardcode the bytes.

    # For A3, let's do: catch sys8's exception with g(0), feed it BACK to sys8.
    # Whole term: ((g(0) (λexc. exc)) ((g(8) nil) QD))
    # = same as A2 actually. Let's make A3 different:
    # A3: Nest g(0) INSIDE sys8's argument:
    # ((g(8) ((g(0) (λe.e)) nil)) QD)
    # = sys8( g(0)(id)(nil) ) (QD)
    # g(0)(id)(nil) should evaluate nil normally (no exception).
    # So this is sys8(nil)(QD) but with g(0) wrapping the arg.

    inner = App(App(g(0), lam(Var(0))), NIL)  # ((g(0) id) nil) — should reduce to nil
    term_a3 = App(App(g(8), inner), parse_term(QD))

    # But wait, QD should be raw. Let's do it as bytes:
    a3_bytes = encode_term(App(g(8), inner)) + QD + bytes([FD, FF])
    raw = send_raw_bytes(a3_bytes)
    analyze_response(raw, "A3", is_sys8=True)
    time.sleep(SLEEP_BETWEEN)

    # ── Test A4 ──────────────────────────────────────────────────────────────
    print("\n--- Test A4: handler=nil, then sys8 ---")
    # ((g(0) (λexc. nil)) ((g(8) nil) QD))
    handler_nil_body = lam(Lam(Lam(Var(0))))  # λexc. nil
    g0_h4 = encode_term(App(g(0), handler_nil_body))
    payload_a4 = g0_h4 + body_bytes + bytes([FD, FF])
    raw = send_raw_bytes(payload_a4)
    analyze_response(raw, "A4", is_sys8=True)
    time.sleep(SLEEP_BETWEEN)


# ══════════════════════════════════════════════════════════════════════════════
# CATEGORY B: Read Binary Files / Quote Globals
# ══════════════════════════════════════════════════════════════════════════════


def run_category_b() -> None:
    print("\n" + "=" * 70)
    print("CATEGORY B: Read Binary Files / Quote Globals")
    print("=" * 70)
    print("Hypothesis: /bin/sudo(15), /bin/sh(14), /bin/false(16) might contain")
    print("lambda bytecode. Quoting g(14), g(15), g(16) reveals their structure.\n")

    # ── Test B1-B3: readfile for /bin/* ──────────────────────────────────────
    bin_files = [(15, "/bin/sudo"), (14, "/bin/sh"), (16, "/bin/false")]
    for idx, (fid, name) in enumerate(bin_files, 1):
        print(f"--- Test B{idx}: readfile({fid}) = {name} ---")
        # ((g(7) int(fid)) QD)
        payload = (
            bytes([0x07])
            + encode_term(encode_byte_term(fid))
            + bytes([FD])
            + QD
            + bytes([FD, FF])
        )
        raw = send_raw_bytes(payload)
        analyze_response(raw, f"B{idx}", is_sys8=False)
        time.sleep(SLEEP_BETWEEN)

    # ── Test B4-B6: quote g(15), g(14), g(16) ──────────────────────────────
    globals_to_quote = [(15, "g(15)/sudo"), (14, "g(14)/sh"), (16, "g(16)/false")]
    for idx, (gid, name) in enumerate(globals_to_quote, 4):
        print(f"\n--- Test B{idx}: quote({name}) ---")
        # ((g(4) g(gid)) QD) — quote the global
        payload = bytes([0x04, gid, FD]) + QD + bytes([FD, FF])
        raw = send_raw_bytes(payload)
        analyze_response(raw, f"B{idx}", is_sys8=False)
        time.sleep(SLEEP_BETWEEN)


# ══════════════════════════════════════════════════════════════════════════════
# CATEGORY C: 3-Leaf Terms as CONTINUATIONS
# ══════════════════════════════════════════════════════════════════════════════


def run_category_c() -> None:
    print("\n" + "=" * 70)
    print("CATEGORY C: 3-Leaf Terms as CONTINUATIONS to sys8")
    print("=" * 70)
    print('Hypothesis: "3 leafs" hint means the CONTINUATION must have 3 leaf nodes.\n')

    # Helper: build ((g(8) nil) K) as bytes, where K is given as a term.
    def sys8_nil_with_k(k_term: object, label: str) -> bytes:
        # ((Var(8) nil) K) → 08 nil FD K FD FF
        return (
            bytes([0x08])
            + encode_term(NIL)
            + bytes([FD])
            + encode_term(k_term)
            + bytes([FD, FF])
        )

    # Helper for using QD: ((g(8) nil) QD) with QD embedded
    # We want sys8(nil)(K) where K is the custom continuation.
    # K receives the sys8 result and does something with it.
    # To observe the result, K should write/quote it — but that requires QD-like behavior.
    #
    # Strategy: wrap K so it still writes output:
    # K_observed = λresult. ((g(2) ((g(4) result) (λquoted. quoted))) (λ_. nil))
    # But this has depth issues with free vars.
    #
    # Alternative: just use the raw K as continuation. If sys8 returns non-Right(6),
    # the behavior will differ (we might get output, or different shape).
    # For observability, we can wrap: ((g(8) nil) (λr. ((QD_body) r)))
    # But QD IS already a continuation. So ((g(8) nil) K) where K is NOT QD
    # means we might not see output. We need a way to observe.
    #
    # Two-stage approach:
    # ((g(8) nil) (λresult. ((g(4) result) (λquoted. ((g(2) quoted) (λ_. nil))))))
    # At depth 0: g(8)=V8
    # At depth 1 (inside λresult): g(4)=V5, g(2)=V3
    # At depth 2 (inside λquoted): g(2)=V4
    # At depth 3 (inside λ_): nil=λ.λ.V0
    #
    # Actually easier: just use QD as the observer and wrap K differently.
    #
    # What we really want to test: does a specific K shape change sys8's permission check?
    # If sys8 checks its continuation's shape before returning Right(6)...
    #
    # But CPS: sys8 computes result, THEN applies K to it. So K shape shouldn't matter
    # for the permission check. UNLESS sys8 inspects K (quotes it / checks structure).
    #
    # Let's test by sending sys8(nil)(K) and observing via a WRAPPER:
    # ((g(4) ((g(8) nil) K_test)) QD)
    # = quote(sys8(nil)(K_test)) then QD prints it.
    # But sys8(nil)(K_test) would first apply K_test to Right(6),
    # yielding K_test(Right(6)), then quote THAT.
    #
    # Hmm, that's not what we want. We want to see if sys8 returns something
    # OTHER than Right(6) when K has 3 leaves.
    #
    # Simplest: just send ((g(8) nil) K) and see if we get any output.
    # If K is λx. ((g(2) ((g(4) x) ID)) ID2) at the right depths,
    # we get QD-like behavior from K itself.
    #
    # Let me build an "observer continuation" at depth 1:
    # OBS = λresult. ((Var(3) ((Var(5) Var(0)) (λq. q))) (λ_. (λ.λ.V0)))
    # At depth 1: g(2)=V3, g(4)=V5, result=V0
    # ((V5 V0) (λq. q)) = quote(result) then pass quoted to identity
    # Hmm, quote is CPS: ((g(4) term) k) → k(Left(quoted_bytes))
    # So ((V5 V0) (λq. ((V4 q) (λ_. nil_d3))))
    # At depth 2 inside λq: g(2)=V4, q=V0
    # ((V4 V0) (λ_. nil))
    # At depth 3: nil = λ.λ.V0
    #
    # OBS = λ. ((V5 V0) (λ. ((V4 V0) (λ. (λ.λ.V0)))))
    # This is write(quote(result)). Let's encode it.

    # OBS at depth 0 (to be used where g(2)=V2, g(4)=V4):
    # At top level as continuation of sys8:
    # OBS = λresult. ((g(4) result) (λquoted. ((g(2) quoted) (λ_. nil))))
    # Depth 0: g(4)=V4, g(2)=V2
    # Depth 1 (λresult): g(4)=V5, g(2)=V3, result=V0
    # Depth 2 (λquoted): g(2)=V4, quoted=V0
    # Depth 3 (λ_): nil at depth 3
    nil_d3 = Lam(Lam(Var(0)))
    obs_inner = lam(
        App(App(Var(4), Var(0)), lam(nil_d3))
    )  # λquoted. ((V4 V0) (λ_. nil))
    OBS = lam(App(App(Var(5), Var(0)), obs_inner))  # λresult. ((V5 V0) (λquoted. ...))

    # Verify OBS encoding doesn't contain FD/FE/FF as var indices
    obs_bytes = encode_term(OBS)
    print(f"Observer continuation (OBS) hex: {obs_bytes.hex()}")
    print(f"OBS term: {term_to_str(OBS)}")
    print()

    # But actually, let me reconsider. We want to test specific K shapes AND observe.
    # Two approaches:
    # 1) Use K directly, accept we might not see output (EMPTY means K was applied to Right(6))
    # 2) Use "K wraps OBS" — but then K doesn't have 3 leaves.
    #
    # Approach: for each K, do TWO sends:
    #   (a) ((g(8) nil) K) — raw, observe if we get any output
    #   (b) ((g(8) nil) OBS) — with OBS, as control
    # But that's 20 requests for C alone. Let's just use OBS for the first test (control)
    # and then use the raw K terms and accept EMPTY = Right(6) applied to K.
    #
    # Actually, the simplest approach: just use QD. QD IS a valid continuation.
    # ((g(8) nil) QD) is the baseline that gives Right(6).
    # For the 3-leaf tests, we send ((g(8) nil) K) where K has 3 leaf nodes.
    # If the result is different from EMPTY or contains unexpected output, that's a clue.
    #
    # Let's be pragmatic: use OBS for all C tests so we can SEE the result.
    # The K IS the continuation, and we want to observe sys8's result.
    # But if K is the continuation, sys8 applies K to the result, not OBS.
    #
    # The only way to both use K as continuation AND see the result:
    # K itself must include observation logic. OR we wrap:
    # ((g(8) nil) (λresult. (K_test result ... then observe)))
    # But then the continuation isn't K_test, it's the wrapper.
    #
    # OK FINAL APPROACH:
    # Test the RAW K as continuation. If we get output, great.
    # If EMPTY (meaning K(Right(6)) produced no output), just note that.
    # If sys8 changes behavior based on K shape, we'd see different output.
    # Also include a QD-based test as control.
    #
    # For the 10 tests, let's just send ((g(8) nil) K) and see what happens.
    # Most will be EMPTY. Any NON-EMPTY response is interesting.

    tests_c = [
        ("C1", "λx.(x x) — self-app", lam(App(Var(0), Var(0)))),
        ("C2", "λx.λy.(x y) — apply", lam(lam(App(Var(1), Var(0))))),
        (
            "C3",
            "λx.λy.λz.((x y) z) — 3-arg apply left",
            lam(lam(lam(App(App(Var(2), Var(1)), Var(0))))),
        ),
        (
            "C4",
            "λx.λy.λz.(x (y z)) — 3-arg apply right",
            lam(lam(lam(App(Var(2), App(Var(1), Var(0)))))),
        ),
        (
            "C5",
            "λx.λy.λz.((z y) x) — reversed 3-arg",
            lam(lam(lam(App(App(Var(0), Var(1)), Var(2))))),
        ),
        (
            "C6",
            "λx.((x x) x) — 3-leaf self-app left",
            lam(App(App(Var(0), Var(0)), Var(0))),
        ),
        (
            "C7",
            "λx.(x (x x)) — 3-leaf self-app right",
            lam(App(Var(0), App(Var(0), Var(0)))),
        ),
        ("C8", "g(14) — echo as continuation", g(14)),
        (
            "C9",
            "g(201) — backdoor as continuation",
            # g(201) = Var(201). 201 < 0xFD = 253, so it's valid.
            Var(201),
        ),
        ("C10", "λr. write(quote(r)) — OBS continuation", OBS),
    ]

    for label, desc, k_term in tests_c:
        print(f"--- Test {label}: {desc} ---")
        k_bytes = encode_term(k_term)
        print(f"  K hex: {k_bytes.hex()}")

        # ((g(8) nil) K)
        payload = (
            bytes([0x08]) + encode_term(NIL) + bytes([FD]) + k_bytes + bytes([FD, FF])
        )
        try:
            raw = send_raw_bytes(payload)
            analyze_response(raw, label, is_sys8=True)
        except Exception as e:
            print(f"  Error: {e}")
        time.sleep(SLEEP_BETWEEN)
        print()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════


def main() -> None:
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║       PROBE: Fresh Hypotheses for BrownOS Syscall 8                ║")
    print("║       3 Categories, 20 Tests Total                                 ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print()

    # Control test: baseline sys8(nil)(QD) — should give Right(6)
    print("--- CONTROL: sys8(nil)(QD) baseline ---")
    payload_ctrl = bytes([0x08]) + encode_term(NIL) + bytes([FD]) + QD + bytes([FD, FF])
    raw = send_raw_bytes(payload_ctrl)
    analyze_response(raw, "CONTROL", is_sys8=True)
    time.sleep(SLEEP_BETWEEN)

    run_category_a()
    run_category_b()
    run_category_c()

    print("\n" + "=" * 70)
    print("ALL TESTS COMPLETE")
    print("=" * 70)
    print("Look for '!!! BREAKTHROUGH !!!' above for any non-Right(6) sys8 results.")


if __name__ == "__main__":
    main()
