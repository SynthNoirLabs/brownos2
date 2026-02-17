#!/usr/bin/env python3
"""
probe_debruijn_bypass.py — De Bruijn index bypass for syscall 8

HYPOTHESIS: sys8 returns Right(6) because the server's permission check is
SYNTACTIC — it scans the raw input bytes for 0x08 and rejects the request
before evaluation. If we can construct a term that beta-reduces to Var(8)
WITHOUT any literal 0x08 byte in the raw payload, the permission check might
be bypassed.

APPROACH: Use lambda wrapping to shift de Bruijn indices.
- Under 1 lambda, Var(9) at byte level refers to the SAME global as Var(8)
  at top level (because the lambda binding shifts all free variables up by 1).
- So: (λx. ((x nil) QD)) applied to Var(9) should beta-reduce to
  ((Var(8) nil) QD) — i.e., sys8(nil) with QD continuation.
- The raw payload would contain 0x09 (not 0x08).

We test many variations:
1. Basic: ((λ. ((0 arg) cont)) Var(9)) — here Var(0) inside the lambda
   captures the lambda's parameter, which is Var(9) = sys8 at top level.
   Wait — this is wrong. Let me think more carefully.

De Bruijn index refresher:
- At the TOP LEVEL, free variables Var(0), Var(1), ... refer to globals.
  Var(8) = syscall 8.
- INSIDE one lambda (λ. body), Var(0) refers to the lambda's parameter.
  Var(1) refers to what was Var(0) at the outer level, etc.
  So to refer to global Var(8) from inside one lambda, you need Var(9).
- The wire encoding is POSTFIX: the raw bytes for Var(9) is just 0x09.

Strategy A: "Apply a function that uses its argument as the syscall"
  Term: ((λ. ((0 arg) cont)) 09) FF
  In AST: App(Lam(App(App(Var(0), arg), cont)), Var(9))
  Beta: ((Var(9) arg) cont) but Var(9) at top level IS Var(9)...

  Wait — after beta-reduction, the lambda is eliminated, so we're back at
  top level. The substitution replaces Var(0) inside with Var(9), but we also
  need to SHIFT the result down by 1 (because the lambda is gone).
  So Var(9) becomes Var(9) — no, free variables in the argument don't shift.

  Actually: in ((λ.M) N), the result is M[0 := N] with all free vars in M
  decremented by 1 (because the lambda binder is removed).

  So if M = App(App(Var(0), arg_shifted), cont_shifted), substituting Var(0)
  with N=Var(9):
  - Var(0) → Var(9), then shift down: Var(9) → Var(8). YES!
  - arg_shifted: any free vars in arg that were shifted up by 1 get shifted
    back down. So if we want `nil` (which has no free vars), no shift needed.
  - cont_shifted: QD contains refs to globals (syscalls write=2, quote=4,
    readdir=5). Inside the lambda these are shifted up by 1 to (3, 5, 6).
    But QD is an opaque byte sequence — we can't just "shift" it.

PROBLEM: QD is a fixed byte sequence with hardcoded de Bruijn indices.
Inside a wrapping lambda, QD's references to global syscalls would be WRONG
(they'd refer to the wrong globals because the lambda shifts everything).

SOLUTION: Don't put QD inside the lambda. Structure:
  ((λ. (0 arg)) Var(9))  — this beta-reduces to (Var(8) arg)
  Then apply QD OUTSIDE:
  (((λ. (0 arg)) Var(9)) QD) FF

Let me verify:
  Full term: App(App(Lam(App(Var(0), arg)), Var(9)), QD)
  Step 1: The inner App(Lam(App(Var(0), arg)), Var(9)) beta-reduces.
    Body: App(Var(0), arg)
    Substitute Var(0) → Var(9)
    Shift free vars in body down by 1: arg has no free vars (nil = λ.λ.0)
    Result: App(Var(8), arg)  ← Var(9) shifted down to Var(8)!
  Step 2: App(App(Var(8), arg), QD) = ((sys8 arg) QD)

  PERFECT. And the raw bytes will contain 0x09 (for Var(9)), NOT 0x08.

Let's also try deeper wrapping:
  Under 2 lambdas: need Var(10), which is byte 0x0A
  Under k lambdas: need Var(8+k)

And we should test with DIFFERENT arguments too (not just nil).
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FD,
    FE,
    FF,
    QD,
    decode_byte_term,
    decode_bytes_list,
    decode_either,
    encode_byte_term,
    encode_bytes_list,
    encode_term,
    parse_term,
)


HOST = "wc3.wechall.net"
PORT = 61221

CONNECT_TIMEOUT = 15.0
READ_TIMEOUT = 5.0
MAX_READ = 10 * 1024

NIL = Lam(Lam(Var(0)))  # Scott nil
IDENTITY = Lam(Var(0))


def recv_smart(sock: socket.socket, timeout_s: float = READ_TIMEOUT) -> bytes:
    """Receive all data, stopping on FF or timeout."""
    sock.settimeout(timeout_s)
    out = b""
    while len(out) < MAX_READ:
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


def query_raw(payload: bytes, retries: int = 3) -> bytes:
    """Send payload, return raw response."""
    delay = 0.2
    for attempt in range(retries):
        try:
            with socket.create_connection(
                (HOST, PORT), timeout=CONNECT_TIMEOUT
            ) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_smart(sock)
        except Exception as e:
            if attempt == retries - 1:
                return f"ERR:{e}".encode()
            time.sleep(delay)
            delay *= 2
    return b""


def interpret(data: bytes) -> str:
    """Interpret raw response."""
    if not data:
        return "EMPTY"
    if data.startswith(b"ERR:"):
        return data.decode("utf-8", "replace")
    if data.startswith(b"Invalid term!"):
        return "Invalid term!"
    if data.startswith(b"Term too big!"):
        return "Term too big!"
    if data.startswith(b"Encoding failed!"):
        return "Encoding failed!"

    if FF not in data:
        text = data.decode("utf-8", "replace")
        return f"Raw (no FF): {text!r}"

    try:
        term = parse_term(data[: data.index(FF) + 1])
    except Exception:
        text = data.decode("utf-8", "replace")
        return f"Parse error, raw: {text!r}"

    try:
        tag, payload = decode_either(term)
        if tag == "Right":
            try:
                return f"Right({decode_byte_term(payload)})"
            except Exception:
                return "Right(<complex>)"
        # Left — try to decode as bytes
        try:
            bs = decode_bytes_list(payload)
            preview = bs[:120].decode("utf-8", "replace")
            return f"Left(len={len(bs)}, {preview!r})"
        except Exception:
            return f"Left(<non-bytes-list>)"
    except Exception:
        return f"Term (non-Either)"


def check_no_byte(payload: bytes, forbidden: int, label: str) -> bool:
    """Verify that a specific byte does NOT appear in the payload (before FF)."""
    content = payload[: payload.index(FF)] if FF in payload else payload
    if forbidden in content:
        print(f"  WARNING: {label} contains forbidden byte 0x{forbidden:02x}!")
        # Find positions
        positions = [i for i, b in enumerate(content) if b == forbidden]
        print(f"    positions: {positions}")
        return False
    return True


def run_test(label: str, payload: bytes, check_forbidden: int | None = 0x08) -> str:
    """Run a single test, optionally checking for forbidden byte."""
    print(f"\n[{label}]")
    print(f"  payload_hex: {payload.hex()}")
    print(f"  payload_len: {len(payload)}")

    if check_forbidden is not None:
        clean = check_no_byte(payload, check_forbidden, label)
        print(f"  no_0x{check_forbidden:02x}_in_payload: {clean}")

    result = query_raw(payload)
    interp = interpret(result)
    print(f"  response_hex: {result.hex()}")
    print(f"  response_len: {len(result)}")
    print(f"  interp: {interp}")
    return interp


# =============================================================================
# PHASE 1: Basic de Bruijn bypass — single lambda wrap
# =============================================================================
def phase_1_single_lambda_wrap():
    """
    Term: (((λ. (0 arg)) Var(9)) QD) FF

    Inside the lambda, Var(0) is the parameter.
    We apply it to Var(9) — which after beta-reduction and shift becomes Var(8) = sys8.
    QD is OUTSIDE the lambda, so its indices are correct.

    Variation: also try with arg NOT being nil.
    """
    print("\n" + "=" * 80)
    print("PHASE 1: Single lambda wrap — sys8 via beta-reduction from Var(9)")
    print("=" * 80)

    # 1a: ((λ. (Var(0) nil)) Var(9)) with QD continuation
    # AST: App(App(Lam(App(Var(0), NIL)), Var(9)), QD_term)
    # But QD is raw bytes, not an AST. We need to construct the full payload.
    #
    # Payload structure:
    # inner_term = App(Lam(App(Var(0), nil)), Var(9))
    # full = App(inner_term, QD_as_term) + FF
    # But QD is already bytes... we can just append:
    # encode(inner_term) + QD + FD + FF

    inner = App(Lam(App(Var(0), NIL)), Var(9))
    inner_bytes = encode_term(inner)
    payload_1a = inner_bytes + QD + bytes([FD, FF])
    run_test("P1a: ((λ.(0 nil)) Var(9)) QD — single wrap, nil arg", payload_1a)

    # 1b: Same but with int 0 as argument
    int0 = encode_byte_term(0)
    inner_1b = App(Lam(App(Var(0), int0)), Var(9))
    payload_1b = encode_term(inner_1b) + QD + bytes([FD, FF])
    run_test("P1b: ((λ.(0 int0)) Var(9)) QD — single wrap, int0 arg", payload_1b)

    # 1c: With the string "ilikephp" as argument
    pw_bytes = encode_bytes_list(b"ilikephp")
    inner_1c = App(Lam(App(Var(0), pw_bytes)), Var(9))
    payload_1c = encode_term(inner_1c) + QD + bytes([FD, FF])
    run_test(
        "P1c: ((λ.(0 'ilikephp')) Var(9)) QD — single wrap, password arg", payload_1c
    )

    # 1d: With gizmore's UID (1000) as argument
    uid = encode_byte_term(1000)
    inner_1d = App(Lam(App(Var(0), uid)), Var(9))
    payload_1d = encode_term(inner_1d) + QD + bytes([FD, FF])
    run_test("P1d: ((λ.(0 int1000)) Var(9)) QD — single wrap, uid1000 arg", payload_1d)

    # 1e: Direct sys8 baseline for comparison (contains 0x08)
    direct = bytes([0x08]) + encode_term(NIL) + bytes([FD]) + QD + bytes([FD, FF])
    run_test(
        "P1e: BASELINE ((sys8 nil) QD) — direct (HAS 0x08)",
        direct,
        check_forbidden=None,
    )


# =============================================================================
# PHASE 2: Double lambda wrap — Var(10) = 0x0A
# =============================================================================
def phase_2_double_lambda_wrap():
    """
    Term: ((λ. (λ. (0 nil))) applied twice to get sys8.
    Actually: (((λ.λ. (1 nil_shifted)) dummy Var(10)) QD)

    Hmm, let me think again. With TWO lambdas:
    - Inside 2 lambdas, global Var(8) is at index 10.
    - Var(1) inside is the outer lambda's param.
    - Var(0) inside is the inner lambda's param.

    Better approach: nest the single-wrap.
    ((λ. ((λ. (0 nil)) Var(0))) Var(9))
    - Outer lambda binds x = Var(9)
    - Inner: (λ. (0 nil)) applied to Var(0) which is x
    - Beta inner: (x nil) = (Var(9) nil)
    - But we're still inside outer lambda, so shift back: Var(9) → Var(8)
    - Wait, Var(0) is the outer param, not a free variable. Let me re-think.

    Actually simplest double wrap:
    ((λ. (0 nil)) ((λ. 0) Var(9)))
    - Inner: (λ.0) applied to Var(9) = Var(9) (identity)
    - Outer: (λ.(0 nil)) applied to Var(9)
    - But evaluation order matters. The server does normal-order (lazy?) reduction.

    Let me just try multiple depths of the basic pattern:
    Depth k: ((λ^k . (0^(k-1) applied-to ... nil)) Var(8+k) ... Var(8+k))

    Actually, the simplest generalization for depth k:
    Use k nested identity wrappers:
    ((λ.0) ((λ.0) ... ((λ.0) Var(8+k))...)) with k identity lambdas
    This should reduce to Var(8) at top level... NO.

    (λ.0) Var(8+k) → Var(8+k) (identity just returns its arg, no shift of free vars in arg)
    So this doesn't help — we'd still have Var(8+k) at top level, not Var(8).

    The SHIFTING only happens when the lambda is a BINDER that gets eliminated.
    Let me be precise:

    ((λ. body) arg):
    1. Substitute: replace Var(0) in body with arg (with appropriate shifting of arg)
    2. Shift: decrement all free variables in the result by 1

    So ((λ. Var(0)) Var(9)):
    1. Substitute Var(0) → Var(9)
    2. But Var(9) was free in arg, not in body. The shift applies to free vars
       that were in body referencing things OUTSIDE the lambda.

    Actually, standard beta reduction: ((λ.M) N) = M[0 := N] where:
    - M[0 := N]: replace Var(0) in M with N (shifting N's vars up appropriately)
    - Then shift all remaining free vars in M down by 1

    For ((λ. Var(0)) Var(9)):
    - M = Var(0), substitute → Var(9). Var(9) is the substituted value.
    - No other free vars in M to shift.
    - Result: Var(9). NOT Var(8)!

    Hmm. So (λ.0) is just identity — it returns its argument unchanged.

    The SHIFT DOWN only affects free variables that were ALREADY in M (the body),
    not the substituted argument.

    So when does the shift happen? When M has free variables OTHER than Var(0).
    Example: ((λ. Var(1)) anything) = Var(0). Here Var(1) in M referred to the
    outer scope's Var(0), and after removing the lambda, it shifts down to Var(0).

    OK so let me reconsider:
    ((λ. App(Var(1), arg_inner)) Var(9)):
    - M = App(Var(1), arg_inner)
    - Var(1) is free in M (refers to outer Var(0)). After substitution (Var(0)
      doesn't appear, nothing to substitute). After shift: Var(1) → Var(0).
    - Result: App(Var(0), arg_inner_shifted)
    - This is NOT sys8 — it's Var(0) which isn't even a syscall.

    Hmm, let me reconsider the ORIGINAL approach:
    ((λ. App(Var(0), nil)) Var(9)):
    - M = App(Var(0), nil)
    - Substitute Var(0) → Var(9): App(Var(9), nil)
    - Shift free vars in (what was M) down by 1:
      Var(9) came from substitution, is it shifted?

    THIS IS THE KEY QUESTION. In standard de Bruijn beta reduction:
    ((λ. M) N) = shift(-1, 0, M[0 := shift(1, 0, N)])

    Where shift(d, c, term):
    - Var(k) → Var(k+d) if k >= c, else Var(k)
    - Lam(body) → Lam(shift(d, c+1, body))
    - App(f, x) → App(shift(d, c, f), shift(d, c, x))

    And M[j := N]:
    - Var(k) → N if k == j, else Var(k)
    - (with appropriate shifting of N when going under lambdas)

    Full standard:
    ((λ. M) N) = shift(-1, 0, M[0 := shift(1, 0, N)])

    So for ((λ. Var(0)) Var(9)):
    - shift(1, 0, N) = shift(1, 0, Var(9)) = Var(10) (since 9 >= 0)
    - M[0 := Var(10)] = Var(0)[0 := Var(10)] = Var(10)
    - shift(-1, 0, Var(10)) = Var(9) (since 10 >= 0, 10-1=9)
    - Result: Var(9). Identity confirmed — no shift effect.

    For ((λ. App(Var(0), nil)) Var(9)):
    - shift(1, 0, Var(9)) = Var(10)
    - M[0 := Var(10)] = App(Var(10), nil) (nil has no free vars to shift)
    - shift(-1, 0, App(Var(10), nil)) = App(Var(9), nil)
    - Result: App(Var(9), nil) = (sys9 nil) — NOT sys8!

    WAIT. This means my whole approach was wrong! The identity wrapper
    doesn't change the index. We'd get Var(9) not Var(8).

    But Var(9) is NOT sys8. At top level, Var(8) = sys8, Var(9) = sys9.
    There's no "shifting back" — the substituted variable keeps its value.

    So the Oracle's suggestion was INCORRECT. A simple lambda wrapper
    doesn't magically turn Var(9) into Var(8) via beta reduction.

    HOWEVER — what about using FREE variables in the body?

    ((λ. App(Var(9), nil)) anything):
    - M = App(Var(9), nil). Var(9) is FREE in M (it refers to global Var(8)
      because we're under one lambda, so 9-1=8).
    - M[0 := anything]: Var(0) doesn't appear, no substitution.
    - shift(-1, 0, App(Var(9), nil)) = App(Var(8), nil)
    - Result: App(Var(8), nil) = (sys8 nil)!

    YES! This works! But... the raw encoding of M = App(Var(9), nil) inside
    the lambda is: 09 <nil> FD. And Var(9) encodes as byte 0x09, not 0x08.

    So the full payload:
    Lam(App(Var(9), nil)) applied to anything, then QD continuation.

    Term: App(App(Lam(App(Var(9), nil)), anything), QD)

    The KEY: Var(9) inside the lambda body IS a free variable referring to
    global Var(8), and after beta-reduction (eliminating the lambda), it
    shifts down to Var(8). The raw bytes contain 0x09, not 0x08!

    We can also apply to NOTHING — just use (λ. (Var(9) nil)) without
    applying it to anything? No, then the lambda stays un-reduced.

    We DO need to apply it. But the argument is irrelevant (never used).
    We can use nil as the dummy argument.
    """
    print("\n" + "=" * 80)
    print("PHASE 2: Correct de Bruijn bypass — free variable shift")
    print("  Inside λ, Var(9) refers to global sys8. After β-reduction, Var(9)→Var(8).")
    print("  Raw bytes contain 0x09, NOT 0x08.")
    print("=" * 80)

    # The term: ((λ. (Var(9) nil)) dummy) with QD
    # dummy = nil (never used, just triggers beta-reduction)
    dummy = NIL

    # 2a: sys8(nil) via shift — single lambda
    inner_2a = App(Lam(App(Var(9), NIL)), dummy)
    payload_2a = encode_term(inner_2a) + QD + bytes([FD, FF])
    run_test("P2a: ((λ.(9 nil)) dummy) QD — free-var shift, nil arg", payload_2a)

    # 2b: sys8(int0) via shift
    int0 = encode_byte_term(0)
    # Inside lambda, int0's vars are all bound (under 9 lambdas), no shift issues
    inner_2b = App(Lam(App(Var(9), int0)), dummy)
    payload_2b = encode_term(inner_2b) + QD + bytes([FD, FF])
    run_test("P2b: ((λ.(9 int0)) dummy) QD — free-var shift, int0 arg", payload_2b)

    # 2c: sys8(password string) via shift
    pw = encode_bytes_list(b"ilikephp")
    inner_2c = App(Lam(App(Var(9), pw)), dummy)
    payload_2c = encode_term(inner_2c) + QD + bytes([FD, FF])
    run_test("P2c: ((λ.(9 'ilikephp')) dummy) QD — free-var shift, pw arg", payload_2c)

    # 2d: Double lambda — inside 2 lambdas, global Var(8) = Var(10)
    inner_2d = App(Lam(App(Lam(App(Var(10), NIL)), dummy)), dummy)
    payload_2d = encode_term(inner_2d) + QD + bytes([FD, FF])
    run_test("P2d: double lambda wrap, Var(10)→Var(8), nil arg", payload_2d)

    # 2e: Triple lambda — Var(11) = 0x0B
    inner_2e = App(Lam(App(Lam(App(Lam(App(Var(11), NIL)), dummy)), dummy)), dummy)
    payload_2e = encode_term(inner_2e) + QD + bytes([FD, FF])
    run_test("P2e: triple lambda wrap, Var(11)→Var(8), nil arg", payload_2e)


# =============================================================================
# PHASE 3: Use the lambda parameter AS the argument to sys8
# =============================================================================
def phase_3_param_as_arg():
    """
    What if the argument to sys8 needs to be something we can only construct
    through beta-reduction? Use the lambda parameter as the sys8 argument.

    Term: ((λ. (Var(9) Var(0))) actual_arg) QD
    - Inside lambda: Var(9) = global sys8, Var(0) = lambda param
    - After beta: (Var(8) actual_arg) QD = ((sys8 actual_arg) QD)

    This way, the raw bytes contain 0x09 for sys8, and the actual arg's
    bytes appear OUTSIDE the lambda (in the application position).
    """
    print("\n" + "=" * 80)
    print("PHASE 3: Parameter as argument — (λ.(9 0)) applied to various args")
    print("=" * 80)

    # The pattern: ((λ. (Var(9) Var(0))) arg) QD FF
    def make_bypass_payload(arg):
        inner = App(Lam(App(Var(9), Var(0))), arg)
        return encode_term(inner) + QD + bytes([FD, FF])

    args = [
        ("nil", NIL),
        ("int0", encode_byte_term(0)),
        ("int1", encode_byte_term(1)),
        ("int42", encode_byte_term(42)),
        ("int201", encode_byte_term(201)),
        ("int1000", encode_byte_term(1000)),
        ("identity", IDENTITY),
        ("'ilikephp'", encode_bytes_list(b"ilikephp")),
        ("'gizmore'", encode_bytes_list(b"gizmore")),
        ("'dloser'", encode_bytes_list(b"dloser")),
        ("'root'", encode_bytes_list(b"root")),
    ]

    for name, arg in args:
        payload = make_bypass_payload(arg)
        run_test(f"P3: sys8({name}) via bypass", payload)


# =============================================================================
# PHASE 4: Bypass with DIFFERENT continuations (not just QD)
# =============================================================================
def phase_4_different_continuations():
    """
    Maybe the permission check also scans for QD patterns. Try with:
    - DBG continuation (write-based, no quote)
    - Identity continuation
    - No continuation (partial application)
    """
    print("\n" + "=" * 80)
    print("PHASE 4: Bypass with different continuations")
    print("=" * 80)

    # 4a: Bypass + identity continuation (just return the result to top level)
    inner_4a = App(Lam(App(App(Var(9), NIL), Var(0))), IDENTITY)
    # Wait — inside the lambda, the continuation should also be correct.
    # Let's think: ((λ. ((Var(9) nil) Var(0))) IDENTITY)
    # Var(9) = sys8, Var(0) = lambda param = IDENTITY
    # After beta: ((sys8 nil) identity) — sys8 returns result, identity passes it through
    # But we won't see anything because identity just returns the term.
    # We need write/quote outside...

    # Better: bypass the syscall, THEN use QD on the result
    # ((λ. (Var(9) nil)) dummy) — produces (sys8 nil) which is a partial application
    # Then: (((λ. (Var(9) nil)) dummy) QD) — applies QD as continuation
    # This is what Phase 2 already does.

    # Let's try: full program with bypass syscall + separate write continuation
    # ((λ. ((Var(9) nil) (λres. ((Var(4) (Var(6) res)) anything)))) dummy)
    # Inside lambda: Var(9)=sys8, Var(4)=write(shifted to 3), Var(6)=quote(shifted to 5)
    # Hmm this gets complicated. Let me just ensure QD works and also try raw write.

    # 4a: Bypass sys8, catch result with write(quote(result))
    # We build the continuation INSIDE the lambda too (using shifted indices)
    # write = Var(2) at top level → Var(3) inside 1 lambda
    # quote = Var(4) at top level → Var(5) inside 1 lambda
    # continuation: λres. ((write (quote res)) something)
    # Inside cont (1 more lambda): write = Var(4), quote = Var(6), res = Var(0)
    # Full: λres. ((Var(4) (Var(6) Var(0))) nil_shifted)

    # Inside the outer lambda + this inner lambda (depth 2):
    # nil has no free vars, so no shift needed
    write_quote_cont = Lam(App(App(Var(4), App(Var(6), Var(0))), NIL))

    inner_4a = App(Lam(App(App(Var(9), NIL), write_quote_cont)), NIL)
    payload_4a = encode_term(inner_4a) + bytes([FF])
    run_test(
        "P4a: bypass sys8(nil) with write(quote(result)) inside lambda",
        payload_4a,
        check_forbidden=0x08,
    )

    # 4b: No continuation at all — just the bypass partial application
    inner_4b = App(Lam(App(Var(9), NIL)), NIL)
    payload_4b = encode_term(inner_4b) + bytes([FF])
    run_test(
        "P4b: bypass sys8(nil) partial application only",
        payload_4b,
        check_forbidden=0x08,
    )

    # 4c: Use the PARAMETER as continuation
    # ((λ. ((Var(9) nil) Var(0))) QD_term)
    # But QD is raw bytes... we can parse it to get the AST
    qd_term = parse_term(QD + bytes([FF]))
    inner_4c = App(Lam(App(App(Var(9), NIL), Var(0))), qd_term)
    payload_4c = encode_term(inner_4c) + bytes([FF])
    run_test(
        "P4c: bypass sys8(nil) with QD as parameter→continuation",
        payload_4c,
        check_forbidden=0x08,
    )


# =============================================================================
# PHASE 5: Bypass using the BACKDOOR result
# =============================================================================
def phase_5_backdoor_then_bypass():
    """
    Chain: first call backdoor to get the pair, then use bypass to call sys8
    with the pair as argument.

    Since server is single-term-per-connection, we need to do this in ONE term:
    ((backdoor nil) (λ pair. ((bypass_sys8 pair) QD)))

    But backdoor = Var(201) = 0xC9. And sys8 = Var(8).

    We construct:
    ((Var(201) nil) continuation)
    where continuation = λ. ( ((λ. (Var(10) Var(1))) dummy) QD_shifted )

    Wait, this gets index-shifting complex. Let me think step by step.

    Top level: backdoor=Var(201), sys8=Var(8)

    continuation_for_backdoor = λ pair. ((sys8_bypass pair) QD)

    Inside this lambda (depth 1):
    - pair = Var(0)
    - sys8 = Var(9) (shifted by 1)
    - For bypass: (λ. (Var(10) Var(0))) — inside depth 2:
      Var(10) = sys8 (shifted by 2 from top = 8+2=10)
      Var(0) = inner lambda param = will be pair
    - Apply bypass to pair: ((λ.(Var(10) Var(0))) Var(0))
      Var(0) on outside = pair
    - After beta: (Var(9) pair) — which is (sys8 pair) at depth 1
    - Then apply QD... but QD needs to be at depth 1 too.

    Actually, simpler: just use the free-var-shift bypass inside the continuation.

    continuation = λ pair. ((Var(9) Var(0)) QD_shifted)

    But Var(9) inside depth 1 is global Var(8) = sys8!
    Wait — NO. Inside the continuation lambda (depth 1), free Var(9)
    refers to global Var(8). So we can DIRECTLY use Var(9) without any bypass!

    The whole point is that the CONTINUATION is already inside a lambda,
    so sys8's index is naturally shifted to 9.

    But the RAW BYTES of the continuation will contain 0x09 for Var(9),
    not 0x08. So if the permission check scans the entire payload for 0x08,
    this naturally avoids it!

    Let's try: ((backdoor nil) (λ pair. ((Var(9) pair) QD)))
    Payload bytes will have: 0xC9 for backdoor, and 0x09 for sys8 ref inside lambda.
    NO 0x08 anywhere!
    """
    print("\n" + "=" * 80)
    print("PHASE 5: Backdoor → sys8 bypass in one term")
    print("  sys8 ref is naturally Var(9) inside continuation lambda")
    print("=" * 80)

    # Parse QD to get its AST so we can embed it properly
    qd_term = parse_term(QD + bytes([FF]))

    # Inside continuation (depth 1):
    # pair = Var(0), sys8 = Var(9), write = Var(3), quote = Var(5), readdir=Var(6)
    # QD references at top level: write=Var(2), quote=Var(4), readdir=Var(5)
    # Inside depth 1, QD indices need +1 shift.
    # Since QD is complex, let's try two approaches:

    # 5a: Use raw QD bytes spliced OUTSIDE the continuation lambda
    # Structure: ((Var(201) nil) (λ. ((Var(9) Var(0)) ???)))
    # We can't easily put QD outside when sys8 is inside the lambda.
    # The continuation gets the result of sys8, which it needs to pass to QD.

    # Alternative: CPS chain
    # ((backdoor nil) (λ bd_result. ((sys8_bypass bd_result) QD)))
    # = ((Var(201) nil) (λ. ( ((λ.(Var(10) Var(0))) Var(0)) ... )))
    # This still has 0x09... let me check if Var(201) or nil or anything has 0x08.

    # Actually, let me just directly construct the CPS term:
    # ((backdoor nil) cont) where cont = λ result. do_stuff(result)

    # Inside cont (depth 1):
    # result = Var(0), backdoor = Var(202), sys8 = Var(9)
    # We want: ((sys8 result) some_qd)
    # = ((Var(9) Var(0)) some_qd_at_depth1)

    # For QD at depth 1 — QD's internals reference write(2→3), quote(4→5), readdir(5→6)
    # We need to shift QD term by +1. Let's write a shift function.

    def shift_term(term, d, c=0):
        """Shift free variables in term by d, with cutoff c."""
        if isinstance(term, Var):
            return Var(term.i + d) if term.i >= c else term
        if isinstance(term, Lam):
            return Lam(shift_term(term.body, d, c + 1))
        if isinstance(term, App):
            return App(shift_term(term.f, d, c), shift_term(term.x, d, c))
        raise TypeError(f"Unknown term: {type(term)}")

    qd_shifted_1 = shift_term(qd_term, 1)  # QD shifted for depth 1

    # 5a: ((Var(201) nil) (λ. ((Var(9) Var(0)) QD_shifted)))
    cont_5a = Lam(App(App(Var(9), Var(0)), qd_shifted_1))
    full_5a = App(App(Var(201), NIL), cont_5a)
    payload_5a = encode_term(full_5a) + bytes([FF])
    run_test(
        "P5a: ((backdoor nil) (λ.((9 0) QD↑1))) — backdoor result→sys8", payload_5a
    )

    # 5b: Same but extract A and B from pair, pass A to sys8
    # Pair = λf. f A B. To extract A: pair (λa.λb. a) = pair True
    # Inside cont (depth 1): pair = Var(0)
    # Extract A: App(Var(0), Lam(Lam(Var(1))))  (True = λa.λb.a)
    # But this gives A which is λa.λb.(b b)
    true_term = Lam(Lam(Var(1)))  # Church True / fst
    false_term = Lam(Lam(Var(0)))  # Church False / snd

    # extract_A = App(Var(0), true_term)  — but this needs to be under cont's lambda
    # To pass A to sys8: ((sys8 (pair True)) QD)
    # Inside depth 1: ((Var(9) (Var(0) True)) QD↑1)
    cont_5b = Lam(App(App(Var(9), App(Var(0), true_term)), qd_shifted_1))
    full_5b = App(App(Var(201), NIL), cont_5b)
    payload_5b = encode_term(full_5b) + bytes([FF])
    run_test("P5b: backdoor→sys8(pair.fst=A) via bypass", payload_5b)

    # 5c: Pass B to sys8
    cont_5c = Lam(App(App(Var(9), App(Var(0), false_term)), qd_shifted_1))
    full_5c = App(App(Var(201), NIL), cont_5c)
    payload_5c = encode_term(full_5c) + bytes([FF])
    run_test("P5c: backdoor→sys8(pair.snd=B) via bypass", payload_5c)

    # 5d: Pass the whole pair to sys8
    cont_5d = Lam(App(App(Var(9), Var(0)), qd_shifted_1))
    full_5d = App(App(Var(201), NIL), cont_5d)
    payload_5d = encode_term(full_5d) + bytes([FF])
    run_test("P5d: backdoor→sys8(pair) via bypass", payload_5d)

    # 5e: Apply pair to itself: pair pair. Then sys8 on that.
    # Inside cont: (Var(0) Var(0)) = pair applied to pair
    cont_5e = Lam(App(App(Var(9), App(Var(0), Var(0))), qd_shifted_1))
    full_5e = App(App(Var(201), NIL), cont_5e)
    payload_5e = encode_term(full_5e) + bytes([FF])
    run_test("P5e: backdoor→sys8(pair pair) via bypass", payload_5e)

    # 5f: omega = (A B) where A = pair.fst, B = pair.snd
    # Inside cont: A = (Var(0) True), B = (Var(0) False)
    # omega = (A B) = ((Var(0) True) (Var(0) False))
    # sys8(omega) — but we know sys8 checks before eval, and omega diverges.
    # Still try to see if bypass changes anything.
    cont_5f = Lam(
        App(
            App(Var(9), App(App(Var(0), true_term), App(Var(0), false_term))),
            qd_shifted_1,
        )
    )
    full_5f = App(App(Var(201), NIL), cont_5f)
    payload_5f = encode_term(full_5f) + bytes([FF])
    run_test(
        "P5f: backdoor→sys8(omega from pair) via bypass",
        payload_5f,
        check_forbidden=0x08,
    )


# =============================================================================
# PHASE 6: Bypass with echo result as sys8 argument
# =============================================================================
def phase_6_echo_bypass():
    """
    Chain echo → sys8 in one term using bypass:
    ((echo something) (λ echo_result. ((sys8_bypass echo_result) QD)))

    echo = Var(14) = 0x0E at top level
    Inside cont lambda: echo result in Var(0), sys8 = Var(9)
    """
    print("\n" + "=" * 80)
    print("PHASE 6: Echo → sys8 bypass chain")
    print("=" * 80)

    qd_term = parse_term(QD + bytes([FF]))

    def shift_term(term, d, c=0):
        if isinstance(term, Var):
            return Var(term.i + d) if term.i >= c else term
        if isinstance(term, Lam):
            return Lam(shift_term(term.body, d, c + 1))
        if isinstance(term, App):
            return App(shift_term(term.f, d, c), shift_term(term.x, d, c))
        raise TypeError(f"Unknown: {type(term)}")

    qd_shifted_1 = shift_term(qd_term, 1)

    # 6a: echo(nil) → sys8(echo_result) via bypass
    cont_6a = Lam(App(App(Var(9), Var(0)), qd_shifted_1))
    full_6a = App(App(Var(14), NIL), cont_6a)
    payload_6a = encode_term(full_6a) + bytes([FF])
    run_test("P6a: echo(nil)→sys8(result) via bypass", payload_6a)

    # 6b: echo(Var(8)) but shifted — echo at top=14, inside echo's arg Var(8) IS sys8
    # But we can't send Var(8) because... oh wait, we CAN send Var(8) as an
    # argument to echo — the byte 0x08 would appear. Unless we bypass echo's
    # arg too. But echo doesn't care about the arg content.
    # The whole point is to avoid 0x08 in the ENTIRE payload.
    # echo(something) → sys8(echo_result=Left(something))
    # So echo_result is Left(something), and we pass that to sys8.
    # That's what 6a already does.

    # 6c: echo(backdoor pair component)
    # Get backdoor result first, extract A, echo it, then sys8 the echo result.
    # This needs a 2-level CPS chain:
    # ((backdoor nil) (λ pair. ((echo (pair True)) (λ echo_res. ((sys8 echo_res) QD)))))
    true_term = Lam(Lam(Var(1)))

    # Inside depth 1 (after backdoor): pair=Var(0), echo=Var(15), sys8=Var(9)
    # Inside depth 2 (after echo): echo_res=Var(0), sys8=Var(10), pair=Var(1)
    qd_shifted_2 = shift_term(qd_term, 2)
    inner_cont = Lam(App(App(Var(10), Var(0)), qd_shifted_2))
    outer_cont = Lam(App(App(Var(15), App(Var(0), true_term)), inner_cont))
    full_6c = App(App(Var(201), NIL), outer_cont)
    payload_6c = encode_term(full_6c) + bytes([FF])
    run_test("P6c: backdoor→echo(A)→sys8(result) via bypass", payload_6c)


# =============================================================================
# PHASE 7: Multiple syscalls chained before sys8 bypass
# =============================================================================
def phase_7_multi_chain_bypass():
    """
    Try chaining multiple "setup" syscalls before sys8:
    - Read a file, then sys8 with file content
    - Read passwd, then sys8 with gizmore's hash
    - Backdoor, then echo, then sys8
    All using bypass (no literal 0x08 in payload).
    """
    print("\n" + "=" * 80)
    print("PHASE 7: Multi-syscall chains → sys8 bypass")
    print("=" * 80)

    qd_term = parse_term(QD + bytes([FF]))

    def shift_term(term, d, c=0):
        if isinstance(term, Var):
            return Var(term.i + d) if term.i >= c else term
        if isinstance(term, Lam):
            return Lam(shift_term(term.body, d, c + 1))
        if isinstance(term, App):
            return App(shift_term(term.f, d, c), shift_term(term.x, d, c))
        raise TypeError(f"Unknown: {type(term)}")

    # 7a: readfile(88=mail) → sys8(file_content)
    # readfile = Var(7) at top level
    # ((readfile int88) (λ result. ((sys8 result) QD)))
    # result is Either. We want to extract Left payload and pass to sys8.
    # Inside depth 1: result=Var(0), sys8=Var(9), readfile=Var(8)... WAIT
    # readfile at top is Var(7), inside 1 lambda = Var(8) = byte 0x08!
    # That would put 0x08 in the payload!
    #
    # But we don't need readfile inside — it's at the top level.
    # ((Var(7) int88) continuation)
    # Var(7) = 0x07, no problem.
    # Inside continuation (depth 1): result=Var(0), sys8=Var(9)

    # result is Either. Unwrap: result (λ payload. do_stuff) (λ err. do_stuff)
    # For Left path: ((sys8 payload) QD)
    # Inside depth 2 (Left handler): payload=Var(0), sys8=Var(10)

    qd_s2 = shift_term(qd_term, 2)
    left_handler = Lam(
        App(App(Var(10), Var(0)), qd_s2)
    )  # λ payload. ((sys8 payload) QD↑2)
    right_handler = Lam(Lam(Var(0)))  # λ err. nil (just return nil on error)

    # continuation: λ result. ((result left_handler) right_handler)
    cont_7a = Lam(App(App(Var(0), left_handler), right_handler))

    full_7a = App(App(Var(7), encode_byte_term(88)), cont_7a)
    payload_7a = encode_term(full_7a) + bytes([FF])
    run_test("P7a: readfile(mail)→unwrap→sys8(content) via bypass", payload_7a)

    # 7b: readfile(65=.history) → sys8(content)
    full_7b = App(App(Var(7), encode_byte_term(65)), cont_7a)
    payload_7b = encode_term(full_7b) + bytes([FF])
    run_test("P7b: readfile(.history)→unwrap→sys8(content) via bypass", payload_7b)

    # 7c: readfile(11=passwd) → sys8(content)
    full_7c = App(App(Var(7), encode_byte_term(11)), cont_7a)
    payload_7c = encode_term(full_7c) + bytes([FF])
    run_test("P7c: readfile(passwd)→unwrap→sys8(content) via bypass", payload_7c)

    # 7d: name(14=/bin/sh) → sys8(name)
    # name = Var(6) at top level
    full_7d = App(App(Var(6), encode_byte_term(14)), cont_7a)
    payload_7d = encode_term(full_7d) + bytes([FF])
    run_test("P7d: name(sh)→unwrap→sys8(name) via bypass", payload_7d)


# =============================================================================
# PHASE 8: Verify our bypass actually works correctly
# =============================================================================
def phase_8_verify_bypass_mechanism():
    """
    To confirm the bypass mechanism works (beta-reduction is happening),
    test it with a KNOWN syscall (not sys8):
    - Use bypass to call sys42 (towel) — should return towel string
    - Use bypass to call echo (14) — should echo back
    - Use bypass to call readfile (7) — should read a file
    If these work, the bypass mechanism is correct and the failure on sys8
    is genuine permission denial, not a broken term.
    """
    print("\n" + "=" * 80)
    print("PHASE 8: Verify bypass mechanism with known syscalls")
    print("  If these return correct results, the bypass β-reduction works.")
    print("=" * 80)

    # 8a: Bypass call to towel (42). Inside λ, Var(43) = global Var(42).
    inner_8a = App(Lam(App(Var(43), NIL)), NIL)
    payload_8a = encode_term(inner_8a) + QD + bytes([FD, FF])
    run_test(
        "P8a: bypass towel(nil) — Var(43)→Var(42)", payload_8a, check_forbidden=0x2A
    )

    # 8b: Bypass call to echo (14). Inside λ, Var(15) = global Var(14).
    inner_8b = App(Lam(App(Var(15), NIL)), NIL)
    payload_8b = encode_term(inner_8b) + QD + bytes([FD, FF])
    run_test(
        "P8b: bypass echo(nil) — Var(15)→Var(14)", payload_8b, check_forbidden=0x0E
    )

    # 8c: Bypass call to readfile (7) with file 88 (mail).
    # Inside λ, readfile = Var(8) = byte 0x08. So this inherently has 0x08!
    # That's interesting — readfile(7) inside a lambda becomes Var(8).
    # Let's skip that and use name (6) → Var(7) inside lambda.
    inner_8c = App(Lam(App(Var(7), encode_byte_term(88))), NIL)
    payload_8c = encode_term(inner_8c) + QD + bytes([FD, FF])
    run_test("P8c: bypass name(88) — Var(7)→Var(6)", payload_8c, check_forbidden=0x06)

    # 8d: Direct towel for comparison
    direct_8d = bytes([0x2A]) + encode_term(NIL) + bytes([FD]) + QD + bytes([FD, FF])
    run_test("P8d: DIRECT towel(nil) for comparison", direct_8d, check_forbidden=None)


def main():
    print("=" * 80)
    print("probe_debruijn_bypass.py — De Bruijn index bypass for syscall 8")
    print(f"target: {HOST}:{PORT}")
    print("=" * 80)
    print()
    print("THEORY: If sys8's permission check is syntactic (scans raw bytes for 0x08),")
    print("we can bypass it by using shifted de Bruijn indices inside lambda wrappers.")
    print("Inside a lambda, global Var(8) = Var(9) at byte level (0x09, not 0x08).")
    print()

    # Run verification FIRST to confirm the mechanism works
    phase_8_verify_bypass_mechanism()
    time.sleep(0.5)

    phase_1_single_lambda_wrap()
    time.sleep(0.5)

    phase_2_double_lambda_wrap()
    time.sleep(0.5)

    phase_3_param_as_arg()
    time.sleep(0.5)

    phase_4_different_continuations()
    time.sleep(0.5)

    phase_5_backdoor_then_bypass()
    time.sleep(0.5)

    phase_6_echo_bypass()
    time.sleep(0.5)

    phase_7_multi_chain_bypass()

    print("\n" + "=" * 80)
    print("ALL PHASES COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
