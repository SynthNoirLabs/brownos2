#!/usr/bin/env python3
"""
probe_double_question.py — Systematically test the ?? ?? FD QD FD pattern.

The cheat sheet says: ?? ?? FD QD FD
Author hint: "don't be too literal with the ??s"
Author hint: "The different outputs betray some core structures"
Author hint: "The second example [?? ?? FD QD FD] is useful in figuring out crucial properties of the codes"

This means ((Var(x) Var(y)) QD) for various x, y.
When x is a syscall, this calls syscall x with arg Var(y) and QD as continuation.
But when x is NOT a syscall... Var(x) is just a global, and (Var(x) Var(y))
applies that global to Var(y) — pure lambda calculus.

We test ALL combinations systematically, including non-syscall globals.
"""

from __future__ import annotations

import socket
import time
import sys
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def recv_all(sock: socket.socket, timeout_s: float = 4.0) -> bytes:
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


def query(payload: bytes, retries: int = 3, timeout_s: float = 5.0) -> bytes:
    delay = 0.2
    last_err: Exception | None = None
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s=timeout_s)
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed to query") from last_err


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


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


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
            return -1
        w = WEIGHTS.get(expr.f.i, -1)
        if w < 0:
            return -1
        sub = eval_bitset_expr(expr.x)
        if sub < 0:
            return -1
        return w + sub
    return -1


def decode_either(term: object) -> tuple[str, object] | None:
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        return None
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var) and body.f.i in (0, 1):
        return ("Left" if body.f.i == 1 else "Right", body.x)
    return None


def decode_byte_term(term: object) -> int:
    try:
        body = strip_lams(term, 9)
        return eval_bitset_expr(body)
    except Exception:
        return -1


def uncons_scott_list(term: object) -> tuple[object, object] | None:
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        return None
    body = term.body.body
    if isinstance(body, Var) and body.i == 0:
        return None  # nil
    if (
        isinstance(body, App)
        and isinstance(body.f, App)
        and isinstance(body.f.f, Var)
        and body.f.f.i == 1
    ):
        return body.f.x, body.x
    return None


def decode_bytes_list(term: object) -> bytes | None:
    out = []
    cur = term
    for _ in range(100000):
        res = uncons_scott_list(cur)
        if res is None:
            return (
                bytes(out)
                if out or (isinstance(cur, Lam) and isinstance(cur.body, Lam))
                else None
            )
        head, cur = res
        b = decode_byte_term(head)
        if b < 0:
            return None
        out.append(b)
    return None


def term_summary(term: object, depth: int = 0) -> str:
    """Short summary of a term."""
    if depth > 5:
        return "..."
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{term_summary(term.body, depth + 1)}"
    if isinstance(term, App):
        return f"({term_summary(term.f, depth + 1)} {term_summary(term.x, depth + 1)})"
    return "?"


def describe_result(raw: bytes) -> str:
    """Describe what we got back."""
    if not raw:
        return "EMPTY (no output)"

    # Check for text responses
    try:
        text = raw.decode("ascii", errors="strict")
        if (
            text.startswith("Invalid")
            or text.startswith("Encoding")
            or text.startswith("Term")
        ):
            return f"ERROR: {text.strip()}"
    except Exception:
        pass

    if FF not in raw:
        return f"NO_FF: {raw[:50].hex()}"

    # Parse as term
    try:
        term = parse_term(raw)
    except Exception as e:
        return f"PARSE_ERR: {e} raw={raw[:30].hex()}"

    # Try to decode as Either
    either = decode_either(term)
    if either:
        tag, payload = either
        if tag == "Right":
            # Error code
            code = decode_byte_term(payload)
            err_names = {
                0: "Exception",
                1: "NotImpl",
                2: "InvalidArg",
                3: "NoSuchFile",
                4: "NotDir",
                5: "NotFile",
                6: "PermDenied",
                7: "RateLimit",
            }
            name = err_names.get(code, f"?{code}")
            return f"Right({code})={name}"
        else:
            # Left — try to decode as bytes
            bs = decode_bytes_list(payload)
            if bs is not None:
                try:
                    text = bs.decode("utf-8", errors="replace")
                    if len(text) > 60:
                        text = text[:60] + "..."
                    return f'Left(str="{text}")'
                except Exception:
                    return f"Left(bytes={bs[:20].hex()})"
            # Not a byte list — describe the term structure
            return f"Left(term={term_summary(payload)})"

    # Not an Either — describe raw term
    summary = term_summary(term)
    if len(summary) > 80:
        summary = summary[:80] + "..."
    return f"TERM: {summary}"


def main():
    # Known syscalls for reference
    known_syscalls = {0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0E, 0x2A, 0xC9}

    # Phase 1: Test ?? ?? FD QD FD for x=0..20, y=0..20 (small globals)
    # This is ((Var(x) Var(y)) QD) — call global x with arg Var(y) and continuation QD
    print("=" * 70)
    print("PHASE 1: ((Var(x) Var(y)) QD) for x=0..20, y=0..20")
    print("Pattern: x y FD QD FD FF")
    print("=" * 70)

    results = {}
    interesting = []

    for x in range(21):
        for y in range(21):
            if x == y == 0:
                # Var(0) applied to Var(0) — might loop, use short timeout
                pass

            payload = bytes([x, y, FD]) + QD + bytes([FD, FF])
            try:
                raw = query(payload, retries=2, timeout_s=4.0)
                desc = describe_result(raw)
            except Exception as e:
                desc = f"TIMEOUT/ERR: {e}"

            results[(x, y)] = desc

            # Flag interesting (non-standard) results
            is_interesting = (
                "NotImpl" not in desc
                and "EMPTY" not in desc
                and "TIMEOUT" not in desc
                and desc != "Right(1)=NotImpl"
            )

            if is_interesting:
                interesting.append((x, y, desc))

            marker = "*" if is_interesting else " "
            print(f"  {marker} x={x:3d} y={y:3d}: {desc}")

            time.sleep(0.15)

    print("\n" + "=" * 70)
    print("INTERESTING RESULTS (non-NotImpl, non-empty, non-timeout):")
    print("=" * 70)
    for x, y, desc in interesting:
        sc_marker = "SYSCALL" if x in known_syscalls else "NON-SC"
        print(f"  [{sc_marker}] x={x:3d} y={y:3d}: {desc}")

    # Phase 2: Specifically test Var(0) behavior
    print("\n" + "=" * 70)
    print("PHASE 2: Var(0) deep investigation")
    print("=" * 70)

    # ((0 0) QD) — identity applied to itself, then QD?
    # (0 QD) — just Var(0) applied to QD
    # ((0 0) (0 0)) — omega-like

    tests_phase2 = [
        ("(Var(0) QD)", bytes([0x00]) + QD + bytes([FD, FF])),
        (
            "((Var(0) Var(0)) (Var(0) Var(0)))",
            bytes([0x00, 0x00, FD, 0x00, 0x00, FD, FD, FF]),
        ),
        ("(Lam(Var(0)) QD)", bytes([0x00, FE]) + QD + bytes([FD, FF])),
        ("(Lam(Lam(Var(0))) QD)", bytes([0x00, FE, FE]) + QD + bytes([FD, FF])),
    ]

    for label, payload in tests_phase2:
        try:
            raw = query(payload, retries=2, timeout_s=4.0)
            desc = describe_result(raw)
        except Exception as e:
            desc = f"TIMEOUT/ERR: {e}"
        print(f"  {label}: {desc}")
        time.sleep(0.15)

    # Phase 3: Test the BACKDOOR PAIR as first ?? in the pattern
    # Backdoor returns pair = λf.f(A)(B) where A=λa.λb.(bb), B=λa.λb.(ab)
    # If we use pair as the "syscall" position: ((pair arg) QD) = ((λf.f A B) arg QD)
    # = ((arg A B) QD) = (((arg A) B) QD)
    # So if arg = sys8: (((sys8 A) B) QD) = sys8 is called with A, continuation (λresult. (B result) QD)
    # Hmm wait — that's not right. Let me think...
    # Actually pair is just passed as a value. In CPS: ((pair arg) QD)
    # pair arg = (λf.f A B) arg = arg A B = ((arg A) B)
    # Then ((arg A B) QD) = (((arg A) B) QD)
    # If arg = Var(8) (sys8): ((sys8 A) B) — CPS call: sys8 with argument A, continuation B
    # Then B gets applied to the result: B result = (λa.λb.(ab)) result = λb.(result b)
    # Then QD gets applied to that: QD (λb.(result b))
    # But sys8(A) will return Right(6) as usual... unless A is special somehow

    print("\n" + "=" * 70)
    print("PHASE 3: Using backdoor pair in ?? ?? FD QD FD pattern")
    print("=" * 70)

    # First, get the backdoor pair
    # Call: ((0xC9 nil) QD) — nil = 00 FE FE
    nil_enc = bytes([0x00, FE, FE])
    backdoor_call = bytes([0xC9]) + nil_enc + bytes([FD]) + QD + bytes([FD, FF])
    try:
        raw = query(backdoor_call, retries=3, timeout_s=5.0)
        print(f"  Backdoor raw: {raw[:80].hex()}")
        backdoor_term = parse_term(raw)
        bd_either = decode_either(backdoor_term)
        if bd_either:
            tag, bd_pair = bd_either
            print(f"  Backdoor: {tag}({term_summary(bd_pair)})")
        else:
            print(f"  Backdoor: {term_summary(backdoor_term)}")
    except Exception as e:
        print(f"  Backdoor call failed: {e}")

    # Now: build inline backdoor pair terms (A and B) and test
    # A = λa.λb.(b b) = encoded: 00 00 FD FE FE
    # B = λa.λb.(a b) = encoded: 01 00 FD FE FE
    A_enc = bytes([0x00, 0x00, FD, FE, FE])
    B_enc = bytes([0x01, 0x00, FD, FE, FE])
    pair_enc = bytes([0x00]) + A_enc + B_enc + bytes([FD, FD, FE])  # λf.((f A) B)

    # Test: ((pair Var(8)) QD) = sys8 called with A, continuation is B, then QD...
    # Actually let's test multiple combos
    pair_tests = [
        ("((pair sys8) QD)", pair_enc + bytes([0x08, FD]) + QD + bytes([FD, FF])),
        ("((pair sys2) QD)", pair_enc + bytes([0x02, FD]) + QD + bytes([FD, FF])),
        ("((pair sys14) QD)", pair_enc + bytes([0x0E, FD]) + QD + bytes([FD, FF])),
        ("((pair sys4) QD)", pair_enc + bytes([0x04, FD]) + QD + bytes([FD, FF])),
        # pair applied to A itself
        ("((pair A) QD)", pair_enc + A_enc + bytes([FD]) + QD + bytes([FD, FF])),
        # pair applied to B
        ("((pair B) QD)", pair_enc + B_enc + bytes([FD]) + QD + bytes([FD, FF])),
        # A applied to B, then QD — this gives omega(= λx.xx), might loop
        ("((A B) QD)", A_enc + B_enc + bytes([FD]) + QD + bytes([FD, FF])),
        # B applied to A, then QD
        ("((B A) QD)", B_enc + A_enc + bytes([FD]) + QD + bytes([FD, FF])),
    ]

    for label, payload in pair_tests:
        try:
            raw = query(payload, retries=2, timeout_s=4.0)
            desc = describe_result(raw)
        except Exception as e:
            desc = f"TIMEOUT/ERR: {e}"
        print(f"  {label}: {desc}")
        time.sleep(0.15)

    # Phase 4: Test with ?? being a lambda term, not just a Var
    # "don't be too literal with the ??s" — maybe ?? can be a multi-byte lambda term
    # Test: ((λx.x sys8_arg) QD) — using identity to pass through
    print("\n" + "=" * 70)
    print("PHASE 4: Non-literal ?? — lambda terms in ?? positions")
    print("=" * 70)

    # Identity = λx.x = 00 FE
    identity_enc = bytes([0x00, FE])

    # Test: ((identity Var(8)) QD) — should be same as (Var(8) QD)?
    # Actually in CPS: ((identity 8) QD) = (8 QD) = sys8 applied to QD... which is weird
    # No wait: ((identity arg) cont) = (arg cont) — so sys8 is applied to cont directly
    # That's not a valid CPS call to sys8

    # What about: (sys8 (identity nil)) QD — sys8 with arg = identity(nil)
    # identity(nil) = nil, so same as sys8(nil)

    # More interesting: what if we use the backdoor output INLINE
    # Chain: first call backdoor, get pair, then use pair as argument to sys8
    # CPS chain: ((0xC9 nil) (λpair. ((0x08 pair) QD)))
    # Encoded: 0xC9 nil FD continuation FD FF
    # where continuation = λpair. ((0x08 pair) QD) = ((Var(9) Var(0)) QD_shifted) FE
    # Wait, under one lambda, sys8 is Var(9) not Var(8)! De Bruijn shift!

    # Under 1 lambda: all globals shift by +1
    # sys8 at top level = Var(8), under 1 lambda = Var(9)
    # QD under 1 lambda: all its free vars shift by +1 too
    # QD's free vars are: 5(readdir), 3(???), 2(write), at top level
    # Under 1 lambda they become 6, 4, 3

    # Actually QD is a closed term (all lambdas, no free vars at top level in its encoding)
    # Wait no — QD raw bytes: 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
    # Parse QD:
    # 05 → Var(5)
    # 00 → Var(0)
    # FD → App(Var(5), Var(0))
    # 00 → Var(0)
    # 05 → Var(5)
    # 00 → Var(0)
    # FD → App(Var(5), Var(0))
    # 03 → Var(3)
    # FD → App(App(Var(5), Var(0)), Var(3))
    # FE → Lam(App(App(Var(5), Var(0)), Var(3)))
    # FD → App(Var(0), Lam(App(App(Var(5), Var(0)), Var(3))))
    # ... this is getting complex. Let me just note that QD has free variables
    # (the top-level 05, 02, etc. reference globals).
    # Under N extra lambdas, those shift by +N.

    # So building a CPS chain properly requires shifting QD's free vars.
    # Let me build the CPS chain manually.

    # Chain: ((backdoor nil) (λpair. ((sys8 pair) QD)))
    # Under 1 lambda (the pair binder):
    #   pair = Var(0)
    #   sys8 = Var(8+1) = Var(9)
    #   readdir(5) in QD → Var(6), write(2) in QD → Var(3), etc.
    #
    # So shifted QD: replace each free var V(n) with V(n+1)
    # QD parses to a term with free vars. Let me compute shifted QD.

    # Actually, the simplest approach: encode the CPS chain as raw bytes
    # using our encode_term function with proper de Bruijn indices.

    # Build: ((0xC9 nil) (λpair. ((0x08 pair) (write(quote(pair))))))
    # But that's complex. Let me just build a simple chain.

    # Chain 1: backdoor → use pair as arg to sys8
    # ((C9 nil) (λresult. ((8+1=9 result) QD_shifted)))
    # result = Var(0), sys8 = Var(9)
    # QD shifted by 1: replace free vars n → n+1

    # Let me build this properly in Python

    def shift_term(term, delta, cutoff=0):
        """Shift free variables in a term by delta."""
        if isinstance(term, Var):
            if term.i >= cutoff:
                return Var(term.i + delta)
            return term
        if isinstance(term, Lam):
            return Lam(shift_term(term.body, delta, cutoff + 1))
        if isinstance(term, App):
            return App(
                shift_term(term.f, delta, cutoff), shift_term(term.x, delta, cutoff)
            )
        return term

    def encode_term(term):
        if isinstance(term, Var):
            if term.i > 0xFC:
                raise ValueError(f"Var({term.i}) exceeds max encodable byte 0xFC")
            return bytes([term.i])
        if isinstance(term, Lam):
            return encode_term(term.body) + bytes([FE])
        if isinstance(term, App):
            return encode_term(term.f) + encode_term(term.x) + bytes([FD])
        raise TypeError(f"Unsupported: {type(term)}")

    # Parse QD as a term
    qd_term = parse_term(QD + bytes([FF]))

    # Chain: ((backdoor nil) (λresult. ((sys8 result) QD_shifted_1)))
    nil_term = Lam(Lam(Var(0)))
    qd_shifted_1 = shift_term(qd_term, 1)

    # Under 1 lambda: sys8 = Var(9)
    inner_chain = App(App(Var(9), Var(0)), qd_shifted_1)
    cont1 = Lam(inner_chain)
    full_chain1 = App(App(Var(0xC9), nil_term), cont1)

    try:
        payload = encode_term(full_chain1) + bytes([FF])
        raw = query(payload, retries=2, timeout_s=6.0)
        desc = describe_result(raw)
    except Exception as e:
        desc = f"ERR: {e}"
    print(f"  Chain: backdoor→sys8(pair): {desc}")
    time.sleep(0.2)

    # Chain: backdoor → use pair.A as arg to sys8
    # ((C9 nil) (λpair. pair (λA.λB. ((sys8+3=11 A) QD_shifted_3))))
    # pair = λf.f(A)(B), so pair(λA.λB.expr) = expr[A/0, B/1]
    # Under 3 lambdas (pair binder + A binder + B binder): sys8 = Var(11)
    qd_shifted_3 = shift_term(qd_term, 3)
    inner_extract = App(App(Var(11), Var(1)), qd_shifted_3)  # sys8(A) with QD as cont
    pair_destructor = Lam(Lam(inner_extract))  # λA.λB. ...
    inner = App(Var(0), pair_destructor)  # pair(λA.λB....)
    cont2 = Lam(inner)  # λpair. pair(λA.λB....)
    full_chain2 = App(App(Var(0xC9), nil_term), cont2)

    try:
        payload = encode_term(full_chain2) + bytes([FF])
        raw = query(payload, retries=2, timeout_s=6.0)
        desc = describe_result(raw)
    except Exception as e:
        desc = f"ERR: {e}"
    print(f"  Chain: backdoor→sys8(A): {desc}")
    time.sleep(0.2)

    # Chain: backdoor → use pair.B as arg to sys8
    qd_shifted_3b = shift_term(qd_term, 3)
    inner_extract_b = App(
        App(Var(11), Var(0)), qd_shifted_3b
    )  # sys8(B) with QD as cont
    pair_destructor_b = Lam(Lam(inner_extract_b))
    inner_b = App(Var(0), pair_destructor_b)
    cont2b = Lam(inner_b)
    full_chain2b = App(App(Var(0xC9), nil_term), cont2b)

    try:
        payload = encode_term(full_chain2b) + bytes([FF])
        raw = query(payload, retries=2, timeout_s=6.0)
        desc = describe_result(raw)
    except Exception as e:
        desc = f"ERR: {e}"
    print(f"  Chain: backdoor→sys8(B): {desc}")
    time.sleep(0.2)

    # Chain: backdoor → use (A B) = omega as arg to sys8
    # This might be interesting: sys8(omega) where omega = λx.xx
    qd_shifted_3c = shift_term(qd_term, 3)
    omega = App(Var(1), Var(0))  # (A B) under the 2 lambdas
    inner_extract_c = App(App(Var(11), omega), qd_shifted_3c)
    pair_destructor_c = Lam(Lam(inner_extract_c))
    inner_c = App(Var(0), pair_destructor_c)
    cont2c = Lam(inner_c)
    full_chain2c = App(App(Var(0xC9), nil_term), cont2c)

    try:
        payload = encode_term(full_chain2c) + bytes([FF])
        raw = query(payload, retries=2, timeout_s=6.0)
        desc = describe_result(raw)
    except Exception as e:
        desc = f"ERR: {e}"
    print(f"  Chain: backdoor→sys8(AB=omega): {desc}")
    time.sleep(0.2)

    # Phase 5: What about using the pair as the CONTINUATION for sys8?
    # sys8(arg, continuation=pair)
    # If sys8 returns Right(6), then pair gets (Right(6)) = Right(6)(A)(B)
    # = (λl.λr.r(6))(A)(B) = B(6) = (λa.λb.ab)(6) = λb.6b
    # That's a function... which wouldn't produce output.
    # But what if sys8 somehow succeeds? Then Left(x)(A)(B) = A(x) = (λa.λb.bb)(x) = λb.bb
    # Which is also a function... hmm.

    print("\n" + "=" * 70)
    print("PHASE 5: sys8 with pair/A/B as continuation")
    print("=" * 70)

    # sys8 with A as continuation, then QD catches the output
    # ((sys8 nil) (λresult. ((A+1 result) QD_shifted_1)))
    # Under 1 lambda: A_inline shifted...
    # Actually simpler: just build ((sys8 nil) A) and wrap with QD differently
    # Hmm, we need QD to capture what comes out.

    # Try: quote the result of applying pair to the sys8 result
    # Chain: ((sys8 arg) (λresult. ((pair result) QD)))
    # pair is not a global! We need to inline it or get it from backdoor.

    # Simplest: two-step CPS chain
    # ((backdoor nil) (λpair. ((sys8+1=9 int0) (λresult. ((pair result) QD_shifted)))))
    # Under 2 lambdas: sys8=Var(10)
    # pair = Var(1), result = Var(0)

    qd_s2 = shift_term(qd_term, 2)
    int0_term = Lam(
        Lam(Lam(Lam(Lam(Lam(Lam(Lam(Lam(Var(0)))))))))
    )  # 9 lambdas, body=Var(0)
    int0_shifted_1 = shift_term(int0_term, 1)

    inner_result = App(App(Var(1), Var(0)), qd_s2)  # (pair result) then QD
    cont_inner = Lam(inner_result)  # λresult. ...
    sys8_call = App(App(Var(9), int0_shifted_1), cont_inner)  # (sys8 int0) cont_inner
    cont_outer = Lam(sys8_call)  # λpair. ...
    full_chain5 = App(App(Var(0xC9), nil_term), cont_outer)

    try:
        payload = encode_term(full_chain5) + bytes([FF])
        raw = query(payload, retries=2, timeout_s=6.0)
        desc = describe_result(raw)
    except Exception as e:
        desc = f"ERR: {e}"
    print(f"  Chain: backdoor→sys8(0) with pair(result): {desc}")
    time.sleep(0.2)

    # Phase 6: Test ?? ?? FD QD FD where first ?? is a LAMBDA TERM
    # What if "??" means an arbitrary term, not just a single byte?
    print("\n" + "=" * 70)
    print("PHASE 6: Arbitrary terms in ?? position")
    print("=" * 70)

    # λx.x (identity) as first ??
    # ((λx.x) arg QD) = (arg QD) — arg applied to QD
    # If arg = sys8, then (sys8 QD) — sys8 treats QD as its argument (not continuation!)
    # That means sys8(QD) with no continuation... interesting!

    for y in [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
        payload = bytes([0x00, FE, y, FD]) + QD + bytes([FD, FF])
        try:
            raw = query(payload, retries=2, timeout_s=4.0)
            desc = describe_result(raw)
        except Exception as e:
            desc = f"TIMEOUT/ERR: {e}"
        print(f"  ((identity Var({y})) QD): {desc}")
        time.sleep(0.15)

    print("\n" + "=" * 70)
    print("PHASE 7: QD as first ?? — QD ?? FD (no trailing QD)")
    print("=" * 70)

    # The cheat sheet also mentions: QD ?? FD
    # This is (QD ??) — applying QD to a value
    # QD is the print continuation, so QD(x) should print x
    # Let's test with various globals

    for y in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 42, 201]:
        payload = QD + bytes([y, FD, FF])
        try:
            raw = query(payload, retries=2, timeout_s=4.0)
            if raw and FF in raw:
                term = parse_term(raw)
                summary = term_summary(term)
                if len(summary) > 60:
                    summary = summary[:60] + "..."
                desc = f"TERM: {summary}"
            elif raw:
                desc = f"RAW: {raw[:40].hex()}"
            else:
                desc = "EMPTY"
        except Exception as e:
            desc = f"ERR: {e}"
        print(f"  (QD Var({y})): {desc}")
        time.sleep(0.15)

    print("\nDone!")


if __name__ == "__main__":
    main()
