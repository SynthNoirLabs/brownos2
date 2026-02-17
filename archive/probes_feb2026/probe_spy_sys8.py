#!/usr/bin/env python3
"""
probe_spy_sys8.py — Test if sys8 INVOKES its argument as a callback.

Key insight from Oracle: sys8 might call its argument like arg(secret_token)
as part of its permission check. If it does, a spy function that writes to
the socket as a side-effect could leak the internal value, even if sys8
ultimately returns Right(6).

We'd see BOTH the spy output AND the Right(6) in the socket stream.

Also tests: strictness (does sys8 force-evaluate its arg?), and
various calling conventions (1-arg, 2-arg callbacks).
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


def recv_all(sock: socket.socket, timeout_s: float = 6.0) -> bytes:
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


def query_raw(payload: bytes, retries: int = 3, timeout_s: float = 6.0) -> bytes:
    """Query and return ALL raw bytes (don't stop at FF)."""
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


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        if term.i > 0xFC:
            raise ValueError(f"Var({term.i}) too large")
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
            if len(stack) < 2:
                raise ValueError("Stack underflow on FD")
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            if not stack:
                raise ValueError("Stack underflow on FE")
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    if len(stack) != 1:
        raise ValueError(f"Invalid parse: stack size {len(stack)}")
    return stack[0]


def shift_term(term: object, delta: int, cutoff: int = 0) -> object:
    """Shift free variables by delta (for de Bruijn index adjustment under lambdas)."""
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_term(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_term(term.f, delta, cutoff), shift_term(term.x, delta, cutoff))
    return term


def term_summary(term: object, depth: int = 0) -> str:
    if depth > 8:
        return "..."
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{term_summary(term.body, depth + 1)}"
    if isinstance(term, App):
        return f"({term_summary(term.f, depth + 1)} {term_summary(term.x, depth + 1)})"
    return "?"


def main():
    qd_term = parse_term(QD + bytes([FF]))

    # =====================================================================
    # PROBE 1: Strictness — does sys8 force-evaluate its argument?
    # Pass omega = (λx.xx)(λx.xx) as argument. If sys8 forces it → timeout.
    # If sys8 is lazy → immediate Right(6).
    # =====================================================================
    print("=" * 70)
    print("PROBE 1: Strictness test — sys8(omega)")
    print("=" * 70)

    # omega = (λx.xx)(λx.xx)
    # λx.xx = Lam(App(Var(0), Var(0))) = 00 00 FD FE
    # omega = (λx.xx)(λx.xx) = 00 00 FD FE 00 00 FD FE FD
    omega_enc = bytes([0x00, 0x00, FD, FE, 0x00, 0x00, FD, FE, FD])
    payload = bytes([0x08]) + omega_enc + bytes([FD]) + QD + bytes([FD, FF])

    start = time.time()
    try:
        raw = query_raw(payload, retries=1, timeout_s=8.0)
        elapsed = time.time() - start
        print(f"  Response ({elapsed:.1f}s): {raw[:80].hex() if raw else 'EMPTY'}")
        if raw:
            try:
                text = raw.decode("ascii", errors="replace")
                print(f"  Text: {text[:100]}")
            except Exception:
                pass
    except Exception as e:
        elapsed = time.time() - start
        print(f"  TIMEOUT/ERROR ({elapsed:.1f}s): {e}")
    print()

    # =====================================================================
    # PROBE 2: Spy functions — does sys8 CALL its argument?
    # Build: spy = λx. ((write (quote x)) <anything>)
    # If sys8 does spy(token), the write side-effect outputs quote(token)
    # =====================================================================
    print("=" * 70)
    print("PROBE 2: Spy argument — sys8(λx.write(quote(x)))")
    print("  If sys8 calls spy(token), we see the token bytes in output")
    print("=" * 70)

    # Build spy = λx. ((write (quote x)) dummy)
    # Under 1 lambda (x binder):
    #   x = Var(0)
    #   write = Var(2+1) = Var(3)   (shifted by 1 for the lambda)
    #   quote = Var(4+1) = Var(5)   (shifted by 1)
    #
    # spy = λx. ((3 (5 0 FD)) dummy)
    # But we need a continuation for write... Let's use QD approach
    #
    # Actually, simplest spy: just use write+quote inline
    # spy = λx. write(quote(x))
    # In CPS: λx. ((quote x) (λqresult. ((write qresult) (λ_.x))))
    # This is getting complex. Let me use a simpler approach.
    #
    # Spy v1: just do side-effect write of x's quote, ignore continuation
    # spy = λx. ((Var(5) Var(0)) (λqr. ((Var(4) Var(0)) (λ_. Var(0)))))
    # Under spy's lambda: quote=Var(5), write=Var(3), x=Var(0)
    # Wait, at top level: write=2, quote=4
    # Under 1 lambda: write=3, quote=5

    # Build: spy = λx. ((quote x) (λqr. ((write qr) (λwr. whatever))))
    # Under spy's λx: quote=5, x=0
    # Under spy's λx and λqr: write=4, qr=0
    # Under spy's λx, λqr, λwr: ...

    # Let me build this as a term tree.
    # spy = λx. ((quote x) cont_after_quote)
    # cont_after_quote = λqr. ((write qr) cont_after_write)
    # cont_after_write = λwr. <anything — just return nil or whatever>

    # Under λx: globals shift +1
    # quote = Var(5), write = Var(3), x = Var(0)
    # Under λx.λqr: globals shift +2
    # write = Var(4), qr = Var(0)
    # Under λx.λqr.λwr: globals shift +3

    nil = Lam(Lam(Var(0)))  # Scott nil

    # cont_after_write: λwr. nil (shifted by 3 from top)
    cont_after_write = Lam(shift_term(nil, 4))  # nil shifted into deep context
    # Actually nil is closed (no free vars), so shifting doesn't change it
    cont_after_write = Lam(nil)  # λwr. nil

    # Under λx.λqr: write = Var(4), qr = Var(0)
    cont_after_quote = Lam(App(App(Var(4), Var(0)), cont_after_write))

    # Under λx: quote = Var(5), x = Var(0)
    spy_v1 = Lam(App(App(Var(5), Var(0)), cont_after_quote))

    spy_v1_enc = encode_term(spy_v1)
    print(f"  spy_v1 bytes: {spy_v1_enc.hex()}")
    print(f"  spy_v1 term: {term_summary(spy_v1)}")

    # Call: ((sys8 spy_v1) QD)
    payload = bytes([0x08]) + spy_v1_enc + bytes([FD]) + QD + bytes([FD, FF])
    print(f"  Payload size: {len(payload)} bytes")

    start = time.time()
    try:
        raw = query_raw(payload, retries=2, timeout_s=8.0)
        elapsed = time.time() - start
        print(f"  Response ({elapsed:.1f}s): len={len(raw)}")
        print(f"  Raw hex: {raw[:120].hex() if raw else 'EMPTY'}")
        if raw:
            # Check if there's data BEFORE the Either result
            # The spy would write bytes, then sys8 returns Right(6) through QD
            # So we might see: <spy output> <QD output with Right(6)>
            ff_positions = [i for i, b in enumerate(raw) if b == FF]
            print(f"  FF positions: {ff_positions}")
            if len(ff_positions) > 1:
                print(f"  *** MULTIPLE FF MARKERS! Spy may have produced output! ***")
                print(f"  Before first FF: {raw[: ff_positions[0]].hex()}")
                print(f"  After first FF: {raw[ff_positions[0] + 1 :].hex()}")
    except Exception as e:
        elapsed = time.time() - start
        print(f"  TIMEOUT/ERROR ({elapsed:.1f}s): {e}")
    print()
    time.sleep(0.3)

    # =====================================================================
    # PROBE 3: Simpler spy — just write a marker string
    # spy = λx. write("SPY") — ignores x, just proves sys8 called it
    # =====================================================================
    print("=" * 70)
    print("PROBE 3: Marker spy — sys8(λx.write(marker))")
    print("=" * 70)

    # Build a string "SPY" as a Scott list
    # S=83, P=80, Y=89
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

    def encode_bytes_list(bs: bytes) -> object:
        nil_inner: object = Lam(Lam(Var(0)))

        def cons(h: object, t: object) -> object:
            return Lam(Lam(App(App(Var(1), h), t)))

        cur: object = nil_inner
        for b in reversed(bs):
            cur = cons(encode_byte_term(b), cur)
        return cur

    marker = encode_bytes_list(b"SPY")
    # marker is closed, no shifting needed

    # spy_marker = λx. ((write marker) (λ_. nil))
    # Under λx: write = Var(3)
    # marker is closed
    cont_write = Lam(nil)  # λ_. nil  (discard write result)
    spy_marker = Lam(App(App(Var(3), shift_term(marker, 1)), shift_term(cont_write, 1)))
    # Wait, marker is closed (all vars are bound inside the 9-lambda byte terms and Scott cons)
    # So shifting doesn't affect it. Same for cont_write (nil is closed).
    # But Var(3) IS a free var (write shifted by 1 for spy's lambda).

    spy_marker_enc = encode_term(spy_marker)
    print(
        f"  spy_marker bytes ({len(spy_marker_enc)}B): {spy_marker_enc[:40].hex()}..."
    )

    payload = bytes([0x08]) + spy_marker_enc + bytes([FD]) + QD + bytes([FD, FF])
    print(f"  Payload size: {len(payload)} bytes")

    start = time.time()
    try:
        raw = query_raw(payload, retries=2, timeout_s=8.0)
        elapsed = time.time() - start
        print(f"  Response ({elapsed:.1f}s): len={len(raw)}")
        print(f"  Raw hex: {raw[:120].hex() if raw else 'EMPTY'}")
        if raw:
            ff_positions = [i for i, b in enumerate(raw) if b == FF]
            print(f"  FF positions: {ff_positions}")
            # Check for "SPY" in raw output
            if b"SPY" in raw:
                print(f"  *** 'SPY' FOUND IN OUTPUT! sys8 CALLED our argument! ***")
            if len(ff_positions) > 1:
                print(f"  *** MULTIPLE FF MARKERS! ***")
    except Exception as e:
        elapsed = time.time() - start
        print(f"  TIMEOUT/ERROR ({elapsed:.1f}s): {e}")
    print()
    time.sleep(0.3)

    # =====================================================================
    # PROBE 4: 2-arg spy — maybe sys8 calls arg(a)(b) like a CPS callback
    # spy2 = λx.λk. write("SP2")
    # =====================================================================
    print("=" * 70)
    print("PROBE 4: 2-arg spy — sys8(λx.λk.write(marker))")
    print("=" * 70)

    marker2 = encode_bytes_list(b"SP2")
    cont_write2 = Lam(nil)
    # spy2 = λx.λk. ((write marker2) (λ_. nil))
    # Under 2 lambdas: write = Var(4)
    spy2 = Lam(Lam(App(App(Var(4), marker2), cont_write2)))

    spy2_enc = encode_term(spy2)
    payload = bytes([0x08]) + spy2_enc + bytes([FD]) + QD + bytes([FD, FF])
    print(f"  Payload size: {len(payload)} bytes")

    start = time.time()
    try:
        raw = query_raw(payload, retries=2, timeout_s=8.0)
        elapsed = time.time() - start
        print(f"  Response ({elapsed:.1f}s): len={len(raw)}")
        print(f"  Raw hex: {raw[:120].hex() if raw else 'EMPTY'}")
        if raw:
            if b"SP2" in raw:
                print(f"  *** 'SP2' FOUND! sys8 calls arg with 2 params! ***")
            ff_positions = [i for i, b in enumerate(raw) if b == FF]
            print(f"  FF positions: {ff_positions}")
    except Exception as e:
        elapsed = time.time() - start
        print(f"  TIMEOUT/ERROR ({elapsed:.1f}s): {e}")
    print()
    time.sleep(0.3)

    # =====================================================================
    # PROBE 5: Echo-based spy — uses echo+QD to print what sys8 passes
    # spy_echo = λx. ((echo x) QD_shifted)
    # This is cleaner: if sys8 calls spy_echo(token), echo prints token
    # =====================================================================
    print("=" * 70)
    print("PROBE 5: Echo spy — sys8(λx.((echo x) QD_shifted))")
    print("=" * 70)

    # Under λx: echo = Var(15), QD shifts by +1
    qd_s1 = shift_term(qd_term, 1)
    spy_echo = Lam(App(App(Var(15), Var(0)), qd_s1))  # echo=14+1=15

    spy_echo_enc = encode_term(spy_echo)
    payload = bytes([0x08]) + spy_echo_enc + bytes([FD]) + QD + bytes([FD, FF])
    print(f"  Payload size: {len(payload)} bytes")

    start = time.time()
    try:
        raw = query_raw(payload, retries=2, timeout_s=8.0)
        elapsed = time.time() - start
        print(f"  Response ({elapsed:.1f}s): len={len(raw)}")
        print(f"  Raw hex: {raw[:120].hex() if raw else 'EMPTY'}")
        if raw:
            ff_positions = [i for i, b in enumerate(raw) if b == FF]
            print(f"  FF positions: {ff_positions}")
            if len(ff_positions) > 1:
                print(f"  *** MULTIPLE FF! Echo spy caught something! ***")
                for i, pos in enumerate(ff_positions):
                    start_pos = 0 if i == 0 else ff_positions[i - 1] + 1
                    segment = raw[start_pos:pos]
                    print(f"  Segment {i}: {segment.hex()}")
    except Exception as e:
        elapsed = time.time() - start
        print(f"  TIMEOUT/ERROR ({elapsed:.1f}s): {e}")
    print()
    time.sleep(0.3)

    # =====================================================================
    # PROBE 6: Direct write spy — write(quote(x)) inline, simpler encoding
    # =====================================================================
    print("=" * 70)
    print("PROBE 6: Direct write+quote spy — sys8(λx.write(quote(x)))")
    print("  Uses CPS chain: quote(x) → write(result)")
    print("=" * 70)

    # spy_wq = λx. ((quote x) (λbytes. ((write bytes) (λ_. nil))))
    # Under λx: quote = Var(5), x = Var(0)
    # Under λx.λbytes: write = Var(4), bytes = Var(0)
    # Under λx.λbytes.λ_: nil

    inner_nil = Lam(nil)  # λ_. nil
    write_call = Lam(
        App(App(Var(4), Var(0)), inner_nil)
    )  # λbytes. write(bytes, λ_.nil)
    spy_wq = Lam(App(App(Var(5), Var(0)), write_call))  # λx. quote(x, λbytes.write...)

    spy_wq_enc = encode_term(spy_wq)
    payload = bytes([0x08]) + spy_wq_enc + bytes([FD]) + QD + bytes([FD, FF])
    print(f"  Payload size: {len(payload)} bytes")

    start = time.time()
    try:
        raw = query_raw(payload, retries=2, timeout_s=8.0)
        elapsed = time.time() - start
        print(f"  Response ({elapsed:.1f}s): len={len(raw)}")
        print(f"  Raw hex: {raw[:120].hex() if raw else 'EMPTY'}")
        if raw:
            ff_positions = [i for i, b in enumerate(raw) if b == FF]
            print(f"  FF positions: {ff_positions}")
            if len(ff_positions) > 1:
                print(f"  *** MULTIPLE FF! write+quote spy caught something! ***")
                for i, pos in enumerate(ff_positions):
                    start_pos = 0 if i == 0 else ff_positions[i - 1] + 1
                    segment = raw[start_pos:pos]
                    print(f"  Segment {i}: {segment.hex()}")
                    try:
                        print(f"    ASCII: {segment.decode('ascii', errors='replace')}")
                    except Exception:
                        pass
    except Exception as e:
        elapsed = time.time() - start
        print(f"  TIMEOUT/ERROR ({elapsed:.1f}s): {e}")
    print()
    time.sleep(0.3)

    # =====================================================================
    # PROBE 7: Password-based argument — what if sys8 needs gizmore's password?
    # sys8(encode_bytes_list(b"ilikephp"))
    # =====================================================================
    print("=" * 70)
    print("PROBE 7: Password as argument — sys8('ilikephp')")
    print("=" * 70)

    passwords = [b"ilikephp", b"gizmore", b"dloser", b"root", b"sudo"]
    for pwd in passwords:
        pwd_term = encode_bytes_list(pwd)
        pwd_enc = encode_term(pwd_term)
        payload = bytes([0x08]) + pwd_enc + bytes([FD]) + QD + bytes([FD, FF])

        start = time.time()
        try:
            raw = query_raw(payload, retries=2, timeout_s=5.0)
            elapsed = time.time() - start
            if raw and FF in raw:
                term = parse_term(raw)
                # Quick decode
                if isinstance(term, Lam) and isinstance(term.body, Lam):
                    body = term.body.body
                    if isinstance(body, App) and isinstance(body.f, Var):
                        if body.f.i == 0:
                            # Right — error
                            print(f"  sys8('{pwd.decode()}'): Right (error)")
                        elif body.f.i == 1:
                            print(f"  *** sys8('{pwd.decode()}'): LEFT — SUCCESS?! ***")
                            print(f"  Raw: {raw.hex()}")
                        else:
                            print(f"  sys8('{pwd.decode()}'): unknown tag={body.f.i}")
                    else:
                        print(f"  sys8('{pwd.decode()}'): unexpected shape")
                else:
                    print(f"  sys8('{pwd.decode()}'): raw={raw[:40].hex()}")
            else:
                print(f"  sys8('{pwd.decode()}'): EMPTY")
        except Exception as e:
            print(f"  sys8('{pwd.decode()}'): ERR: {e}")
        time.sleep(0.2)
    print()

    # =====================================================================
    # PROBE 8: Tiny closed normal forms as sys8 argument
    # The author said "3 leafs" — maybe the arg needs to be a specific
    # closed lambda term
    # =====================================================================
    print("=" * 70)
    print("PROBE 8: Tiny closed lambda terms as sys8 argument")
    print("=" * 70)

    # Generate small closed lambda terms
    tiny_terms = [
        ("I = λx.x", Lam(Var(0))),
        ("K = λx.λy.x", Lam(Lam(Var(1)))),
        ("KI = λx.λy.y", Lam(Lam(Var(0)))),
        (
            "S = λf.λg.λx.f x (g x)",
            Lam(Lam(Lam(App(App(Var(2), Var(0)), App(Var(1), Var(0)))))),
        ),
        ("ω = λx.xx", Lam(App(Var(0), Var(0)))),
        ("K* = λx.λy.λz.x", Lam(Lam(Lam(Var(2))))),
        ("C = λf.λx.λy.fyx", Lam(Lam(Lam(App(App(Var(2), Var(0)), Var(1)))))),
        ("B = λf.λg.λx.f(gx)", Lam(Lam(Lam(App(Var(2), App(Var(1), Var(0))))))),
        ("True = λt.λf.t", Lam(Lam(Var(1)))),  # Same as K
        ("False = λt.λf.f", Lam(Lam(Var(0)))),  # Same as KI = nil
        ("0 (Church) = λf.λx.x", Lam(Lam(Var(0)))),
        ("1 (Church) = λf.λx.fx", Lam(Lam(App(Var(1), Var(0))))),
        ("2 (Church) = λf.λx.f(fx)", Lam(Lam(App(Var(1), App(Var(1), Var(0)))))),
        ("pair = λx.λy.λf.fxy", Lam(Lam(Lam(App(App(Var(0), Var(2)), Var(1)))))),
        (
            "Y = λf.(λx.f(xx))(λx.f(xx))",
            Lam(
                App(
                    Lam(App(Var(1), App(Var(0), Var(0)))),
                    Lam(App(Var(1), App(Var(0), Var(0)))),
                )
            ),
        ),
        ("Backdoor A = λa.λb.bb", Lam(Lam(App(Var(0), Var(0))))),
        ("Backdoor B = λa.λb.ab", Lam(Lam(App(Var(1), Var(0))))),
        ("λx.λy.λz.z", Lam(Lam(Lam(Var(0))))),
        ("λx.λy.λz.y", Lam(Lam(Lam(Var(1))))),
        ("λx.λy.λz.x", Lam(Lam(Lam(Var(2))))),
        # Byte term for specific numbers
        ("int0", encode_byte_term(0)),
        ("int1", encode_byte_term(1)),
        ("int8", encode_byte_term(8)),
        ("int42", encode_byte_term(42)),
        ("int201", encode_byte_term(201)),
    ]

    for label, term in tiny_terms:
        term_enc = encode_term(term)
        payload = bytes([0x08]) + term_enc + bytes([FD]) + QD + bytes([FD, FF])

        try:
            raw = query_raw(payload, retries=2, timeout_s=5.0)
            if raw and FF in raw:
                parsed = parse_term(raw)
                if isinstance(parsed, Lam) and isinstance(parsed.body, Lam):
                    body = parsed.body.body
                    if isinstance(body, App) and isinstance(body.f, Var):
                        if body.f.i == 1:
                            print(f"  *** LEFT: sys8({label}) SUCCEEDED! ***")
                            print(f"  Raw: {raw.hex()}")
                        elif body.f.i == 0:
                            # Decode error code
                            WEIGHTS = {
                                0: 0,
                                1: 1,
                                2: 2,
                                3: 4,
                                4: 8,
                                5: 16,
                                6: 32,
                                7: 64,
                                8: 128,
                            }
                            err = "?"
                            try:
                                inner = body.x
                                for _ in range(9):
                                    if isinstance(inner, Lam):
                                        inner = inner.body
                                    else:
                                        break

                                # eval bitset
                                def eval_bs(e):
                                    if isinstance(e, Var):
                                        return WEIGHTS.get(e.i, -1)
                                    if isinstance(e, App) and isinstance(e.f, Var):
                                        w = WEIGHTS.get(e.f.i, -1)
                                        s = eval_bs(e.x)
                                        return w + s if w >= 0 and s >= 0 else -1
                                    return -1

                                code = eval_bs(inner)
                                err_names = {
                                    0: "Exc",
                                    1: "NotImpl",
                                    2: "InvArg",
                                    3: "NoFile",
                                    4: "NotDir",
                                    5: "NotFile",
                                    6: "Perm",
                                    7: "Rate",
                                }
                                err = err_names.get(code, f"?{code}")
                            except Exception:
                                pass
                            print(f"  sys8({label}): Right({err})")
                        else:
                            print(f"  sys8({label}): tag={body.f.i}")
                    else:
                        print(f"  sys8({label}): shape={term_summary(parsed)[:60]}")
                else:
                    print(f"  sys8({label}): {term_summary(parsed)[:60]}")
            elif raw:
                print(f"  sys8({label}): raw_no_ff={raw[:40].hex()}")
            else:
                print(f"  sys8({label}): EMPTY")
        except Exception as e:
            print(f"  sys8({label}): ERR: {e}")
        time.sleep(0.15)

    # =====================================================================
    # PROBE 9: What if sys8 needs a SPECIFIC integer — the UID?
    # In /etc/passwd, gizmore has UID 1000, dloser has UID 1002
    # Maybe sys8 checks if the argument matches a specific UID
    # =====================================================================
    print("\n" + "=" * 70)
    print("PROBE 9: UID-based argument — sys8(uid)")
    print("=" * 70)

    uids = [0, 100, 1000, 1002, 65534, 255]
    for uid in uids:
        uid_term = encode_byte_term(uid)
        uid_enc = encode_term(uid_term)
        payload = bytes([0x08]) + uid_enc + bytes([FD]) + QD + bytes([FD, FF])

        try:
            raw = query_raw(payload, retries=2, timeout_s=5.0)
            if raw and FF in raw:
                parsed = parse_term(raw)
                if isinstance(parsed, Lam) and isinstance(parsed.body, Lam):
                    body = parsed.body.body
                    if (
                        isinstance(body, App)
                        and isinstance(body.f, Var)
                        and body.f.i == 1
                    ):
                        print(f"  *** LEFT: sys8(uid={uid}) SUCCEEDED! ***")
                        print(f"  Raw: {raw.hex()}")
                    else:
                        print(f"  sys8(uid={uid}): Right (error)")
                else:
                    print(f"  sys8(uid={uid}): {term_summary(parsed)[:40]}")
            else:
                print(f"  sys8(uid={uid}): EMPTY")
        except Exception as e:
            print(f"  sys8(uid={uid}): ERR: {e}")
        time.sleep(0.15)

    print("\nAll probes complete!")


if __name__ == "__main__":
    main()
