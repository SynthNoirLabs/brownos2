#!/usr/bin/env python3
"""
probe_arity_bomb.py - Determine if/how sys8 forces its argument.

Key insight: If sys8(λa.λb.g(0), cont) HANGS but sys8(nil, cont) returns quickly,
then sys8 is applying its argument to 2 values (telling us the expected shape).

g(0) diverges for all inputs, so λ^N.g(0) is a "bomb" that detonates only if the
argument is forced by applying it to N values.

Also tests:
- Meta-syscall: pass sys8 a byte-list encoding a known program
- No-quote continuation to avoid serialization blindness
- Selective field bombs: Either-like structures with g(0) in specific positions
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Any

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FF,
    FD,
    FE,
    QD,
    encode_bytes_list,
    encode_term,
    encode_byte_term,
)

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


def shift_db(term: object, delta: int, cutoff: int = 0) -> object:
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_db(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_db(term.f, delta, cutoff), shift_db(term.x, delta, cutoff))
    return term


def to_db(term: object, env: tuple[str, ...] = ()) -> object:
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


def g(i: int) -> NGlob:
    return NGlob(i)


def v(n: str) -> NVar:
    return NVar(n)


def lam(p: str, b: object) -> NLam:
    return NLam(p, b)


def app(f: object, x: object) -> NApp:
    return NApp(f, x)


def apps(*t: object) -> object:
    out = t[0]
    for x in t[1:]:
        out = app(out, x)
    return out


NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)


def recv_all(sock: socket.socket, timeout_s: float = 5.0) -> bytes:
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


def query_named_timed(term: object, timeout_s: float = 5.0) -> tuple[bytes, float]:
    """Returns (response, elapsed_seconds)."""
    payload = encode_term(to_db(term)) + bytes([FF])
    try:
        start = time.monotonic()
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            result = recv_all(sock, timeout_s=timeout_s)
        elapsed = time.monotonic() - start
        return result, elapsed
    except Exception as e:
        elapsed = time.monotonic() - start
        return f"ERR:{e}".encode(), elapsed


def write_str(s: str) -> object:
    return apps(g(2), NConst(encode_bytes_list(s.encode("latin-1"))), NIL)


def obs_no_quote() -> object:
    """Write-only observer: no quote involved. Writes 'L' for Left, error string for Right."""
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
    left_handler = lam("_payload", write_str("L"))
    return lam("res", apps(v("res"), left_handler, right_handler))


OBS = obs_no_quote()


def classify(raw: bytes, elapsed: float) -> str:
    if not raw:
        if elapsed >= 4.5:
            return "TIMEOUT(diverged?)"
        return "EMPTY"
    text = raw.decode("latin-1", errors="replace")
    if "Permission denied" in text:
        return f"PERM_DENIED({elapsed:.2f}s)"
    if "Not implemented" in text:
        return f"NOT_IMPL({elapsed:.2f}s)"
    if "Invalid" in text:
        return f"INVALID({elapsed:.2f}s)"
    if "Encoding failed" in text:
        return f"ENCODING_FAILED({elapsed:.2f}s)"
    if text.strip() == "L":
        return f"LEFT!({elapsed:.2f}s)"
    if text.strip() == "?":
        return f"UNKNOWN_ERR({elapsed:.2f}s)"
    return f"OTHER({text[:60]!r},{elapsed:.2f}s)"


def make_bomb(arity: int) -> object:
    """λ^arity. g(0) — a term that diverges only if applied to `arity` arguments."""
    params = [f"_b{i}" for i in range(arity)]
    body: object = g(0)  # g(0) diverges for ALL inputs
    for p in reversed(params):
        body = lam(p, body)
    return body


def make_bomb_partial(arity: int, position: int) -> object:
    """Like bomb but g(0) only in one specific argument position.
    λ^arity. arg[position] (others are nil)."""
    params = [f"_b{i}" for i in range(arity)]
    body = v(params[position])  # return the specific argument
    for p in reversed(params):
        body = lam(p, body)
    return body


def phase_1_arity_bombs() -> None:
    """
    Test sys8 with λ^N.g(0) for various N.
    If sys8 forces its argument by applying it, the bomb detonates and we get a timeout.
    If sys8 just checks something else first, we get Permission denied quickly.
    """
    print("=" * 72)
    print("PHASE 1: Arity bombs - does sys8 force its argument?")
    print("=" * 72)

    # Baseline: sys8(nil, OBS) - should be fast Permission denied
    out, elapsed = query_named_timed(apps(g(8), NIL, OBS), timeout_s=5.0)
    print(f"  baseline sys8(nil, OBS) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # Baseline: sys8(g(0), OBS) - g(0) as arg. If sys8 forces arg, it diverges.
    # g(0) itself when used as a value (not applied) should be fine.
    # But if sys8 tries to APPLY g(0) to something, g(0)(x) diverges.
    out, elapsed = query_named_timed(apps(g(8), g(0), OBS), timeout_s=5.0)
    print(f"  baseline sys8(g(0), OBS) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # Now: bombs of various arities
    for arity in range(1, 10):
        bomb = make_bomb(arity)
        out, elapsed = query_named_timed(apps(g(8), bomb, OBS), timeout_s=5.0)
        print(f"  sys8(λ^{arity}.g(0), OBS) -> {classify(out, elapsed)}")
        time.sleep(0.3)

    # Also test with the continuation being g(0) to see if sys8 even reaches the cont
    print()
    print("  --- sys8 with g(0) as CONTINUATION ---")
    out, elapsed = query_named_timed(apps(g(8), NIL, g(0)), timeout_s=5.0)
    print(f"  sys8(nil, g(0)) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # If sys8(nil, g(0)) diverges, it means sys8 DOES call the continuation with Right(6)
    # and then g(0)(Right(6)) diverges. This would prove sys8 evaluates normally.

    # Direct g(0) application to check it diverges
    out, elapsed = query_named_timed(apps(g(0), NIL), timeout_s=5.0)
    print(f"  g(0)(nil) -> {classify(out, elapsed)}")
    time.sleep(0.3)


def phase_2_meta_syscall() -> None:
    """
    Test: pass sys8 a Scott byte-list that encodes a known-good program.
    Maybe sys8 is an "eval" syscall that executes embedded programs.
    """
    print("\n" + "=" * 72)
    print("PHASE 2: Meta-syscall - is sys8 an eval?")
    print("=" * 72)

    # Build byte lists that encode various programs
    # towel(nil, QD) = 2A 00 FE FE FD QD FD FF
    towel_prog = bytes([0x2A]) + encode_term(NIL_DB) + bytes([FD]) + QD + bytes([FD])
    towel_bytes = NConst(encode_bytes_list(towel_prog))

    # echo(nil, QD)
    echo_prog = bytes([0x0E]) + encode_term(NIL_DB) + bytes([FD]) + QD + bytes([FD])
    echo_bytes = NConst(encode_bytes_list(echo_prog))

    # Just the byte 0x08 (sys8 itself)
    sys8_byte = NConst(encode_byte_term(8))

    # The byte list [0x08, 0xFF]
    sys8_wire = NConst(encode_bytes_list(bytes([0x08, 0xFF])))

    test_cases = [
        ("sys8(towel_program_bytes, OBS)", apps(g(8), towel_bytes, OBS)),
        ("sys8(echo_program_bytes, OBS)", apps(g(8), echo_bytes, OBS)),
        ("sys8(byte(8), OBS)", apps(g(8), sys8_byte, OBS)),
        ("sys8([0x08, 0xFF], OBS)", apps(g(8), sys8_wire, OBS)),
    ]

    for label, term in test_cases:
        out, elapsed = query_named_timed(term, timeout_s=5.0)
        print(f"  {label} -> {classify(out, elapsed)}")
        time.sleep(0.35)


def phase_3_selective_field_bombs() -> None:
    """
    Test with Either-shaped values where one branch is g(0) (diverges).
    If sys8 only inspects the Left branch of a Left(bomb), it would hang.
    If sys8 only inspects the Right branch of a Right(bomb), it would hang.
    """
    print("\n" + "=" * 72)
    print("PHASE 3: Selective field bombs - which branch does sys8 inspect?")
    print("=" * 72)

    # Left(g(0)) — if sys8 unwraps Left, it hits g(0) and could diverge
    # But g(0) as a value is just an opaque closure; it only diverges when APPLIED.
    # So Left(g(0)) would only diverge if sys8 applies the inner value.
    left_bomb = lam("l", lam("r", app(v("l"), g(0))))  # Left(g(0))
    right_bomb = lam("l", lam("r", app(v("r"), g(0))))  # Right(g(0))

    # Left(λx.g(0)(x)) — payload that diverges when called
    left_active_bomb = lam("l", lam("r", app(v("l"), lam("x", app(g(0), v("x"))))))

    # Right(λx.g(0)(x))
    right_active_bomb = lam("l", lam("r", app(v("r"), lam("x", app(g(0), v("x"))))))

    # Left(nil) — should NOT diverge
    left_nil = lam("l", lam("r", app(v("l"), NIL)))
    # Right(nil) — should NOT diverge
    right_nil = lam("l", lam("r", app(v("r"), NIL)))

    test_cases = [
        ("sys8(Left(nil), OBS)", apps(g(8), left_nil, OBS)),
        ("sys8(Right(nil), OBS)", apps(g(8), right_nil, OBS)),
        ("sys8(Left(g(0)), OBS)", apps(g(8), left_bomb, OBS)),
        ("sys8(Right(g(0)), OBS)", apps(g(8), right_bomb, OBS)),
        ("sys8(Left(λx.⊥), OBS)", apps(g(8), left_active_bomb, OBS)),
        ("sys8(Right(λx.⊥), OBS)", apps(g(8), right_active_bomb, OBS)),
    ]

    for label, term in test_cases:
        out, elapsed = query_named_timed(term, timeout_s=5.0)
        print(f"  {label} -> {classify(out, elapsed)}")
        time.sleep(0.35)


def phase_4_continuation_probing() -> None:
    """
    Test what happens with different continuations:
    - g(0) as continuation (diverges if cont is called)
    - identity as continuation (returns the result directly)
    - λres. write(quote(res)) without the Either unwrap
    """
    print("\n" + "=" * 72)
    print("PHASE 4: Continuation probing")
    print("=" * 72)

    # Already partly done, but let's be systematic

    # If cont=g(0), and sys8 calls cont(Right(6)), then g(0)(Right(6)) diverges
    # This tells us: does sys8 actually invoke the continuation?
    out, elapsed = query_named_timed(apps(g(8), NIL, g(0)), timeout_s=5.0)
    print(f"  sys8(nil, g(0)) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # What about cont = λres. (write "CONT_CALLED" nil)?
    cont_marker = lam("_res", write_str("CONT_CALLED"))
    out, elapsed = query_named_timed(apps(g(8), NIL, cont_marker), timeout_s=5.0)
    print(f"  sys8(nil, λ_.write('CONT_CALLED')) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # sys8 with no continuation at all (just partial application, then apply to QD)
    # This is: (sys8(nil))(QD)
    out, elapsed = query_named_timed(
        apps(app(g(8), NIL), NConst(Lam(Lam(Var(0))))), timeout_s=5.0
    )
    print(f"  (sys8(nil))(nil) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # Compare with towel behavior for calibration
    out, elapsed = query_named_timed(apps(g(42), NIL, g(0)), timeout_s=5.0)
    print(f"  towel(nil, g(0)) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # And echo
    out, elapsed = query_named_timed(apps(g(14), NIL, g(0)), timeout_s=5.0)
    print(f"  echo(nil, g(0)) -> {classify(out, elapsed)}")
    time.sleep(0.3)


def phase_5_identity_cont() -> None:
    """
    Use identity as continuation: sys8(arg, λx.x)
    Then the result (Right(6)) is returned "raw" — but it goes nowhere.
    We can wrap in a write+quote to see it without QD.
    """
    print("\n" + "=" * 72)
    print("PHASE 5: sys8 with raw QD (baseline) vs write-only")
    print("=" * 72)

    # Standard QD for comparison
    qd_bytes = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

    # sys8(nil, QD) - standard
    payload = (
        bytes([8]) + encode_term(NIL_DB) + bytes([FD]) + qd_bytes + bytes([FD, FF])
    )
    out, elapsed = query_named_timed(apps(g(8), NIL, OBS), timeout_s=5.0)
    print(f"  sys8(nil, OBS_no_quote) -> {classify(out, elapsed)}")
    time.sleep(0.3)

    # sys8(nil) with a continuation that ONLY writes a fixed marker regardless of result
    # This tests whether sys8 even reaches the continuation
    cont_always_write = lam("_", write_str("REACHED"))
    out, elapsed = query_named_timed(apps(g(8), NIL, cont_always_write), timeout_s=5.0)
    print(f"  sys8(nil, λ_.write('REACHED')) -> {classify(out, elapsed)}")
    time.sleep(0.3)


def main() -> None:
    print("=" * 72)
    print("probe_arity_bomb.py - Structural probing of sys8")
    print(f"target: {HOST}:{PORT}")
    print("=" * 72)

    phase_1_arity_bombs()
    phase_2_meta_syscall()
    phase_3_selective_field_bombs()
    phase_4_continuation_probing()
    phase_5_identity_cont()

    print("\nAll phases complete.")


if __name__ == "__main__":
    main()
