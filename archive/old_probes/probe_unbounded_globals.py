#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass

from solve_brownos_answer import App, Lam, Var
from solve_brownos_answer import QD as QD_BYTES
from solve_brownos_answer import decode_byte_term, decode_bytes_list, decode_either, encode_term, parse_term, query

FF = 0xFF

I_TERM: object = Lam(Var(0))
NIL_TERM: object = Lam(Lam(Var(0)))
QD_TERM: object = parse_term(QD_BYTES)


def shift(term: object, delta: int, cutoff: int = 0) -> object:
    """De Bruijn shift (increase free vars >= cutoff by delta)."""

    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    raise TypeError(f"Unsupported term node: {type(term)}")


def church_n(n: int) -> object:
    """Church numeral n"""

    body: object = Var(0)  # x
    for _ in range(n):
        body = App(Var(1), body)  # f (..)
    return Lam(Lam(body))


def build_shift_n_then_call(*, base: int, shifts: int) -> object:
    """Historical helper (kept for reference).

    Earlier reversing work treated syscall 0x0E as “lift by +2”. With correct Scott-Either
    semantics, 0x0E behaves like an echo: the apparent “+2” is just the lifted payload living
    under Either’s two lambdas, and normal unwrapping cancels it.

    This means this builder does **not** actually reach new global indices.
    """

    n_term = church_n(shifts)

    # We build the whole program under an outer binder for `expr0`, then apply it to Var(base).
    # That way, `expr0` is a *local* (small de Bruijn index) rather than a global reference.

    # C0 = \k. k expr0
    # In C0's body: k=Var(0), expr0=Var(1)
    c0 = Lam(App(Var(0), Var(1)))

    # F = \comp. \k. comp (\expr. (0x0E expr) (\e. k (e I I)))
    # With the outer `expr0` binder in scope:
    # - inside \expr.: env = [expr, k, comp, expr0, globals...]
    #   so syscall0e is at Var(0x0E + 4)
    # - inside \e.: env = [e, expr, k, comp, expr0, globals...]
    #   so k is Var(2)
    e = Var(0)
    unwrap_e = App(App(e, I_TERM), I_TERM)
    cont_e = Lam(App(Var(2), unwrap_e))
    call_0e = App(App(Var(0x0E + 4), Var(0)), cont_e)
    cont_expr = Lam(call_0e)
    f_term = Lam(Lam(App(Var(1), cont_expr)))

    comp_n = App(App(n_term, f_term), c0)

    # Kfinal = \expr. (expr NIL) QD
    # Here (inside Kfinal's body) env = [expr, expr0, globals...], so we shift QD by +2.
    kfinal = Lam(App(App(Var(0), NIL_TERM), shift(QD_TERM, 2)))

    body = App(comp_n, kfinal)
    program = Lam(body)

    return App(program, Var(base))


@dataclass(frozen=True)
class Result:
    base: int
    shifts: int
    global_index: int
    kind: str
    detail: str


def classify(term: object) -> tuple[str, str]:
    try:
        tag, payload = decode_either(term)
    except Exception:
        return ("non_either", str(term)[:200])

    if tag == "Right":
        try:
            code = decode_byte_term(payload)
            return ("either_right", f"Right({code})")
        except Exception:
            return ("either_right", "Right(<non-int>)")

    # Left
    try:
        bs = decode_bytes_list(payload)
        preview = bs[:120].decode("utf-8", "replace")
        return ("either_left", f"Left(bytes:{len(bs)}:{preview!r})")
    except Exception:
        return ("either_left", "Left(<non-bytes>)")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="(Historical) Attempted hidden-global probe via Church-iterated syscall 0x0E. Kept for reference."
    )
    ap.add_argument("--base", type=int, default=252)
    ap.add_argument(
        "--shifts",
        type=int,
        required=True,
        help="Number of 0x0E shifts to apply (each adds +2 to the Var index)",
    )
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--retries", type=int, default=3)
    args = ap.parse_args()

    term = build_shift_n_then_call(base=args.base, shifts=args.shifts)
    payload = encode_term(term) + bytes([FF])

    try:
        resp = query(payload, retries=args.retries, timeout_s=args.timeout)
    except Exception as e:
        print(f"error: {type(e).__name__}: {e}")
        return

    out_term = parse_term(resp)
    kind, detail = classify(out_term)
    g = args.base + 2 * args.shifts
    print(f"base={args.base} shifts={args.shifts} g={g} -> {kind} {detail}")


if __name__ == "__main__":
    main()
