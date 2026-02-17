#!/usr/bin/env python3
"""
Unlock sweep probe: call a candidate global `g` first, then call syscall 8.

Hypothesis:
  Some global (possibly returning Right(1) / "Not implemented") mutates state
  or installs a capability in the VM, after which syscall 8 may succeed.

Program shape (per case):
  (g arg) (\\_. write("B\\n"); (8 NIL) CONT_TAG)

We avoid QD/quote() entirely.
"""

from __future__ import annotations

import argparse
import time

from solve_brownos_answer import App, Lam, Var, encode_byte_term, encode_bytes_list, encode_term

from probe_safe_print import FF, I, NIL, query_all, shift


def cps(syscall_num: int, arg: object, cont: object) -> object:
    return App(App(Var(syscall_num), arg), cont)


def build_cont_tag() -> object:
    """
    Continuation that distinguishes Either branches without quote().

    On Left(_):        write("LEFT\\n")
    On Right(code):    write(errorString(code))
    """
    write = 0x02
    error_string = 0x01

    left_marker = encode_bytes_list(b"LEFT\n")

    # Left handler: λpayload. (write left_marker) I
    left_handler = Lam(App(App(Var(write + 2), left_marker), I))

    # errorString(code) continuation: λe2. e2 (λbs. (write bs) I) (λ_. I)
    left2 = Lam(App(App(Var(write + 4), Var(0)), I))
    right2 = Lam(I)
    cont_err = Lam(App(App(Var(0), left2), right2))

    # Right handler: λcode. (errorString code) cont_err
    right_handler = Lam(App(App(Var(error_string + 2), Var(0)), cont_err))

    # Whole: λres. res left_handler right_handler
    return Lam(App(App(Var(0), left_handler), right_handler))


CONT_TAG = build_cont_tag()


def seq_write(marker: bytes, next_term: object) -> object:
    """
    Sequence helper:
      write(marker) >>= \\_. next_term
    """
    return cps(0x02, encode_bytes_list(marker), Lam(shift(next_term, 1)))


def build_program(g: int, arg: object) -> object:
    """
    Build:
      (g arg) (\\_. write("B\\n"); (8 NIL) CONT_TAG)
    """
    call8 = cps(0x08, NIL, CONT_TAG)
    after_g = seq_write(b"B\n", call8)
    cont_g = Lam(shift(after_g, 1))  # ignore g-result

    call_g = App(App(Var(g), arg), cont_g)
    return call_g


def parse_int(s: str) -> int:
    s = s.strip().lower()
    if s.startswith("0x"):
        return int(s, 16)
    return int(s, 10)


def default_g_list() -> list[int]:
    # Start with high globals and a few known interesting ones.
    gs = list(range(240, 253)) + [0x0E, 0x08, 0xC9, 0x04, 0x05, 0x06, 0x07, 0x2A]
    # Dedup while preserving order.
    seen: set[int] = set()
    out: list[int] = []
    for g in gs:
        if 0 <= g <= 252 and g not in seen:
            out.append(g)
            seen.add(g)
    return out


def default_args() -> list[tuple[str, object]]:
    return [
        ("NIL", NIL),
        ("I", I),
        ("V8", Var(0x08)),
        ("V14", Var(0x0E)),
        ("V201", Var(0xC9)),
        ("int0", encode_byte_term(0)),
        ("int8", encode_byte_term(8)),
        ("bs'A'", encode_bytes_list(b"A")),
    ]


def minimal_args() -> list[tuple[str, object]]:
    # Keep it tiny: a few "likely meaningful" globals plus NIL.
    return [
        ("NIL", NIL),
        ("V8", Var(0x08)),
        ("V14", Var(0x0E)),
        ("V201", Var(0xC9)),
    ]


def run_case(g: int, g_name: str, arg_name: str, arg: object, timeout_s: float) -> tuple[str, bytes]:
    term = build_program(g, arg)
    out = query_all(encode_term(term) + bytes([FF]), timeout_s=timeout_s)
    label = f"g={g_name:<5} arg={arg_name:<6}"
    return label, out


def main() -> None:
    ap = argparse.ArgumentParser(description="BrownOS unlock sweep probe (g then syscall8).")
    ap.add_argument("--start", type=parse_int, default=240, help="Start g (inclusive) for range scan (default: 240).")
    ap.add_argument("--end", type=parse_int, default=252, help="End g (inclusive) for range scan (default: 252).")
    ap.add_argument(
        "--extra",
        type=str,
        default="",
        help="Comma-separated extra g values (decimal or 0x..) to include.",
    )
    ap.add_argument("--full", action="store_true", help="Scan all g in [0,252].")
    ap.add_argument("--delay", type=float, default=0.6, help="Delay between requests (default: 0.6s).")
    ap.add_argument("--timeout", type=float, default=5.0, help="Socket timeout per case (default: 5.0s).")
    ap.add_argument(
        "--argset",
        choices=["default", "minimal"],
        default="default",
        help="Argument set to use (default: default).",
    )
    args = ap.parse_args()

    if args.full:
        gs = list(range(0, 253))
    else:
        gs = default_g_list()
        # Also include user-provided range.
        for g in range(max(0, args.start), min(252, args.end) + 1):
            if g not in gs:
                gs.append(g)

    if args.extra.strip():
        for part in args.extra.split(","):
            g = parse_int(part)
            if 0 <= g <= 252 and g not in gs:
                gs.append(g)

    arg_cases = minimal_args() if args.argset == "minimal" else default_args()

    print(f"Running {len(gs)} g-values x {len(arg_cases)} args = {len(gs) * len(arg_cases)} cases")
    print("Output includes internal marker: B\\n (after g, before 8).")
    print()

    delay = args.delay
    for g in gs:
        g_name = f"0x{g:02x}"
        for arg_name, arg in arg_cases:
            try:
                label, out = run_case(g, g_name, arg_name, arg, timeout_s=args.timeout)
                txt = out.decode("utf-8", "replace") if out else "<empty>"
                print(f"{label} -> {txt!r}")
                if "Not so fast!" in txt:
                    delay = max(delay, 2.5)
                elif delay > args.delay:
                    delay = max(args.delay, delay * 0.85)
            except Exception as e:
                print(f"g={g_name:<5} arg={arg_name:<6} -> ERROR: {e}")
            time.sleep(delay)


if __name__ == "__main__":
    main()
