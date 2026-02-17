#!/usr/bin/env python3
"""
Probe globals 251/252 with a variety of small arguments.

Rationale:
- The "special bytes" hint might refer to values near 0xFB..0xFF.
- Our broad sweep only tested args {nil,int0,int1}. These probes expand arg shapes.

Output is produced without quote():
- If syscall returns Right(code): prints errorString(code)
- If syscall returns Left(_): prints a marker ("LEFT\\n") only (payload may not be bytes)
"""

from __future__ import annotations

import time

from solve_brownos_answer import App, Lam, Var, encode_byte_term, encode_bytes_list, encode_term

from probe_safe_print import FF, I, NIL, query_all, shift


def cps(syscall_num: int, arg: object, cont: object) -> object:
    return App(App(Var(syscall_num), arg), cont)


def build_cont_tag_left_only() -> object:
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


CONT_TAG = build_cont_tag_left_only()


def run_case(syscall_num: int, name: str, arg: object, timeout_s: float = 4.0) -> str:
    term = cps(syscall_num, arg, CONT_TAG)
    out = query_all(encode_term(term) + bytes([FF]), timeout_s=timeout_s)
    return out.decode("utf-8", "replace")


def main() -> None:
    args: list[tuple[str, object]] = [
        ("NIL", NIL),
        ("I", I),
        ("byte(0)", encode_byte_term(0)),
        ("byte(1)", encode_byte_term(1)),
        ("byte(8)", encode_byte_term(8)),
        ("bytes('A')", encode_bytes_list(b"A")),
        ("bytes('test')", encode_bytes_list(b"test")),
    ]

    syscalls = [
        (0xFB, "251"),
        (0xFC, "252"),
    ]

    for sc, sc_name in syscalls:
        print(f"=== syscall {sc_name} (0x{sc:02x}) ===")
        for arg_name, arg in args:
            try:
                out = run_case(sc, arg_name, arg)
                out_s = out if out else "<empty>"
                print(f"{arg_name:10} -> {out_s!r}")
            except Exception as e:
                print(f"{arg_name:10} -> ERROR: {e}")
            time.sleep(0.4)
        print()


if __name__ == "__main__":
    main()

