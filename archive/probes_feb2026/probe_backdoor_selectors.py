#!/usr/bin/env python3
"""
Backdoor selector brute-force (small terms only).

Idea:
  backdoor(nil) -> Left(pair) where pair = λs. s A B

Try small 2-arg selectors `s` (esp. all 16 "3-leaf" bodies under 2 lambdas),
compute (pair s), then feed that derived term into syscall 8, printing results
without quote() (so special-byte experiments don't hang).
"""

from __future__ import annotations

import time

from solve_brownos_answer import App, Lam, Var, encode_bytes_list, encode_term

from probe_safe_print import CONT_PRINT, FF, I, NIL, query_all, shift


def cps(syscall_num: int, arg: object, cont: object) -> object:
    return App(App(Var(syscall_num), arg), cont)


def build_cont_after8(ret_marker: bytes) -> object:
    """
    Continuation for syscall 8:
      write(ret_marker); then CONT_PRINT(result)
    """
    ret_term = encode_bytes_list(ret_marker)
    ret_term_s1 = shift(ret_term, 1)

    cont_print_s2 = shift(CONT_PRINT, 2)
    cont2 = Lam(App(cont_print_s2, Var(1)))  # inside cont2: V0=write_result, V1=result

    write_s1 = Var(2 + 1)
    body = App(App(write_s1, ret_term_s1), cont2)
    return Lam(body)


CONT_AFTER8 = build_cont_after8(b"R\n")


def selector_2lam(body: object) -> object:
    return Lam(Lam(body))


def generate_selectors() -> list[tuple[str, object]]:
    a = Var(1)
    b = Var(0)

    selectors: list[tuple[str, object]] = []

    # Common "pair selectors" and small probes.
    selectors.append(("fst", selector_2lam(a)))
    selectors.append(("snd", selector_2lam(b)))
    selectors.append(("ab", selector_2lam(App(a, b))))
    selectors.append(("ba", selector_2lam(App(b, a))))
    selectors.append(("aa", selector_2lam(App(a, a))))
    selectors.append(("bb", selector_2lam(App(b, b))))

    # All 16 three-leaf bodies, two tree shapes:
    #   Lxyz := ((x y) z)
    #   Rxyz := (x (y z))
    def leaf(bit: int) -> object:
        return a if bit else b

    for shape in ("L", "R"):
        for bits in range(8):
            x = leaf((bits >> 2) & 1)
            y = leaf((bits >> 1) & 1)
            z = leaf((bits >> 0) & 1)
            if shape == "L":
                body = App(App(x, y), z)
            else:
                body = App(x, App(y, z))
            selectors.append((f"{shape}{bits:03b}", selector_2lam(body)))

    return selectors


def build_program(selector_name: str, selector: object) -> object:
    """
    Program:
      backdoor(nil) >>= \\either.
        either
          (\\pair. write(label) >>= \\_. 8(pair selector) CONT_AFTER8)
          (\\_.   write(\"BDR\\n\") >>= \\_. I)
    """
    label = f"{selector_name}\n".encode("ascii", "replace")
    label_term_s2 = shift(encode_bytes_list(label), 2)
    bdr_term_s2 = shift(encode_bytes_list(b"BDR\n"), 2)

    # backdoor result is Either at V0 (depth1)
    # Left handler: pair at V0 (depth2)
    write_s2 = Var(2 + 2)

    selector_s3 = shift(selector, 3)  # closed, but keep consistent
    cont_after8_s3 = shift(CONT_AFTER8, 3)

    # After marker write: depth3 (V0=write_result, V1=pair)
    derived = App(Var(1), selector_s3)  # (pair selector) => selector A B
    call8 = App(App(Var(8 + 3), derived), cont_after8_s3)
    after_marker = Lam(call8)
    do_marker_then_8 = App(App(write_s2, label_term_s2), after_marker)
    left_handler = Lam(do_marker_then_8)

    # Right handler (shouldn't happen with correct nil)
    right_handler = Lam(App(App(write_s2, bdr_term_s2), Lam(shift(I, 3))))

    k = Lam(App(App(Var(0), left_handler), right_handler))
    return cps(0xC9, NIL, k)


def run_one(name: str, selector: object, timeout_s: float = 4.0) -> str:
    term = build_program(name, selector)
    out = query_all(encode_term(term) + bytes([FF]), timeout_s=timeout_s)
    return out.decode("utf-8", "replace")


def main() -> None:
    selectors = generate_selectors()

    print(f"Running {len(selectors)} selectors...")
    print("Output format per case: label, then (maybe) 'R', then error text.\n")

    for name, sel in selectors:
        try:
            out = run_one(name, sel)
            out_s = out if out else "<empty>"
            print(f"{name:6} -> {out_s!r}")
        except Exception as e:
            print(f"{name:6} -> ERROR: {e}")
        time.sleep(0.5)


if __name__ == "__main__":
    main()

