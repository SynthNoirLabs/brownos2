#!/usr/bin/env python3
from __future__ import annotations

import time
from itertools import product

from probe_mail_focus import (
    DISC8,
    NIL,
    app,
    apps,
    classify,
    g,
    lam,
    query_named,
    to_db,
    v,
    write_marker,
)
from solve_brownos_answer import App, FF, Lam, Var, encode_term


def max_var_index(term: object) -> int:
    if isinstance(term, Var):
        return term.i
    if isinstance(term, Lam):
        return max_var_index(term.body)
    if isinstance(term, App):
        return max(max_var_index(term.f), max_var_index(term.x))
    return -1


def payload_info(named_term: object) -> tuple[int, int]:
    db = to_db(named_term)
    wire = encode_term(db) + bytes([FF])
    return len(wire), max_var_index(db)


def run_case(name: str, term: object, timeout_s: float = 10.0) -> tuple[str, bytes]:
    out = query_named(term, timeout_s=timeout_s)
    return classify(out), out


def prog_echo_then_use(special: int, mode: str) -> object:
    # echo(special) -> Left(e) ; use e in different ways.
    if mode == "201_e":
        tail = apps(g(201), v("e"), lam("r", apps(v("r"), lam("_", write_marker("L")), lam("_", write_marker("R")))))
    elif mode == "8_e":
        tail = apps(g(8), v("e"), DISC8)
    elif mode == "8_nil_cont_e":
        tail = apps(apps(g(8), NIL), v("e"), DISC8)
    elif mode == "echo_e_then_201":
        tail = apps(
            g(14),
            v("e"),
            lam(
                "r2",
                apps(
                    v("r2"),
                    lam(
                        "z",
                        apps(
                            g(201),
                            v("z"),
                            lam("r3", apps(v("r3"), lam("_", write_marker("L")), lam("_", write_marker("R")))),
                        ),
                    ),
                    lam("_e2", write_marker("2")),
                ),
            ),
        )
    elif mode == "echo_e_then_8":
        tail = apps(
            g(14),
            v("e"),
            lam(
                "r2",
                apps(
                    v("r2"),
                    lam("z", apps(g(8), v("z"), DISC8)),
                    lam("_e2", write_marker("2")),
                ),
            ),
        )
    else:
        raise ValueError(f"Unknown mode: {mode}")

    return apps(
        g(14),
        g(special),
        lam(
            "r0",
            apps(
                v("r0"),
                lam("e", tail),
                lam("_e0", write_marker("0")),
            ),
        ),
    )


def make_pair_e_forms() -> list[tuple[str, object]]:
    forms: list[tuple[str, object]] = []
    for shape in ("left", "right"):
        for a, b, c in product(("pair", "e"), repeat=3):
            if shape == "left":
                body = app(app(v(a), v(b)), v(c))
                name = f"{shape}:(({a} {b}) {c})"
            else:
                body = app(v(a), app(v(b), v(c)))
                name = f"{shape}:({a} ({b} {c}))"
            forms.append((name, body))
    return forms


def prog_special_backdoor_form(special: int, expr: object, mode: str) -> object:
    # echo(special)->e ; 201(nil)->pair ; echo(expr(pair,e))->y ; then consume y.
    if mode == "201_y":
        tail = apps(
            g(201),
            v("y"),
            lam("r3", apps(v("r3"), lam("_", write_marker("L")), lam("_", write_marker("R")))),
        )
    elif mode == "8_y":
        tail = apps(g(8), v("y"), DISC8)
    elif mode == "8_nil_cont_y":
        tail = apps(apps(g(8), NIL), v("y"), DISC8)
    else:
        raise ValueError(f"Unknown mode: {mode}")

    return apps(
        g(14),
        g(special),
        lam(
            "r0",
            apps(
                v("r0"),
                lam(
                    "e",
                    apps(
                        g(201),
                        NIL,
                        lam(
                            "r1",
                            apps(
                                v("r1"),
                                lam(
                                    "pair",
                                    apps(
                                        g(14),
                                        expr,
                                        lam(
                                            "r2",
                                            apps(
                                                v("r2"),
                                                lam("y", tail),
                                                lam("_e2", write_marker("2")),
                                            ),
                                        ),
                                    ),
                                ),
                                lam("_e1", write_marker("1")),
                            ),
                        ),
                    ),
                ),
                lam("_e0", write_marker("0")),
            ),
        ),
    )


def main() -> None:
    print("=== Raw/Shallow Special-Byte Probe ===")
    print("Goal: keep 251/252 controlled and detect de Bruijn pollution early.\n")

    echo_modes = [
        "201_e",
        "8_e",
        "8_nil_cont_e",
        "echo_e_then_201",
        "echo_e_then_8",
    ]

    print("[1] Echo(special) shallow uses")
    for special in (251, 252):
        print(f"\n  special={special}")
        for mode in echo_modes:
            term = prog_echo_then_use(special, mode)
            plen, vmax = payload_info(term)
            cls, out = run_case(mode, term)
            polluted = "yes" if vmax >= 253 else "no"
            print(
                f"    mode={mode:16s} -> {cls:8s} "
                f"len={plen:4d} vmax={vmax:3d} polluted={polluted:3s} raw={out!r}"
            )
            time.sleep(0.03)

    print("\n[2] Echo(special)+Backdoor+3-leaf(pair,e) (shallow family)")
    forms = make_pair_e_forms()
    test_modes = ["201_y", "8_y", "8_nil_cont_y"]
    for special in (251, 252):
        print(f"\n  special={special}")
        for mode in test_modes:
            l_count = 0
            non_r = 0
            polluted_n = 0
            for name, expr in forms:
                term = prog_special_backdoor_form(special, expr, mode)
                plen, vmax = payload_info(term)
                cls, out = run_case(name, term)
                if cls == "L":
                    l_count += 1
                if cls != "R":
                    non_r += 1
                if vmax >= 253:
                    polluted_n += 1
                print(
                    f"    {mode:12s} {name:22s} -> {cls:8s} "
                    f"len={plen:4d} vmax={vmax:3d} raw={out!r}"
                )
                time.sleep(0.02)
            print(
                f"    summary mode={mode}: non_R={non_r}/{len(forms)}, "
                f"L={l_count}, polluted_terms={polluted_n}"
            )


if __name__ == "__main__":
    main()
