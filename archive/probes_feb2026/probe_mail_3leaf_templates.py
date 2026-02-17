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
from solve_brownos_answer import FF, encode_term, parse_term


def make_3leaf_forms() -> list[tuple[str, object]]:
    forms: list[tuple[str, object]] = []
    for shape in ("left", "right"):
        for a, b, c in product(("pair", "e"), repeat=3):
            if shape == "left":
                body = app(app(v(a), v(b)), v(c))
                name = f"(({a} {b}) {c})"
            else:
                body = app(v(a), app(v(b), v(c)))
                name = f"({a} ({b} {c}))"
            forms.append((f"{shape}:{name}", body))
    return forms


def is_wire_valid(named_term: object) -> bool:
    try:
        db = to_db(named_term)
        wire = encode_term(db) + bytes([FF])
        parsed = parse_term(wire)
        return parsed == db
    except Exception:
        return False


def prog_backdoor_then_echo(echo_arg: object, token_expr: object) -> object:
    # 201(nil) -> Left(pair)
    #   -> 14(echo_arg) -> Left(e)
    #      -> 8(token_expr(pair,e))
    echo_handler = lam(
        "res2",
        apps(
            v("res2"),
            lam("e", apps(g(8), token_expr, DISC8)),
            lam("_err2", write_marker("2")),
        ),
    )
    first_left = lam("pair", apps(g(14), echo_arg, echo_handler))
    first_handler = lam(
        "res1",
        apps(
            v("res1"),
            first_left,
            lam("_err1", write_marker("1")),
        ),
    )
    return apps(g(201), NIL, first_handler)


def prog_echo_then_backdoor(echo_arg: object, token_expr: object) -> object:
    # 14(echo_arg) -> Left(e)
    #   -> 201(nil) -> Left(pair)
    #      -> 8(token_expr(pair,e))
    backdoor_handler = lam(
        "res1",
        apps(
            v("res1"),
            lam("pair", apps(g(8), token_expr, DISC8)),
            lam("_err1", write_marker("1")),
        ),
    )
    echo_left = lam("e", apps(g(201), NIL, backdoor_handler))
    echo_handler = lam(
        "res0",
        apps(
            v("res0"),
            echo_left,
            lam("_err0", write_marker("0")),
        ),
    )
    return apps(g(14), echo_arg, echo_handler)


def main() -> None:
    print("=== Mail/Echo/3-Leaf Template Probe ===")

    forms = make_3leaf_forms()
    echo_args = [
        ("nil", NIL),
        ("g251", g(251)),
        ("g252", g(252)),
    ]

    total = 0
    skipped_invalid = 0
    non_r = 0

    for form_name, form in forms:
        for arg_name, arg in echo_args:
            # token expression depends on bound vars: pair/e
            token_expr = form

            cases = [
                ("backdoor_then_echo", prog_backdoor_then_echo(arg, token_expr)),
                ("echo_then_backdoor", prog_echo_then_backdoor(arg, token_expr)),
            ]

            for order_name, term in cases:
                total += 1

                if not is_wire_valid(term):
                    skipped_invalid += 1
                    continue

                out = query_named(term, timeout_s=10.0)
                cls = classify(out)
                if cls != "R":
                    non_r += 1
                    print(
                        f"{order_name:18s} arg={arg_name:4s} form={form_name:22s}"
                        f" -> {cls:8s} len={len(out)} raw={out!r}"
                    )
                time.sleep(0.02)

    print(
        f"summary: total={total}, valid_tested={total - skipped_invalid},"
        f" invalid_skipped={skipped_invalid}, non_R={non_r}"
    )


if __name__ == "__main__":
    main()
