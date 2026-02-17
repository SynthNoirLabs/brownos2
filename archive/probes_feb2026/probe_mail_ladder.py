#!/usr/bin/env python3
from __future__ import annotations

import time

from probe_mail_focus import (
    DISC8,
    NIL,
    NConst,
    apps,
    classify,
    g,
    lam,
    make_3leaf_selectors,
    query_named,
    v,
    write_marker,
)
from solve_brownos_answer import QD, parse_term


QD_TERM = NConst(parse_term(QD))


def fst_sel() -> object:
    return lam("a", lam("b", v("a")))


def selector_fixed() -> object:
    # One of the accepted 3-leaf selectors from stage2.
    return make_3leaf_selectors()[0][1]  # left:((va va) va)


def build_chain(depth: int, final_builder) -> object:
    sel = selector_fixed()

    def go(level: int, arg_term: object) -> object:
        res = f"res{level}"
        eres = f"eres{level}"
        yname = f"y{level}"
        err_e = f"ee{level}"

        if level == depth:
            done = final_builder(v(yname), arg_term)
        else:
            done = apps(
                g(201),
                v(yname),
                lam(
                    f"rnext{level}",
                    apps(
                        v(f"rnext{level}"),
                        lam(f"pnext{level}", go(level + 1, v(f"pnext{level}"))),
                        lam(f"enext{level}", write_marker("x")),
                    ),
                ),
            )

        return apps(
            g(14),
            apps(arg_term, sel),
            lam(
                eres,
                apps(
                    v(eres),
                    lam(yname, done),
                    lam(err_e, write_marker("e")),
                ),
            ),
        )

    start = apps(
        g(201),
        NIL,
        lam(
            "res0",
            apps(
                v("res0"),
                lam("pair0", go(1, v("pair0"))),
                lam("er0", write_marker("E")),
            ),
        ),
    )
    return start


def run(name: str, term: object, timeout_s: float = 12.0) -> tuple[str, bytes]:
    out = query_named(term, timeout_s=timeout_s)
    return classify(out), out


def main() -> None:
    print("=== Mail Ladder Probe (fixed 3-leaf selector) ===")

    def quote_y(y: object, _pair: object) -> object:
        return apps(QD_TERM, y)

    def test_201_y(y: object, _pair: object) -> object:
        return apps(
            g(201),
            y,
            lam(
                "r",
                apps(
                    v("r"),
                    lam("_ok", write_marker("L")),
                    lam("_err", write_marker("R")),
                ),
            ),
        )

    def test_8_y(y: object, _pair: object) -> object:
        return apps(g(8), y, DISC8)

    def test_8_y_cont(y: object, _pair: object) -> object:
        return apps(apps(g(8), NIL), y, DISC8)

    def test_8_pairfst(pair: object, _unused: object) -> object:
        return apps(g(8), apps(pair, fst_sel(), NIL), DISC8)

    actions = [
        ("quote_y", quote_y),
        ("201_y", test_201_y),
        ("8_y", test_8_y),
        ("8_nil_cont_y_disc", test_8_y_cont),
        ("8_pairfst", lambda y, pair: test_8_pairfst(pair, y)),
    ]

    for depth in range(1, 8):
        print(f"\n[depth={depth}]")
        for action_name, action in actions:
            term = build_chain(depth, action)
            cls, out = run(action_name, term)
            raw = out.hex() if action_name == "quote_y" else repr(out)
            print(f"{action_name:20s} -> {cls:8s} raw={raw}")
            time.sleep(0.04)


if __name__ == "__main__":
    main()
