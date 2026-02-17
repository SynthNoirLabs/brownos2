#!/usr/bin/env python3
from __future__ import annotations

from itertools import product
from typing import Iterable

from probe_mail_focus import (
    DISC8,
    NIL,
    app,
    apps,
    classify,
    g,
    lam,
    make_3leaf_selectors,
    query_named,
    v,
    write_marker,
)


def run(name: str, term: object) -> tuple[str, bytes]:
    out = query_named(term, timeout_s=10.0)
    return classify(out), out


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def semantic_nil_selectors() -> Iterable[tuple[str, object]]:
    # Selectors where pair(selector) is semantically nil-ish but not canonical.
    yield "const_I", lam("a", lam("b", lam("x", v("x"))))
    yield "eta_I", lam("a", lam("b", lam("x", apps(lam("y", v("y")), v("x")))))
    yield "beta_I", lam("a", lam("b", apps(lam("z", lam("x", v("x"))), v("a"))))


def prog_201_direct(sel: object) -> object:
    # 201(nil)->pair ; 201(pair sel)
    return apps(
        g(201),
        NIL,
        lam(
            "res1",
            apps(
                v("res1"),
                lam(
                    "pair",
                    apps(
                        g(201),
                        apps(v("pair"), sel),
                        lam("r2", apps(v("r2"), lam("_", write_marker("L")), lam("_", write_marker("R")))),
                    ),
                ),
                lam("_e1", write_marker("E")),
            ),
        ),
    )


def prog_201_via_echo(sel: object) -> object:
    # 201(nil)->pair ; x=pair sel ; echo(x)->y ; 201(y)
    return apps(
        g(201),
        NIL,
        lam(
            "res1",
            apps(
                v("res1"),
                lam(
                    "pair",
                    apps(
                        g(14),
                        apps(v("pair"), sel),
                        lam(
                            "res2",
                            apps(
                                v("res2"),
                                lam(
                                    "y",
                                    apps(
                                        g(201),
                                        v("y"),
                                        lam(
                                            "r3",
                                            apps(v("r3"), lam("_", write_marker("L")), lam("_", write_marker("R"))),
                                        ),
                                    ),
                                ),
                                lam("_e2", write_marker("e")),
                            ),
                        ),
                    ),
                ),
                lam("_e1", write_marker("E")),
            ),
        ),
    )


def prog_3leaf_via_echo_to_8(sel: object) -> object:
    # 201(nil)->pair ; x=pair(sel3leaf) ; echo(x)->y ; 201(y)->ok ; 8(nil)
    return apps(
        g(201),
        NIL,
        lam(
            "res1",
            apps(
                v("res1"),
                lam(
                    "pair",
                    apps(
                        g(14),
                        apps(v("pair"), sel),
                        lam(
                            "res2",
                            apps(
                                v("res2"),
                                lam(
                                    "y",
                                    apps(
                                        g(201),
                                        v("y"),
                                        lam(
                                            "r3",
                                            apps(
                                                v("r3"),
                                                lam("_ok", apps(g(8), NIL, DISC8)),
                                                lam("_err", write_marker("r")),
                                            ),
                                        ),
                                    ),
                                ),
                                lam("_e2", write_marker("e")),
                            ),
                        ),
                    ),
                ),
                lam("_e1", write_marker("E")),
            ),
        ),
    )


def make_3leaf_pair_e_forms() -> list[tuple[str, object]]:
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


def prog_echo_special_backdoor_3leaf(arg: int, expr: object, to_sys8: bool) -> object:
    # echo(arg)->e ; 201(nil)->pair ; x=expr(pair,e) ; echo(x)->y ; 201(y)
    success_tail = apps(g(8), NIL, DISC8) if to_sys8 else write_marker("L")
    return apps(
        g(14),
        g(arg),
        lam(
            "res0",
            apps(
                v("res0"),
                lam(
                    "e",
                    apps(
                        g(201),
                        NIL,
                        lam(
                            "res1",
                            apps(
                                v("res1"),
                                lam(
                                    "pair",
                                    apps(
                                        g(14),
                                        expr,
                                        lam(
                                            "res2",
                                            apps(
                                                v("res2"),
                                                lam(
                                                    "y",
                                                    apps(
                                                        g(201),
                                                        v("y"),
                                                        lam(
                                                            "r3",
                                                            apps(
                                                                v("r3"),
                                                                lam("_ok", success_tail),
                                                                lam("_err", write_marker("R")),
                                                            ),
                                                        ),
                                                    ),
                                                ),
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
    section("Semantic Nil via Echo")
    for name, sel in semantic_nil_selectors():
        c_direct, out_direct = run("direct", prog_201_direct(sel))
        c_echo, out_echo = run("via_echo", prog_201_via_echo(sel))
        print(
            f"{name:8s} direct={c_direct:5s} raw={out_direct!r} "
            f"via_echo={c_echo:5s} raw={out_echo!r}"
        )

    section("3-Leaf over A/B")
    accepted = 0
    for name, sel in make_3leaf_selectors():
        c, out = run(name, prog_201_via_echo(sel))
        if c == "L":
            accepted += 1
        print(f"{name:24s} -> {c:5s} raw={out!r}")
    print(f"accepted via echo: {accepted}/{len(make_3leaf_selectors())}")

    section("3-Leaf A/B -> syscall8")
    for name, sel in make_3leaf_selectors():
        c, out = run(name, prog_3leaf_via_echo_to_8(sel))
        print(f"{name:24s} -> {c:8s} raw={out!r}")

    section("Echo(Special) + Backdoor + 3-Leaf(pair,e)")
    forms = make_3leaf_pair_e_forms()
    for arg in (251, 252):
        print(f"\narg={arg}")
        direct_l = 0
        to8_non_r = 0
        for name, expr in forms:
            c_direct, _ = run(name, prog_echo_special_backdoor_3leaf(arg, expr, to_sys8=False))
            c_to8, _ = run(name, prog_echo_special_backdoor_3leaf(arg, expr, to_sys8=True))
            if c_direct == "L":
                direct_l += 1
            if c_to8 != "R":
                to8_non_r += 1
            print(f"{name:22s} direct={c_direct:5s} to8={c_to8:5s}")
        print(f"summary arg={arg}: direct_L={direct_l}/{len(forms)}, to8_non_R={to8_non_r}")


if __name__ == "__main__":
    main()
