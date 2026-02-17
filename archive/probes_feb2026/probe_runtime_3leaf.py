#!/usr/bin/env python3
"""
3-leaf arguments to sys8 built from RUNTIME values (not just global refs).

Key insight: previous 3-leaf tests used only raw global Var indices.
This probe binds actual values from backdoor(201) and echo(251/252)
as local variables, then builds 3-leaf combinations from them.

Alphabet: {A_live, B_live, v253, v254, nil}
Shapes: ((x y) z) and (x (y z))
All fed to sys8 with proper Left/Right discrimination + error string extraction.
"""

from __future__ import annotations

import time
from itertools import product

from probe_mail_focus import (
    DISC8,
    NIL,
    NConst,
    apps,
    classify,
    g,
    lam,
    query_named,
    v,
    write_marker,
    int_term,
    app,
)
from solve_brownos_answer import (
    encode_bytes_list,
    encode_term,
    parse_term,
    QD,
    decode_bytes_list,
    decode_either,
)


QD_TERM = NConst(parse_term(QD))


def run(name: str, term: object, timeout_s: float = 12.0) -> tuple[str, bytes]:
    out = query_named(term, timeout_s=timeout_s)
    cls = classify(out)
    tag = "***" if cls not in ("R", "silent", "encfail", "invalid") else "   "
    print(f"  {tag} {name:60s} -> {cls:10s} raw={out[:50]!r}")
    if cls not in ("R", "silent", "encfail", "invalid", "E", "B"):
        print(f"      INTERESTING: full output = {out!r}")
    return cls, out


def write_str(s: str) -> object:
    return apps(g(2), NConst(encode_bytes_list(s.encode())), NIL)


def sys8_full_disc(arg: object) -> object:
    """sys8(arg) with full discrimination: Left -> write payload via quote, Right -> error string via sys1."""
    return apps(
        g(8),
        arg,
        lam(
            "res",
            apps(
                v("res"),
                lam(
                    "payload",
                    # Left: write "L:" then quote the payload
                    apps(
                        g(2),
                        NConst(encode_bytes_list(b"L:")),
                        lam(
                            "_w",
                            apps(
                                g(4),
                                v("payload"),
                                lam(
                                    "qr",
                                    apps(
                                        v("qr"),
                                        lam("qbytes", apps(g(2), v("qbytes"), NIL)),
                                        lam("qerr", write_str("Q?")),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
                lam(
                    "errcode",
                    # Right: write "R:" then error string
                    apps(
                        g(2),
                        NConst(encode_bytes_list(b"R:")),
                        lam(
                            "_w",
                            apps(
                                g(1),
                                v("errcode"),
                                lam(
                                    "sr",
                                    apps(
                                        v("sr"),
                                        lam("strbytes", apps(g(2), v("strbytes"), NIL)),
                                        lam("_se", write_str("??")),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )


def build_3leaf_probe(
    leaves_dict: dict,
    assoc: str,
    a: str,
    b: str,
    c: str,  # type: ignore
) -> object:
    """Build a 3-leaf term from named leaves."""
    la = leaves_dict[a]
    lb = leaves_dict[b]
    lc = leaves_dict[c]
    if assoc == "left":
        return apps(la, lb, lc)  # ((a b) c)
    else:
        return app(la, apps(lb, lc))  # (a (b c))


def main():
    print("=" * 70)
    print("RUNTIME 3-LEAF PROBE: sys8 with live backdoor + echo values")
    print("=" * 70)

    # ============================================================
    # Setup: extract runtime values into a big nested lambda
    # ============================================================

    # We need: A_live, B_live from backdoor, v253 from echo(251), v254 from echo(252)
    # Then build all 3-leaf combos and test each with sys8.

    # Since we can't easily loop in lambda calculus, we'll generate
    # specific named terms for the most promising combos.

    fst_sel = lam("a", lam("b", v("a")))
    snd_sel = lam("a", lam("b", v("b")))

    # Helper: extract A and B from live pair
    def extract_A_B(tail_builder):
        """backdoor(nil)->pair, A=pair(fst), B=pair(snd), tail_builder(A, B)"""
        return apps(
            g(201),
            NIL,
            lam(
                "br",
                apps(
                    v("br"),
                    lam(
                        "pair",
                        tail_builder(
                            apps(v("pair"), fst_sel),
                            apps(v("pair"), snd_sel),
                        ),
                    ),
                    lam("_be", write_str("BD_ERR")),
                ),
            ),
        )

    def extract_echo_val(idx: int, name: str, tail_builder):
        """echo(Var(idx))->Left(val), extract val, tail_builder(val)"""
        return apps(
            g(14),
            g(idx),
            lam(
                "er",
                apps(
                    v("er"),
                    lam(name, tail_builder(v(name))),
                    lam("_ee", write_str("ECHO_ERR")),
                ),
            ),
        )

    # ============================================================
    # Phase 1: Simple combinations with A, B, nil
    # ============================================================
    print("\n[1] 3-leaf combos of {A_live, B_live, nil} -> sys8")

    leaf_names_1 = ["A", "B", "nil"]
    combos_1 = list(product(leaf_names_1, repeat=3))

    for a_n, b_n, c_n in combos_1:
        for assoc in ("left", "right"):
            combo_name = (
                f"{'L' if assoc == 'left' else 'R'}:(({a_n} {b_n}) {c_n})"
                if assoc == "left"
                else f"R:({a_n} ({b_n} {c_n}))"
            )

            def make_term(an=a_n, bn=b_n, cn=c_n, asc=assoc):
                def inner(A, B):
                    leaves = {"A": A, "B": B, "nil": NIL}
                    combo = build_3leaf_probe(leaves, asc, an, bn, cn)
                    return sys8_full_disc(combo)

                return extract_A_B(inner)

            run(combo_name, make_term())
            time.sleep(0.03)

    # ============================================================
    # Phase 2: Combinations with v253, v254
    # ============================================================
    print("\n[2] 3-leaf combos including v253/v254 -> sys8")

    # Generate all combos of {v253, v254, nil} that include at least one vN
    leaf_names_2 = ["v253", "v254", "nil"]
    combos_2 = [
        (a, b, c)
        for a, b, c in product(leaf_names_2, repeat=3)
        if "v253" in (a, b, c) or "v254" in (a, b, c)
    ]

    for a_n, b_n, c_n in combos_2:
        for assoc in ("left",):  # Just left-assoc to save requests
            combo_name = f"(({a_n} {b_n}) {c_n})"

            def make_term(an=a_n, bn=b_n, cn=c_n, asc=assoc):
                def inner_echo2(e1, e2):
                    leaves = {"v253": e1, "v254": e2, "nil": NIL}
                    combo = build_3leaf_probe(leaves, asc, an, bn, cn)
                    return sys8_full_disc(combo)

                def inner_echo1(e1):
                    return extract_echo_val(252, "e2", lambda e2: inner_echo2(e1, e2))

                return extract_echo_val(251, "e1", inner_echo1)

            run(combo_name, make_term())
            time.sleep(0.03)

    # ============================================================
    # Phase 3: Mixed: {A_live, B_live, v253, v254}
    # ============================================================
    print("\n[3] Mixed: {A, B, v253, v254} -> sys8 (selected combos)")

    mixed_combos = [
        ("A", "v253", "B"),
        ("A", "v254", "B"),
        ("B", "v253", "A"),
        ("B", "v254", "A"),
        ("v253", "A", "B"),
        ("v253", "B", "A"),
        ("v254", "A", "B"),
        ("v254", "B", "A"),
        ("A", "B", "v253"),
        ("A", "B", "v254"),
        ("B", "A", "v253"),
        ("B", "A", "v254"),
        ("v253", "v254", "A"),
        ("v253", "v254", "B"),
        ("v254", "v253", "A"),
        ("v254", "v253", "B"),
        ("A", "v253", "v254"),
        ("B", "v253", "v254"),
    ]

    for a_n, b_n, c_n in mixed_combos:
        combo_name = f"(({a_n} {b_n}) {c_n})"

        def make_term(an=a_n, bn=b_n, cn=c_n):
            def inner(A, B):
                def with_echo(e1, e2):
                    leaves = {"A": A, "B": B, "v253": e1, "v254": e2, "nil": NIL}
                    combo = build_3leaf_probe(leaves, "left", an, bn, cn)
                    return sys8_full_disc(combo)

                return extract_echo_val(
                    251,
                    "e1",
                    lambda e1: extract_echo_val(
                        252, "e2", lambda e2: with_echo(e1, e2)
                    ),
                )

            return extract_A_B(inner)

        run(combo_name, make_term())
        time.sleep(0.03)

    # ============================================================
    # Phase 4: The "freeze" hint — omega-like terms as args
    # ============================================================
    print("\n[4] Omega-like terms from live components -> sys8")

    # (A B) = omega = λx.(x x)
    # (B A) = ?
    # ((A B) (A B)) = omega omega = diverges! Skip.
    # Just (A B) and (B A) as 2-leaf args:
    run(
        "sys8((A B)) = sys8(omega_live)",
        extract_A_B(lambda A, B: sys8_full_disc(apps(A, B))),
    )
    time.sleep(0.05)

    run(
        "sys8((B A))",
        extract_A_B(lambda A, B: sys8_full_disc(apps(B, A))),
    )
    time.sleep(0.05)

    # What about (A v253)?
    run(
        "sys8((A v253))",
        extract_A_B(
            lambda A, B: extract_echo_val(
                251, "e", lambda e: sys8_full_disc(apps(A, e))
            )
        ),
    )
    time.sleep(0.05)

    run(
        "sys8((B v253))",
        extract_A_B(
            lambda A, B: extract_echo_val(
                251, "e", lambda e: sys8_full_disc(apps(B, e))
            )
        ),
    )
    time.sleep(0.05)

    print("\n" + "=" * 70)
    print("RUNTIME 3-LEAF PROBE COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
