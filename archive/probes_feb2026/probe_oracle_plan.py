#!/usr/bin/env python3
"""
Oracle-guided probe: exploit echo-manufactured hidden globals (Var 253/254/255).

Strategy:
1. echo(251) -> Left(Var(253)), echo(252) -> Left(Var(254))
2. Try Var(253/254) AS syscalls (hidden globals)
3. Try 3-leaf combinations of special vars with syscall 8
4. Try special vars as capability tokens for syscall 8
5. Bracket with write markers to detect silent success
"""

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
    query_named,
    to_db,
    v,
    write_marker,
)
from solve_brownos_answer import FF, App, Lam, Var, encode_term, parse_term, QD


QD_TERM = NConst(parse_term(QD))


def run(name: str, term: object, timeout_s: float = 12.0) -> tuple[str, bytes]:
    out = query_named(term, timeout_s=timeout_s)
    cls = classify(out)
    print(f"  {name:50s} -> {cls:10s} raw={out!r}")
    return cls, out


def extract_echo(special_idx: int, var_name: str, tail_builder) -> object:
    """echo(special_idx) -> Left(var_name) -> tail_builder(v(var_name))"""
    return apps(
        g(14),
        g(special_idx),
        lam(
            "r",
            apps(
                v("r"),
                lam(var_name, tail_builder(v(var_name))),
                lam("_e", write_marker("E")),
            ),
        ),
    )


def extract_two_echo(
    idx1: int, name1: str, idx2: int, name2: str, tail_builder
) -> object:
    """echo(idx1)->name1, echo(idx2)->name2, then tail_builder(v(name1), v(name2))"""
    return extract_echo(
        idx1,
        name1,
        lambda v1: extract_echo(
            idx2,
            name2,
            lambda v2: tail_builder(v1, v2),
        ),
    )


def extract_backdoor(pair_name: str, tail_builder) -> object:
    """backdoor(nil) -> Left(pair_name) -> tail_builder(v(pair_name))"""
    return apps(
        g(201),
        NIL,
        lam(
            "br",
            apps(
                v("br"),
                lam(pair_name, tail_builder(v(pair_name))),
                lam("_be", write_marker("B")),
            ),
        ),
    )


def syscall_disc(syscall_num: int, arg, left_char="L", right_char="R") -> object:
    """((syscall arg) disc) where disc writes left_char or right_char"""
    disc = lam(
        "res",
        apps(
            v("res"),
            lam("_l", write_marker(left_char)),
            lam("_r", write_marker(right_char)),
        ),
    )
    return apps(g(syscall_num), arg, disc)


def syscall_qd(syscall_num: int, arg) -> object:
    """((syscall arg) QD) - print the result"""
    return apps(g(syscall_num), arg, QD_TERM)


def main() -> None:
    print("=" * 70)
    print("ORACLE-GUIDED PROBE: Hidden Globals via Echo")
    print("=" * 70)

    # ===== PHASE 1: Verify echo manufacturing =====
    print("\n[1] Verify echo(251)->Var(253), echo(252)->Var(254)")
    run("echo(251) -> QD", extract_echo(251, "e", lambda e: apps(QD_TERM, e)))
    run("echo(252) -> QD", extract_echo(252, "e", lambda e: apps(QD_TERM, e)))
    time.sleep(0.1)

    # ===== PHASE 2: Try Var(253/254) as hidden syscalls =====
    print("\n[2] Var(253) and Var(254) AS SYSCALLS (hidden globals)")
    for idx, name in [(251, "v253"), (252, "v254")]:
        # Try: ((v253 nil) QD)  - use it like a syscall
        run(
            f"(({name} nil) QD)",
            extract_echo(idx, "e", lambda e: apps(e, NIL, QD_TERM)),
        )
        time.sleep(0.05)

        # Try: ((v253 nil) disc) - with discriminator
        run(
            f"(({name} nil) disc)",
            extract_echo(
                idx,
                "e",
                lambda e: apps(
                    e,
                    NIL,
                    lam(
                        "res",
                        apps(
                            v("res"),
                            lam("_l", write_marker("L")),
                            lam("_r", write_marker("R")),
                        ),
                    ),
                ),
            ),
        )
        time.sleep(0.05)

        # Try just (v253 QD) - maybe it's a single-arg function
        run(
            f"({name} QD)",
            extract_echo(idx, "e", lambda e: apps(e, QD_TERM)),
        )
        time.sleep(0.05)

        # Try (v253 nil) with no continuation - detect side effects
        run(
            f"write('A') then ({name} nil) then write('Z')",
            extract_echo(
                idx,
                "e",
                lambda e: apps(
                    g(2),
                    NConst(
                        Lam(
                            Lam(
                                App(
                                    App(Var(1), Lam(*[Lam(Var(0))] * 0 or [Var(0)])),
                                    Var(0),
                                )
                            )
                        )
                    ),  # just a marker
                    lam("_", apps(e, NIL, lam("_r", write_marker("Z")))),
                ),
            ),
        )
        time.sleep(0.05)

    # ===== PHASE 3: Try both Var(253) AND Var(254) together =====
    print("\n[3] Both v253 and v254 together - 3-leaf combinations")

    # All 2-leaf apps of {v253, v254}
    combos_2leaf = [
        ("(v253 v254)", lambda v1, v2: apps(v1, v2)),
        ("(v254 v253)", lambda v1, v2: apps(v2, v1)),
        ("(v253 v253)", lambda v1, v2: apps(v1, v1)),
        ("(v254 v254)", lambda v1, v2: apps(v2, v2)),
    ]

    for name, builder in combos_2leaf:
        # Try each combo as syscall 8 arg
        run(
            f"sys8({name})",
            extract_two_echo(
                251,
                "e1",
                252,
                "e2",
                lambda v1, v2: syscall_disc(8, builder(v1, v2)),
            ),
        )
        time.sleep(0.05)

        # Also try feeding it to QD to see what it produces
        run(
            f"QD({name})",
            extract_two_echo(
                251,
                "e1",
                252,
                "e2",
                lambda v1, v2: apps(QD_TERM, builder(v1, v2)),
            ),
        )
        time.sleep(0.05)

    # 3-leaf combinations: ((a b) c) and (a (b c))
    print("\n[4] 3-leaf combinations of {v253, v254, nil}")
    leaves_map = {
        "v253": lambda v1, v2: v1,
        "v254": lambda v1, v2: v2,
        "nil": lambda v1, v2: NIL,
    }

    three_leaf_combos = []
    for a_name in ["v253", "v254", "nil"]:
        for b_name in ["v253", "v254", "nil"]:
            for c_name in ["v253", "v254", "nil"]:
                if a_name == "nil" and b_name == "nil" and c_name == "nil":
                    continue  # skip all-nil
                # left-assoc: ((a b) c)
                three_leaf_combos.append(
                    (f"(({a_name} {b_name}) {c_name})", a_name, b_name, c_name, "left")
                )
                # right-assoc: (a (b c))
                three_leaf_combos.append(
                    (f"({a_name} ({b_name} {c_name}))", a_name, b_name, c_name, "right")
                )

    for name, a_name, b_name, c_name, assoc in three_leaf_combos:

        def make_builder(an, bn, cn, asc):
            def builder(v1, v2):
                a = leaves_map[an](v1, v2)
                b = leaves_map[bn](v1, v2)
                c = leaves_map[cn](v1, v2)
                if asc == "left":
                    return apps(a, b, c)
                else:
                    return apps(a, apps(b, c))

            return builder

        bld = make_builder(a_name, b_name, c_name, assoc)

        # Feed to syscall 8
        run(
            f"sys8({name})",
            extract_two_echo(
                251,
                "e1",
                252,
                "e2",
                lambda v1, v2, b=bld: syscall_disc(8, b(v1, v2)),
            ),
        )
        time.sleep(0.03)

    # ===== PHASE 5: Echo-ladder values into syscall 8 =====
    print("\n[5] Echo-ladder y_n values into syscall 8")
    # backdoor(nil)->pair, echo(pair sel)->y1, try sys8(y1)

    sel = lam("a", lam("b", apps(v("a"), v("a"), v("a"))))  # ((a a) a) - 3-leaf

    for depth in range(1, 5):

        def build_chain(d, sel_term):
            """Build chain of depth d, returning y_d to syscall 8"""

            def go(level, pair_var_name):
                if level == d:
                    # At final depth: echo(pair sel)->y, syscall8(y)
                    return apps(
                        g(14),
                        apps(v(pair_var_name), sel_term),
                        lam(
                            f"ey{level}",
                            apps(
                                v(f"ey{level}"),
                                lam(f"y{level}", syscall_disc(8, v(f"y{level}"))),
                                lam(f"_ee{level}", write_marker("e")),
                            ),
                        ),
                    )
                else:
                    # Intermediate: echo(pair sel)->y, 201(y)->pair2, recurse
                    return apps(
                        g(14),
                        apps(v(pair_var_name), sel_term),
                        lam(
                            f"ey{level}",
                            apps(
                                v(f"ey{level}"),
                                lam(
                                    f"y{level}",
                                    apps(
                                        g(201),
                                        v(f"y{level}"),
                                        lam(
                                            f"r{level}",
                                            apps(
                                                v(f"r{level}"),
                                                lam(
                                                    f"p{level}",
                                                    go(level + 1, f"p{level}"),
                                                ),
                                                lam(f"_re{level}", write_marker("x")),
                                            ),
                                        ),
                                    ),
                                ),
                                lam(f"_ee{level}", write_marker("e")),
                            ),
                        ),
                    )

            return extract_backdoor("pair0", lambda p: go(1, "pair0"))

        term = build_chain(depth, sel)
        run(f"ladder depth={depth} -> sys8(y_{depth})", term, timeout_s=15.0)
        time.sleep(0.1)

    # ===== PHASE 6: Combine special vars with backdoor pair =====
    print("\n[6] Special vars combined with backdoor pair")

    # Get v253 via echo, get pair via backdoor, try various combos with syscall 8
    def echo_plus_backdoor(tail_builder) -> object:
        """echo(251)->v253, backdoor(nil)->pair, tail_builder(v253, pair)"""
        return extract_echo(
            251,
            "v253",
            lambda v253: extract_backdoor(
                "pair",
                lambda pair: tail_builder(v253, pair),
            ),
        )

    combos = [
        ("sys8(pair v253)", lambda v253, pair: syscall_disc(8, apps(pair, v253))),
        ("sys8(v253)", lambda v253, pair: syscall_disc(8, v253)),
        (
            "(v253 pair) -> sys8",
            lambda v253, pair: apps(v253, pair, lam("r", syscall_disc(8, v("r")))),
        ),
        (
            "((pair v253) sys8_disc)",
            lambda v253, pair: apps(pair, v253, lam("r", syscall_disc(8, v("r")))),
        ),
        # Try pair selector that extracts A, then (A v253)
        (
            "sys8((pair fst) v253)",
            lambda v253, pair: syscall_disc(
                8, apps(apps(pair, lam("a", lam("b", v("a")))), v253)
            ),
        ),
        # Try echo on (pair v253) first, then sys8
        (
            "echo(pair v253)->z, sys8(z)",
            lambda v253, pair: apps(
                g(14),
                apps(pair, v253),
                lam(
                    "er",
                    apps(
                        v("er"),
                        lam("z", syscall_disc(8, v("z"))),
                        lam("_ee", write_marker("e")),
                    ),
                ),
            ),
        ),
    ]

    for name, builder in combos:
        run(name, echo_plus_backdoor(builder))
        time.sleep(0.05)

    # ===== PHASE 7: Try v253 as first arg to syscall 8, nil as second =====
    print("\n[7] v253/v254 as capability token for sys8 (2-arg hypothesis)")

    for idx, vname in [(251, "v253"), (252, "v254")]:
        # ((sys8 v253) nil disc)  -- v253 as arg, nil as extra
        run(
            f"((sys8 {vname}) nil disc)",
            extract_echo(idx, "e", lambda e: apps(apps(g(8), e), NIL, DISC8)),
        )
        time.sleep(0.05)

        # ((sys8 nil) v253 disc) -- nil as arg, v253 as extra/continuation
        run(
            f"((sys8 nil) {vname} disc)",
            extract_echo(idx, "e", lambda e: apps(apps(g(8), NIL), e, DISC8)),
        )
        time.sleep(0.05)

        # (sys8 v253 disc) -- standard CPS
        run(
            f"(sys8 {vname} disc)",
            extract_echo(idx, "e", lambda e: syscall_disc(8, e)),
        )
        time.sleep(0.05)

    # ===== PHASE 8: Try manufacturing Var(255) via double echo =====
    print("\n[8] Attempt to manufacture Var(255) via echo chains")

    # echo(253) should give Left(Var(255)) if pattern holds
    # But Var(253) can't be directly encoded! We need echo-manufactured v253
    # echo(v253) where v253 came from echo(251)
    run(
        "echo(echo(251)) -> v255?",
        extract_echo(
            251,
            "v253",
            lambda v253: apps(
                g(14),
                v253,
                lam(
                    "r2",
                    apps(
                        v("r2"),
                        lam("v255", apps(QD_TERM, v("v255"))),
                        lam("_e2", write_marker("E")),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.1)

    # If v255 exists, try 3-leaf combos with all three
    run(
        "echo(v253)->v255, sys8(v255)",
        extract_echo(
            251,
            "v253",
            lambda v253: apps(
                g(14),
                v253,
                lam(
                    "r2",
                    apps(
                        v("r2"),
                        lam("v255", syscall_disc(8, v("v255"))),
                        lam("_e2", write_marker("E")),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.1)

    # Try all three: v253, v254, v255
    def extract_three(tail_builder) -> object:
        """Get v253 (echo 251), v254 (echo 252), v255 (echo v253), then tail"""
        return extract_echo(
            251,
            "v253",
            lambda v253: extract_echo(
                252,
                "v254",
                lambda v254: apps(
                    g(14),
                    v253,  # echo(v253) to get v255
                    lam(
                        "r3",
                        apps(
                            v("r3"),
                            lam("v255", tail_builder(v253, v254, v("v255"))),
                            lam("_e3", write_marker("3")),
                        ),
                    ),
                ),
            ),
        )

    three_combos = [
        ("((v253 v254) v255)", lambda a, b, c: apps(a, b, c)),
        ("((v253 v255) v254)", lambda a, b, c: apps(a, c, b)),
        ("((v254 v253) v255)", lambda a, b, c: apps(b, a, c)),
        ("((v254 v255) v253)", lambda a, b, c: apps(b, c, a)),
        ("((v255 v253) v254)", lambda a, b, c: apps(c, a, b)),
        ("((v255 v254) v253)", lambda a, b, c: apps(c, b, a)),
        ("(v253 (v254 v255))", lambda a, b, c: apps(a, apps(b, c))),
        ("(v254 (v253 v255))", lambda a, b, c: apps(b, apps(a, c))),
        ("(v255 (v253 v254))", lambda a, b, c: apps(c, apps(a, b))),
    ]

    print("\n[9] 3-leaf combos of v253/v254/v255 -> sys8")
    for name, builder in three_combos:
        run(
            f"sys8({name})",
            extract_three(lambda a, b, c, bld=builder: syscall_disc(8, bld(a, b, c))),
        )
        time.sleep(0.05)

    # Also try them directly (not through syscall 8) - they might BE the answer
    print("\n[10] 3-leaf combos as direct terms (hidden syscall?)")
    for name, builder in three_combos[:3]:
        run(
            f"({name} nil QD) as syscall",
            extract_three(
                lambda a, b, c, bld=builder: apps(bld(a, b, c), NIL, QD_TERM)
            ),
        )
        time.sleep(0.05)

    print("\n" + "=" * 70)
    print("PROBE COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
