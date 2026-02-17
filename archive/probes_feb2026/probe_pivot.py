#!/usr/bin/env python3
"""
Pivot probe: new attack vectors after Oracle plan findings.

Key insight: echo-extracted values are just Var(251/252) after beta-reduction.
Applying free vars to each other creates stuck terms -> "Invalid term!".

New strategies:
1. Global variable references as syscall 8 arguments (Var(201), Var(14), etc.)
2. Password strings as syscall 8 arguments
3. LIVE backdoor pair from actual 201 call (not reconstructed) as sys8 arg
4. Systematic scan of global indices 0-252 as sys8 arg
5. Using echo's output as continuation (not argument) for sys8
6. Different echo seeds fed to sys8
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
    v,
    write_marker,
)
from solve_brownos_answer import (
    FF,
    Lam,
    Var,
    App,
    encode_bytes_list,
    encode_byte_term,
    encode_term,
    parse_term,
    QD,
)


QD_TERM = NConst(parse_term(QD))


def run(name: str, term: object, timeout_s: float = 12.0) -> tuple[str, bytes]:
    out = query_named(term, timeout_s=timeout_s)
    cls = classify(out)
    print(f"  {name:55s} -> {cls:10s} raw={out[:30]!r}")
    return cls, out


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


def extract_echo(seed, var_name: str, tail_builder) -> object:
    """echo(seed) -> Left(var_name) -> tail_builder(v(var_name))"""
    return apps(
        g(14),
        seed,
        lam(
            "r",
            apps(
                v("r"),
                lam(var_name, tail_builder(v(var_name))),
                lam("_e", write_marker("E")),
            ),
        ),
    )


def syscall_disc(syscall_num, arg, left_char="L", right_char="R") -> object:
    disc = lam(
        "res",
        apps(
            v("res"),
            lam("_l", write_marker(left_char)),
            lam("_r", write_marker(right_char)),
        ),
    )
    if isinstance(syscall_num, int):
        return apps(g(syscall_num), arg, disc)
    else:
        return apps(syscall_num, arg, disc)


def syscall_qd(syscall_num: int, arg) -> object:
    return apps(g(syscall_num), arg, QD_TERM)


def main() -> None:
    print("=" * 70)
    print("PIVOT PROBE: New Attack Vectors")
    print("=" * 70)

    # ===== PHASE 1: Syscall REFERENCES as arguments =====
    print("\n[1] Global variable references as sys8 argument")
    # "3 leaves" = ((Var(8) Var(X)) Var(Y))
    # Try X = various syscall numbers, Y = QD/disc
    interesting_globals = [
        (0, "error(0)"),
        (1, "sys1"),
        (2, "write"),
        (4, "quote"),
        (5, "readdir"),
        (6, "name"),
        (7, "readfile"),
        (8, "sys8_itself"),
        (14, "echo"),
        (42, "towel"),
        (201, "backdoor"),
    ]

    for idx, desc in interesting_globals:
        run(f"sys8(Var({idx})={desc}) + QD", syscall_qd(8, g(idx)))
        time.sleep(0.05)

    # ===== PHASE 2: Password / string arguments =====
    print("\n[2] Password strings as sys8 argument")
    passwords = [
        "ilikephp",
        "dloser",
        "gizmore",
        "backdoor",
        "BrownOS",
        "root",
        "admin",
        "solution",
    ]
    for pw in passwords:
        pw_term = NConst(encode_bytes_list(pw.encode()))
        run(f"sys8('{pw}')", syscall_disc(8, pw_term))
        time.sleep(0.05)

    # ===== PHASE 3: LIVE backdoor pair as sys8 argument =====
    print("\n[3] Live backdoor pair (from actual 201 call) as sys8 arg")

    # Chain: 201(nil) -> Left(pair) -> sys8(pair) + disc
    run(
        "201(nil)->pair, sys8(pair) disc",
        extract_backdoor("pair", lambda pair: syscall_disc(8, pair)),
    )

    # Also try: 201(nil)->pair, sys8(pair) QD
    run(
        "201(nil)->pair, sys8(pair) QD",
        extract_backdoor("pair", lambda pair: syscall_qd(8, pair)),
    )

    # Try: pair applied to sys8 = ((sys8 A) B)
    # pair = λf. f A B, so (pair sys8) = sys8 A B = ((sys8 A) B)
    # where A and B are LIVE from backdoor, not reconstructed
    run(
        "201(nil)->pair, (pair sys8) = ((sys8 A_live) B_live)",
        extract_backdoor("pair", lambda pair: apps(pair, g(8))),
    )

    # pair applied to sys8 with QD: ((pair sys8) QD)
    run(
        "201(nil)->pair, ((pair sys8) QD)",
        extract_backdoor("pair", lambda pair: apps(pair, g(8), QD_TERM)),
    )
    time.sleep(0.1)

    # ===== PHASE 4: Live pair selectors fed to sys8 =====
    print("\n[4] Extract A_live, B_live from pair, use with sys8")

    # fst_sel = λa.λb.a (select A from pair)
    fst_sel = lam("a", lam("b", v("a")))
    # snd_sel = λa.λb.b (select B from pair)
    snd_sel = lam("a", lam("b", v("b")))

    run(
        "201->pair, sys8(pair fst) = sys8(A_live)",
        extract_backdoor("pair", lambda pair: syscall_disc(8, apps(pair, fst_sel))),
    )

    run(
        "201->pair, sys8(pair snd) = sys8(B_live)",
        extract_backdoor("pair", lambda pair: syscall_disc(8, apps(pair, snd_sel))),
    )

    # Try using echo on the pair BEFORE passing to sys8
    run(
        "201->pair, echo(pair)->y, sys8(y)",
        extract_backdoor(
            "pair",
            lambda pair: extract_echo(pair, "y", lambda y: syscall_disc(8, y)),
        ),
    )

    # Echo the pair with selector applied, THEN feed to sys8
    run(
        "201->pair, echo(pair fst)->y, sys8(y)",
        extract_backdoor(
            "pair",
            lambda pair: extract_echo(
                apps(pair, fst_sel),
                "y",
                lambda y: syscall_disc(8, y),
            ),
        ),
    )

    run(
        "201->pair, echo(pair snd)->y, sys8(y)",
        extract_backdoor(
            "pair",
            lambda pair: extract_echo(
                apps(pair, snd_sel),
                "y",
                lambda y: syscall_disc(8, y),
            ),
        ),
    )
    time.sleep(0.1)

    # ===== PHASE 5: Echo various seeds, then feed to sys8 =====
    print("\n[5] Echo various seeds -> sys8")

    seeds = [
        ("nil", NIL),
        ("identity", lam("x", v("x"))),
        ("K", lam("x", lam("y", v("x")))),
        ("omega", lam("x", apps(v("x"), v("x")))),
        ("((nil nil) nil)", apps(NIL, NIL, NIL)),
        ("sys8_ref", g(8)),
        ("backdoor_ref", g(201)),
        ("echo_ref", g(14)),
    ]

    for seed_name, seed in seeds:
        run(
            f"echo({seed_name})->y, sys8(y)",
            extract_echo(seed, "y", lambda y: syscall_disc(8, y)),
        )
        time.sleep(0.05)

    # ===== PHASE 6: Use echo output as CONTINUATION for sys8 =====
    print("\n[6] Echo output as continuation for sys8")
    # What if echo manufactures a special continuation?
    for seed_name, seed in seeds[:5]:
        run(
            f"echo({seed_name})->y, ((sys8 nil) y)",
            extract_echo(seed, "y", lambda y: apps(g(8), NIL, y)),
        )
        time.sleep(0.05)

    # ===== PHASE 7: Backdoor pair as CONTINUATION for sys8 =====
    print("\n[7] Live backdoor pair as continuation for sys8")
    run(
        "201->pair, ((sys8 nil) pair)",
        extract_backdoor("pair", lambda pair: apps(g(8), NIL, pair)),
    )

    run(
        "201->pair, ((sys8 nil) (pair fst)) = ((sys8 nil) A_live)",
        extract_backdoor("pair", lambda pair: apps(g(8), NIL, apps(pair, fst_sel))),
    )

    run(
        "201->pair, ((sys8 nil) (pair snd)) = ((sys8 nil) B_live)",
        extract_backdoor("pair", lambda pair: apps(g(8), NIL, apps(pair, snd_sel))),
    )
    time.sleep(0.1)

    # ===== PHASE 8: Echo-ladder with sys8 as action at each depth =====
    print("\n[8] Scan global indices 0-20, 42, 100-110, 200-210 as sys8 arg")
    scan_indices = (
        list(range(21)) + [42] + list(range(100, 111)) + list(range(200, 211))
    )
    for idx in scan_indices:
        cls, _ = run(f"sys8(Var({idx}))", syscall_disc(8, g(idx)), timeout_s=5.0)
        if cls not in ("R", "silent"):
            print(f"    *** INTERESTING: idx={idx} gave {cls} ***")
        time.sleep(0.02)

    # ===== PHASE 9: Try file IDs as byte terms to sys8 =====
    print("\n[9] File IDs (byte terms) as sys8 argument")
    important_file_ids = [0, 1, 8, 11, 14, 15, 16, 46, 65, 88, 201, 255]
    for fid in important_file_ids:
        fid_term = NConst(encode_byte_term(fid))
        run(f"sys8(byte_term({fid}))", syscall_disc(8, fid_term))
        time.sleep(0.05)

    # ===== PHASE 10: Double-echo chain to sys8 =====
    print("\n[10] Double/triple echo chains -> sys8")
    # echo(echo(nil))->y, sys8(y)
    run(
        "echo(nil)->y1, echo(y1)->y2, sys8(y2)",
        extract_echo(
            NIL,
            "y1",
            lambda y1: extract_echo(
                y1,
                "y2",
                lambda y2: syscall_disc(8, y2),
            ),
        ),
    )

    # echo(((nil nil) nil))->y1, echo(y1)->y2, sys8(y2)
    seed3 = apps(NIL, NIL, NIL)
    run(
        "echo(((nil nil)nil))->y1, echo(y1)->y2, sys8(y2)",
        extract_echo(
            seed3,
            "y1",
            lambda y1: extract_echo(
                y1,
                "y2",
                lambda y2: syscall_disc(8, y2),
            ),
        ),
    )

    # Triple echo
    run(
        "echo^3(((nil nil)nil))->y3, sys8(y3)",
        extract_echo(
            seed3,
            "y1",
            lambda y1: extract_echo(
                y1,
                "y2",
                lambda y2: extract_echo(
                    y2,
                    "y3",
                    lambda y3: syscall_disc(8, y3),
                ),
            ),
        ),
    )

    # ===== PHASE 11: The "freeze" hint - apply echo to special combos =====
    print("\n[11] 'Freeze' hint: echo on special byte combos")
    # Author: "combining the special bytes... froze my whole system!"
    # echo(Var(251)) works. What about echo on App/Lam-like values?
    # Try echo on values near 253
    for idx in [250, 251, 252]:
        run(
            f"echo(Var({idx}))->y, sys8(y)",
            extract_echo(g(idx), "y", lambda y: syscall_disc(8, y)),
        )
        time.sleep(0.05)

    # What if we apply echo to the ECHO syscall itself?
    # echo(echo) where echo=Var(14)
    run(
        "echo(echo)->y, sys8(y)",
        extract_echo(g(14), "y", lambda y: syscall_disc(8, y)),
    )

    # echo(sys8)
    run(
        "echo(sys8)->y, sys8(y)",
        extract_echo(g(8), "y", lambda y: syscall_disc(8, y)),
    )

    print("\n" + "=" * 70)
    print("PIVOT PROBE COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
