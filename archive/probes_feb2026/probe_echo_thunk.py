#!/usr/bin/env python3
"""
CRITICAL: Echo preserves unevaluated expressions (thunks)!

echo(((write 'X') nil)) returns Left(((write 'X') nil)) WITHOUT executing the write.
echo(((sys8 nil) id)) returns Left(((sys8 nil) id)) WITHOUT executing sys8.

This means echo can capture terms containing syscall references and
pass them to other syscalls as data.

NEW HYPOTHESIS: sys8 checks its argument for the presence of specific
sub-structures (like a Var(8) reference, or a backdoor call, or echo).
Echo is the only way to CREATE such arguments because normal evaluation
would execute the syscalls before sys8 sees them.

The "3 leafs" hint might mean: the CAPTURED thunk has 3 leaf nodes.
"""

from __future__ import annotations

import socket
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
    int_term,
    app,
)
from solve_brownos_answer import (
    App,
    Lam,
    Var,
    encode_bytes_list,
    encode_byte_term,
    encode_term,
    parse_term,
    QD,
    FF,
)


def write_str(s: str) -> object:
    return apps(g(2), NConst(encode_bytes_list(s.encode())), NIL)


def run(name: str, term: object, timeout_s: float = 15.0) -> tuple[str, bytes]:
    out = query_named(term, timeout_s=timeout_s)
    cls = classify(out)
    tag = "***" if cls not in ("R", "silent", "encfail", "invalid") else "   "
    print(f"  {tag} {name:65s} -> {cls:10s} len={len(out)} raw={out[:80]!r}")
    if cls not in ("R", "silent", "encfail", "invalid"):
        print(f"      full = {out!r}")
    return cls, out


def extract_echo(seed, var_name: str, tail_builder) -> object:
    """echo(seed) -> Left(thunk) -> extract thunk -> tail_builder(thunk)"""
    return apps(
        g(14),
        seed,
        lam(
            "r",
            apps(
                v("r"),
                lam(var_name, tail_builder(v(var_name))),
                lam("_e", write_str("E")),
            ),
        ),
    )


def extract_backdoor(pair_name: str, tail_builder) -> object:
    return apps(
        g(201),
        NIL,
        lam(
            "br",
            apps(
                v("br"),
                lam(pair_name, tail_builder(v(pair_name))),
                lam("_be", write_str("B")),
            ),
        ),
    )


def main():
    print("=" * 70)
    print("ECHO THUNK PROBE: Using echo to capture unevaluated expressions")
    print("=" * 70)

    # ================================================================
    # SECTION 1: Capture sys8 calls via echo, then pass to sys8
    # ================================================================
    print("\n[1] Echo captures sys8 thunks -> pass to sys8")

    # 1a: echo(((sys8 nil) id)) -> thunk -> sys8(thunk) -> disc
    # The thunk IS ((sys8 nil) id), an unevaluated expression.
    # sys8 receives a data structure containing a reference to itself!
    identity = lam("x", v("x"))
    run(
        "echo(((sys8 nil) id)) -> thunk -> sys8(thunk)",
        extract_echo(
            apps(g(8), NIL, identity),
            "thunk",
            lambda thunk: apps(g(8), thunk, DISC8),
        ),
    )
    time.sleep(0.15)

    # 1b: echo((sys8 nil)) -> thunk (partially applied) -> sys8(thunk)
    run(
        "echo((sys8 nil)) -> thunk -> sys8(thunk)",
        extract_echo(
            apps(g(8), NIL),
            "thunk",
            lambda thunk: apps(g(8), thunk, DISC8),
        ),
    )
    time.sleep(0.15)

    # 1c: echo(sys8) -> thunk (just the syscall ref) -> sys8(thunk)
    # We already tested sys8(echo_extracted_var) but that was testing Var(14).
    # Now echo(Var(8)) should give us a captured Var(8) reference.
    run(
        "echo(sys8_ref) -> thunk -> sys8(thunk)",
        extract_echo(
            g(8),
            "thunk",
            lambda thunk: apps(g(8), thunk, DISC8),
        ),
    )
    time.sleep(0.15)

    # 1d: echo(echo) -> thunk -> sys8(thunk)
    run(
        "echo(echo_ref) -> thunk -> sys8(thunk)",
        extract_echo(
            g(14),
            "thunk",
            lambda thunk: apps(g(8), thunk, DISC8),
        ),
    )
    time.sleep(0.15)

    # ================================================================
    # SECTION 2: 3-leaf thunks captured by echo
    # ================================================================
    print("\n[2] 3-leaf thunks captured by echo -> pass to sys8")

    # "My record is 3 leafs" — what if the THUNK has 3 leaves?
    # echo(((A B) C)) preserves ((A B) C) as a thunk with 3 leaf Var nodes.

    # 3-leaf thunks with sys8 + echo + other syscalls
    three_leaf_thunks = [
        ("((sys8 echo) write)", apps(g(8), g(14), g(2))),
        ("((sys8 echo) echo)", apps(g(8), g(14), g(14))),
        ("((sys8 echo) sys8)", apps(g(8), g(14), g(8))),
        ("((sys8 echo) quote)", apps(g(8), g(14), g(4))),
        ("((sys8 echo) backdoor)", apps(g(8), g(14), g(201))),
        ("((echo sys8) write)", apps(g(14), g(8), g(2))),
        ("((echo sys8) echo)", apps(g(14), g(8), g(14))),
        ("((echo sys8) sys8)", apps(g(14), g(8), g(8))),
        ("((sys8 write) echo)", apps(g(8), g(2), g(14))),
        ("((sys8 backdoor) echo)", apps(g(8), g(201), g(14))),
        ("((sys8 nil_term) echo)", apps(g(8), NIL, g(14))),
        ("(sys8 (echo write))", apps(g(8), app(g(14), g(2)))),
        ("(sys8 (echo sys8))", apps(g(8), app(g(14), g(8)))),
        ("(echo (sys8 echo))", apps(g(14), app(g(8), g(14)))),
        ("(echo (sys8 write))", apps(g(14), app(g(8), g(2)))),
        ("((sys8 echo) nil)", apps(g(8), g(14), NIL)),
        ("((backdoor nil) echo)", apps(g(201), NIL, g(14))),
        ("((backdoor nil) sys8)", apps(g(201), NIL, g(8))),
        ("((backdoor echo) sys8)", apps(g(201), g(14), g(8))),
        # The most promising: echo captures, then feeds to sys8
        ("((echo ((sys8 nil) id)) disc)", None),  # handled separately below
    ]

    for name, thunk_expr in three_leaf_thunks:
        if thunk_expr is None:
            continue
        # echo(thunk_expr) -> extract -> sys8(extracted_thunk) -> disc
        run(
            f"echo({name}) -> thunk -> sys8(thunk)",
            extract_echo(
                thunk_expr,
                "thunk",
                lambda thunk: apps(g(8), thunk, DISC8),
            ),
        )
        time.sleep(0.1)

    # ================================================================
    # SECTION 3: Pass the WHOLE Left wrapper (including echo's lambdas) to sys8
    # ================================================================
    print("\n[3] Pass echo's Left wrapper (NOT extracted) directly to sys8")

    # echo(X) returns Left(X_thunk) = λl.λr.(l X_thunk)
    # Don't extract: pass the ENTIRE λl.λr.(l X_thunk) to sys8
    # sys8 receives a lambda that, when applied, would give the thunk

    thunks_to_wrap = [
        ("sys8_ref", g(8)),
        ("echo_ref", g(14)),
        ("nil", NIL),
        ("((sys8 nil) id)", apps(g(8), NIL, identity)),
        ("((sys8 echo) write)", apps(g(8), g(14), g(2))),
        ("((echo sys8) echo)", apps(g(14), g(8), g(14))),
        ("((backdoor nil) id)", apps(g(201), NIL, identity)),
    ]

    for name, expr in thunks_to_wrap:
        # echo(expr) -> Left_wrapper -> sys8(Left_wrapper) -> disc
        run(
            f"echo({name}) -> Left_wrapper -> sys8(Left_wrapper)",
            apps(
                g(14),
                expr,
                lam("left_wrapper", apps(g(8), v("left_wrapper"), DISC8)),
            ),
        )
        time.sleep(0.1)

    # ================================================================
    # SECTION 4: Echo-captured backdoor operations -> sys8
    # ================================================================
    print("\n[4] Echo-captured backdoor thunks -> sys8")

    # echo(((backdoor nil) handler)) captures the backdoor call as a thunk
    # Then pass this thunk to sys8
    run(
        "echo(((backdoor nil) id)) -> thunk -> sys8(thunk)",
        extract_echo(
            apps(g(201), NIL, identity),
            "thunk",
            lambda thunk: apps(g(8), thunk, DISC8),
        ),
    )
    time.sleep(0.15)

    # The backdoor thunk with a selector that extracts omega
    apply_sel = lam("a", lam("b", apps(v("a"), v("b"))))
    run(
        "echo(((backdoor nil) (λr.r (λp.p apply_sel) id))) -> thunk -> sys8(thunk)",
        extract_echo(
            apps(
                g(201),
                NIL,
                lam("r", apps(v("r"), lam("p", apps(v("p"), apply_sel)), identity)),
            ),
            "thunk",
            lambda thunk: apps(g(8), thunk, DISC8),
        ),
    )
    time.sleep(0.15)

    # ================================================================
    # SECTION 5: Chain: echo captures partial sys8 -> apply to make it work
    # ================================================================
    print("\n[5] Echo captures partial sys8, then complete the call")

    # echo(sys8) -> Left(sys8_ref) -> extract -> now we have a "blessed" sys8 ref
    # Apply it: ((blessed_sys8 arg) disc)
    run(
        "echo(sys8) -> blessed -> ((blessed nil) disc)",
        extract_echo(
            g(8),
            "blessed",
            lambda blessed: apps(blessed, NIL, DISC8),
        ),
    )
    time.sleep(0.15)

    # echo((sys8 echo)) -> Left((sys8 echo)) -> extract -> partial app
    # Then: (partial disc) = ((sys8 echo) disc) BUT with echo-captured version
    run(
        "echo((sys8 echo)) -> partial -> (partial disc)",
        extract_echo(
            apps(g(8), g(14)),
            "partial",
            lambda partial: apps(partial, DISC8),
        ),
    )
    time.sleep(0.15)

    # echo((sys8 nil)) -> Left((sys8 nil)) -> extract -> partial
    # Then: (partial echo) = ((sys8 nil) echo)
    run(
        "echo((sys8 nil)) -> partial -> (partial echo_ref)",
        extract_echo(
            apps(g(8), NIL),
            "partial",
            lambda partial: apps(partial, g(14)),
        ),
    )
    time.sleep(0.15)

    # ================================================================
    # SECTION 6: The ultimate test — echo captures a value that
    # WOULD make sys8 succeed if passed correctly
    # ================================================================
    print("\n[6] Creative combinations")

    # What if sys8 needs its OWN output fed back?
    # echo(Right(6)) -> Left(Right(6)) -> sys8 receives the echoed error
    right6 = NConst(Lam(Lam(App(Var(0), encode_byte_term(6)))))
    run(
        "echo(Right(6)) -> thunk -> sys8(thunk)",
        extract_echo(
            right6,
            "thunk",
            lambda thunk: apps(g(8), thunk, DISC8),
        ),
    )
    time.sleep(0.15)

    # What about echo(Left(nil))? A fake success result
    left_nil = NConst(Lam(Lam(App(Var(1), Lam(Lam(Var(0)))))))
    run(
        "echo(Left(nil)) -> thunk -> sys8(thunk)",
        extract_echo(
            left_nil,
            "thunk",
            lambda thunk: apps(g(8), thunk, DISC8),
        ),
    )
    time.sleep(0.15)

    # Nested echo: echo(echo(sys8)) -> outer Left -> extract -> inner Left -> extract -> sys8
    run(
        "echo(echo(sys8)) -> Left(Left(sys8)) -> extract outer -> sys8(inner_left)",
        extract_echo(
            apps(
                g(14), g(8), identity
            ),  # echo(sys8) -> Left(sys8) -> id(Left(sys8)) = Left(sys8)
            "echoed",
            lambda echoed: apps(g(8), echoed, DISC8),
        ),
    )
    time.sleep(0.15)

    # What if we need to pass echo's result to backdoor, and then backdoor's result to sys8?
    # echo(X) -> Left(thunk) -> backdoor(thunk) -> Left(pair?) -> sys8(pair)
    run(
        "echo(nil) -> thunk -> backdoor(thunk) -> ??? -> sys8",
        extract_echo(
            NIL,
            "thunk",
            lambda thunk: apps(
                g(201),
                thunk,
                lam(
                    "br",
                    apps(
                        v("br"),
                        lam("bval", apps(g(8), v("bval"), DISC8)),
                        lam("_berr", write_str("BR")),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.15)

    print("\n" + "=" * 70)
    print("ECHO THUNK PROBE COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
