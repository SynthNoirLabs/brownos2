#!/usr/bin/env python3
from __future__ import annotations

from probe_mail_focus import (
    DISC8,
    NIL,
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


def disc_201(arg: object) -> object:
    return apps(
        g(201),
        arg,
        lam(
            "r",
            apps(
                v("r"),
                lam("_ok", write_marker("L")),
                lam("_err", write_marker("R")),
            ),
        ),
    )


def via_echo(seed: object, tail_builder) -> object:
    return apps(
        g(14),
        seed,
        lam(
            "r",
            apps(
                v("r"),
                lam("y", tail_builder(v("y"))),
                lam("_e", write_marker("e")),
            ),
        ),
    )


def run(name: str, term: object) -> None:
    out = query_named(term, timeout_s=10.0)
    cls = classify(out)
    plen, vmax = payload_info(term)
    polluted = "yes" if vmax >= 253 else "no"
    print(
        f"{name:18s} -> {cls:8s} len={plen:4d} vmax={vmax:3d} "
        f"polluted={polluted:3s} raw={out!r}"
    )


def main() -> None:
    print("=== Mail Chain Minimization Probe ===")

    # Reduced seed from delta minimization:
    # x = ((nil nil) nil)
    x = apps(NIL, NIL, NIL)

    print("\n[1] Direct vs via-echo on syscall 201")
    run("201(x)", disc_201(x))
    run("echo(x)->201", via_echo(x, disc_201))
    run(
        "echo(x)->echo->201",
        via_echo(
            x,
            lambda y: via_echo(
                y,
                disc_201,
            ),
        ),
    )

    print("\n[2] Syscall8 matrix on reduced seed")
    run("8(x)", apps(g(8), x, DISC8))
    run("8(nil) x DISC8", apps(apps(g(8), NIL), x, DISC8))
    run("echo(x)->8(y)", via_echo(x, lambda y: apps(g(8), y, DISC8)))
    run(
        "echo(x)->8(nil)y",
        via_echo(
            x,
            lambda y: apps(apps(g(8), NIL), y, DISC8),
        ),
    )
    run(
        "echo(x)->(8 y)DISC8",
        via_echo(
            x,
            lambda y: apps(apps(g(8), y), DISC8),
        ),
    )

    print("\n[3] Parser-edge check: semantic path, different representation")
    # Direct A/B are rejected by 201; this reduced x path is accepted via echo.
    a = lam("a", lam("b", apps(v("b"), v("b"))))
    b = lam("a", lam("b", apps(v("a"), v("b"))))
    run("201(A)", disc_201(a))
    run("echo(A)->201", via_echo(a, disc_201))
    run("201(B)", disc_201(b))
    run("echo(B)->201", via_echo(b, disc_201))


if __name__ == "__main__":
    main()
