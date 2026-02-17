#!/usr/bin/env python3
from __future__ import annotations

import time

from solve_brownos_answer import App, Lam, Var, encode_bytes_list

from probe_mail_focus import (
    DISC8,
    NConst,
    NIL,
    apps,
    g,
    lam,
    query_named,
    v,
)


def int_term(n: int) -> object:
    expr: object = Var(0)
    for idx, weight in ((1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)):
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def seq_write(ch: str, next_term: object) -> object:
    # ((write [ch]) (\_. next_term))
    return apps(g(2), NConst(encode_bytes_list(ch.encode())), lam("_", next_term))


def classify(raw: bytes) -> str:
    if not raw:
        return "silent"
    if raw.startswith(b"Invalid term!"):
        return "invalid"
    if raw.startswith(b"Encoding failed!"):
        return "encfail"
    txt = raw.decode("latin-1", errors="replace")
    marks = "".join(ch for ch in txt if ch in "LRElrBF")
    return marks if marks else f"other:{raw[:20].hex()}"


def either_then_8(pre: object, left_mark: str = "l", right_mark: str = "r") -> object:
    after = apps(g(8), NIL, DISC8)
    handler = lam(
        "res",
        apps(
            v("res"),
            lam("_left", seq_write(left_mark, after)),
            lam("_right", seq_write(right_mark, after)),
        ),
    )
    return apps(pre, handler)


def scenario_stage2_backdoor_then_8(selector: object) -> object:
    # 201 nil -> Left(pair) -> 201(pair selector) -> (Left/Right marker) -> syscall8
    after = apps(g(8), NIL, DISC8)

    disc2 = lam(
        "res2",
        apps(
            v("res2"),
            lam("_x", seq_write("l", after)),
            lam("_err2", seq_write("r", after)),
        ),
    )

    left1 = lam("pair", apps(g(201), apps(v("pair"), selector), disc2))
    handler1 = lam(
        "res1",
        apps(
            v("res1"),
            left1,
            lam("_err1", seq_write("E", after)),
        ),
    )
    return apps(g(201), NIL, handler1)


def scenario_backdoor_cont_then_8(selector: object) -> object:
    # Try continuation-shaped access:
    # 201 nil -> Left(pair) -> (((sys8 nil) (pair selector)) (\_. (sys8 nil) DISC8))
    after = apps(g(8), NIL, DISC8)
    left1 = lam(
        "pair",
        apps(
            apps(g(8), NIL),
            apps(v("pair"), selector),
            lam("_k", after),
        ),
    )
    handler1 = lam(
        "res1",
        apps(
            v("res1"),
            left1,
            lam("_err1", seq_write("E", after)),
        ),
    )
    return apps(g(201), NIL, handler1)


def main() -> None:
    print("=== State-After-NonR Probe ===")
    print("Each scenario runs first action, then checks syscall8 in same program.\n")

    selectors = []
    # A small, semantically interesting subset from prior mail tests.
    selectors.append(("sel_pair_fst", lam("a", lam("b", apps(v("a"), apps(v("a"), v("a")))))))
    selectors.append(("sel_A_A_like", lam("a", lam("b", apps(apps(v("a"), v("b")), v("b"))))))
    selectors.append(("sel_B_A_like", lam("a", lam("b", apps(apps(v("b"), v("a")), v("a"))))))

    file88 = NConst(int_term(88))

    scenarios: list[tuple[str, object]] = []
    scenarios.append(("baseline_8", apps(g(8), NIL, DISC8)))
    scenarios.append(("backdoor_nil_then_8", either_then_8(apps(g(201), NIL))))
    scenarios.append(("echo_251_then_8", either_then_8(apps(g(14), g(251)))))
    scenarios.append(("echo_252_then_8", either_then_8(apps(g(14), g(252)))))
    scenarios.append(("read_mailfile88_then_8", either_then_8(apps(g(7), file88), "l", "F")))
    scenarios.append(("sys8_then_sys8", either_then_8(apps(g(8), NIL))))

    for name, sel in selectors:
        scenarios.append((f"stage2_backdoor_{name}", scenario_stage2_backdoor_then_8(sel)))
        scenarios.append((f"backdoor_cont_{name}", scenario_backdoor_cont_then_8(sel)))

    for name, term in scenarios:
        out = query_named(term, timeout_s=8.0)
        print(f"{name:34s} -> {classify(out):10s} len={len(out)}")
        time.sleep(0.06)


if __name__ == "__main__":
    main()
