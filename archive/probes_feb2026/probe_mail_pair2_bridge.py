#!/usr/bin/env python3
from __future__ import annotations

import time
from collections import Counter

from probe_mail_focus import (
    DISC8,
    NIL,
    apps,
    classify,
    g,
    lam,
    make_3leaf_selectors,
    query_named,
    v,
    write_marker,
)


def fst_sel() -> object:
    return lam("a", lam("b", v("a")))


def snd_sel() -> object:
    return lam("a", lam("b", v("b")))


def stage_chain(sel: object) -> object:
    # 201(nil)->pair ; echo(pair sel)->y ; 201(y)
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
                                            "res3",
                                            apps(
                                                v("res3"),
                                                lam("_pair2", write_marker("L")),
                                                lam("_err3", write_marker("r")),
                                            ),
                                        ),
                                    ),
                                ),
                                lam("_err2", write_marker("e")),
                            ),
                        ),
                    ),
                ),
                lam("_err1", write_marker("E")),
            ),
        ),
    )


def candidate_expr(kind: str, sel: object) -> object:
    if kind == "y":
        return v("y")
    if kind == "y_nil":
        return apps(v("y"), NIL)
    if kind == "pair2":
        return v("pair2")
    if kind == "pair2_fst_nil":
        return apps(v("pair2"), fst_sel(), NIL)
    if kind == "pair2_snd_nil":
        return apps(v("pair2"), snd_sel(), NIL)
    if kind == "pair2_sel_nil":
        return apps(v("pair2"), sel, NIL)
    if kind == "sel_pair2_parts":
        return apps(
            sel,
            apps(v("pair2"), fst_sel(), NIL),
            apps(v("pair2"), snd_sel(), NIL),
        )
    raise ValueError(f"Unknown candidate kind: {kind}")


def full_chain(sel: object, cand_kind: str, call_mode: str) -> object:
    cand = candidate_expr(cand_kind, sel)
    if call_mode == "arg":
        tail = apps(g(8), cand, DISC8)
    elif call_mode == "cont":
        # Treat candidate as continuation-like value: ((8 nil) candidate) DISC8
        tail = apps(apps(g(8), NIL), cand, DISC8)
    else:
        raise ValueError(f"Unknown call mode: {call_mode}")

    # 201(nil)->pair ; echo(pair sel)->y ; 201(y)->pair2 ; then syscall8 path.
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
                                            "res3",
                                            apps(
                                                v("res3"),
                                                lam("pair2", tail),
                                                lam("_err3", write_marker("r")),
                                            ),
                                        ),
                                    ),
                                ),
                                lam("_err2", write_marker("e")),
                            ),
                        ),
                    ),
                ),
                lam("_err1", write_marker("E")),
            ),
        ),
    )


def run(term: object, timeout_s: float = 10.0) -> tuple[str, bytes]:
    out = query_named(term, timeout_s=timeout_s)
    return classify(out), out


def main() -> None:
    print("=== Mail -> Echo -> 201(y) -> syscall8 Bridge Probe ===")

    selectors = make_3leaf_selectors()
    accepted: list[tuple[str, object]] = []

    print("\n[1] Stage acceptance (L means 201(y) accepted)")
    for name, sel in selectors:
        cls, out = run(stage_chain(sel))
        if cls == "L":
            accepted.append((name, sel))
        print(f"{name:24s} -> {cls:8s} raw={out!r}")
        time.sleep(0.03)

    print(f"accepted selectors: {len(accepted)}/{len(selectors)}")
    if not accepted:
        return

    candidate_kinds = [
        "y",
        "y_nil",
        "pair2",
        "pair2_fst_nil",
        "pair2_snd_nil",
        "pair2_sel_nil",
        "sel_pair2_parts",
    ]
    call_modes = ["arg", "cont"]

    print("\n[2] Accepted selectors -> syscall8 bridges")
    counts: Counter[str] = Counter()

    for sel_name, sel in accepted:
        for cand_kind in candidate_kinds:
            for call_mode in call_modes:
                cls, out = run(full_chain(sel, cand_kind, call_mode))
                counts[cls] += 1
                print(
                    f"{sel_name:24s} cand={cand_kind:16s} call={call_mode:4s}"
                    f" -> {cls:8s} raw={out!r}"
                )
                time.sleep(0.03)

    print("\nsummary:")
    for key, value in sorted(counts.items(), key=lambda kv: kv[0]):
        print(f"  {key:8s}: {value}")


if __name__ == "__main__":
    main()
