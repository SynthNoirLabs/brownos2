#!/usr/bin/env python3
from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from probe_mail_focus import (
    DISC8,
    FD,
    FF,
    HOST,
    PORT,
    NIL,
    app,
    apps,
    classify,
    g,
    lam,
    query_named,
    recv_all,
    v,
)


@dataclass(frozen=True)
class ProbeResult:
    approach: str
    case: str
    cls: str
    out: bytes


def query_raw(payload: bytes, timeout_s: float = 8.0, retries: int = 3) -> bytes:
    delay = 0.15
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s=timeout_s)
        except Exception:
            time.sleep(delay)
            delay = min(delay * 2.0, 1.5)
    return b""


def run_named_case(
    approach: str, case: str, term: object, timeout_s: float = 10.0
) -> ProbeResult:
    out = query_named(term, timeout_s=timeout_s)
    cls = classify(out)
    print(f"  {case:50s} -> {cls:10s} len={len(out):3d} raw={out!r}")
    time.sleep(0.05)
    return ProbeResult(approach=approach, case=case, cls=cls, out=out)


def run_raw_case(
    approach: str, case: str, payload: bytes, timeout_s: float = 8.0
) -> ProbeResult:
    out = query_raw(payload, timeout_s=timeout_s)
    cls = classify(out)
    print(
        f"  {case:34s} payload={payload.hex()} -> {cls:10s} len={len(out):3d} raw={out!r}"
    )
    time.sleep(0.05)
    return ProbeResult(approach=approach, case=case, cls=cls, out=out)


def print_summary(name: str, results: list[ProbeResult]) -> None:
    counts: dict[str, int] = {}
    for item in results:
        counts[item.cls] = counts.get(item.cls, 0) + 1
    left_only = sum(1 for item in results if item.cls == "L")
    print(f"  summary[{name}]: total={len(results)} left={left_only} classes={counts}")


def prog_a_partial_left(seed: int) -> object:
    # A) (Left handler) only, then pass that function to syscall 8.
    identity = lam("x", v("x"))
    return apps(
        g(14),
        g(seed),
        lam(
            "left_term",
            apps(g(8), app(v("left_term"), identity), DISC8),
        ),
    )


def prog_b_left_direct(seed: int) -> object:
    # B) Pass the full Left wrapper itself to syscall 8.
    return apps(
        g(14),
        g(seed),
        lam("left_term", apps(g(8), v("left_term"), DISC8)),
    )


def prog_c_nested_echo(seed: int) -> object:
    # C) echo(echo(x)) without unwrapping either layer.
    return apps(
        g(14),
        g(seed),
        lam(
            "left1",
            apps(
                g(14),
                v("left1"),
                lam("left2", apps(g(8), v("left2"), DISC8)),
            ),
        ),
    )


def prog_c_nested_echo_partial(seed: int) -> object:
    # C-variant: partially apply outer Left before syscall 8.
    identity = lam("x", v("x"))
    return apps(
        g(14),
        g(seed),
        lam(
            "left1",
            apps(
                g(14),
                v("left1"),
                lam("left2", apps(g(8), app(v("left2"), identity), DISC8)),
            ),
        ),
    )


def prog_d_left_fn_position(seed: int) -> object:
    # D) Build closure (Left sys8), then pass closure as sys8 argument.
    return apps(
        g(14),
        g(seed),
        lam(
            "left_term",
            apps(g(8), app(v("left_term"), g(8)), DISC8),
        ),
    )


def prog_d_left_fn_position_execute(seed: int) -> object:
    # D-variant: execute ((Left sys8) nil) to force sys8(x_shifted).
    return apps(
        g(14),
        g(seed),
        lam(
            "left_term",
            apps(app(v("left_term"), g(8)), NIL, DISC8),
        ),
    )


LEAF_NAMES = {
    0x02: "2",
    0x08: "8",
    0x0E: "14",
    0xC9: "201",
    0xFB: "251",
    0xFC: "252",
}


def leaf_name(b: int) -> str:
    return LEAF_NAMES.get(b, f"0x{b:02x}")


def payload_left_assoc(a: int, b: int, c: int) -> bytes:
    # ((a b) c)
    return bytes([a, b, FD, c, FD, FF])


def payload_right_assoc(a: int, b: int, c: int) -> bytes:
    # (a (b c))
    return bytes([a, b, c, FD, FD, FF])


def run_approach_e() -> list[ProbeResult]:
    # E) 3-leaf minimal payloads, including the two explicit examples.
    triples = [
        (0x08, 0x0E, 0x02),
        (0x0E, 0x08, 0x02),
        (0x08, 0x0E, 0xFB),
        (0x08, 0x0E, 0xFC),
        (0x0E, 0x08, 0xFB),
        (0x0E, 0x08, 0xFC),
        (0x08, 0x02, 0x0E),
        (0x0E, 0x02, 0x08),
        (0xC9, 0x0E, 0x08),
        (0x08, 0xC9, 0x0E),
    ]

    results: list[ProbeResult] = []
    for a, b, c in triples:
        left_case = f"left (({leaf_name(a)} {leaf_name(b)}) {leaf_name(c)})"
        right_case = f"right ({leaf_name(a)} ({leaf_name(b)} {leaf_name(c)}))"
        results.append(run_raw_case("E", left_case, payload_left_assoc(a, b, c)))
        results.append(run_raw_case("E", right_case, payload_right_assoc(a, b, c)))
    return results


def main() -> None:
    print("=== BrownOS Breakthrough Probe ===")
    print("Mode: no QD, no quote, write-based probing only")
    print(
        "Target: preserve echo Left wrappers and feed shifted structures to syscall 8"
    )

    all_results: list[ProbeResult] = []

    print("\n[A] Partial Left application -> syscall8")
    a_results: list[ProbeResult] = []
    for seed in (251, 252):
        a_results.append(
            run_named_case(
                "A",
                f"echo({seed}) ; sys8(Left id)",
                prog_a_partial_left(seed),
            )
        )
    print_summary("A", a_results)
    all_results.extend(a_results)

    print("\n[B] Direct Left wrapper as syscall8 argument")
    b_results: list[ProbeResult] = []
    for seed in (251, 252):
        b_results.append(
            run_named_case(
                "B",
                f"echo({seed}) ; sys8(Left)",
                prog_b_left_direct(seed),
            )
        )
    print_summary("B", b_results)
    all_results.extend(b_results)

    print("\n[C] Nested echo without unwrapping")
    c_results: list[ProbeResult] = []
    for seed in (251, 252):
        c_results.append(
            run_named_case(
                "C",
                f"echo(echo({seed})) ; sys8(outer_left)",
                prog_c_nested_echo(seed),
            )
        )
        c_results.append(
            run_named_case(
                "C",
                f"echo(echo({seed})) ; sys8((outer_left id))",
                prog_c_nested_echo_partial(seed),
            )
        )
    print_summary("C", c_results)
    all_results.extend(c_results)

    print("\n[D] Left in function position")
    d_results: list[ProbeResult] = []
    for seed in (251, 252):
        d_results.append(
            run_named_case(
                "D",
                f"echo({seed}) ; sys8(Left sys8)",
                prog_d_left_fn_position(seed),
            )
        )
        d_results.append(
            run_named_case(
                "D",
                f"echo({seed}) ; ((Left sys8) nil) DISC8",
                prog_d_left_fn_position_execute(seed),
            )
        )
    print_summary("D", d_results)
    all_results.extend(d_results)

    print("\n[E] 3-leaf raw payload sweep (6-byte cores)")
    e_results = run_approach_e()
    print_summary("E", e_results)
    all_results.extend(e_results)

    print("\n=== Global Summary ===")
    print_summary("all", all_results)
    left_hits = [r for r in all_results if r.cls == "L"]
    if left_hits:
        print("  candidate left outcomes:")
        for item in left_hits:
            print(f"    [{item.approach}] {item.case}")
    else:
        print("  candidate left outcomes: none")


if __name__ == "__main__":
    main()
