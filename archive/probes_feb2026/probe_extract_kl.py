#!/usr/bin/env python3
"""
Extract the payload from the K-L breakthrough.

Phase 1 showed: echo(251)->k, then (k (sys8_result)) produces Left!
Now we need to figure out WHAT is in that Left.

Also: understand WHY this works. Is it a genuine sys8 success,
or is k (a high-index global var) just a function that happens
to restructure Right(6) into something that looks like Left?

Key tests:
1. Extract the K-L payload and try to decode it as bytes
2. Compare: does (k (Right(6))) also give Left? (control test)
3. Does (k arbitrary_value) always give Left? (is k just a projector?)
4. What IS global variable ~251 in this VM?
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
    to_db,
)
from solve_brownos_answer import (
    App,
    Lam,
    Var,
    encode_bytes_list,
    encode_byte_term,
    encode_term,
    parse_term,
    decode_bytes_list,
    decode_either,
    decode_byte_term,
    QD,
    FF,
)


def write_str(s: str) -> object:
    return apps(g(2), NConst(encode_bytes_list(s.encode())), NIL)


def write_then(marker: str, then: object) -> object:
    return apps(g(2), NConst(encode_bytes_list(marker.encode())), lam("_w", then))


def extract_echo(seed, var_name: str, tail_builder) -> object:
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


def run(name: str, term: object, timeout_s: float = 15.0) -> tuple[str, bytes]:
    out = query_named(term, timeout_s=timeout_s)
    cls = classify(out)
    tag = "***" if cls not in ("R", "silent", "encfail", "invalid") else "   "
    print(f"  {tag} {name:65s} -> {cls:10s} len={len(out)} raw={out[:80]!r}")
    if cls not in ("R", "silent", "encfail", "invalid"):
        print(f"      full output = {out!r}")
    return cls, out


def run_raw(name: str, payload: bytes, timeout_s: float = 15.0) -> tuple[str, bytes]:
    delay = 0.15
    out = b""
    for _ in range(3):
        try:
            with socket.create_connection(
                ("wc3.wechall.net", 61221), timeout=timeout_s
            ) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                sock.settimeout(timeout_s)
                while True:
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        out += chunk
                    except socket.timeout:
                        break
                break
        except Exception:
            time.sleep(delay)
            delay *= 2
    cls = classify(out)
    tag = "***" if cls not in ("R", "silent", "encfail", "invalid") else "   "
    print(f"  {tag} {name:65s} -> {cls:10s} len={len(out)} raw={out[:80]!r}")
    if cls not in ("R", "silent", "encfail", "invalid"):
        print(f"      full output = {out!r}")
    return cls, out


def main():
    print("=" * 70)
    print("K-L BREAKTHROUGH EXTRACTION")
    print("=" * 70)

    # ================================================================
    # SECTION 1: CONTROL TESTS — Is k just a function that always returns Left?
    # ================================================================
    print("\n[1] Control tests: does (k X) always give Left for any X?")

    # 1a: k applied to Right(6) directly (not from sys8)
    right6 = lam("l", lam("r", apps(v("r"), NConst(int_term(6)))))
    run(
        "echo(251)->k, ((k Right(6)) left_h right_h)",
        extract_echo(
            g(251),
            "k",
            lambda k: apps(
                apps(k, right6),
                lam("_l", write_str("K-L")),
                lam("_r", write_str("K-R")),
            ),
        ),
    )
    time.sleep(0.15)

    # 1b: k applied to nil
    run(
        "echo(251)->k, ((k nil) left_h right_h)",
        extract_echo(
            g(251),
            "k",
            lambda k: apps(
                apps(k, NIL),
                lam("_l", write_str("K-L")),
                lam("_r", write_str("K-R")),
            ),
        ),
    )
    time.sleep(0.15)

    # 1c: k applied to identity
    identity = lam("x", v("x"))
    run(
        "echo(251)->k, ((k I) left_h right_h)",
        extract_echo(
            g(251),
            "k",
            lambda k: apps(
                apps(k, identity),
                lam("_l", write_str("K-L")),
                lam("_r", write_str("K-R")),
            ),
        ),
    )
    time.sleep(0.15)

    # 1d: k applied to Left(nil)
    left_nil = lam("l", lam("r", apps(v("l"), NIL)))
    run(
        "echo(251)->k, ((k Left(nil)) left_h right_h)",
        extract_echo(
            g(251),
            "k",
            lambda k: apps(
                apps(k, left_nil),
                lam("_l", write_str("K-L")),
                lam("_r", write_str("K-R")),
            ),
        ),
    )
    time.sleep(0.15)

    # ================================================================
    # SECTION 2: What IS global 251? Test Var(N) for N around 251
    # ================================================================
    print("\n[2] What are globals around index 251?")

    # Test if Var(N) applied to sys8 result gives Left
    for n in range(248, 253):
        # ((Var(n) (Right(6))) left_h right_h)
        # Build at top level (depth 0), so Var(n) = g(n)
        run(
            f"((g({n}) Right(6)) left_h right_h)",
            apps(
                apps(g(n), right6),
                lam("_l", write_str(f"L{n}")),
                lam("_r", write_str(f"R{n}")),
            ),
        )
        time.sleep(0.1)

    # ================================================================
    # SECTION 3: Extract the payload from K-L
    # ================================================================
    print("\n[3] Extract payload from K-L result")

    # If (k sys8_result) gives Left(payload), extract payload and:
    # a) Try to quote it
    # b) Try to decode as byte list
    # c) Try to write it directly

    # 3a: Extract and quote the payload
    run(
        "echo(251)->k, sys8(nil)->res, (k res)->force, Left->payload, quote(payload)->write",
        extract_echo(
            g(251),
            "k",
            lambda k: apps(
                g(8),
                NIL,
                lam(
                    "res",
                    apps(
                        apps(k, v("res")),
                        lam(
                            "payload",
                            apps(
                                g(4),
                                v("payload"),
                                lam(
                                    "qr",
                                    apps(
                                        v("qr"),
                                        lam("qb", apps(g(2), v("qb"), NIL)),
                                        lam("_qe", write_str("QE")),
                                    ),
                                ),
                            ),
                        ),
                        lam("_r", write_str("NOT-LEFT")),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.15)

    # 3b: Extract and write the payload directly (if it's a byte list)
    run(
        "echo(251)->k, sys8(nil)->res, (k res)->Left(payload), write(payload)",
        extract_echo(
            g(251),
            "k",
            lambda k: apps(
                g(8),
                NIL,
                lam(
                    "res",
                    apps(
                        apps(k, v("res")),
                        lam(
                            "payload",
                            apps(g(2), v("payload"), NIL),
                        ),
                        lam("_r", write_str("NOT-LEFT")),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.15)

    # 3c: Extract, try to decode as either (is payload itself an Either?)
    run(
        "echo(251)->k, sys8(nil)->res, (k res)->Left(payload), (payload L-handler R-handler)",
        extract_echo(
            g(251),
            "k",
            lambda k: apps(
                g(8),
                NIL,
                lam(
                    "res",
                    apps(
                        apps(k, v("res")),
                        lam(
                            "payload",
                            apps(
                                v("payload"),
                                lam("_inner_l", write_str("INNER-L")),
                                lam("_inner_r", write_str("INNER-R")),
                            ),
                        ),
                        lam("_r", write_str("NOT-LEFT")),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.15)

    # ================================================================
    # SECTION 4: Use QD to see the full structure
    # ================================================================
    print("\n[4] Use QD on (k (sys8 result))")

    QD_TERM = NConst(parse_term(QD))

    # 4a: echo(251)->k, sys8(nil)->res, quote(k res) -> QD
    # Wait, QD IS a continuation. Let me use it properly.
    # ((sys8 nil) (λres. ((quote (k res)) QD_continuation)))
    # Or better: just do ((k (sys8_result)) QD) but k is the function...
    # Let me think...
    # sys8(nil) -> cont receives Right(6)
    # We want: cont = (λres. quote((k res)) -> QD)
    run(
        "echo(251)->k, sys8(nil)->res, quote(k res) -> write",
        extract_echo(
            g(251),
            "k",
            lambda k: apps(
                g(8),
                NIL,
                lam(
                    "res",
                    apps(
                        g(4),
                        apps(k, v("res")),
                        lam(
                            "qr",
                            apps(
                                v("qr"),
                                lam("qb", apps(g(2), v("qb"), NIL)),
                                lam("_qe", write_str("QE")),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.15)

    # 4b: Also quote k itself to see what it is
    run(
        "echo(251)->k, quote(k) -> write",
        extract_echo(
            g(251),
            "k",
            lambda k: apps(
                g(4),
                k,
                lam(
                    "qr",
                    apps(
                        v("qr"),
                        lam("qb", apps(g(2), v("qb"), NIL)),
                        lam("_qe", write_str("QE")),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.15)

    # ================================================================
    # SECTION 5: Test different echo seeds with the same pattern
    # ================================================================
    print("\n[5] Different echo seeds with same k-applied-to-result pattern")

    for seed in range(0, 20):
        cls, _ = run(
            f"echo({seed})->k, sys8(nil), (k res) left/right",
            extract_echo(
                g(seed),
                "k",
                lambda k: apps(
                    g(8),
                    NIL,
                    lam(
                        "res",
                        apps(
                            apps(k, v("res")),
                            lam("_l", write_str(f"L")),
                            lam("_r", write_str(f"R")),
                        ),
                    ),
                ),
            ),
        )
        time.sleep(0.08)

    # Also try around the boundary
    for seed in range(248, 253):
        cls, _ = run(
            f"echo({seed})->k, sys8(nil), (k res) left/right",
            extract_echo(
                g(seed),
                "k",
                lambda k: apps(
                    g(8),
                    NIL,
                    lam(
                        "res",
                        apps(
                            apps(k, v("res")),
                            lam("_l", write_str(f"L")),
                            lam("_r", write_str(f"R")),
                        ),
                    ),
                ),
            ),
        )
        time.sleep(0.08)

    print("\n" + "=" * 70)
    print("EXTRACTION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
