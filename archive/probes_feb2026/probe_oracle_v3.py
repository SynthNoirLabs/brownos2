#!/usr/bin/env python3
"""
Oracle V3 Probe: Fresh attack vectors from Oracle consultation.

Key insights:
1. NEVER use QD/quote to observe sys8 results - use write-based handlers only
2. Echo-manufactured Var(253/254) might work as RESULT TRANSFORMERS
3. "3 leafs" might mean 3 environment slots (sys8 under lambdas)
4. sys8 might gate side-effects (unlock filesystem changes)
5. Try composing special-byte artifacts (FD/FE/FF) on the result path

All probes use write markers to detect Left vs Right branches.
"""

from __future__ import annotations

import socket
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
    either_disc,
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


def run(name: str, term: object, timeout_s: float = 15.0) -> tuple[str, bytes]:
    out = query_named(term, timeout_s=timeout_s)
    cls = classify(out)
    tag = "***" if cls not in ("R", "silent", "encfail", "invalid") else "   "
    print(f"  {tag} {name:65s} -> {cls:10s} raw={out[:60]!r}")
    if cls not in ("R", "silent", "encfail", "invalid"):
        print(f"      INTERESTING: full output = {out!r}")
    return cls, out


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


def extract_backdoor(pair_name: str, tail_builder) -> object:
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


# ============================================================
# PHASE 1: Echo-manufactured artifact as RESULT TRANSFORMER
# ============================================================
def phase1_result_transformer():
    """
    Use echo(251) to get Var(253) at runtime.
    Apply this as a FUNCTION to sys8's result.
    Var(253) = 0xFD in wire format = App marker.
    If the VM treats it as a function, applying it might do something unexpected.
    """
    print("\n[PHASE 1] Echo artifact as result transformer on sys8 output")

    # 1a: echo(251)->k, then ((sys8 nil) (λres. ((k res) handler)))
    # k is the echo-extracted value. Apply k to sys8's result.
    run(
        "echo(251)->k, sys8(nil), apply k to result",
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
                        lam("_l", write_str("K-L")),
                        lam("_r", write_str("K-R")),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.15)

    # 1b: Same with echo(252)
    run(
        "echo(252)->k, sys8(nil), apply k to result",
        extract_echo(
            g(252),
            "k",
            lambda k: apps(
                g(8),
                NIL,
                lam(
                    "res",
                    apps(
                        apps(k, v("res")),
                        lam("_l", write_str("K-L")),
                        lam("_r", write_str("K-R")),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.15)

    # 1c: Apply echo artifact to the ARGUMENT before passing to sys8
    run(
        "echo(251)->k, sys8(k nil), disc",
        extract_echo(
            g(251),
            "k",
            lambda k: apps(
                g(8),
                apps(k, NIL),
                DISC8,
            ),
        ),
    )
    time.sleep(0.15)

    # 1d: Use echo artifact as CONTINUATION directly
    run(
        "echo(251)->k, ((sys8 nil) k)",
        extract_echo(
            g(251),
            "k",
            lambda k: apps(g(8), NIL, k),
        ),
    )
    time.sleep(0.15)

    # 1e: Compose two echo artifacts
    run(
        "echo(251)->k1, echo(252)->k2, sys8(nil), (k1 (k2 res))",
        extract_echo(
            g(251),
            "k1",
            lambda k1: extract_echo(
                g(252),
                "k2",
                lambda k2: apps(
                    g(8),
                    NIL,
                    lam(
                        "res",
                        apps(
                            apps(k1, apps(k2, v("res"))),
                            lam("_l", write_str("KK-L")),
                            lam("_r", write_str("KK-R")),
                        ),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.15)


# ============================================================
# PHASE 2: sys8 under lambdas (environment slot attack)
# ============================================================
def phase2_env_slots():
    """
    "3 leaves" might mean sys8 runs inside a scope with 3 bound variables.
    Test sys8 under lambda binders with various values bound.
    """
    print("\n[PHASE 2] sys8 under lambda binders (environment slot attack)")

    # The idea: (λa.λb.λc. ((sys8 nil) disc)) applied to 3 arguments
    # sys8 at depth 3 becomes Var(8+3)=Var(11). BUT that might change what sys8 sees.
    # Actually, in de Bruijn, sys8 is always the global at its fixed position.
    # Under 3 lambdas, sys8 = Var(8+3) = Var(11).
    # The environment slots (a=Var(2), b=Var(1), c=Var(0)) are available.

    # Test with various "privileged" values as the bound variables
    privileged = [
        ("nil", NIL),
        ("echo_ref", g(14)),
        ("backdoor_ref", g(201)),
        ("sys8_ref", g(8)),
        ("write_ref", g(2)),
        ("quote_ref", g(4)),
    ]

    # First: sys8 under 1 lambda, bound to each privileged value
    for name, val in privileged:
        run(
            f"(λa. sys8(a) disc) {name}",
            apps(
                lam("a", apps(g(8), v("a"), DISC8)),
                val,
            ),
        )
        time.sleep(0.1)

    # sys8 where the ARGUMENT is the bound variable from backdoor
    fst = lam("a", lam("b", v("a")))
    snd = lam("a", lam("b", v("b")))
    apply_sel = lam("a", lam("b", apps(v("a"), v("b"))))

    # 3-deep: backdoor->pair, extract A and B, bind as lambdas, call sys8
    run(
        "bd->pair, (λA.λB.λω. sys8(ω) disc)(pair fst)(pair snd)(pair apply)",
        extract_backdoor(
            "pair",
            lambda pair: apps(
                lam(
                    "A",
                    lam(
                        "B",
                        lam(
                            "omega",
                            apps(g(8), v("omega"), DISC8),
                        ),
                    ),
                ),
                apps(pair, fst),
                apps(pair, snd),
                apps(pair, apply_sel),
            ),
        ),
    )
    time.sleep(0.1)


# ============================================================
# PHASE 3: Side-effect gating (sys8 unlocks something)
# ============================================================
def phase3_side_effect_gating():
    """
    Call sys8 first (even though it returns Right), then probe
    if filesystem or other syscalls behave differently.
    """
    print("\n[PHASE 3] Side-effect gating: sys8 then probe")

    # 3a: sys8(nil), then readfile(88) (mail)
    run(
        "sys8(nil) -> ignore -> readfile(88) -> write",
        apps(
            g(8),
            NIL,
            lam(
                "_res1",
                apps(
                    g(7),
                    NConst(int_term(88)),
                    lam(
                        "rf",
                        apps(
                            v("rf"),
                            lam("bytes", write_then("M:", write_str("done"))),
                            lam("err", write_str("F?")),
                        ),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.15)

    # 3b: sys8(nil), then try sys8 AGAIN
    run(
        "sys8(nil) -> ignore -> sys8(nil) -> disc",
        apps(
            g(8),
            NIL,
            lam(
                "_res1",
                apps(g(8), NIL, DISC8),
            ),
        ),
    )
    time.sleep(0.15)

    # 3c: sys8 with backdoor pair, then sys8 with nil
    run(
        "bd->pair, sys8(pair)->ignore, sys8(nil)->disc",
        extract_backdoor(
            "pair",
            lambda pair: apps(
                g(8),
                pair,
                lam(
                    "_res1",
                    apps(g(8), NIL, DISC8),
                ),
            ),
        ),
    )
    time.sleep(0.15)

    # 3d: backdoor(nil) THEN sys8(nil) -- does backdoor "unlock" something?
    run(
        "bd(nil)->ignore, sys8(nil)->disc",
        apps(
            g(201),
            NIL,
            lam(
                "_bd",
                apps(g(8), NIL, DISC8),
            ),
        ),
    )
    time.sleep(0.15)

    # 3e: sys8(nil), then probe NEW file IDs
    for fid in [8, 100, 200, 255, 257, 300, 500, 1000]:
        run(
            f"sys8(nil) -> name({fid})",
            apps(
                g(8),
                NIL,
                lam(
                    "_r",
                    apps(
                        g(6),
                        NConst(int_term(fid)),
                        lam(
                            "nr",
                            apps(
                                v("nr"),
                                lam("_name", write_str(f"N{fid}")),
                                lam("_err", write_str(f"E{fid}")),
                            ),
                        ),
                    ),
                ),
            ),
        )
        time.sleep(0.08)


# ============================================================
# PHASE 4: "Combining special bytes" — compose FD/FE/FF analogs
# ============================================================
def phase4_special_byte_compose():
    """
    The author said "combining the special bytes" produces interesting results.
    Try using echo-manufactured 253, 254 values in various compositions.
    Also try echo on values NEAR the boundary.
    """
    print("\n[PHASE 4] Composing special byte artifacts")

    # 4a: echo(251)->v253, echo(252)->v254, then (v253 v254) as arg to sys8
    run(
        "echo(251)->e1, echo(252)->e2, sys8((e1 e2))",
        extract_echo(
            g(251),
            "e1",
            lambda e1: extract_echo(
                g(252),
                "e2",
                lambda e2: apps(g(8), apps(e1, e2), DISC8),
            ),
        ),
    )
    time.sleep(0.15)

    # 4b: (v254 v253)
    run(
        "echo(251)->e1, echo(252)->e2, sys8((e2 e1))",
        extract_echo(
            g(251),
            "e1",
            lambda e1: extract_echo(
                g(252),
                "e2",
                lambda e2: apps(g(8), apps(e2, e1), DISC8),
            ),
        ),
    )
    time.sleep(0.15)

    # 4c: echo(253) — Var(253) is 0xFD but can't be encoded in wire!
    # We need to BUILD Var(253) via echo: echo(Var(251)) gives Left containing Var(253).
    # But we can NEST echoes: echo(echo(249)) -> 249+2+2 = 253?
    # No, echo normalizes: echo(249) -> Left(Var(249+2)) under Left = Var(251).
    # Extracting: Var(251). echo(251) -> Left(Var(253)).
    # So double echo = echo(echo_extract(249)) = echo(251) = Left(Var(253)).
    # We need 3 echoes to get Var(255) = FF!
    # echo(249)->251, echo(251)->253, echo(253)->255!
    # But we CAN'T extract 253 — that's the whole problem.
    # UNLESS we don't extract — just pass the Left wrapper around!

    # 4d: Chain echo WITHOUT extracting: echo(249) -> Left(251) -> echo(Left(251))
    # echo takes any term. Left(251) = λl.λr.(l Var(251)). That's a valid term.
    # echo(Left(251)) = Left(Left(251)_normalized) with all free vars shifted +2.
    # Left(251) has no free vars (it's closed), so echo(Left(251)) = Left(Left(251)).
    # Not useful...

    # 4e: What about echo on ITSELF? echo(echo) = echo(Var(14))
    # echo normalizes Var(14) -> Left(Var(14+2)) = Left(Var(16))
    # Under the Left lambdas: Var(16). Extracted: Var(14) = echo again. Not useful.

    # 4f: Build Var(253) indirectly via beta-reduction
    # λx. (x) applied to Var(253)? Can't construct Var(253) in the first place.
    # BUT: echo gives us Left(Var(253)). If we apply Left(Var(253)) to identity...
    # Left(v253) = λl.λr.(l v253). Applied to id: (λl.λr.(l v253) id) = λr.(id v253) = λr.v253
    # That's Lam(Var(253)). Now what? We have a lambda wrapping 253.
    # Apply to anything: (Lam(Var(253)) X) = Var(253)[0:=X]
    # Since 253 > 0, substitution doesn't touch it: result = Var(252) (shifted down by 1 because the lambda is removed)
    # Hmm, not quite. In de Bruijn, (λ.body) arg = body[0:=arg] with shift.
    # Var(253) with index > 0: after substitution at level 0, free vars ≥ 1 get decremented.
    # So Var(253) becomes Var(252). We lost one!
    # To get Var(253), we'd need Var(254) inside the lambda. That requires echo(252).

    # 4g: Key test - pass the ENTIRE Left wrapper (not extracted payload) to sys8
    # echo(X) returns Left(X_norm). If we pass the WHOLE Left(X_norm) to sys8:
    # sys8 receives λl.λr.(l X_norm).
    for seed in range(248, 253):
        run(
            f"echo({seed}) -> LEFT_WRAPPER -> sys8(LEFT_WRAPPER) -> disc",
            apps(
                g(14),
                g(seed),
                lam("left_val", apps(g(8), v("left_val"), DISC8)),
            ),
        )
        time.sleep(0.1)

    # 4h: echo(seed) -> don't unwrap -> sys8(echo_result)
    # The continuation to echo IS the raw Left value
    # echo(251) -> cont receives Left(Var(253))
    # If cont = (λx. sys8(x) disc), then x = Left(Var(253))
    # This is the same as 4g. Already tested in probe_breakthrough.py.
    # Let's try something different: echo on OMEGA
    omega = NConst(Lam(App(Var(0), Var(0))))
    run(
        "echo(ω) -> LEFT_WRAPPER -> sys8(LEFT_WRAPPER) -> disc",
        apps(
            g(14),
            omega,
            lam("left_val", apps(g(8), v("left_val"), DISC8)),
        ),
    )
    time.sleep(0.15)


# ============================================================
# PHASE 5: sys8 with backdoor A/B as CONTINUATION
# ============================================================
def phase5_continuation_variants():
    """
    Test sys8 with different continuations, especially backdoor-derived ones.
    The continuation determines HOW the result is consumed.
    """
    print("\n[PHASE 5] sys8 with various continuations (not just disc)")

    fst = lam("a", lam("b", v("a")))
    snd = lam("a", lam("b", v("b")))

    # 5a: sys8 with backdoor A (λab.(bb)) as continuation
    run(
        "bd->pair, sys8(nil) cont=(pair fst)=A",
        extract_backdoor(
            "pair",
            lambda pair: apps(g(8), NIL, apps(pair, fst)),
        ),
    )
    time.sleep(0.1)

    # 5b: sys8 with backdoor B (λab.(ab)) as continuation
    run(
        "bd->pair, sys8(nil) cont=(pair snd)=B",
        extract_backdoor(
            "pair",
            lambda pair: apps(g(8), NIL, apps(pair, snd)),
        ),
    )
    time.sleep(0.1)

    # 5c: sys8 with the PAIR ITSELF as continuation
    # pair = λf.f A B. As continuation: (pair result) = result A B
    # If result = Right(6): (Right(6) A B) = (λl.λr.(r 6) A B) = (B 6) = (λab.(ab) 6) = λb.(6 b)
    # If result = Left(x): (Left(x) A B) = (A x) = (λab.(bb) x) = λb.(bb) — weird.
    run(
        "bd->pair, sys8(nil) cont=pair",
        extract_backdoor(
            "pair",
            lambda pair: apps(g(8), NIL, pair),
        ),
    )
    time.sleep(0.1)

    # 5d: sys8 with identity as continuation
    identity = lam("x", v("x"))
    run(
        "sys8(nil) cont=identity",
        apps(g(8), NIL, identity),
    )
    time.sleep(0.1)

    # 5e: sys8 with ECHO as continuation!
    # ((sys8 nil) echo) where echo = Var(14)
    # sys8 returns result, passes to echo: (echo result) = echo(result)
    # echo would return Left(result_normalized)
    # We need a third continuation for echo...
    # Actually: ((sys8 nil) echo) is partially applied echo. We need:
    # ((sys8 nil) (λresult. ((echo result) handler)))
    run(
        "sys8(nil) -> echo(result) -> write Left/Right",
        apps(
            g(8),
            NIL,
            lam(
                "result",
                apps(
                    g(14),
                    v("result"),
                    lam(
                        "eres",
                        apps(
                            v("eres"),
                            lam("_l", write_str("EL")),
                            lam("_r", write_str("ER")),
                        ),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.1)

    # 5f: sys8 with WRITE as continuation
    # ((sys8 nil) (λresult. ((write result) nil)))
    # If result is a byte list, write prints it!
    run(
        "sys8(nil) -> write(result) -> nil",
        apps(
            g(8),
            NIL,
            lam(
                "result",
                apps(g(2), v("result"), NIL),
            ),
        ),
    )
    time.sleep(0.1)

    # 5g: sys8 with QUOTE as continuation
    # ((sys8 nil) (λresult. ((quote result) write_handler)))
    run(
        "sys8(nil) -> quote(result) -> write",
        apps(
            g(8),
            NIL,
            lam(
                "result",
                apps(
                    g(4),
                    v("result"),
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
    )
    time.sleep(0.1)


# ============================================================
# PHASE 6: Backdoor second-stage with echo values
# ============================================================
def phase6_backdoor_echo_chain():
    """
    Chain: echo(251)->v253, backdoor(v253) instead of backdoor(nil).
    Or: backdoor(nil)->pair, echo(pair)->echoed_pair, sys8(echoed_pair).
    """
    print("\n[PHASE 6] Backdoor + echo chains")

    # 6a: backdoor with echo-manufactured value as argument (not nil)
    # backdoor usually only accepts nil. But with v253...
    run(
        "echo(251)->k, backdoor(k) -> disc",
        extract_echo(
            g(251),
            "k",
            lambda k: apps(
                g(201),
                k,
                lam(
                    "br",
                    apps(
                        v("br"),
                        lam("_l", write_str("BL")),
                        lam("_r", write_str("BR")),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.15)

    # 6b: echo(pair) where pair is from backdoor
    run(
        "bd->pair, echo(pair)->ep, sys8(ep) disc",
        extract_backdoor(
            "pair",
            lambda pair: extract_echo(
                pair,
                "ep",
                lambda ep: apps(g(8), ep, DISC8),
            ),
        ),
    )
    time.sleep(0.15)

    # 6c: echo(A) where A is from backdoor
    fst = lam("a", lam("b", v("a")))
    run(
        "bd->pair, echo(A=pair fst)->ea, sys8(ea) disc",
        extract_backdoor(
            "pair",
            lambda pair: extract_echo(
                apps(pair, fst),
                "ea",
                lambda ea: apps(g(8), ea, DISC8),
            ),
        ),
    )
    time.sleep(0.15)

    # 6d: Double backdoor - backdoor(nil)->pair, extract omega = pair apply,
    # backdoor(omega) -> ???
    apply_sel = lam("a", lam("b", apps(v("a"), v("b"))))
    run(
        "bd->pair, omega=pair(λab.ab), backdoor(omega) -> disc",
        extract_backdoor(
            "pair",
            lambda pair: apps(
                g(201),
                apps(pair, apply_sel),
                lam(
                    "br2",
                    apps(
                        v("br2"),
                        lam("x2", apps(g(8), v("x2"), DISC8)),
                        lam("_e2", write_str("B2R")),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.15)


# ============================================================
# PHASE 7: sys8 with string arguments we haven't tried
# ============================================================
def phase7_string_args():
    """
    Test sys8 with various string arguments, including those derived
    from filesystem content and challenge themes.
    """
    print("\n[PHASE 7] sys8 with fresh string arguments")

    strings_to_try = [
        "Permission denied",  # error 6 message
        "brownos",
        "BrownOS",
        "lambda",
        "Lambda",
        "λ",
        "selfapply",
        "self-apply",
        "self apply",
        "Ω",
        "ω",
        "omega",
        "Omega",
        "OMEGA",
        "root",
        "admin",
        "sudo",
        "su",
        "login",
        "kernel",
        "interrupt",
        "syscall",
        "backdoor",
        "echo",
        "mail",
        "dloser",
        "gizmore",
        "boss",
        "evil",
        "42",
        "towel",
        "Don't Panic!",
        "Don't Panic",
        "ilikephp",
        "I like PHP",
        "wtf",
        "Uhm... yeah... no...",
        "secret",
        "password",
        "access",
        "granted",
        "denied",
        "success",
        "solution",
        "answer",
        "key",
        "flag",
        "Open Sesame",
        "open sesame",
        "hack",
        "hacker",
        "0xFD",
        "0xFE",
        "0xFF",
        "FD",
        "FE",
        "253",
        "254",
        "255",
        "201",
        "3",
        "3 leafs",
        "three",
        "Oh, go choke on a towel!",
        "choke",
        "x.xx",
        "\\x.xx",
        "xx",
        "ss",
        "yy",
        "ww",
        "S",
        "K",
        "I",
        "B",
        "C",
        "W",
        "Y",
        "SKI",
        "SKK",
        "GZKc.2/VQffio",  # gizmore's password hash
    ]

    for s in strings_to_try:
        s_term = NConst(encode_bytes_list(s.encode("utf-8", errors="replace")))
        out = query_named(apps(g(8), s_term, DISC8), timeout_s=8.0)
        cls = classify(out)
        tag = "***" if cls not in ("R", "silent") else "   "
        if tag == "***":
            print(f"  {tag} sys8('{s}') -> {cls:10s} raw={out[:60]!r}")
            print(f"      INTERESTING: full = {out!r}")
        time.sleep(0.05)

    print("  (All strings that weren't printed returned R or silent)")


# ============================================================
# PHASE 8: Systematic global-variable scan as sys8 arg
# ============================================================
def phase8_global_scan():
    """
    Test sys8(Var(N)) for a wider range of global indices.
    Some globals might be internal VM functions we haven't discovered.
    """
    print("\n[PHASE 8] sys8(Var(N)) global variable scan")

    interesting_ranges = (
        list(range(0, 20))
        + list(range(40, 45))
        + list(range(198, 210))
        + list(range(248, 253))
    )

    for n in interesting_ranges:
        out = query_named(apps(g(8), g(n), DISC8), timeout_s=8.0)
        cls = classify(out)
        tag = "***" if cls not in ("R", "silent") else "   "
        if tag == "***":
            print(f"  {tag} sys8(g({n})) -> {cls:10s} raw={out[:60]!r}")
        time.sleep(0.05)

    print("  (Globals not printed all returned R or silent)")


# ============================================================
# PHASE 9: The "kernel" hypothesis — echo as interrupt
# ============================================================
def phase9_kernel_interrupt():
    """
    gizmore said: "cmd to interrupt and transfer my parameters to the kernel"
    tehron: "Wait... there is a kernel!?"

    What if echo IS the interrupt mechanism? What if you need to echo
    something specific to "transfer parameters to the kernel"?
    """
    print("\n[PHASE 9] Echo as kernel interrupt")

    # 9a: echo(sys8) — echo the syscall 8 function itself
    run(
        "echo(sys8_ref) -> disc",
        apps(
            g(14),
            g(8),
            lam(
                "r",
                apps(
                    v("r"),
                    lam("_l", write_str("L")),
                    lam("_r", write_str("R")),
                ),
            ),
        ),
    )
    time.sleep(0.1)

    # 9b: echo applied to ((sys8 nil) handler)
    # i.e., echo the RESULT of sys8
    run(
        "sys8(nil)->res, echo(res)->disc",
        apps(
            g(8),
            NIL,
            lam(
                "res",
                apps(
                    g(14),
                    v("res"),
                    lam(
                        "er",
                        apps(
                            v("er"),
                            lam("_l", write_str("EL")),
                            lam("_r", write_str("ER")),
                        ),
                    ),
                ),
            ),
        ),
    )
    time.sleep(0.1)

    # 9c: What if echo on a PAIR of (sys8, nil) triggers something?
    pair_fn = lam("f", apps(v("f"), g(8), NIL))
    run(
        "echo(pair(sys8, nil)) -> disc",
        apps(
            g(14),
            pair_fn,
            lam(
                "r",
                apps(
                    v("r"),
                    lam("_l", write_str("L")),
                    lam("_r", write_str("R")),
                ),
            ),
        ),
    )
    time.sleep(0.1)

    # 9d: echo on (sys8 nil) — partially applied
    run(
        "echo(sys8 nil) -> disc [partial application]",
        apps(
            g(14),
            apps(g(8), NIL),
            lam(
                "r",
                apps(
                    v("r"),
                    lam("_l", write_str("L")),
                    lam("_r", write_str("R")),
                ),
            ),
        ),
    )
    time.sleep(0.15)

    # 9e: echo on QD
    QD_TERM_RAW = NConst(parse_term(QD))
    run(
        "echo(QD_term) -> disc",
        apps(
            g(14),
            QD_TERM_RAW,
            lam(
                "r",
                apps(
                    v("r"),
                    lam("_l", write_str("L")),
                    lam("_r", write_str("R")),
                ),
            ),
        ),
    )
    time.sleep(0.1)


def main() -> None:
    print("=" * 70)
    print("ORACLE V3 PROBE: Fresh Attack Vectors")
    print("=" * 70)

    phase1_result_transformer()
    phase2_env_slots()
    phase3_side_effect_gating()
    phase4_special_byte_compose()
    phase5_continuation_variants()
    phase6_backdoor_echo_chain()
    phase7_string_args()
    phase8_global_scan()
    phase9_kernel_interrupt()

    print("\n" + "=" * 70)
    print("ORACLE V3 PROBE COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
