#!/usr/bin/env python3
"""
Oracle Harness: definitive probe for syscall 8.

Design principles (from Oracle consultation):
1. NEVER use quote on echo-manufactured values (Var 253+)
2. Write markers BEFORE and AFTER sys8 to eliminate SILENT ambiguity
3. Probe filesystem state before/after sys8 in same payload
4. Test live backdoor objects vs reconstructions (capability/identity check)
5. Place echo-manufactured values in structured positions (continuations, pairs)
6. All in one connection where possible (state may not persist across connections)
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
    int_term,
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


QD_TERM = NConst(parse_term(QD))


def run(name: str, term: object, timeout_s: float = 15.0) -> tuple[str, bytes]:
    out = query_named(term, timeout_s=timeout_s)
    cls = classify(out)
    tag = "***" if cls not in ("R", "silent", "encfail", "invalid") else "   "
    print(f"  {tag} {name:60s} -> {cls:10s} raw={out[:60]!r}")
    if cls not in ("R", "silent", "encfail", "invalid"):
        print(f"      INTERESTING: full output = {out!r}")
    return cls, out


# ============================================================
# Helpers
# ============================================================


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


def write_str(s: str) -> object:
    """Write a string marker to the socket."""
    return apps(g(2), NConst(encode_bytes_list(s.encode())), NIL)


def seq(first: object, then: object) -> object:
    """Sequence: do first, ignore result, do then.
    first must be CPS-style returning to a continuation.
    We use: first with continuation (λ_. then)
    But write_marker already includes NIL as continuation...
    Let me restructure: write returns to its continuation.
    write(bytes, λ_. then)
    """
    # Actually write_marker uses NIL as continuation, so it discards.
    # We need a different approach. Let's build write with explicit continuation.
    return first  # We'll chain differently


def write_then(marker: str, then: object) -> object:
    """Write marker string, then continue with `then`."""
    return apps(g(2), NConst(encode_bytes_list(marker.encode())), lam("_w", then))


def sys8_with_disc(arg: object) -> object:
    """Call sys8 with arg, discriminate L vs R via write markers."""
    return apps(
        g(8),
        arg,
        lam(
            "res",
            apps(
                v("res"),
                lam("_l", write_str("L")),
                lam("_r", write_str("R")),
            ),
        ),
    )


def sys8_with_disc_then(arg: object, then_builder) -> object:
    """Call sys8, discriminate, then continue with more code.
    then_builder receives the L/R tag info implicitly (we can't easily thread it).
    Instead we write the tag AND continue.
    """
    return apps(
        g(8),
        arg,
        lam(
            "res",
            apps(
                v("res"),
                lam(
                    "_l",
                    write_then("L", then_builder()),
                ),
                lam(
                    "_r",
                    write_then("R", then_builder()),
                ),
            ),
        ),
    )


def readfile_write(file_id: int, marker: str, then: object) -> object:
    """Read file by ID, write its first few bytes prefixed by marker, then continue."""
    fid_term = NConst(int_term(file_id))
    return apps(
        g(7),
        fid_term,
        lam(
            "rf_res",
            apps(
                v("rf_res"),
                lam(
                    "rf_bytes",
                    write_then(marker, then),
                ),
                lam("rf_err", write_then(marker + "?", then)),
            ),
        ),
    )


# ============================================================
# PHASE 1: Before/After filesystem probe around sys8
# ============================================================


def phase1_before_after():
    """Write "A", call sys8(nil), write "Z". If sys8 hangs/crashes, we won't see Z."""
    print("\n[PHASE 1] Before/After markers around sys8")

    # Test 1: Basic before/after with nil argument
    term = write_then(
        "A",
        sys8_with_disc_then(
            NIL,
            lambda: write_str("Z"),
        ),
    )
    run("write(A) -> sys8(nil) -> disc -> write(Z)", term)
    time.sleep(0.1)

    # Test 2: Before/after with identity
    identity = lam("x", v("x"))
    term2 = write_then(
        "A",
        sys8_with_disc_then(
            identity,
            lambda: write_str("Z"),
        ),
    )
    run("write(A) -> sys8(id) -> disc -> write(Z)", term2)
    time.sleep(0.1)


# ============================================================
# PHASE 2: Live backdoor object vs reconstruction
# ============================================================


def phase2_capability():
    """Test if the LIVE backdoor pair has different behavior than a reconstruction."""
    print("\n[PHASE 2] Live backdoor object vs reconstruction for sys8")

    # Reconstructed A and B
    A_recon = NConst(Lam(Lam(App(Var(0), Var(0)))))  # λa.λb.(b b)
    B_recon = NConst(Lam(Lam(App(Var(1), Var(0)))))  # λa.λb.(a b)
    pair_recon = lam("f", apps(v("f"), A_recon, B_recon))  # λf.f A B

    # Test 2a: Live pair from backdoor -> sys8
    run(
        "LIVE: bd(nil)->pair, sys8(pair)",
        extract_backdoor("pair", lambda pair: sys8_with_disc(pair)),
    )
    time.sleep(0.1)

    # Test 2b: Reconstructed pair -> sys8
    run(
        "RECON: sys8(reconstructed_pair)",
        sys8_with_disc(pair_recon),
    )
    time.sleep(0.1)

    # Test 2c: Live pair echoed -> sys8
    run(
        "LIVE+ECHO: bd->pair, echo(pair)->y, sys8(y)",
        extract_backdoor(
            "pair",
            lambda pair: extract_echo(pair, "ey", lambda ey: sys8_with_disc(ey)),
        ),
    )
    time.sleep(0.1)

    # Test 2d: Reconstructed pair echoed -> sys8
    run(
        "RECON+ECHO: echo(recon_pair)->y, sys8(y)",
        extract_echo(pair_recon, "ey", lambda ey: sys8_with_disc(ey)),
    )
    time.sleep(0.1)

    # Test 2e: Live A (fst of pair) -> sys8
    fst_sel = lam("a", lam("b", v("a")))
    snd_sel = lam("a", lam("b", v("b")))
    run(
        "LIVE_A: bd->pair, sys8(pair fst)",
        extract_backdoor("pair", lambda pair: sys8_with_disc(apps(pair, fst_sel))),
    )
    time.sleep(0.1)

    # Test 2f: Live B -> sys8
    run(
        "LIVE_B: bd->pair, sys8(pair snd)",
        extract_backdoor("pair", lambda pair: sys8_with_disc(apps(pair, snd_sel))),
    )
    time.sleep(0.1)

    # Test 2g: Live omega = (A B) -> sys8
    # WARNING: omega = λx.(x x), applying it diverges! But passing it as DATA to sys8 should be fine.
    # pair = λf. f A B, so (pair (λa.λb. a b)) = ((λa.λb. a b) A B) = A B = ω
    # Actually we need to be careful: ω applied to anything diverges.
    # Let's extract A and B separately and apply.
    # Better: use pair with a selector that returns (A B) without fully reducing.
    # Actually sys8(ω) where ω = λx.(xx) could diverge during evaluation if the VM is strict.
    # Let's try the reconstructed ω first (it's safe as data).
    omega_recon = NConst(Lam(App(Var(0), Var(0))))  # λx.(x x)
    run(
        "RECON_OMEGA: sys8(λx.xx)",
        sys8_with_disc(omega_recon),
    )
    time.sleep(0.1)

    # Test 2h: Live (A B) computed via pair
    # pair (λa.λb. (a b)) = (A B) but this evaluates (A B) = ω = λx.(xx)
    # which is a normal form! So it's safe.
    apply_sel = lam("a", lam("b", apps(v("a"), v("b"))))
    run(
        "LIVE_AB: bd->pair, sys8(pair (λab.ab)) = sys8(ω_live)",
        extract_backdoor("pair", lambda pair: sys8_with_disc(apps(pair, apply_sel))),
    )
    time.sleep(0.1)


# ============================================================
# PHASE 3: Echo-manufactured values in structured positions
# ============================================================


def phase3_structured():
    """Place echo values inside continuations, pairs, and lists for sys8."""
    print("\n[PHASE 3] Echo values in structured positions for sys8")

    # 3a: v253 as CONTINUATION for sys8
    # ((sys8 nil) v253) -- v253 IS the continuation
    run(
        "v253 AS CONTINUATION: echo(251)->e, ((sys8 nil) e)",
        extract_echo(g(251), "e", lambda e: apps(g(8), NIL, e)),
    )
    time.sleep(0.1)

    # 3b: v254 as continuation
    run(
        "v254 AS CONTINUATION: echo(252)->e, ((sys8 nil) e)",
        extract_echo(g(252), "e", lambda e: apps(g(8), NIL, e)),
    )
    time.sleep(0.1)

    # 3c: v253 inside a Scott pair as arg to sys8
    # Build pair(v253, nil) = λf. f v253 nil
    run(
        "PAIR(v253,nil) AS ARG: echo(251)->e, sys8(λf.f e nil)",
        extract_echo(
            g(251),
            "e",
            lambda e: sys8_with_disc(lam("f", apps(v("f"), e, NIL))),
        ),
    )
    time.sleep(0.1)

    # 3d: v253 inside a byte list (cons(v253, nil)) as arg to sys8
    # cons(x, nil) = λc.λn. c x nil
    run(
        "LIST[v253] AS ARG: echo(251)->e, sys8(cons(e,nil))",
        extract_echo(
            g(251),
            "e",
            lambda e: sys8_with_disc(lam("c", lam("n", apps(v("c"), e, NIL)))),
        ),
    )
    time.sleep(0.1)

    # 3e: Echo-manufactured value as the LEFT handler in sys8's Either result
    # This is unusual: what if we give sys8 a continuation that, for Right,
    # applies v253?
    # ((sys8 nil) (λres. ((res v253) v254)))
    run(
        "v253/v254 IN DISC: echo(251)->e1, echo(252)->e2, ((sys8 nil) (λr. r e1 e2))",
        extract_echo(
            g(251),
            "e1",
            lambda e1: extract_echo(
                g(252),
                "e2",
                lambda e2: apps(
                    g(8),
                    NIL,
                    lam("res", apps(v("res"), e1, e2)),
                ),
            ),
        ),
    )
    time.sleep(0.1)

    # 3f: Use backdoor pair components + echo values together
    fst_sel = lam("a", lam("b", v("a")))
    run(
        "BD_A + v253: bd->pair, echo(251)->e, sys8((pair fst) e)",
        extract_backdoor(
            "pair",
            lambda pair: extract_echo(
                g(251),
                "e",
                lambda e: sys8_with_disc(apps(apps(pair, fst_sel), e)),
            ),
        ),
    )
    time.sleep(0.1)

    # 3g: The LIVE backdoor pair applied with echo value as selector
    run(
        "BD_PAIR(v253): bd->pair, echo(251)->e, sys8(pair e)",
        extract_backdoor(
            "pair",
            lambda pair: extract_echo(
                g(251),
                "e",
                lambda e: sys8_with_disc(apps(pair, e)),
            ),
        ),
    )
    time.sleep(0.1)


# ============================================================
# PHASE 4: sys8 calling convention test
# ============================================================


def phase4_calling_convention():
    """Test if sys8 has a non-standard calling convention."""
    print("\n[PHASE 4] Sys8 calling convention variations")

    # 4a: Standard CPS: ((sys8 arg) cont)
    # Already tested extensively. Skip.

    # 4b: What if sys8 takes TWO arguments before continuation?
    # ((sys8 arg1 arg2) cont) = (((sys8 arg1) arg2) cont)
    run(
        "2-ARG: ((sys8 nil nil) disc)",
        apps(g(8), NIL, NIL, DISC8),
    )
    time.sleep(0.1)

    # 4c: What if sys8 takes 3 args?
    run(
        "3-ARG: ((sys8 nil nil nil) disc)",
        apps(g(8), NIL, NIL, NIL, DISC8),
    )
    time.sleep(0.1)

    # 4d: What if arg must be a specific password string?
    for pw in ["su dloser", "ilikephp", "sudo su dloser"]:
        pw_term = NConst(encode_bytes_list(pw.encode()))
        run(
            f"sys8('{pw}')",
            write_then("A", sys8_with_disc_then(pw_term, lambda: write_str("Z"))),
        )
        time.sleep(0.1)

    # 4e: What if the arg is a file ID as integer term?
    for fid in [8, 88, 256]:
        fid_term = NConst(int_term(fid))
        run(
            f"sys8(int_term({fid}))",
            sys8_with_disc(fid_term),
        )
        time.sleep(0.1)

    # 4f: What if sys8 needs (password, user_id) pair?
    pw_term = NConst(encode_bytes_list(b"ilikephp"))
    uid_term = NConst(int_term(1000))  # gizmore's uid
    pair_arg = lam("f", apps(v("f"), pw_term, uid_term))
    run(
        "sys8(pair(ilikephp, 1000))",
        sys8_with_disc(pair_arg),
    )
    time.sleep(0.1)

    # 4g: sys8 with user/password as two separate args
    user_term = NConst(encode_bytes_list(b"gizmore"))
    run(
        "sys8(gizmore, ilikephp, disc)",
        apps(g(8), user_term, pw_term, DISC8),
    )
    time.sleep(0.1)

    run(
        "sys8(dloser, ilikephp, disc)",
        apps(g(8), NConst(encode_bytes_list(b"dloser")), pw_term, DISC8),
    )
    time.sleep(0.1)


# ============================================================
# PHASE 5: Filesystem state before/after sys8
# ============================================================


def phase5_filesystem_probe():
    """Check if sys8 modifies filesystem state (new files, changed content)."""
    print("\n[PHASE 5] Filesystem state before/after sys8")

    # Read mail (88) before sys8, call sys8, read mail after
    # If sys8 has a side effect, the mail might change or new files appear
    term = readfile_write(
        88,
        "M1:",
        sys8_with_disc_then(
            NIL,
            lambda: readfile_write(88, "M2:", write_str("Z")),
        ),
    )
    run("readfile(88) before/after sys8(nil)", term)
    time.sleep(0.2)

    # Check if a new file appeared at interesting IDs after sys8
    # Try reading file 257 after sys8
    term2 = sys8_with_disc_then(
        NIL,
        lambda: apps(
            g(6),
            NConst(int_term(257)),
            lam(
                "nr",
                apps(
                    v("nr"),
                    lam("nname", write_then("NEW!", write_str("Z"))),
                    lam("nerr", write_str("Z")),
                ),
            ),
        ),
    )
    run("sys8(nil) then name(257)", term2)
    time.sleep(0.1)

    # Check readdir of root after sys8
    term3 = sys8_with_disc_then(
        NIL,
        lambda: apps(g(5), NConst(int_term(0)), QD_TERM),
    )
    run("sys8(nil) then readdir(0) via QD", term3)
    time.sleep(0.1)


# ============================================================
# PHASE 6: The "3 leaves" with proper detection
# ============================================================


def phase6_three_leaves():
    """Test 3-leaf programs with before/after markers."""
    print("\n[PHASE 6] 3-leaf programs with before/after markers")

    # The 3-leaf programs that were SILENT before.
    # Now wrap them: write("A"), then the 3-leaf, then write("Z")
    # Problem: 3-leaf programs are raw bytes, not named terms.
    # We need to embed them in a sequence.

    # Approach: write("A"), then in continuation embed the 3-leaf program,
    # then write("Z").
    # But 3-leaf programs ARE the whole program. They don't have continuations.
    # To test them: ((sys8 echo) write) = sys8 applied to echo, then write as continuation
    # If sys8 returns Left(x), then (write x) writes x to socket
    # If sys8 returns Right(e), then (write e) writes the error code... but not as readable text.

    # Actually, the hint "3 leaves" means the solution program is just 3 Var nodes.
    # The result might be the answer written to socket as a SIDE EFFECT.
    # Let's try ((sys8 echo) write) and see if we get bytes.
    # write = syscall 2. If sys8 returns something and passes it to write as continuation...

    # Wait. CPS: ((sys8 arg) cont). Here arg=echo(Var(14)), cont=write(Var(2)).
    # sys8 would do: (cont result) = (write result) = write applied to result.
    # But write expects ((write bytes) cont), not (write bytes).
    # So (write result) is partially applied — it still needs a continuation.
    # That means ((sys8 echo) write) = sys8(echo) returns result, passes to write:
    # (write result) is a function waiting for a continuation.
    # Since nothing provides it, evaluation stops — SILENT.

    # For the 3-leaf to work, we need all 3 leaves to be meaningful.
    # What if it's ((echo arg) cont) where both arg and cont serve sys8?
    # Or ((backdoor nil) handler)?

    # Let's be systematic: 3-leaf means ((Var(a) Var(b)) Var(c)) or (Var(a) (Var(b) Var(c)))
    # The MOST interesting: ((Var(8) Var(14)) Var(14)) = ((sys8 echo) echo)
    # sys8 gets echo as arg, echo as continuation.
    # If sys8 returns Left(x), then (echo Left(x)) = echo applied to Left(x).
    # echo is CPS: ((echo arg) cont). Here echo only gets ONE arg (Left(x)).
    # That's partially applied again...

    # WAIT. What about the hint more literally:
    # "My record is 3 leafs" — the WHOLE PROGRAM has 3 variable leaves.
    # That includes lambdas! A program like λ.λ.((Var(2) Var(1)) Var(0))
    # has 3 leaves but also 2 lambdas. That's more complex than ((a b) c).

    # Actually: what if the program is the ARGUMENT to sys8, not the whole program?
    # "I need 3 leaves for the argument that makes sys8 succeed"
    # Then sys8 + QD continuation adds more leaves.

    # The author said specifically "3 leafs" — probably the solution argument to sys8.
    # All our 3-leaf tests as ARGUMENTS (via extract_echo + named terms) returned R.

    # But there's another interpretation: the ENTIRE payload to the server is 3 leaves.
    # That would be: the program ((A B) C) sent as `A B FD C FD FF` = 6 bytes.

    # Let's test ALL possible 3-leaf programs where at least one leaf is sys8(8):
    # Handled by phase6_three_leaves_raw() instead.
    pass


def phase6_three_leaves_raw():
    """Raw 3-leaf programs that include sys8, with full important syscall set."""
    print("\n[PHASE 6] Systematic 3-leaf raw payloads with sys8")

    import socket

    def query_raw(payload: bytes, timeout_s: float = 8.0) -> bytes:
        delay = 0.15
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
                    out = b""
                    while True:
                        try:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            out += chunk
                        except socket.timeout:
                            break
                    return out
            except Exception:
                time.sleep(delay)
                delay *= 2
        return b""

    # Important syscall indices
    important = [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]
    results = []

    for a in important:
        for b in important:
            for c in important:
                if 8 not in (a, b, c):
                    continue

                # Left-assoc: ((a b) c)
                payload_l = bytes([a, b, 0xFD, c, 0xFD, 0xFF])
                out_l = query_raw(payload_l)
                cls_l = classify(out_l)
                if cls_l not in ("silent", "R"):
                    print(f"  *** LEFT (({a} {b}) {c}) -> {cls_l} raw={out_l[:40]!r}")
                results.append(("L", a, b, c, cls_l, out_l))

                # Right-assoc: (a (b c))
                payload_r = bytes([a, b, c, 0xFD, 0xFD, 0xFF])
                out_r = query_raw(payload_r)
                cls_r = classify(out_r)
                if cls_r not in ("silent", "R"):
                    print(f"  *** RIGHT ({a} ({b} {c})) -> {cls_r} raw={out_r[:40]!r}")
                results.append(("R", a, b, c, cls_r, out_r))

                time.sleep(0.02)

    # Summary
    classes = {}
    for assoc, a, b, c, cls, out in results:
        classes[cls] = classes.get(cls, 0) + 1
    print(f"\n  3-leaf summary: {len(results)} tests, classes={classes}")
    non_trivial = [
        (assoc, a, b, c, cls, out)
        for assoc, a, b, c, cls, out in results
        if cls not in ("silent", "R")
    ]
    if non_trivial:
        print("  NON-TRIVIAL RESULTS:")
        for assoc, a, b, c, cls, out in non_trivial:
            print(f"    {assoc}-assoc ({a},{b},{c}) -> {cls} raw={out[:60]!r}")
    else:
        print("  All results were silent or R. No breakthroughs.")


# ============================================================
# PHASE 7: "Why would an OS need echo?" — echo as the answer path
# ============================================================


def phase7_echo_is_the_path():
    """What if echo itself produces the answer when given the right input?
    Not feeding to sys8, but echo's output IS the answer."""
    print("\n[PHASE 7] Echo as direct answer path")

    # What if echo on certain inputs writes something to the socket?
    # echo is CPS: ((echo arg) cont). cont receives Left(result).
    # If we use write as the continuation: ((echo arg) write)
    # write would receive Left(result). But write expects a byte list, not an Either.
    # Unless Left(result) happens to be a valid byte list...

    # Let's try: echo(nil) -> write the raw Left wrapper
    # Actually, let's extract and write the result directly
    interesting_seeds = [
        ("nil", NIL),
        ("identity", lam("x", v("x"))),
        ("omega", NConst(Lam(App(Var(0), Var(0))))),
        ("sys8_ref", g(8)),
        ("echo_ref", g(14)),
        ("backdoor_ref", g(201)),
    ]

    for seed_name, seed in interesting_seeds:
        # Echo the seed, extract the value, write it raw
        run(
            f"echo({seed_name})->y, write(quote(y))",
            extract_echo(
                seed,
                "y",
                lambda y: apps(
                    g(4),
                    y,
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
        )
        time.sleep(0.1)

    # Also try: echo on backdoor pair
    run(
        "echo(bd_pair)->y, write(quote(y))",
        extract_backdoor(
            "pair",
            lambda pair: extract_echo(
                pair,
                "y",
                lambda y: apps(
                    g(4),
                    y,
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
    )
    time.sleep(0.1)

    # What about echo(echo(x))? Double echo.
    run(
        "echo(echo(nil))->y, write(quote(y))",
        extract_echo(
            NIL,
            "y1",
            lambda y1: extract_echo(
                y1,
                "y2",
                lambda y2: apps(
                    g(4),
                    y2,
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
    )
    time.sleep(0.1)


# ============================================================
# PHASE 8: What if sys8 succeeds but returns Left with the answer?
# We need to write the Left payload.
# ============================================================


def phase8_extract_left():
    """If sys8 somehow returns Left, write its payload directly."""
    print("\n[PHASE 8] Extract Left payload from sys8 if it ever succeeds")

    # For each interesting argument, write sys8's Left payload if it returns Left
    args = [
        ("nil", NIL),
        ("identity", lam("x", v("x"))),
        ("omega_recon", NConst(Lam(App(Var(0), Var(0))))),
    ]

    for name, arg in args:
        term = apps(
            g(8),
            arg,
            lam(
                "res",
                apps(
                    v("res"),
                    lam(
                        "payload",
                        # Try to write the payload via quote+write
                        apps(
                            g(4),
                            v("payload"),
                            lam(
                                "qr",
                                apps(
                                    v("qr"),
                                    lam(
                                        "qb",
                                        apps(g(2), v("qb"), lam("_", write_str("!"))),
                                    ),
                                    lam("qe", write_str("Q?")),
                                ),
                            ),
                        ),
                    ),
                    lam("err", write_str("R")),
                ),
            ),
        )
        run(f"sys8({name}) -> extract Left -> write", term)
        time.sleep(0.1)

    # Same but with live backdoor pair
    term_bd = extract_backdoor(
        "pair",
        lambda pair: apps(
            g(8),
            pair,
            lam(
                "res",
                apps(
                    v("res"),
                    lam(
                        "payload",
                        apps(
                            g(4),
                            v("payload"),
                            lam(
                                "qr",
                                apps(
                                    v("qr"),
                                    lam(
                                        "qb",
                                        apps(g(2), v("qb"), lam("_", write_str("!"))),
                                    ),
                                    lam("qe", write_str("Q?")),
                                ),
                            ),
                        ),
                    ),
                    lam("err", write_str("R")),
                ),
            ),
        ),
    )
    run("sys8(live_bd_pair) -> extract Left -> write", term_bd)
    time.sleep(0.1)


def main() -> None:
    print("=" * 70)
    print("ORACLE HARNESS: Definitive Syscall 8 Probe")
    print("=" * 70)

    phase1_before_after()
    phase2_capability()
    phase3_structured()
    phase4_calling_convention()
    phase5_filesystem_probe()
    phase6_three_leaves_raw()
    phase7_echo_is_the_path()
    phase8_extract_left()

    print("\n" + "=" * 70)
    print("ORACLE HARNESS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
