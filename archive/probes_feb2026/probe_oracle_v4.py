#!/usr/bin/env python3
"""
Oracle V4 Probe: Special bytes smuggling via echo.

Key insight: sys8 might need "code-as-data" with reserved opcodes FD/FE/FF.
Echo is the ONLY way to manufacture Var(253+) values at runtime.
"3 leafs" might be literally: 08 0E FB FD FD FF = sys8(echo(251))

Phase 1: sys8(omega) — strict or lazy?
Phase 2: Literal 3-leaf candidates
Phase 3: Echo-extracted inner values (Var(253)) to sys8
Phase 4: Double-echo shift (Var(255) = 0xFF as data)
Phase 5: sys8(encode_bytes_list(b"ilikephp")) — close password branch
Phase 6: sys8 with byte-list containing FD/FE/FF opcodes
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
    FD,
    FE,
    decode_either,
    decode_byte_term,
    decode_bytes_list,
)

HOST = "wc3.wechall.net"
PORT = 61221


def recv_all_raw(sock: socket.socket, timeout_s: float) -> bytes:
    sock.settimeout(timeout_s)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    return out


def query_raw(payload: bytes, timeout_s: float = 8.0) -> tuple[bytes, float]:
    """Send payload, return (output, elapsed_seconds)."""
    start = time.monotonic()
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            out = recv_all_raw(sock, timeout_s=timeout_s)
            elapsed = time.monotonic() - start
            return out, elapsed
    except Exception as e:
        return f"ERR:{e}".encode(), time.monotonic() - start


def describe(data: bytes) -> str:
    if not data:
        return "EMPTY"
    if data.startswith(b"Invalid term!"):
        return "INVALID"
    if data.startswith(b"Term too big!"):
        return "TOO_BIG"
    if data.startswith(b"Encoding failed!"):
        return "ENC_FAIL"
    try:
        text = data.decode("ascii")
        if text.isprintable():
            return f"TEXT:{text!r}"
    except:
        pass
    return f"HEX:{data.hex()} ({len(data)}b)"


def run_raw(name: str, payload: bytes, timeout_s: float = 8.0):
    out, elapsed = query_raw(payload, timeout_s=timeout_s)
    desc = describe(out)
    interesting = desc not in ("EMPTY", "INVALID")
    tag = "***" if interesting else "   "
    print(f"  {tag} {name:60s} -> {desc} ({elapsed:.1f}s)")
    if interesting and desc.startswith("HEX:"):
        # Try to parse as Either
        try:
            if 0xFF in out:
                term = parse_term(out)
                t, p = decode_either(term)
                if t == "Right":
                    code = decode_byte_term(p)
                    print(f"      Decoded: Right({code})")
                else:
                    print(f"      Decoded: Left({p})")
        except:
            pass
    return out, elapsed


def run_named(name: str, term_obj, timeout_s: float = 10.0):
    out = query_named(term_obj, timeout_s=timeout_s)
    cls = classify(out)
    interesting = cls not in ("R", "silent", "encfail", "invalid")
    tag = "***" if interesting else "   "
    print(f"  {tag} {name:60s} -> {cls:10s} len={len(out)} raw={out[:60]!r}")
    if interesting:
        print(f"      full = {out!r}")
    return cls, out


def write_str(s: str):
    return apps(g(2), NConst(encode_bytes_list(s.encode())), NIL)


def extract_echo(seed, var_name: str, tail_builder):
    """echo(seed) -> Left(thunk) -> extract thunk -> tail_builder(thunk)"""
    return apps(
        g(14),
        seed,
        lam(
            "echo_res",
            apps(
                v("echo_res"),
                lam(var_name, tail_builder(v(var_name))),
                lam("_echo_err", write_str("E")),
            ),
        ),
    )


def main():
    print("=" * 70)
    print("ORACLE V4 PROBE: Special bytes via echo")
    print("=" * 70)

    # ================================================================
    # PHASE 1: sys8(omega) — is sys8 strict in its argument?
    # ================================================================
    print("\n[1] sys8(omega) — does it evaluate the argument?")
    print("    If immediate Right(6): sys8 rejects BEFORE evaluating arg")
    print("    If hangs/timeout: sys8 tries to evaluate arg (omega diverges)")

    # Build omega from backdoor
    # backdoor(nil) -> Left(pair) -> pair(λab.ab) = (A B) = ω
    # Then sys8(ω ω) should loop if sys8 evaluates its arg

    # Method 1: Direct ω application (ω ω loops)
    # Build: backdoor(nil) -> extract pair -> pair(λab.ab) = omega -> sys8(omega omega)
    omega_probe = apps(
        g(201),
        NIL,
        lam(
            "bd_res",
            apps(
                v("bd_res"),
                lam(
                    "pair",
                    # pair(λab.ab) = apply first to second = (A B) = ω
                    # Then: ω ω diverges. Pass to sys8 as arg.
                    # Actually, let's first just pass ω (not ω ω) to sys8
                    apps(
                        g(8),
                        apps(v("pair"), lam("a", lam("b", apps(v("a"), v("b"))))),
                        DISC8,
                    ),
                ),
                lam("_bd_err", write_str("BD-ERR")),
            ),
        ),
    )
    cls1, out1 = run_named("sys8(omega) via backdoor pair", omega_probe, timeout_s=12.0)
    time.sleep(0.2)

    # Also: sys8(ω ω) = sys8(diverging)
    omega_omega_probe = apps(
        g(201),
        NIL,
        lam(
            "bd_res",
            apps(
                v("bd_res"),
                lam(
                    "pair",
                    apps(
                        g(8),
                        # ω ω = self-apply omega
                        app(
                            apps(v("pair"), lam("a", lam("b", apps(v("a"), v("b"))))),
                            apps(
                                v("pair"), lam("a2", lam("b2", apps(v("a2"), v("b2"))))
                            ),
                        ),
                        DISC8,
                    ),
                ),
                lam("_bd_err2", write_str("BD-ERR")),
            ),
        ),
    )
    cls2, out2 = run_named(
        "sys8(omega omega) = diverging arg", omega_omega_probe, timeout_s=12.0
    )
    time.sleep(0.2)

    # ================================================================
    # PHASE 2: Literal 3-leaf candidates
    # ================================================================
    print("\n[2] Literal 3-leaf programs (raw bytes)")

    three_leaf_programs = [
        # sys8(echo(251)) — "3 leafs": 08 0E FB
        ("sys8(echo(251))", bytes([0x08, 0x0E, 0xFB, FD, FD, FF])),
        ("echo(sys8(251))", bytes([0x0E, 0x08, 0xFB, FD, FD, FF])),
        # sys8(echo(252))
        ("sys8(echo(252))", bytes([0x08, 0x0E, 0xFC, FD, FD, FF])),
        # sys8(echo(250))
        ("sys8(echo(250))", bytes([0x08, 0x0E, 0xFA, FD, FD, FF])),
        # ((sys8 echo) 251)
        ("((sys8 echo) 251)", bytes([0x08, 0x0E, FD, 0xFB, FD, FF])),
        ("((sys8 echo) 252)", bytes([0x08, 0x0E, FD, 0xFC, FD, FF])),
        # ((sys8 251) echo)
        ("((sys8 251) echo)", bytes([0x08, 0xFB, FD, 0x0E, FD, FF])),
        ("((sys8 252) echo)", bytes([0x08, 0xFC, FD, 0x0E, FD, FF])),
        # (echo (sys8 251))
        ("(echo (sys8 251))", bytes([0x0E, 0x08, 0xFB, FD, FD, FF])),
        # sys8(echo(0)) — echo(0) is simple
        ("sys8(echo(0))", bytes([0x08, 0x0E, 0x00, FD, FD, FF])),
        # 3 leaves with backdoor
        ("sys8(backdoor(251))", bytes([0x08, 0xC9, 0xFB, FD, FD, FF])),
        ("((sys8 backdoor) 251)", bytes([0x08, 0xC9, FD, 0xFB, FD, FF])),
    ]

    for name, payload in three_leaf_programs:
        run_raw(name, payload)
        time.sleep(0.1)

    # ================================================================
    # PHASE 3: Echo-extracted inner values to sys8
    # ================================================================
    print("\n[3] Echo-extracted Var(253+) values to sys8")
    print("    echo(251) -> Left(Var(253)) -> extract Var(253) -> sys8(Var(253))")

    # echo(251) produces Left(X) where X = Var(253) (shifted +2 by Left wrapper)
    # When we EXTRACT X from Left, the shift cancels, giving us back Var(251)
    # But what if we DON'T extract — pass the raw Left to sys8?
    # Or extract and use IMMEDIATELY under the Right lambda where the shift stays?

    # Method A: extract and pass to sys8 (shift cancels, gives Var(251))
    for seed_val in [251, 252, 250, 249]:
        run_named(
            f"echo({seed_val}) -> extract -> sys8(extracted)",
            extract_echo(
                g(seed_val),
                "val",
                lambda val: apps(g(8), val, DISC8),
            ),
        )
        time.sleep(0.1)

    # Method B: Don't extract from Left — pass entire Left(Var(253)) to sys8
    for seed_val in [251, 252, 250]:
        run_named(
            f"echo({seed_val}) -> Left_wrapper -> sys8(Left_wrapper)",
            apps(
                g(14),
                g(seed_val),
                lam("left_wrapper", apps(g(8), v("left_wrapper"), DISC8)),
            ),
        )
        time.sleep(0.1)

    # Method C: Use echo's Left wrapper as CONTINUATION to sys8
    # sys8(nil, echo_result)
    for seed_val in [251, 252]:
        run_named(
            f"sys8(nil, cont=echo({seed_val}).Left)",
            apps(
                g(14),
                g(seed_val),
                lam("left_wrapper", apps(g(8), NIL, v("left_wrapper"))),
            ),
        )
        time.sleep(0.1)

    # ================================================================
    # PHASE 4: Double-echo shift to create higher Var values
    # ================================================================
    print("\n[4] Double-echo: manufacture Var(255) = 0xFF as data")
    print("    echo(251) -> Left(Var(253)); echo(result) -> Left(Left(Var(255)))")

    # echo(echo(251)) with continuation handling
    # echo(251) returns Left(X) where X internally has Var(253)
    # echo(Left(X)) returns Left(Left(X)) where inner vars shift +2 more
    # So Var(253) → Var(255) under double Left
    # But when we extract, shifts cancel. We need to use it WITHOUT extracting.

    # Method: echo(251), then echo the entire Left result, then pass double-wrapped to sys8
    double_echo_probe = apps(
        g(14),
        g(251),
        lam(
            "echo1_left",
            # echo1_left = Left(Var(253)) — but from our perspective it's Left(Var(251))
            # Now echo the entire Left wrapper
            apps(
                g(14),
                v("echo1_left"),
                lam(
                    "echo2_left",
                    # echo2_left = Left(echo1_left_shifted) = Left(Left(Var(253+2)))
                    apps(g(8), v("echo2_left"), DISC8),
                ),
            ),
        ),
    )
    run_named("double echo(251) -> sys8(double_Left)", double_echo_probe)
    time.sleep(0.1)

    # Also: echo(252) double
    double_echo_252 = apps(
        g(14),
        g(252),
        lam(
            "e1",
            apps(
                g(14),
                v("e1"),
                lam("e2", apps(g(8), v("e2"), DISC8)),
            ),
        ),
    )
    run_named("double echo(252) -> sys8(double_Left)", double_echo_252)
    time.sleep(0.1)

    # ================================================================
    # PHASE 5: sys8 with password/credential strings
    # ================================================================
    print("\n[5] sys8 with credential strings as byte lists")

    credentials = [
        ("ilikephp", b"ilikephp"),
        ("GZKc.2/VQffio", b"GZKc.2/VQffio"),
        ("gizmore", b"gizmore"),
        ("root", b"root"),
        ("sudo deluser dloser", b"sudo deluser dloser"),
        ("00fefe", b"\x00\xfe\xfe"),  # nil bytes
        ("/bin/sh", b"/bin/sh"),
        ("/home/gizmore", b"/home/gizmore"),
    ]

    for name, data in credentials:
        byte_list = NConst(encode_bytes_list(data))
        run_named(
            f"sys8(bytestr {name!r})",
            apps(g(8), byte_list, DISC8),
        )
        time.sleep(0.1)

    # ================================================================
    # PHASE 6: sys8 with bytecode-as-data (programs as byte lists)
    # ================================================================
    print("\n[6] sys8 with bytecode programs as byte lists")
    print("    What if sys8 is 'exec' that runs a program?")

    bytecode_programs = [
        # nil program: 00 FE FE FF
        ("nil prog", b"\x00\xfe\xfe\xff"),
        # identity: 00 FE FF
        ("id prog", b"\x00\xfe\xff"),
        # echo(nil): 0E 00 FE FE FD FF
        ("echo(nil) prog", b"\x0e\x00\xfe\xfe\xfd\xff"),
        # Just FF
        ("just FF", b"\xff"),
        # sys8(nil) with QD: 08 00 FE FE FD <QD> FD FF
        (
            "sys8(nil)+QD prog",
            bytes([0x08, 0x00, 0xFE, 0xFE, 0xFD]) + QD + bytes([0xFD, 0xFF]),
        ),
        # The QD itself as bytecode
        ("QD prog", QD + bytes([0xFF])),
        # Just bytes: FD FE FF (the special bytes)
        ("FD FE FF", b"\xfd\xfe\xff"),
        # Backdoor start: 00 FE FE
        ("00 FE FE (nil)", b"\x00\xfe\xfe"),
        # The bytecode for the "3 leaf" hint
        ("3leaf: 08 0E FB FD FD FF", b"\x08\x0e\xfb\xfd\xfd\xff"),
    ]

    for name, bytecode in bytecode_programs:
        byte_list = NConst(encode_bytes_list(bytecode))
        run_named(
            f"sys8(bytecode {name!r})",
            apps(g(8), byte_list, DISC8),
        )
        time.sleep(0.1)

    # ================================================================
    # PHASE 7: sys8 with integer arguments we might have missed
    # ================================================================
    print("\n[7] sys8 with specific integer arguments")

    for n in [8, 14, 42, 201, 253, 254, 255, 256, 88, 65, 46, 11]:
        int_arg = NConst(encode_byte_term(n))
        run_named(
            f"sys8(int {n})",
            apps(g(8), int_arg, DISC8),
        )
        time.sleep(0.05)

    # ================================================================
    # PHASE 8: Use echo to manufacture Var(FD/FE/FF) and pass to sys8
    # within a SINGLE term (no extraction)
    # ================================================================
    print("\n[8] Echo + sys8 without extraction — sys8 sees internal Var(253+)")

    # Key idea: Inside echo's Left handler, we're under 2 lambdas.
    # So if we capture Var(251) via echo, inside the handler it becomes Var(253).
    # If we apply sys8 INSIDE the handler, sys8 sees Var(253) as its argument.
    # But wait — we're under lambdas, so Var(253) = global 253 - binder_depth.
    # Actually no: in de Bruijn, Var(253) at depth 2 = global 251.
    # The shifts cancel. Hmm.

    # BUT: what if we use NConst to embed a term with literal Var(253)?
    # NConst shifts by the current binder depth. At depth 0, Var(253) stays Var(253).
    # So: sys8(Var(253)) at top level = bytes: 08 FD FD FF — wait, Var(253) = byte 0xFD
    # which is the App marker! This is UNPARSEABLE in wire format!

    # THIS is the key insight: Var(253), Var(254), Var(255) CANNOT be sent over the wire
    # because those byte values are FD/FE/FF markers. The ONLY way to create them is
    # at RUNTIME via echo's +2 shift under the Left wrapper.

    # So the question is: can we construct a term where sys8 sees a Var(253+)
    # as its argument, using echo's runtime shift?

    # Inside echo(251)'s Left handler at depth +2:
    # The captured value is conceptually Var(253), but when referenced as a bound
    # variable in the handler, it resolves to the original Var(251).
    # There's no way to "keep" the shifted value — the shift is a property of
    # the encoding under lambdas, not the actual value.

    # UNLESS we use the raw echo Left wrapper without extracting.
    # echo(251) = Left(Var(253 in raw encoding))
    # If we quote this, quote tries to serialize Var(253) → 0xFD → conflict!
    # "Encoding failed!" = proof that Var(253) EXISTS in the term.

    # What if sys8 doesn't care about our encoding? What if sys8 internally
    # pattern-matches on the RAW TERM and looks for Var(253/254/255)?

    # We already tested sys8(echo_Left_wrapper) → R.
    # But what about sys8(echo_Left_wrapper_of_252)?
    # echo(252) → Left(Var(254)) in raw = FE = lambda marker!
    # echo(250) → Left(Var(252)) in raw = FC = still valid Var

    # Let me try ALL near-boundary values
    for seed in range(248, 253):
        # Pass the UN-EXTRACTED Left wrapper to sys8
        run_named(
            f"sys8(Left_raw from echo({seed}))",
            apps(
                g(14),
                g(seed),
                lam("lw", apps(g(8), v("lw"), DISC8)),
            ),
        )
        time.sleep(0.05)

    # ================================================================
    # PHASE 9: What if sys8 needs a PAIR (like backdoor format)?
    # ================================================================
    print("\n[9] sys8 with pair-structured arguments")

    # Scott pair: λf. f A B
    # What if sys8 needs (username, password) pair?
    pairs = [
        (
            "pair(gizmore, ilikephp)",
            lam(
                "f",
                apps(
                    v("f"),
                    NConst(encode_bytes_list(b"gizmore")),
                    NConst(encode_bytes_list(b"ilikephp")),
                ),
            ),
        ),
        (
            "pair(root, x)",
            lam(
                "f",
                apps(
                    v("f"),
                    NConst(encode_bytes_list(b"root")),
                    NConst(encode_bytes_list(b"x")),
                ),
            ),
        ),
        (
            "pair(dloser, x)",
            lam(
                "f",
                apps(
                    v("f"),
                    NConst(encode_bytes_list(b"dloser")),
                    NConst(encode_bytes_list(b"x")),
                ),
            ),
        ),
    ]
    for name, pair_term in pairs:
        run_named(
            f"sys8({name})",
            apps(g(8), pair_term, DISC8),
        )
        time.sleep(0.1)

    print("\n" + "=" * 70)
    print("ORACLE V4 PROBE COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
