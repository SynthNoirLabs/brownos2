#!/usr/bin/env python3
"""
Oracle V5 Probe: Out-of-band data, multi-term, non-singleton stacks,
sys8 without continuation, write-based observation.

Key insight from Oracle consultation:
1) Out-of-band data: bytes AFTER 0xFF, or multi-term per connection
2) Non-singleton parse stacks: leave 2+ items on stack at 0xFF
3) sys8 without CPS continuation
4) Use write-based debug instead of QD to avoid "Encoding failed!" blind spots
5) Echo-manufactured Var(253) as a runtime primitive
6) "3 params before the trap" — stack manipulation
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
    NGlob,
    NLam,
    NApp,
    NVar,
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


def query_raw(
    payload: bytes, timeout_s: float = 8.0, shutdown: bool = True
) -> tuple[bytes, float]:
    """Send payload, return (output, elapsed_seconds)."""
    start = time.monotonic()
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            if shutdown:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            out = recv_all_raw(sock, timeout_s=timeout_s)
            elapsed = time.monotonic() - start
            return out, elapsed
    except Exception as e:
        return f"ERR:{e}".encode(), time.monotonic() - start


def query_raw_twostage(
    payload1: bytes, payload2: bytes, delay: float = 0.5, timeout_s: float = 8.0
) -> tuple[bytes, float]:
    """Send payload1, wait, send payload2, then read."""
    start = time.monotonic()
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload1)
            time.sleep(delay)
            sock.sendall(payload2)
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
    if data.startswith(b"ERR:"):
        return data.decode("utf-8", "replace")
    try:
        text = data.decode("ascii")
        if text.isprintable() or text.strip().isprintable():
            return f"TEXT:{text!r}"
        return f"HEX:{data.hex()} ({len(data)}b)"
    except:
        pass
    return f"HEX:{data.hex()} ({len(data)}b)"


def run_raw(name: str, payload: bytes, timeout_s: float = 8.0, shutdown: bool = True):
    out, elapsed = query_raw(payload, timeout_s=timeout_s, shutdown=shutdown)
    desc = describe(out)
    interesting = desc not in ("EMPTY", "INVALID")
    tag = "***" if interesting else "   "
    print(f"  {tag} {name:60s} -> {desc} ({elapsed:.1f}s)")
    if interesting and desc.startswith("HEX:"):
        try:
            if 0xFF in out:
                term = parse_term(out)
                t, p = decode_either(term)
                if t == "Right":
                    code = decode_byte_term(p)
                    print(f"      Decoded: Right({code})")
                else:
                    print(f"      Decoded: Left(payload)")
        except:
            pass
    return out, elapsed


def run_raw_twostage(
    name: str,
    payload1: bytes,
    payload2: bytes,
    delay: float = 0.5,
    timeout_s: float = 8.0,
):
    out, elapsed = query_raw_twostage(
        payload1, payload2, delay=delay, timeout_s=timeout_s
    )
    desc = describe(out)
    interesting = desc not in ("EMPTY", "INVALID")
    tag = "***" if interesting else "   "
    print(f"  {tag} {name:60s} -> {desc} ({elapsed:.1f}s)")
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


# Write-based discriminator: writes "L" for Left, "R" for Right
# Unlike QD, this doesn't use quote, so Var(253+) won't cause Encoding failed
DISC_WRITE = lam(
    "res",
    apps(
        v("res"),
        lam("_l", write_str("L")),
        lam("_r", write_str("R")),
    ),
)

# More detailed: write "L:" then try to observe the payload
DISC_WRITE_DETAIL = lam(
    "res",
    apps(
        v("res"),
        lam(
            "left_val",
            # Write "L" marker then try to write the left value as bytes
            # (this will only work if left_val is a bytes list, otherwise just "L")
            apps(g(2), NConst(encode_bytes_list(b"L")), NIL),
        ),
        lam(
            "right_val",
            apps(g(2), NConst(encode_bytes_list(b"R")), NIL),
        ),
    ),
)


def main():
    print("=" * 70)
    print("ORACLE V5 PROBE: Out-of-band, multi-term, stack tricks")
    print("=" * 70)

    # ================================================================
    # PHASE 1: Out-of-band data AFTER 0xFF
    # ================================================================
    print("\n[1] Out-of-band data after 0xFF")
    print("    What if the server reads bytes after FF as 'stdin' for syscalls?")
    print("    Or if extra data changes VM state?")

    # sys8(nil) with QD, then extra bytes after FF
    base_sys8 = bytes([0x08, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])

    extras = [
        ("sys8+QD then 'ilikephp\\n'", base_sys8 + b"ilikephp\n"),
        ("sys8+QD then 0x00FEFE (nil bytes)", base_sys8 + bytes([0x00, FE, FE])),
        ("sys8+QD then FF", base_sys8 + bytes([FF])),
        ("sys8+QD then 'gizmore\\nilikephp\\n'", base_sys8 + b"gizmore\nilikephp\n"),
        ("sys8+QD then backdoor bytes 00FEFE", base_sys8 + bytes([0x00, FE, FE, FF])),
        ("sys8+QD then identity FE bytes", base_sys8 + bytes([0x00, FE, FF])),
    ]

    for name, payload in extras:
        run_raw(name, payload)
        time.sleep(0.15)

    # ================================================================
    # PHASE 2: Multi-term per connection
    # ================================================================
    print("\n[2] Multi-term per connection (term1 FF term2 FF)")
    print("    What if the server processes multiple terms sequentially?")

    # echo(nil) first, then sys8(nil)+QD
    echo_nil = bytes([0x0E, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])
    sys8_qd = bytes([0x08, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])

    multi_terms = [
        ("echo(nil)+QD THEN sys8(nil)+QD", echo_nil + sys8_qd),
        (
            "backdoor(nil)+QD THEN sys8(nil)+QD",
            bytes([0xC9, 0x00, FE, FE, FD]) + QD + bytes([FD, FF]) + sys8_qd,
        ),
        (
            "write('test') THEN sys8(nil)+QD",
            # Simple: just write 'A' then sys8
            # ((write [0x41]) nil) FF ((sys8 nil) QD) FF
            bytes([0x02])
            + encode_term(encode_bytes_list(b"A"))
            + bytes([FD, 0x00, FE, FE, FD, FF])
            + sys8_qd,
        ),
        ("sys8(nil)+QD THEN sys8(nil)+QD (double call)", sys8_qd + sys8_qd),
    ]

    for name, payload in multi_terms:
        run_raw(name, payload)
        time.sleep(0.15)

    # ================================================================
    # PHASE 3: Two-stage sends (send term, wait, send more)
    # ================================================================
    print("\n[3] Two-stage sends (term first, then more bytes after delay)")

    twostage = [
        ("sys8(nil)+QD ... then 'ilikephp'", sys8_qd, b"ilikephp\n"),
        ("sys8(nil)+QD ... then sys8(nil)+QD", sys8_qd, sys8_qd),
        (
            "echo(251)+QD ... then sys8(nil)+QD",
            bytes([0x0E, 0xFB, FD]) + QD + bytes([FD, FF]),
            sys8_qd,
        ),
        # Send term without FF first, then send FF separately
        (
            "sys8(nil)+QD split: term then FF",
            bytes([0x08, 0x00, FE, FE, FD]) + QD + bytes([FD]),
            bytes([FF]),
        ),
    ]

    for name, p1, p2 in twostage:
        run_raw_twostage(name, p1, p2, delay=0.3)
        time.sleep(0.15)

    # ================================================================
    # PHASE 4: Non-singleton parse stacks
    # ================================================================
    print("\n[4] Non-singleton parse stacks (multiple items at FF)")
    print("    What if leaving 2+ items on the stack is 'passing parameters'?")
    print("    gizmore: 'transfer my parameters to the kernel'")

    stack_probes = [
        # Leave 2 items: sys8 and nil (no FD to apply them)
        ("stack[sys8, nil]", bytes([0x08, 0x00, FE, FE, FF])),
        # Leave 3 items: sys8, nil, QD
        ("stack[sys8, nil, QD]", bytes([0x08, 0x00, FE, FE]) + QD + bytes([FF])),
        # Leave 3 items: sys8, echo, nil
        ("stack[sys8, echo, nil]", bytes([0x08, 0x0E, 0x00, FE, FE, FF])),
        # Leave 3 items: 3 Var "leafs"
        ("stack[Var8, Var14, Var201]", bytes([0x08, 0x0E, 0xC9, FF])),
        # Leave 2 items: sys8 applied to nil, then QD (no outer FD)
        ("stack[(sys8 nil), QD]", bytes([0x08, 0x00, FE, FE, FD]) + QD + bytes([FF])),
        # Leave 2 items: (sys8 nil) and nil
        ("stack[(sys8 nil), nil]", bytes([0x08, 0x00, FE, FE, FD, 0x00, FE, FE, FF])),
        # "3 leafs" literally: 3 bare variables
        ("stack[Var0, Var0, Var0]", bytes([0x00, 0x00, 0x00, FF])),
        ("stack[Var8, Var0, Var0]", bytes([0x08, 0x00, 0x00, FF])),
        ("stack[Var8, Var14, Var0]", bytes([0x08, 0x0E, 0x00, FF])),
        # Stack underflow: FD with only 1 item
        # This is likely "Invalid term!" but let's check
        ("stack underflow: 0x08 FD", bytes([0x08, FD, FF])),
        # Empty program
        ("empty: just FF", bytes([FF])),
        # Single Var
        ("stack[Var8]", bytes([0x08, FF])),
        ("stack[Var14]", bytes([0x0E, FF])),
    ]

    for name, payload in stack_probes:
        run_raw(name, payload)
        time.sleep(0.1)

    # ================================================================
    # PHASE 5: sys8 WITHOUT continuation (just (sys8 arg), not ((sys8 arg) k))
    # ================================================================
    print("\n[5] sys8 without continuation — observe via side effects")
    print("    What if sys8 performs a side effect (writes answer to socket)?")

    # (sys8 nil) — one application, no continuation
    nocont = [
        ("(sys8 nil) alone", bytes([0x08, 0x00, FE, FE, FD, FF])),
        ("(sys8 Var0) alone", bytes([0x08, 0x00, FD, FF])),
        # sys8 alone (no application at all)
        ("sys8 alone (Var8)", bytes([0x08, FF])),
        # (sys8 ilikephp_bytes) alone
        (
            "(sys8 'ilikephp') alone",
            bytes([0x08])
            + encode_term(encode_bytes_list(b"ilikephp"))
            + bytes([FD, FF]),
        ),
        # (sys8 gizmore_password_pair) alone
        # pair = λf.f "gizmore" "ilikephp"
    ]

    for name, payload in nocont:
        run_raw(name, payload, timeout_s=12.0)
        time.sleep(0.15)

    # ================================================================
    # PHASE 6: sys8 with write-based observation (no QD/quote)
    # ================================================================
    print("\n[6] sys8 with write-based discriminator (avoids Encoding failed!)")

    # Test sys8 with various args using write-based DISC instead of QD
    write_disc_tests = [
        ("sys8(nil) write-disc", apps(g(8), NIL, DISC_WRITE)),
        ("sys8(Var0) write-disc", apps(g(8), g(0), DISC_WRITE)),
        # echo-extracted values without QD
        (
            "echo(251)->extract->sys8 write-disc",
            apps(
                g(14),
                g(251),
                lam(
                    "eres",
                    apps(
                        v("eres"),
                        lam("extracted", apps(g(8), v("extracted"), DISC_WRITE)),
                        lam("_eerr", write_str("E")),
                    ),
                ),
            ),
        ),
        # echo Left wrapper directly to sys8
        (
            "echo(251)->Left_wrapper->sys8 write-disc",
            apps(
                g(14), g(251), lam("left_wrap", apps(g(8), v("left_wrap"), DISC_WRITE))
            ),
        ),
        # Double echo
        (
            "echo(echo(251))->sys8 write-disc",
            apps(
                g(14),
                g(251),
                lam(
                    "e1",
                    apps(g(14), v("e1"), lam("e2", apps(g(8), v("e2"), DISC_WRITE))),
                ),
            ),
        ),
    ]

    for name, term in write_disc_tests:
        run_named(name, term, timeout_s=10.0)
        time.sleep(0.15)

    # ================================================================
    # PHASE 7: Echo-manufactured Var(253) as runtime primitive
    # ================================================================
    print("\n[7] Echo Var(253) as runtime primitive — does it reduce?")
    print("    If Var(253)=App marker, it might be a kernel-level 'apply'")

    # echo(251) produces Left(Var(253 in raw)), extract it, then APPLY it
    # to some args and see if anything special happens
    prim_tests = [
        # Extract Var(253 raw) and apply to two args: maybe it's "App"?
        (
            "echo(251) extract -> apply to nil nil",
            apps(
                g(14),
                g(251),
                lam(
                    "eres",
                    apps(
                        v("eres"),
                        lam("prim", apps(v("prim"), NIL, NIL)),
                        lam("_err", write_str("E")),
                    ),
                ),
            ),
        ),
        # Extract and try as continuation to sys8
        (
            "echo(251) extract -> as sys8 cont",
            apps(
                g(14),
                g(251),
                lam(
                    "eres",
                    apps(
                        v("eres"),
                        lam("prim", apps(g(8), NIL, v("prim"))),
                        lam("_err", write_str("E")),
                    ),
                ),
            ),
        ),
        # Quote the RESULT of applying echo's Left to identity
        # (not the raw Left which breaks quote)
        (
            "echo(251) -> extract -> quote(extracted)",
            apps(
                g(14),
                g(251),
                lam(
                    "eres",
                    apps(
                        v("eres"),
                        lam(
                            "extracted",
                            apps(
                                g(4),
                                v("extracted"),
                                lam(
                                    "qres",
                                    apps(
                                        v("qres"),
                                        lam("qbytes", apps(g(2), v("qbytes"), NIL)),
                                        lam("_qerr", write_str("Q")),
                                    ),
                                ),
                            ),
                        ),
                        lam("_eerr", write_str("E")),
                    ),
                ),
            ),
        ),
    ]

    for name, term in prim_tests:
        run_named(name, term, timeout_s=10.0)
        time.sleep(0.15)

    # ================================================================
    # PHASE 8: Chaining echo BEFORE sys8 in various ways (state change)
    # ================================================================
    print("\n[8] Echo as kernel interrupt: echo(X) THEN sys8(Y)")
    print("    Does echo change VM state that sys8 checks?")

    echo_state_tests = [
        # echo(nil) then sys8(nil)
        (
            "echo(nil) THEN sys8(nil)",
            apps(g(14), NIL, lam("_e", apps(g(8), NIL, DISC_WRITE))),
        ),
        # echo(ilikephp) then sys8(nil)
        (
            "echo('ilikephp') THEN sys8(nil)",
            apps(
                g(14),
                NConst(encode_bytes_list(b"ilikephp")),
                lam("_e", apps(g(8), NIL, DISC_WRITE)),
            ),
        ),
        # echo(gizmore's hash) then sys8
        (
            "echo('GZKc.2/VQffio') THEN sys8(nil)",
            apps(
                g(14),
                NConst(encode_bytes_list(b"GZKc.2/VQffio")),
                lam("_e", apps(g(8), NIL, DISC_WRITE)),
            ),
        ),
        # echo(backdoor_pair) then sys8
        # first get pair from backdoor, then echo it, then sys8
        (
            "backdoor->pair->echo(pair)->sys8(nil)",
            apps(
                g(201),
                NIL,
                lam(
                    "bd_res",
                    apps(
                        v("bd_res"),
                        lam(
                            "pair",
                            apps(
                                g(14), v("pair"), lam("_e", apps(g(8), NIL, DISC_WRITE))
                            ),
                        ),
                        lam("_err", write_str("B")),
                    ),
                ),
            ),
        ),
        # echo(omega) then sys8
        (
            "backdoor->pair->omega->echo(omega)->sys8(nil)",
            apps(
                g(201),
                NIL,
                lam(
                    "bd_res",
                    apps(
                        v("bd_res"),
                        lam(
                            "pair",
                            apps(
                                g(14),
                                apps(
                                    v("pair"), lam("a", lam("b", apps(v("a"), v("b"))))
                                ),
                                lam("_e", apps(g(8), NIL, DISC_WRITE)),
                            ),
                        ),
                        lam("_err", write_str("B")),
                    ),
                ),
            ),
        ),
        # echo(int 1000) for gizmore's UID
        (
            "echo(int1000=gizmore UID) THEN sys8(nil)",
            apps(g(14), NConst(int_term(1000)), lam("_e", apps(g(8), NIL, DISC_WRITE))),
        ),
        # echo(int 0) for root UID
        (
            "echo(int0=root UID) THEN sys8(nil)",
            apps(g(14), NConst(int_term(0)), lam("_e", apps(g(8), NIL, DISC_WRITE))),
        ),
    ]

    for name, term in echo_state_tests:
        run_named(name, term, timeout_s=10.0)
        time.sleep(0.15)

    # ================================================================
    # PHASE 9: "sudo" — authenticate then sys8
    # ================================================================
    print("\n[9] sudo-style: pass credentials via some mechanism then sys8")

    # What if sys8 takes a PAIR of (credential, command)?
    # pair = λf.f cred cmd
    sudo_tests = [
        # sys8(pair(ilikephp, nil))
        (
            "sys8(pair('ilikephp', nil))",
            apps(
                g(8),
                lam("f", apps(v("f"), NConst(encode_bytes_list(b"ilikephp")), NIL)),
                DISC_WRITE,
            ),
        ),
        # sys8(pair(1000, nil)) — UID-based auth
        (
            "sys8(pair(uid1000, nil))",
            apps(g(8), lam("f", apps(v("f"), NConst(int_term(1000)), NIL)), DISC_WRITE),
        ),
        # sys8(pair(0, nil)) — root UID
        (
            "sys8(pair(uid0, nil))",
            apps(g(8), lam("f", apps(v("f"), NConst(int_term(0)), NIL)), DISC_WRITE),
        ),
        # sys8 with backdoor pair directly
        (
            "backdoor(nil)->pair->sys8(pair)",
            apps(
                g(201),
                NIL,
                lam(
                    "bd",
                    apps(
                        v("bd"),
                        lam("pair", apps(g(8), v("pair"), DISC_WRITE)),
                        lam("_err", write_str("B")),
                    ),
                ),
            ),
        ),
        # sys8(backdoor_omega)
        (
            "backdoor->omega->sys8(omega)",
            apps(
                g(201),
                NIL,
                lam(
                    "bd",
                    apps(
                        v("bd"),
                        lam(
                            "pair",
                            apps(
                                g(8),
                                apps(
                                    v("pair"), lam("a", lam("b", apps(v("a"), v("b"))))
                                ),
                                DISC_WRITE,
                            ),
                        ),
                        lam("_err", write_str("B")),
                    ),
                ),
            ),
        ),
    ]

    for name, term in sudo_tests:
        run_named(name, term, timeout_s=10.0)
        time.sleep(0.15)

    # ================================================================
    # PHASE 10: What if the answer isn't from sys8 at all?
    # ================================================================
    print("\n[10] Non-sys8 answer candidates: test against hash")
    print("     Running hash checks on unexplored candidates")

    import hashlib

    target = "9252ed65ffac2aa763adb21ef72c0178f1d83286"

    def check_hash(candidate: str) -> bool:
        h = hashlib.sha1(candidate.encode("utf-8")).hexdigest()
        for _ in range(56153):
            h = hashlib.sha1(h.encode("utf-8")).hexdigest()
        return h == target

    # Extended candidate list — things we might not have tried
    candidates = [
        # Exact file content strings (with/without newline)
        "Uhm... yeah... no...",
        "Uhm... yeah... no...\n",
        "Oh, go choke on a towel!",
        "Oh go choke on a towel",
        # Backdoor pair components
        "lambda a.lambda b.(b b)",
        "lambda a.lambda b.(a b)",
        "\\a.\\b.(b b)",
        "\\a.\\b.(a b)",
        # The specific hex of the backdoor pair
        "00 01 FD FE FE 00 01 FD FE FE",
        # The omega combinator in various formats
        "\\x.(x x)",
        "lambda x.(x x)",
        "(\\x.x x)(\\x.x x)",
        # The "3 leaf" program bytes
        "08 0E FB",
        "080EFB",
        # Error code 6
        "Permission denied",
        "permission denied",
        # Gizmore's quote about kernel
        "interrupt",
        "kernel",
        # CPS-related
        "continuation",
        "call/cc",
        # The string from .history
        "sodu deluser dloser",
        "sudo deluser dloser",
        # Backdoor email content
        "Backdoor is ready at syscall 201; start with 00 FE FE.",
        "Backdoor is ready at syscall 201",
        # Simple answers
        "42",
        "brownos",
        "BrownOS",
        "brown",
        "Brown",
        "the brownos",
        "The BrownOS",
        # File 256
        "wtf",
        "WTF",
        # Access log format
        "access",
        # Echo-related
        "echo",
        "Echo",
        # PHP reference (gizmore likes PHP)
        "ilikephp",
        "I like PHP",
        "php",
        "PHP",
        # Numeric answers
        "0",
        "1",
        "6",
        "8",
        "14",
        "201",
        "253",
        "256",
        # Lambda calculus terms
        "Lam(Lam(App(Var(1), Var(0))))",
        "\\l.\\r.l",
        "\\l.\\r.r",
        "Left",
        "Right",
        "left",
        "right",
        # Sys8 with specific results
        "Right(6)",
        "Right 6",
        # De Bruijn
        "de Bruijn",
        "de bruijn",
        "debruijn",
        # Challenge author
        "dloser",
        "gizmore",
        "Gizmore",
        "tehron",
        "space",
        # Combinators
        "S",
        "K",
        "I",
        "SKI",
        "Y",
        "omega",
        "Omega",
        # OS concepts
        "root",
        "admin",
        "su",
        "sudo",
        # The actual important one: Maybe the answer is a specific lambda term bytecode
        # represented as hex
        "00FE",
        "00FEFE",
        "08",
        "0E",
        "C9",
        "FDFE",
        "FDFEFF",
        # Boolean / Church
        "true",
        "false",
        "True",
        "False",
        # What if it's literally the word "towel"?
        "towel",
        "Towel",
        "42 towel",
        # Hitchhiker's reference
        "Don't Panic",
        "dont panic",
        # Password-related
        "x",
        "password",
        "shadow",
        # What if the answer is just a single character?
        "L",
        "R",
        "E",
        # Success message format
        "success",
        "granted",
        "access granted",
        "permission granted",
        # Shell
        "sh",
        "/bin/sh",
        # What if it involves the hash itself?
        "9252ed65ffac2aa763adb21ef72c0178f1d83286",
        # mailer
        "mailer",
        "boss@evil.com",
        # Possible numeric answers
        "1000",
        "1002",
        "100",
        # Delivery failure
        "Delivery failure",
    ]

    print(f"  Testing {len(candidates)} candidates against hash...")
    found = False
    for c in candidates:
        if check_hash(c):
            print(f"  *** HASH MATCH: {c!r} ***")
            found = True
    if not found:
        print(f"  No hash matches found in {len(candidates)} candidates.")

    print("\n" + "=" * 70)
    print("ORACLE V5 PROBE COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
