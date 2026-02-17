#!/usr/bin/env python3
"""
Probe: Does calling echo BEFORE sys8 change sys8's behavior?

Hypothesis: echo might set some internal state (like a "logged in" flag)
that sys8 checks. The challenge narrative supports this:
- gizmore's password is "ilikephp"
- The mail says "Backdoor is ready at syscall 201"
- gizmore: "cmd to interrupt and transfer my parameters to the kernel"

What if the sequence is:
1. echo(password) → sets auth state
2. sys8(arg) → now succeeds because authenticated

OR:
1. echo(some_specific_term) → "interrupt" that transfers to kernel
2. Result of echo feeds into sys8

Also testing: using echo to build a self-referencing/recursive structure.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FD,
    FE,
    FF,
    encode_term,
    encode_byte_term,
    encode_bytes_list,
    parse_term,
)

HOST = "wc3.wechall.net"
PORT = 61221

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


@dataclass(frozen=True)
class NVar:
    name: str


@dataclass(frozen=True)
class NGlob:
    index: int


@dataclass(frozen=True)
class NLam:
    param: str
    body: object


@dataclass(frozen=True)
class NApp:
    f: object
    x: object


@dataclass(frozen=True)
class NConst:
    term: object


def shift_db(term: object, delta: int, cutoff: int = 0) -> object:
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_db(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_db(term.f, delta, cutoff), shift_db(term.x, delta, cutoff))
    return term


def to_db(term: object, env: tuple[str, ...] = ()) -> object:
    if isinstance(term, NVar):
        return Var(env.index(term.name))
    if isinstance(term, NGlob):
        return Var(term.index + len(env))
    if isinstance(term, NLam):
        return Lam(to_db(term.body, (term.param,) + env))
    if isinstance(term, NApp):
        return App(to_db(term.f, env), to_db(term.x, env))
    if isinstance(term, NConst):
        return shift_db(term.term, len(env))
    raise TypeError(f"Unsupported: {type(term)}")


def g(i: int) -> NGlob:
    return NGlob(i)


def v(n: str) -> NVar:
    return NVar(n)


def lam(p: str, b: object) -> NLam:
    return NLam(p, b)


def app(f: object, x: object) -> NApp:
    return NApp(f, x)


def apps(*ts: object) -> object:
    out = ts[0]
    for t in ts[1:]:
        out = app(out, t)
    return out


NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)


def int_n(n: int) -> NConst:
    return NConst(encode_byte_term(n))


def str_term(s: str) -> NConst:
    return NConst(encode_bytes_list(s.encode()))


def recv_all(sock: socket.socket, timeout_s: float) -> bytes:
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


def send_named(term: object, timeout_s: float = 5.0) -> bytes:
    payload = encode_term(to_db(term)) + bytes([FF])
    delay = 0.15
    for _ in range(3):
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
            delay *= 2
    return b""


def classify(out: bytes) -> str:
    if not out:
        return "EMPTY"
    if out.startswith(b"Invalid term!"):
        return "INVALID"
    if out.startswith(b"Encoding failed!"):
        return "ENCFAIL"
    try:
        text = out.decode("ascii", errors="replace")
        if all(c.isprintable() or c in "\r\n\t" for c in text):
            return f"TEXT:{text[:100]}"
    except Exception:
        pass
    return f"HEX:{out[:60].hex()}"


def make_dbg() -> object:
    """Quote-free Either observer. Right→error string→write. Left→write 'L'."""
    return lam(
        "result",
        apps(
            v("result"),
            lam("leftval", apps(g(2), str_term("L:"), NIL)),
            lam(
                "errcode",
                apps(
                    g(1),
                    v("errcode"),
                    lam(
                        "es_res",
                        apps(
                            v("es_res"),
                            lam("errstr", apps(g(2), v("errstr"), NIL)),
                            lam("es_err", NIL),
                        ),
                    ),
                ),
            ),
        ),
    )


def make_dbg_write() -> object:
    """Quote-free Either observer. Left→write content. Right→error string→write."""
    return lam(
        "result",
        apps(
            v("result"),
            lam("leftval", apps(g(2), v("leftval"), NIL)),
            lam(
                "errcode",
                apps(
                    g(1),
                    v("errcode"),
                    lam(
                        "es_res",
                        apps(
                            v("es_res"),
                            lam("errstr", apps(g(2), v("errstr"), NIL)),
                            lam("es_err", NIL),
                        ),
                    ),
                ),
            ),
        ),
    )


def main():
    print("=" * 60)
    print("PROBE: Echo-then-sys8 sequences")
    print("=" * 60)

    DBG = make_dbg()
    DBG_W = make_dbg_write()

    # ------------------------------------------------------------------
    # SECTION 1: echo(X) → ignore result → sys8(nil) → DBG
    # ------------------------------------------------------------------
    print("\n--- Section 1: echo(X) → ignore → sys8(nil) → DBG ---")

    echo_args = [
        ("nil", NIL),
        ("int_0", int_n(0)),
        ("g(8)", g(8)),
        ("g(0)", g(0)),
        ("g(14)", g(14)),
        ("g(201)", g(201)),
        ("str_ilikephp", str_term("ilikephp")),
        ("str_gizmore", str_term("gizmore")),
        ("str_root", str_term("root")),
        ("str_sudo", str_term("sudo")),
        ("str_kernel", str_term("kernel")),
        ("identity", lam("x", v("x"))),
    ]

    for name, arg in echo_args:
        # echo(arg) → _result → sys8(nil) → DBG
        term = apps(g(0x0E), arg, lam("_echo_res", apps(g(8), NIL, DBG)))
        out = send_named(term)
        print(f"  echo({name}) → sys8(nil): {classify(out)}")
        time.sleep(0.08)

    # ------------------------------------------------------------------
    # SECTION 2: echo(X) → result → sys8(result) → DBG
    # (pass echo's result directly to sys8)
    # ------------------------------------------------------------------
    print("\n--- Section 2: echo(X) → sys8(echo_result) → DBG ---")

    for name, arg in echo_args[:8]:
        term = apps(g(0x0E), arg, lam("echo_res", apps(g(8), v("echo_res"), DBG)))
        out = send_named(term)
        print(f"  echo({name}) → sys8(result): {classify(out)}")
        time.sleep(0.08)

    # ------------------------------------------------------------------
    # SECTION 3: Multiple echo calls chained before sys8
    # ------------------------------------------------------------------
    print("\n--- Section 3: Multiple echoes chained → sys8 ---")

    # echo(ilikephp) → echo(result) → echo(result) → sys8(final)
    term = apps(
        g(0x0E),
        str_term("ilikephp"),
        lam(
            "e1",
            apps(
                g(0x0E),
                v("e1"),
                lam("e2", apps(g(0x0E), v("e2"), lam("e3", apps(g(8), v("e3"), DBG)))),
            ),
        ),
    )
    out = send_named(term)
    print(f"  echo^3(ilikephp) → sys8: {classify(out)}")
    time.sleep(0.1)

    # echo(g(8)) → echo(result) → sys8(final)
    term = apps(
        g(0x0E),
        g(8),
        lam("e1", apps(g(0x0E), v("e1"), lam("e2", apps(g(8), v("e2"), DBG)))),
    )
    out = send_named(term)
    print(f"  echo(g(8)) → echo(result) → sys8: {classify(out)}")
    time.sleep(0.1)

    # ------------------------------------------------------------------
    # SECTION 4: echo as "interrupt" — echo(sys8)
    # What if echoing syscall 8 itself does something?
    # ------------------------------------------------------------------
    print("\n--- Section 4: echo(sys8) variations ---")

    # echo(sys8) → Left(sys8_ref) → extract → apply to (nil, DBG)
    term = apps(
        g(0x0E),
        g(8),
        lam(
            "echo_res",
            apps(
                v("echo_res"),
                lam(
                    "sys8_ref",  # Left branch
                    apps(v("sys8_ref"), NIL, DBG),
                ),
                lam("err", apps(g(2), str_term("E"), NIL)),
            ),
        ),
    )
    out = send_named(term)
    print(f"  echo(sys8) → extract Left → apply(nil, DBG): {classify(out)}")
    time.sleep(0.1)

    # echo(sys8) → Left(sys8_ref) → extract → sys8(sys8_ref, DBG)
    term = apps(
        g(0x0E),
        g(8),
        lam(
            "echo_res",
            apps(
                v("echo_res"),
                lam("sys8_ref", apps(g(8), v("sys8_ref"), DBG)),
                lam("err", apps(g(2), str_term("E"), NIL)),
            ),
        ),
    )
    out = send_named(term)
    print(f"  echo(sys8) → sys8(echoed_sys8): {classify(out)}")
    time.sleep(0.1)

    # ------------------------------------------------------------------
    # SECTION 5: Backdoor + echo combination
    # ------------------------------------------------------------------
    print("\n--- Section 5: Backdoor + echo combinations ---")

    # backdoor(nil) → pair → echo(pair) → result → sys8(result, DBG)
    term = apps(
        g(201),
        NIL,
        lam(
            "bd_res",
            apps(
                v("bd_res"),
                lam(
                    "pair",
                    apps(
                        g(0x0E),
                        v("pair"),
                        lam("echo_res", apps(g(8), v("echo_res"), DBG)),
                    ),
                ),
                lam("err", apps(g(2), str_term("BE"), NIL)),
            ),
        ),
    )
    out = send_named(term)
    print(f"  bd → pair → echo(pair) → sys8(echo_res): {classify(out)}")
    time.sleep(0.1)

    # echo(backdoor) → sys8(echo_result)
    term = apps(g(0x0E), g(201), lam("echo_res", apps(g(8), v("echo_res"), DBG)))
    out = send_named(term)
    print(f"  echo(g(201)) → sys8(echo_res): {classify(out)}")
    time.sleep(0.1)

    # ------------------------------------------------------------------
    # SECTION 6: The UID/auth hypothesis
    # What if sys8 needs ECHO to have been called with gizmore's UID?
    # ------------------------------------------------------------------
    print("\n--- Section 6: Auth via echo with credentials ---")

    # passwd line: gizmore:GZKc.2/VQffio:1000:1000:...
    # uid=1000, password=ilikephp

    creds = [
        ("pair(uid,pw)", lam("f", apps(v("f"), int_n(1000), str_term("ilikephp")))),
        (
            "pair(user,pw)",
            lam("f", apps(v("f"), str_term("gizmore"), str_term("ilikephp"))),
        ),
        ("pair(uid,0)", lam("f", apps(v("f"), int_n(1000), int_n(0)))),
        ("int_1000", int_n(1000)),
        ("pair(0,pw)", lam("f", apps(v("f"), int_n(0), str_term("ilikephp")))),
    ]

    for name, cred in creds:
        # echo(cred) → _ → sys8(nil, DBG)
        term = apps(g(0x0E), cred, lam("_", apps(g(8), NIL, DBG)))
        out = send_named(term)
        print(f"  echo({name}) → sys8(nil): {classify(out)}")
        time.sleep(0.1)

    # ------------------------------------------------------------------
    # SECTION 7: Syscall 3 (not implemented?) - but what if it needs echo?
    # ------------------------------------------------------------------
    print("\n--- Section 7: Syscall 3 investigation ---")

    # g(3) returned Right(1) = NotImpl for normal args
    # But QD internals reference g(3) — what role does it play?

    # QD: λres. (g(4) res (λbytes. (bytes (λbyte. (g(4) byte g(2))) g(1))))
    # Wait — let me re-examine QD. The bytes reference g(3) inside the lambda:
    # QD raw: 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
    # Parse: Lam(App(App(Var(5), Var(0)), Lam(App(App(Var(0), Lam(App(App(Var(5), Var(0)), Var(3)))), Var(2)))))
    # At top level (inside 1 lambda): Var(5)=g(4), Var(0)=arg
    #   continuation: Lam(App(App(Var(0), Lam(App(App(Var(5), Var(0)), Var(3)))), Var(2)))
    #   Inside that lambda (2 lambdas deep): Var(0)=bytes, Var(2)=g(0), Var(5)=g(3)
    #   Wait: Var(0)=current lambda param (bytes), Var(1)=outer lambda param (res),
    #   Var(2)=g(0), Var(3)=g(1), Var(4)=g(2), Var(5)=g(3)
    #   So: bytes (λbyte. (g(3) byte g(1))) g(0)
    # Hmm, g(3) and g(1) and g(0) inside the 2-lambda deep context...
    # g(0) used as the "nil" case of list traversal?
    # g(1) = error_string, g(3) = not_implemented?

    # Actually QD does: quote(term) → Left(bytes) → fold bytes through write
    # The inner part: bytes (λbyte. (quote byte, write)) nil_case
    # But that uses g(3) as quote inside? Let me re-check:
    # Inside 2 lambdas:
    #   Var(5) = g(5-2) = g(3) at top level
    #   Var(3) = g(3-2) = g(1) at top level
    #   Var(2) = g(2-2) = g(0) at top level
    # Wait that's not right. Globals start at Var(0) at top level.
    # Inside 1 lambda: globals shift by +1. g(0)=Var(1), g(1)=Var(2), etc.
    # Inside 2 lambdas: g(0)=Var(2), g(1)=Var(3), g(2)=Var(4), g(3)=Var(5)
    # So inside 2 lambdas:
    #   Var(5) = g(3)    ← syscall 3 (not implemented!?)
    #   Var(3) = g(1)    ← error_string
    #   Var(2) = g(0)    ← the "stuck" thing

    # Wait, but QD WORKS! It successfully writes results. So:
    # Inside the continuation (2 lambdas deep):
    # bytes_list (λbyte. (g(3) byte g(1))) g(0)
    # This calls the Scott list with:
    #   cons_handler = λbyte. (g(3) byte g(1))  → for each byte: g(3)(byte, g(1))
    #   nil_handler = g(0)
    # And QD successfully outputs bytes...
    # So g(3) must be WRITE (not "not implemented"), and g(0) must be the nil case!

    # OMG. Let me re-analyze: QD at top level:
    # λres. (g(4) res (λbytes. (bytes (λbyte. (g(3) byte g(1))) g(0))))
    # g(4) = quote
    # g(3) = ??? (used as the per-byte handler)
    # g(1) = ??? (continuation for g(3))
    # g(0) = nil handler

    # If g(3) is write_byte or write: g(3)(byte, g(1)) writes byte then continues with g(1)
    # g(1) continuation... continues what?
    # This is a fold: for each byte in the list, call handler(byte), chain continuations

    # CRITICAL: QD uses g(3) to write individual bytes!
    # g(3) is NOT "not implemented" — it must be write or write_byte!
    # But we tested g(3)(nil)(QD) and got Right(1) = NotImpl?

    # Unless... g(3) IS write but expects different args than what we tested!
    # Let's test g(3) with a byte term and a continuation

    for n in [0x41, 0x42, 0x00]:  # 'A', 'B', 0
        term = apps(g(3), int_n(n), lam("_", apps(g(2), str_term("OK"), NIL)))
        out = send_named(term)
        print(f"  g(3)(int({n}), write_OK): {classify(out)}")
        time.sleep(0.1)

    # g(3) with raw byte value (not encoded as 9-lambda)
    for n in [0x41, 0x00]:
        term = apps(g(3), NConst(Var(n)), lam("_", apps(g(2), str_term("OK"), NIL)))
        out = send_named(term, timeout_s=4.0)
        print(f"  g(3)(Var({n}), write_OK): {classify(out)}")
        time.sleep(0.1)

    # Actually, maybe the issue is that QD's "g(3)" when tested as a syscall
    # from top-level is really syscall index 3. But inside QD's lambdas,
    # Var(5) maps to g(3) because QD adds 2 lambdas.
    # So g(3) at top level = syscall 3.
    # But QD uses g(3) INSIDE 2 lambdas, and it works.
    # This means syscall 3 DOES work with the right argument types!

    # What does syscall 3 do? In QD's context:
    # bytes_list applied to (λbyte. (g(3) byte continuation)) nil_case
    # So it's called as: g(3)(byte_term)(next_step)
    # This looks like: write_byte(byte, continuation)

    # Let's test sys3 with byte terms properly
    byte_A = NConst(encode_byte_term(0x41))
    term = apps(g(3), byte_A, lam("_", apps(g(2), str_term("|DONE"), NIL)))
    out = send_named(term)
    print(f"\n  g(3)(byte_A, then_write_DONE): {classify(out)}")
    time.sleep(0.1)

    # With the NIL continuation (just like in QD's nil case = g(0))
    term = apps(g(3), byte_A, NIL)
    out = send_named(term)
    print(f"  g(3)(byte_A, nil): {classify(out)}")
    time.sleep(0.1)

    # Actually wait... let me re-read QD more carefully.
    # QD: λres. ((g(4) res) (λbytes. ((bytes (λbyte. ((g(3) byte) g(1)))) g(0))))
    # Parsing the App tree more carefully from the hex:
    # 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
    # Stack trace:
    # 05 → Var(5)
    # 00 → Var(0)
    # FD → App(Var(5), Var(0))
    # 00 → Var(0) [new]
    # 05 → Var(5) [new]
    # 00 → Var(0) [new]
    # FD → App(Var(5), Var(0))
    # 03 → Var(3)
    # FD → App(App(Var(5),Var(0)), Var(3))
    # FE → Lam(App(App(Var(5),Var(0)), Var(3)))
    # FD → App(Var(0), Lam(App(App(Var(5),Var(0)), Var(3))))
    # 02 → Var(2)
    # FD → App(App(Var(0), Lam(App(App(Var(5),Var(0)), Var(3)))), Var(2))
    # FE → Lam(App(App(Var(0), Lam(App(App(Var(5),Var(0)), Var(3)))), Var(2)))
    # FD → App(App(Var(5),Var(0)), Lam(App(App(Var(0), Lam(App(App(Var(5),Var(0)), Var(3)))), Var(2))))
    # FE → Lam(App(App(Var(5),Var(0)), Lam(App(App(Var(0), Lam(App(App(Var(5),Var(0)), Var(3)))), Var(2)))))

    # So QD = λ. ((V5 V0) (λ. ((V0 (λ. ((V5 V0) V3))) V2)))
    # Under lambda 1: V5=g(4), V0=res
    # Inner: (g(4) res) applied to continuation λ. ((V0 (λ. ((V5 V0) V3))) V2)
    # Under lambda 2: V0=bytes (from quote), V2=g(0), V5=g(3)
    # bytes_list(λ. ((V5 V0) V3))(V2) = bytes_list(λ. ((g(3) V0) g(1)))(g(0))
    # Under lambda 3: V0=byte_elem, V3=g(1), V5=g(3)
    # (g(3) byte_elem) g(1)

    # So QD conceptually: quote(res, λbytes. bytes(λbyte. g(3)(byte, g(1)), g(0)))
    # g(3) is called with (byte, g(1)) for each byte in the quoted output
    # g(1) is the CONTINUATION for g(3)

    # This means: g(3)(byte, continuation) writes a single byte then calls continuation
    # g(0) is called when the list is empty (nil handler)
    # g(1) acts as the "recursive" continuation — it's passed as continuation to g(3) each time

    # But wait, g(1) from top level is... error_string (syscall 1)!
    # That can't be right as a continuation for write_byte...
    # Unless g(1) HERE is not being used as a syscall but as a TERM that gets
    # passed to g(3) as its continuation, and g(3)(byte, k) writes byte then calls k.
    # But k = g(1) = error_string. So after writing each byte, it calls error_string?
    # That doesn't make sense for the output we see...

    # WAIT. The Scott list fold works differently:
    # bytes = cons(h, t) = λc.λn. c h t
    # bytes (cons_handler) (nil_handler)
    # = cons_handler h t
    # For QD: cons_handler = λbyte. g(3)(byte, g(1))
    # So: (λbyte. g(3)(byte, g(1))) h t
    # = g(3)(h, g(1)) t
    # g(3)(h, g(1)) needs to return something that gets applied to t!
    # So g(3)(byte, continuation) → continuation gets called with result,
    # result is then applied to the TAIL of the list.

    # g(3) is write-byte: g(3)(byte, k) writes the byte, then calls k(something)
    # k = g(1). So g(1) gets called with the write result.
    # g(1)(write_result) should return a FUNCTION that accepts the tail.
    # g(1) = error_string. error_string(write_result) = Left("some string")
    # which then gets applied to tail...

    # This is getting confused. Let me just TEST what g(3) does.

    print("\n--- Deeper g(3) testing ---")
    # Test: what does g(3) return when used in CPS?
    term = apps(g(3), int_n(0x41), NConst(parse_term(QD + bytes([FF]))))
    out = send_named(term)
    print(f"  g(3)(0x41, QD): {classify(out)}")
    time.sleep(0.1)

    # Direct byte write test
    term = apps(
        g(3), int_n(0x48), lam("r", apps(g(3), int_n(0x49), NIL))
    )  # 'H' then 'I'
    out = send_named(term)
    print(f"  g(3)(H, then g(3)(I)): {classify(out)}")
    time.sleep(0.1)

    print("\n" + "=" * 60)
    print("PROBE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
