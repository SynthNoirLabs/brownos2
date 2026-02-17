#!/usr/bin/env python3
"""
Probe g(0) as the BrownOS kernel/evaluator.

Key hypothesis: g(0) is the kernel entry point. It takes a program (in some format)
and executes it in a privileged context where sys8 might succeed.

Tests:
A. g(0) with a raw lambda term that writes "K|"
B. g(0) with a quoted/serialized form of that term
C. g(0) reading from socket (interactive kernel)
D. g(0) with the BrownOS frame structure
E. sys8 inside g(0) evaluation
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
    decode_either,
    decode_bytes_list,
)

HOST = "wc3.wechall.net"
PORT = 61221

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


# --- Named term builder ---
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


# --- Network ---
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
    return query_raw(payload, timeout_s=timeout_s)


def query_raw(payload: bytes, timeout_s: float = 5.0, retries: int = 3) -> bytes:
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
            delay = min(delay * 2.0, 2.0)
    return b""


def query_interactive(
    payload1: bytes,
    payload2: bytes = b"",
    delay_between: float = 0.5,
    timeout_s: float = 5.0,
) -> bytes:
    """Send payload1, optionally wait, then send payload2, collect all output."""
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload1)
            if payload2:
                time.sleep(delay_between)
                try:
                    sock.sendall(payload2)
                except OSError:
                    pass
            # Don't shutdown write yet if we might need to send more
            if not payload2:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            else:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            return recv_all(sock, timeout_s=timeout_s)
    except Exception as e:
        return f"ERROR:{e}".encode()


def classify(out: bytes) -> str:
    if not out:
        return "EMPTY"
    if out.startswith(b"Invalid term!"):
        return "INVALID"
    if out.startswith(b"Encoding failed!"):
        return "ENCFAIL"
    if out.startswith(b"Term too big!"):
        return "TOOBIG"
    try:
        text = out.decode("ascii", errors="replace")
        if all(c.isprintable() or c in "\r\n\t" for c in text):
            return f"TEXT:{text[:100]}"
    except Exception:
        pass
    return f"HEX:{out[:60].hex()}"


def make_dbg() -> object:
    """Quote-free Either observer. Left->write "L", Right->write error string."""
    right_branch = lam(
        "errcode",
        apps(
            g(1),
            v("errcode"),
            lam(
                "es_result",
                apps(
                    v("es_result"),
                    lam("errstr", apps(g(2), v("errstr"), NIL)),
                    lam("es_err", NIL),
                ),
            ),
        ),
    )
    left_branch = lam("leftval", apps(g(2), str_term("L"), NIL))
    return lam("result", apps(v("result"), left_branch, right_branch))


def make_dbg_write() -> object:
    """Quote-free Either observer. Left->write content, Right->write error string."""
    right_branch = lam(
        "errcode",
        apps(
            g(1),
            v("errcode"),
            lam(
                "es_result",
                apps(
                    v("es_result"),
                    lam("errstr", apps(g(2), v("errstr"), NIL)),
                    lam("es_err", NIL),
                ),
            ),
        ),
    )
    left_branch = lam("leftval", apps(g(2), v("leftval"), NIL))
    return lam("result", apps(v("result"), left_branch, right_branch))


def main():
    print("=" * 60)
    print("PROBE: g(0) as BrownOS Kernel")
    print("=" * 60)

    DBG = make_dbg()
    DBG_W = make_dbg_write()

    # ------------------------------------------------------------------
    # TEST A: g(0) with raw lambda term that writes "K|"
    # ------------------------------------------------------------------
    print("\n--- TEST A: g(0) with raw lambda term ---")

    # A1: write_program = write("K|", nil)
    # As a term: ((g(2) "K|") nil)
    write_prog = apps(g(2), str_term("K|"), NIL)

    # g(0)(write_prog) — no continuation needed since g(0) doesn't return
    out = send_named(apps(g(0), write_prog))
    print(f"  A1: g(0)(write('K|', nil)): {classify(out)}")
    time.sleep(0.15)

    # A2: Same but with a dummy continuation
    out = send_named(apps(g(0), write_prog, NIL))
    print(f"  A2: g(0)(write('K|', nil))(nil): {classify(out)}")
    time.sleep(0.15)

    # A3: g(0) applied to just the string "K|" (byte list)
    out = send_named(apps(g(0), str_term("K|")))
    print(f"  A3: g(0)('K|'): {classify(out)}")
    time.sleep(0.15)

    # A4: g(0) applied to a CPS program: sys8(nil) → write result
    sys8_prog = apps(g(8), NIL, DBG_W)
    out = send_named(apps(g(0), sys8_prog))
    print(f"  A4: g(0)(sys8(nil,DBG_W)): {classify(out)}")
    time.sleep(0.15)

    # A5: g(0) applied to QD applied to int 42
    qd_term = NConst(parse_term(QD + bytes([FF])))
    out = send_named(apps(g(0), apps(qd_term, int_n(42))))
    print(f"  A5: g(0)(QD(42)): {classify(out)}")
    time.sleep(0.15)

    # ------------------------------------------------------------------
    # TEST B: g(0) with QUOTED (serialized) programs
    # ------------------------------------------------------------------
    print("\n--- TEST B: g(0) with quoted programs ---")

    # The idea: serialize a program to bytes via quote, then feed bytes to g(0)
    # quote(term) → Left(bytes) → g(0)(bytes)

    # B1: quote(write("K|", nil)) → bytes → g(0)(bytes)
    def quote_then_g0(inner: object) -> object:
        return apps(
            g(4),
            inner,
            lam(
                "q_result",
                apps(
                    v("q_result"),
                    lam("bytes", apps(g(0), v("bytes"))),
                    lam("q_err", apps(g(2), str_term("QE"), NIL)),
                ),
            ),
        )

    out = send_named(quote_then_g0(write_prog))
    print(f"  B1: g(0)(quote(write('K|'))): {classify(out)}")
    time.sleep(0.15)

    # B2: Feed raw bytes of a small program directly as a byte list
    # The program: sys8 nil QD → bytes: 08 00fefe FD QD FD FF
    # = [0x08, 0x00, 0xFE, 0xFE, 0xFD] + QD_bytes + [0xFD, 0xFF]
    prog_bytes = bytes([0x08, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])
    out = send_named(apps(g(0), NConst(encode_bytes_list(prog_bytes))))
    print(f"  B2: g(0)(bytelist of 'sys8 nil QD'): {classify(out)}")
    time.sleep(0.15)

    # B3: Feed the bytes of "write('K|') nil" as a byte list
    write_k_bytes = encode_term(to_db(write_prog)) + bytes([FF])
    out = send_named(apps(g(0), NConst(encode_bytes_list(write_k_bytes))))
    print(f"  B3: g(0)(bytelist of write('K|')): {classify(out)}")
    time.sleep(0.15)

    # B4: g(0) with just the bytes of QD itself
    qd_bytes_list = NConst(encode_bytes_list(QD + bytes([FF])))
    out = send_named(apps(g(0), qd_bytes_list))
    print(f"  B4: g(0)(bytelist of QD): {classify(out)}")
    time.sleep(0.15)

    # ------------------------------------------------------------------
    # TEST C: Interactive kernel (g(0) reading from socket)
    # ------------------------------------------------------------------
    print("\n--- TEST C: Interactive kernel test ---")

    # C1: Send g(0)(nil) WITHOUT FF first, then send more bytes
    # If g(0) reads from socket, the second send should be consumed
    payload1_no_ff = encode_term(to_db(apps(g(0), NIL)))  # no FF
    payload2 = bytes([FF])  # just the FF to close the term
    out = query_interactive(payload1_no_ff, payload2, delay_between=0.3)
    print(f"  C1: g(0)(nil) [split send]: {classify(out)}")
    time.sleep(0.15)

    # C2: Send g(0) as first term (complete with FF), then send a second program
    term1 = encode_term(to_db(apps(g(0), NIL))) + bytes([FF])
    term2 = bytes([0x08, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])
    out = query_interactive(term1, term2, delay_between=0.5, timeout_s=5.0)
    print(f"  C2: g(0)(nil) then sys8_prog: {classify(out)}")
    time.sleep(0.15)

    # C3: Just g(0) alone (no argument) with FF
    out = query_raw(bytes([0x00, FF]))
    print(f"  C3: bare Var(0) + FF: {classify(out)}")
    time.sleep(0.15)

    # C4: g(0) then second program without shutting down write
    try:
        with socket.create_connection((HOST, PORT), timeout=5.0) as sock:
            # Send g(0)(nil) + FF
            sock.sendall(term1)
            time.sleep(1.0)
            # Now send another program on same socket
            try:
                sock.sendall(term2)
            except OSError as e:
                print(f"  C4: second send failed: {e}")
            time.sleep(0.5)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            out = recv_all(sock, timeout_s=3.0)
            print(f"  C4: g(0)(nil)+FF then sys8+FF [no shutdown]: {classify(out)}")
    except Exception as e:
        print(f"  C4: ERROR: {e}")
    time.sleep(0.15)

    # ------------------------------------------------------------------
    # TEST D: BrownOS frame structure as g(0) argument
    # ------------------------------------------------------------------
    print("\n--- TEST D: BrownOS frame structure ---")

    # The cheat sheet: BrownOS[<syscall> <argument> FD <rest> FD]
    # What if we need to build this as a lambda term structure?
    # ((syscall argument) rest) is the normal CPS form
    # But what if g(0) expects it in a DIFFERENT structure?

    # D1: g(0) applied to the CPS structure itself
    # ((sys8 nil) QD) as a term, passed to g(0)
    cps_prog = apps(g(8), NIL, NConst(parse_term(QD + bytes([FF]))))
    out = send_named(apps(g(0), cps_prog))
    print(f"  D1: g(0)(((sys8 nil) QD)): {classify(out)}")
    time.sleep(0.15)

    # D2: g(0) with 3-tuple structure: (syscall, arg, rest)
    # Using Scott triple: λf. f syscall arg rest
    triple = lam("f", apps(v("f"), g(8), NIL, NConst(parse_term(QD + bytes([FF])))))
    out = send_named(apps(g(0), triple))
    print(f"  D2: g(0)(triple(sys8, nil, QD)): {classify(out)}")
    time.sleep(0.15)

    # D3: g(0) with a pair (syscall, arg) and QD as second argument
    pair = lam("f", apps(v("f"), g(8), NIL))
    out = send_named(apps(g(0), pair, NConst(parse_term(QD + bytes([FF])))))
    print(f"  D3: g(0)(pair(sys8,nil), QD): {classify(out)}")
    time.sleep(0.15)

    # ------------------------------------------------------------------
    # TEST E: More g(0) variations
    # ------------------------------------------------------------------
    print("\n--- TEST E: g(0) variations ---")

    # E1: g(0)(g(0)) — self application of kernel
    out = send_named(apps(g(0), g(0)), timeout_s=5.0)
    print(f"  E1: g(0)(g(0)): {classify(out)}")
    time.sleep(0.15)

    # E2: g(0)(identity) — kernel with identity function
    identity = lam("x", v("x"))
    out = send_named(apps(g(0), identity))
    print(f"  E2: g(0)(λx.x): {classify(out)}")
    time.sleep(0.15)

    # E3: backdoor → pair → g(0)(pair)
    out = send_named(
        apps(
            g(201),
            NIL,
            lam(
                "bd_res",
                apps(
                    v("bd_res"),
                    lam("pair", apps(g(0), v("pair"))),
                    lam("err", apps(g(2), str_term("BE"), NIL)),
                ),
            ),
        )
    )
    print(f"  E3: g(0)(backdoor_pair): {classify(out)}")
    time.sleep(0.15)

    # E4: g(0) with the backdoor omega combinator (A B = λx.xx)
    # Construct: backdoor → pair → A B → omega → g(0)(omega)
    out = send_named(
        apps(
            g(201),
            NIL,
            lam(
                "bd_res",
                apps(
                    v("bd_res"),
                    lam(
                        "pair",
                        # pair = λx.λy.((x A) B), so pair(λa.λb.a) = ((λa.λb.a A) B) = A
                        # pair(λa.λb.b) = ((λa.λb.b A) B) = B
                        # We need to get A and B and compute (A B)
                        # pair(λa.λb.(a b)) = ((λa.λb.(a b) A) B) = A B = omega
                        apps(
                            g(0),
                            apps(v("pair"), lam("a", lam("b", apps(v("a"), v("b"))))),
                        ),
                    ),
                    lam("err", apps(g(2), str_term("BE"), NIL)),
                ),
            ),
        )
    )
    print(f"  E4: g(0)(omega from backdoor): {classify(out)}")
    time.sleep(0.15)

    # E5: Various globals fed to g(0)
    for idx in [1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
        out = send_named(apps(g(0), g(idx)), timeout_s=4.0)
        result = classify(out)
        if result != "EMPTY":
            print(f"  E5: g(0)(g({idx})): {result}")
        time.sleep(0.08)
    print(f"  E5: all g(0)(g(N)) results shown above (EMPTY ones hidden)")

    # E6: g(0) with integer arguments
    for n in [0, 1, 8, 42, 201, 255]:
        out = send_named(apps(g(0), int_n(n)), timeout_s=4.0)
        result = classify(out)
        if result != "EMPTY":
            print(f"  E6: g(0)(int({n})): {result}")
        time.sleep(0.08)
    print(f"  E6: all g(0)(int(N)) results shown above (EMPTY ones hidden)")

    # ------------------------------------------------------------------
    # TEST F: What if g(0) needs TWO specific arguments?
    # ------------------------------------------------------------------
    print("\n--- TEST F: g(0) with two arguments ---")

    # F1: g(0)(sys8)(nil)  — kernel(syscall, argument)
    out = send_named(apps(g(0), g(8), NIL))
    print(f"  F1: g(0)(g(8))(nil): {classify(out)}")
    time.sleep(0.1)

    # F2: g(0)(nil)(sys8)
    out = send_named(apps(g(0), NIL, g(8)))
    print(f"  F2: g(0)(nil)(g(8)): {classify(out)}")
    time.sleep(0.1)

    # F3: g(0)(sys8)(nil)(QD) — three args
    out = send_named(apps(g(0), g(8), NIL, NConst(parse_term(QD + bytes([FF])))))
    print(f"  F3: g(0)(g(8))(nil)(QD): {classify(out)}")
    time.sleep(0.1)

    # F4: g(0) with backdoor pair as first arg, sys8 as second
    out = send_named(
        apps(
            g(201),
            NIL,
            lam(
                "bd_res",
                apps(
                    v("bd_res"),
                    lam("pair", apps(g(0), v("pair"), g(8))),
                    lam("err", apps(g(2), str_term("BE"), NIL)),
                ),
            ),
        )
    )
    print(f"  F4: g(0)(bd_pair)(g(8)): {classify(out)}")
    time.sleep(0.1)

    # ------------------------------------------------------------------
    # TEST G: Does g(0) write directly to socket?
    # ------------------------------------------------------------------
    print("\n--- TEST G: g(0) direct socket write test ---")

    # G1: write("BEFORE|") → g(0)(write("INSIDE|", nil))
    # If g(0) executes the write, we should see "BEFORE|INSIDE|"
    out = send_named(
        apps(
            g(2),
            str_term("BEFORE|"),
            lam("_", apps(g(0), apps(g(2), str_term("INSIDE|"), NIL))),
        )
    )
    print(f"  G1: write('BEFORE|') → g(0)(write('INSIDE|')): {classify(out)}")
    time.sleep(0.15)

    # G2: Same but g(0) wrapping sys8+write
    out = send_named(
        apps(g(2), str_term("BEFORE|"), lam("_", apps(g(0), apps(g(8), NIL, DBG_W))))
    )
    print(f"  G2: write('BEFORE|') → g(0)(sys8(nil)+write): {classify(out)}")
    time.sleep(0.15)

    print("\n" + "=" * 60)
    print("PROBE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
