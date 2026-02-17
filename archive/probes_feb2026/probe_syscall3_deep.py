#!/usr/bin/env python3
"""
Deep investigation of syscall 3 (g(3)).

Previously thought to be "not implemented", but it DOES work with integer arguments!
QD shows it's used inside the debug continuation itself.
Need to figure out what syscall 3 actually does.
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
    decode_byte_term,
    strip_lams,
    eval_bitset_expr,
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


def shift_db(term, delta, cutoff=0):
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_db(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_db(term.f, delta, cutoff), shift_db(term.x, delta, cutoff))
    return term


def to_db(term, env=()):
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


def g(i):
    return NGlob(i)


def v(n):
    return NVar(n)


def lam(p, b):
    return NLam(p, b)


def app(f, x):
    return NApp(f, x)


def apps(*ts):
    out = ts[0]
    for t in ts[1:]:
        out = app(out, t)
    return out


NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)


def int_n(n):
    return NConst(encode_byte_term(n))


def str_term(s):
    return NConst(encode_bytes_list(s.encode()))


def recv_all(sock, timeout_s):
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


def send_named(term, timeout_s=5.0):
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


def classify(out):
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
    except:
        pass
    return f"HEX:{out[:60].hex()}"


def decode_result(out):
    """Try to parse QD output and decode Either."""
    if not out or FF not in out:
        return None
    try:
        term = parse_term(out)
        tag, payload = decode_either(term)
        if tag == "Right":
            code = decode_byte_term(payload)
            return f"Right({code})"
        elif tag == "Left":
            try:
                bs = decode_bytes_list(payload)
                return f"Left(bytes={bs!r})"
            except:
                return f"Left(term={payload})"
    except Exception as e:
        return f"ParseError({e})"


def make_dbg_full():
    """DBG that shows L: or error string, plus writes the raw tag."""
    return lam(
        "result",
        apps(
            v("result"),
            lam(
                "leftval",
                apps(
                    g(2),
                    str_term("L:"),
                    lam(
                        "_",
                        apps(
                            g(4),
                            v("leftval"),
                            lam(
                                "q_res",
                                apps(
                                    v("q_res"),
                                    lam("qbytes", apps(g(2), v("qbytes"), NIL)),
                                    lam("qerr", apps(g(2), str_term("QE"), NIL)),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            lam(
                "errcode",
                apps(
                    g(1),
                    v("errcode"),
                    lam(
                        "es_res",
                        apps(
                            v("es_res"),
                            lam(
                                "errstr",
                                apps(
                                    g(2),
                                    str_term("R:"),
                                    lam("_", apps(g(2), v("errstr"), NIL)),
                                ),
                            ),
                            lam("es_err", NIL),
                        ),
                    ),
                ),
            ),
        ),
    )


QD_TERM = NConst(parse_term(QD + bytes([FF])))


def main():
    print("=" * 60)
    print("PROBE: Syscall 3 Deep Investigation")
    print("=" * 60)

    DBG = make_dbg_full()

    # ------------------------------------------------------------------
    # Section 1: g(3) with QD to see what it returns
    # ------------------------------------------------------------------
    print("\n--- Section 1: g(3)(X, QD) ---")

    test_args = [
        ("nil", NIL),
        ("int_0", int_n(0)),
        ("int_1", int_n(1)),
        ("int_42", int_n(42)),
        ("int_65", int_n(65)),  # 'A'
        ("int_255", int_n(255)),
        ("str_A", str_term("A")),
        ("str_ilikephp", str_term("ilikephp")),
        ("g(0)", g(0)),
        ("g(2)", g(2)),
        ("g(3)", g(3)),
        ("g(4)", g(4)),
        ("g(8)", g(8)),
        ("g(14)", g(14)),
        ("identity", lam("x", v("x"))),
    ]

    for name, arg in test_args:
        out = send_named(apps(g(3), arg, QD_TERM))
        result = decode_result(out)
        print(f"  g(3)({name}, QD): {result or classify(out)}")
        time.sleep(0.08)

    # ------------------------------------------------------------------
    # Section 2: g(3) with DBG (quote-free)
    # ------------------------------------------------------------------
    print("\n--- Section 2: g(3)(X, DBG) ---")

    for name, arg in test_args:
        out = send_named(apps(g(3), arg, DBG))
        print(f"  g(3)({name}, DBG): {classify(out)}")
        time.sleep(0.08)

    # ------------------------------------------------------------------
    # Section 3: What if g(3) is write_byte? Test if it outputs raw bytes.
    # ------------------------------------------------------------------
    print("\n--- Section 3: g(3) output detection ---")

    # write("PRE|") → g(3)(int_65) → write("|POST")
    for n in [65, 66, 48, 0x0A]:
        out = send_named(
            apps(
                g(2),
                str_term("PRE|"),
                lam(
                    "_",
                    apps(g(3), int_n(n), lam("_2", apps(g(2), str_term("|POST"), NIL))),
                ),
            )
        )
        print(f"  PRE|g(3)(int_{n})|POST: {classify(out)}")
        time.sleep(0.08)

    # ------------------------------------------------------------------
    # Section 4: g(3) in the EXACT way QD uses it
    # ------------------------------------------------------------------
    print("\n--- Section 4: QD-style usage of g(3) ---")

    # In QD: g(3)(byte, g(1))
    # g(1) = error_string syscall
    # Let's replicate: g(3)(int_65, g(1))
    # Then apply the result to something?

    # Actually in QD's fold:
    # cons(h, t)(cons_handler)(nil_handler) = cons_handler(h)(t)
    # cons_handler = λbyte. g(3)(byte, g(1))
    # So: (λbyte. g(3)(byte, g(1)))(h)(t) = g(3)(h, g(1))(t)
    # g(3)(h, g(1)) must return a FUNCTION that accepts t (the tail)
    # Then that function processes the tail...

    # g(3)(byte, continuation) → continuation(result) → result(tail)
    # For the Scott list fold to work, the result after continuation
    # must be applicable to the tail.

    # In QD: g(3)(byte, g(1))
    # g(1) = error_string. So g(1)(result) = Left("error string for result")
    # Then Left("...")(tail) = λl.λr.(l "...")(tail) = ...
    # That doesn't make sense for a list fold!

    # UNLESS g(3) doesn't work like other CPS syscalls.
    # What if g(3)(byte, continuation) writes byte to socket AND
    # returns the continuation directly (without calling it with a result)?

    # Let me test: g(3)(byte, identity)(write("AFTER"))
    out = send_named(
        apps(
            apps(g(3), int_n(65), lam("x", v("x"))),  # g(3)(65, id)
            apps(g(2), str_term("AFTER"), NIL),  # then apply result to write("AFTER")
        )
    )
    print(f"  (g(3)(65, id))(write('AFTER')): {classify(out)}")
    time.sleep(0.1)

    # g(3)(byte, K)(something) — K = λx.λy.x
    K = lam("x", lam("y", v("x")))
    out = send_named(apps(apps(g(3), int_n(65), K), apps(g(2), str_term("AFTER"), NIL)))
    print(f"  (g(3)(65, K))(write('AFTER')): {classify(out)}")
    time.sleep(0.1)

    # What if g(3) writes the byte and then returns its second argument?
    # g(3)(byte, k) → k  (writes byte as side effect, returns k)
    # Then g(3)(byte, g(1))(tail) = g(1)(tail) = error_string(tail)
    # But tail is the rest of the list...

    # Let me just test: does g(3) write a byte?
    # Simple: g(3)(int_65, nil)  — if it writes 'A', we'll see it
    out = send_named(apps(g(3), int_n(65), NIL))
    print(f"  g(3)(65, nil): {classify(out)}")  # We saw EMPTY before
    time.sleep(0.1)

    # g(3)(65, write("K"))  — if g(3) writes 'A' then calls continuation
    out = send_named(apps(g(3), int_n(65), lam("_", apps(g(2), str_term("K"), NIL))))
    print(
        f"  g(3)(65, λ_.write('K')): {classify(out)}"
    )  # We saw "K" before, meaning cont called but no 'A'
    time.sleep(0.1)

    # ------------------------------------------------------------------
    # Section 5: What IS syscall 3? Let's test with WRONG arg types
    # ------------------------------------------------------------------
    print("\n--- Section 5: g(3) return value analysis ---")

    # g(3) with QD showed Right(0) for nil, and we need to decode others
    # Let's test g(3) result directly with Either discrimination

    either_disc = lam(
        "res",
        apps(
            v("res"),
            lam(
                "l",
                apps(
                    g(2),
                    str_term("LEFT:"),
                    lam(
                        "_",
                        apps(
                            g(4),
                            v("l"),
                            lam(
                                "qr",
                                apps(
                                    v("qr"),
                                    lam("qb", apps(g(2), v("qb"), NIL)),
                                    lam("qe", apps(g(2), str_term("QE"), NIL)),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            lam(
                "r",
                apps(
                    g(2),
                    str_term("RIGHT:"),
                    lam(
                        "_",
                        apps(
                            g(1),
                            v("r"),
                            lam(
                                "er",
                                apps(
                                    v("er"),
                                    lam("es", apps(g(2), v("es"), NIL)),
                                    lam("ee", NIL),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )

    for name, arg in test_args[:8]:
        out = send_named(apps(g(3), arg, either_disc))
        print(f"  g(3)({name}): {classify(out)}")
        time.sleep(0.08)

    # ------------------------------------------------------------------
    # Section 6: What if g(3) IS the key? Chain: g(3) → sys8
    # ------------------------------------------------------------------
    print("\n--- Section 6: g(3) → sys8 chains ---")

    # g(3)(arg) → result → sys8(result)
    sys8_dbg = lam(
        "g3_result",
        apps(
            v("g3_result"),
            lam(
                "l",
                apps(
                    g(8),
                    v("l"),
                    lam(
                        "s8r",
                        apps(
                            v("s8r"),
                            lam(
                                "sl",
                                apps(
                                    g(2),
                                    str_term("S8_LEFT:"),
                                    lam(
                                        "_",
                                        apps(
                                            g(4),
                                            v("sl"),
                                            lam(
                                                "qr",
                                                apps(
                                                    v("qr"),
                                                    lam("qb", apps(g(2), v("qb"), NIL)),
                                                    lam(
                                                        "qe",
                                                        apps(g(2), str_term("QE"), NIL),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                            lam(
                                "sr",
                                apps(
                                    g(2),
                                    str_term("S8_RIGHT:"),
                                    lam(
                                        "_",
                                        apps(
                                            g(1),
                                            v("sr"),
                                            lam(
                                                "er",
                                                apps(
                                                    v("er"),
                                                    lam("es", apps(g(2), v("es"), NIL)),
                                                    lam("ee", NIL),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            lam(
                "r",
                apps(
                    g(2),
                    str_term("G3_RIGHT:"),
                    lam(
                        "_",
                        apps(
                            g(1),
                            v("r"),
                            lam(
                                "er",
                                apps(
                                    v("er"),
                                    lam("es", apps(g(2), v("es"), NIL)),
                                    lam("ee", NIL),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )

    # g(3)(int_N) → on Left(x): sys8(x)
    for n in [0, 1, 8, 14, 42, 65, 100, 201, 255]:
        out = send_named(apps(g(3), int_n(n), sys8_dbg))
        print(f"  g(3)(int_{n}) → sys8(Left): {classify(out)}")
        time.sleep(0.08)

    # g(3)(string args) → sys8
    for s in ["ilikephp", "gizmore", "root", "sudo", "kernel"]:
        out = send_named(apps(g(3), str_term(s), sys8_dbg))
        print(f"  g(3)('{s}') → sys8(Left): {classify(out)}")
        time.sleep(0.08)

    # ------------------------------------------------------------------
    # Section 7: g(3) with backdoor pair
    # ------------------------------------------------------------------
    print("\n--- Section 7: g(3) with backdoor pair ---")

    # backdoor → pair → g(3)(pair)
    out = send_named(
        apps(
            g(201),
            NIL,
            lam(
                "bd_res",
                apps(
                    v("bd_res"),
                    lam("pair", apps(g(3), v("pair"), either_disc)),
                    lam("err", apps(g(2), str_term("BE"), NIL)),
                ),
            ),
        )
    )
    print(f"  g(3)(backdoor_pair): {classify(out)}")

    print("\n" + "=" * 60)
    print("PROBE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
