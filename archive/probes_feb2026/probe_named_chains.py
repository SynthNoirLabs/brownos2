#!/usr/bin/env python3
"""
Use the named-term builder (probe_mail_focus) for correct CPS chains.

Key findings so far:
- Globals are OPAQUE primitives (quote shows just the Var byte)
- Server processes exactly ONE term per connection (no persistent state)
- sys8 DOES call its continuation with Right(6)
- Arguments ARE evaluated before syscalls receive them
- Backdoor returns Left(pair) where pair = λx.λy.((x A) B)
  with A = λa.λb.(b b), B = λa.λb.(a b)

This probe uses named terms for correct de Bruijn conversion to:
1. Extract pair from backdoor and feed components to sys8
2. Test sys8 with carefully constructed arguments
3. Test if sys8's continuation affects the permission check
4. Try using the pair combinator (A B = ω) as a key
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from probe_mail_focus import (
    FD,
    FE,
    FF,
    HOST,
    PORT,
    NIL,
    NConst,
    NLam,
    NApp,
    NVar,
    NGlob,
    app,
    apps,
    g,
    lam,
    v,
    to_db,
    recv_all,
    classify,
    encode_bytes_list,
)
from solve_brownos_answer import (
    App,
    Lam,
    Var,
    encode_term,
    parse_term,
    decode_either,
    decode_byte_term,
    decode_bytes_list,
    encode_byte_term,
)


QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def query_named(term: object, timeout_s: float = 10.0, retries: int = 3) -> bytes:
    """Send a named term, convert to DB, send to server with FF."""
    db_term = to_db(term)
    payload = encode_term(db_term) + bytes([FF])
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


def qd_term() -> object:
    """Build QD as a named term.
    QD = λresult. ((write (quote result)) (λ_. result))
    Actually QD = λres. ((g(2) ((g(4) res) (λquoted. quoted))) ???)

    Let me parse QD from its bytes to understand its exact structure.
    QD = 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE

    Parsing (postfix):
    05 -> V5
    00 -> V0
    FD -> App(V5, V0)
    00 -> V0
    05 -> V5
    00 -> V0
    FD -> App(V5, V0)
    03 -> V3
    FD -> App(App(V5,V0), V3)
    FE -> Lam(App(App(V5,V0), V3))
    FD -> App(V0, Lam(App(App(V5,V0), V3)))
    02 -> V2
    FD -> App(App(V0, Lam(App(App(V5,V0), V3))), V2)
    FE -> Lam(App(App(V0, Lam(App(App(V5,V0), V3))), V2))
    FD -> App(App(V5, V0), Lam(App(App(V0, Lam(App(App(V5,V0), V3))), V2)))
    FE -> Lam(App(App(V5, V0), Lam(App(App(V0, Lam(App(App(V5,V0), V3))), V2))))

    So QD = Lam(App(App(V5, V0), Lam(App(App(V0, Lam(App(App(V5, V0), V3))), V2))))

    In named form (at top level, V5=g(5), V3=g(3), V2=g(2)):
    QD = λres. (g(5) res (λx. (x (λy. (g(5) y g(3))) g(2))))

    Wait, that doesn't look right. Let me re-parse more carefully.
    """
    # Just use QD as a raw constant
    qd_parsed = parse_term(QD_BYTES + bytes([FF]))
    return NConst(qd_parsed)


QD = qd_term()


def pretty(term: object, depth: int = 0) -> str:
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{pretty(term.body, depth + 1)}"
    if isinstance(term, App):
        return f"({pretty(term.f, depth)} {pretty(term.x, depth)})"
    return str(term)


def decode_and_print(label: str, resp: bytes) -> str:
    """Decode response and print analysis."""
    if not resp:
        print(f"  {label}: EMPTY")
        return "EMPTY"

    if resp.startswith(b"Invalid term!"):
        print(f"  {label}: INVALID TERM")
        return "INVALID"

    if resp.startswith(b"Encoding failed!"):
        print(f"  {label}: ENCODING FAILED")
        return "ENCFAIL"

    try:
        term = parse_term(resp)
        tag, payload = decode_either(term)
        if tag == "Left":
            # Try to decode as bytes
            bs = None
            try:
                bs = decode_bytes_list(payload)
            except Exception:
                pass
            if bs is not None:
                try:
                    text = bs.decode("utf-8", errors="replace")
                    print(f"  {label}: Left(string='{text}')")
                    return f"Left(str={text})"
                except Exception:
                    print(f"  {label}: Left(bytes={bs.hex()[:60]})")
                    return f"Left(bytes)"
            else:
                print(f"  {label}: Left(term={pretty(payload)[:100]})")
                return f"Left(term)"
        elif tag == "Right":
            errcode = decode_byte_term(payload)
            print(f"  {label}: Right({errcode})")
            return f"Right({errcode})"
        else:
            print(f"  {label}: raw={resp.hex()[:60]}")
            return "other"
    except Exception as e:
        print(f"  {label}: PARSE ERROR: {e}  raw={resp.hex()[:60]}")
        return "error"


def main():
    print("=" * 60)
    print("NAMED-TERM CPS CHAINS FOR SYS8 INVESTIGATION")
    print("=" * 60)

    # ============================================================
    # PART 1: Baseline tests using named terms
    # ============================================================
    print("\n--- PART 1: Baselines ---")

    # 1a: sys8(nil) via QD
    term = apps(g(8), NIL, QD)
    resp = query_named(term)
    decode_and_print("sys8(nil)", resp)
    time.sleep(0.15)

    # 1b: echo(nil) via QD
    term = apps(g(14), NIL, QD)
    resp = query_named(term)
    decode_and_print("echo(nil)", resp)
    time.sleep(0.15)

    # 1c: backdoor(nil) via QD
    term = apps(g(201), NIL, QD)
    resp = query_named(term)
    decode_and_print("backdoor(nil)", resp)
    time.sleep(0.15)

    # ============================================================
    # PART 2: CPS chain — backdoor → extract pair → sys8 with pair
    # ============================================================
    print("\n--- PART 2: Backdoor → extract → sys8 ---")

    # 2a: backdoor(nil) → unwrap Left → sys8(pair_val) → QD
    # CPS: ((backdoor nil)
    #   (λresult. ((result
    #     (λpair_val. ((sys8 pair_val) QD)))
    #     (λerr. nil))))
    term = apps(
        g(201),
        NIL,
        lam(
            "result",
            apps(
                v("result"),
                lam("pair_val", apps(g(8), v("pair_val"), QD)),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("backdoor→sys8(pair)", resp)
    time.sleep(0.2)

    # 2b: backdoor → extract A (fst) → sys8(A)
    # pair = λf. f A B, so pair(λa.λb.a) = A
    # CPS: ((backdoor nil)
    #   (λresult. ((result
    #     (λpair_val. ((pair_val (λa.λb.((sys8 a) QD)))))
    #     (λerr. nil)))))
    term = apps(
        g(201),
        NIL,
        lam(
            "result",
            apps(
                v("result"),
                lam(
                    "pair_val",
                    app(v("pair_val"), lam("a", lam("b", apps(g(8), v("a"), QD)))),
                ),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("backdoor→pair(λa.λb.sys8(a))", resp)
    time.sleep(0.2)

    # 2c: backdoor → extract B (snd) → sys8(B)
    term = apps(
        g(201),
        NIL,
        lam(
            "result",
            apps(
                v("result"),
                lam(
                    "pair_val",
                    app(v("pair_val"), lam("a", lam("b", apps(g(8), v("b"), QD)))),
                ),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("backdoor→pair(λa.λb.sys8(b))", resp)
    time.sleep(0.2)

    # 2d: backdoor → extract (A B) = ω → sys8(ω)
    term = apps(
        g(201),
        NIL,
        lam(
            "result",
            apps(
                v("result"),
                lam(
                    "pair_val",
                    app(
                        v("pair_val"),
                        lam("a", lam("b", apps(g(8), app(v("a"), v("b")), QD))),
                    ),
                ),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("backdoor→pair(λa.λb.sys8(a b))", resp)
    time.sleep(0.2)

    # 2e: backdoor → extract (B A) → sys8(B A)
    term = apps(
        g(201),
        NIL,
        lam(
            "result",
            apps(
                v("result"),
                lam(
                    "pair_val",
                    app(
                        v("pair_val"),
                        lam("a", lam("b", apps(g(8), app(v("b"), v("a")), QD))),
                    ),
                ),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("backdoor→pair(λa.λb.sys8(b a))", resp)
    time.sleep(0.2)

    # ============================================================
    # PART 3: Use pair components as CONTINUATION for sys8
    # ============================================================
    print("\n--- PART 3: Pair components as sys8 CONTINUATION ---")

    # 3a: sys8(nil, pair) — use the PAIR itself as continuation
    term = apps(
        g(201),
        NIL,
        lam(
            "result",
            apps(
                v("result"),
                lam("pair_val", apps(g(8), NIL, v("pair_val"))),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("sys8(nil, pair)", resp)
    time.sleep(0.2)

    # 3b: sys8(nil, A) — use A as continuation
    term = apps(
        g(201),
        NIL,
        lam(
            "result",
            apps(
                v("result"),
                lam(
                    "pair_val",
                    app(v("pair_val"), lam("a", lam("b", apps(g(8), NIL, v("a"))))),
                ),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("sys8(nil, A)", resp)
    time.sleep(0.2)

    # 3c: sys8(nil, B) — use B as continuation
    term = apps(
        g(201),
        NIL,
        lam(
            "result",
            apps(
                v("result"),
                lam(
                    "pair_val",
                    app(v("pair_val"), lam("a", lam("b", apps(g(8), NIL, v("b"))))),
                ),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("sys8(nil, B)", resp)
    time.sleep(0.2)

    # ============================================================
    # PART 4: sys8 with password-like arguments (using named terms)
    # ============================================================
    print("\n--- PART 4: sys8 with specific string arguments ---")

    strings_to_try = [
        "ilikephp",
        "gizmore",
        "dloser",
        "root",
        "mailer",
        "brownos",
        "kernel",
        "sudo",
    ]

    for s in strings_to_try:
        str_term = NConst(encode_bytes_list(s.encode()))
        term = apps(g(8), str_term, QD)
        resp = query_named(term, timeout_s=8)
        decode_and_print(f"sys8('{s}')", resp)
        time.sleep(0.15)

    # ============================================================
    # PART 5: sys8 with integer arguments (UID-like)
    # ============================================================
    print("\n--- PART 5: sys8 with integer arguments ---")

    for n in [0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 42, 100, 201, 255, 256, 1000, 1002]:
        int_t = NConst(encode_byte_term(n))
        term = apps(g(8), int_t, QD)
        resp = query_named(term, timeout_s=8)
        decode_and_print(f"sys8({n})", resp)
        time.sleep(0.1)

    # ============================================================
    # PART 6: sys8 with syscall globals as arguments
    # ============================================================
    print("\n--- PART 6: sys8(other_syscall) ---")

    for gid, gname in [
        (1, "error_string"),
        (2, "write"),
        (4, "quote"),
        (5, "readdir"),
        (6, "name"),
        (7, "readfile"),
        (14, "echo"),
        (42, "towel"),
        (201, "backdoor"),
    ]:
        term = apps(g(8), g(gid), QD)
        resp = query_named(term, timeout_s=8)
        decode_and_print(f"sys8(g({gid})={gname})", resp)
        time.sleep(0.1)

    # ============================================================
    # PART 7: What if sys8 needs a PAIR (arg, credential)?
    # ============================================================
    print("\n--- PART 7: sys8 with pair arguments ---")

    # Scott pair: λf. f a b
    def scott_pair(a: object, b: object) -> object:
        return lam("f", apps(v("f"), a, b))

    # 7a: sys8(pair(nil, nil))
    term = apps(g(8), scott_pair(NIL, NIL), QD)
    resp = query_named(term)
    decode_and_print("sys8(pair(nil,nil))", resp)
    time.sleep(0.15)

    # 7b: sys8(pair(1000, "ilikephp"))
    uid_term = NConst(encode_byte_term(1000))
    pwd_term = NConst(encode_bytes_list(b"ilikephp"))
    term = apps(g(8), scott_pair(uid_term, pwd_term), QD)
    resp = query_named(term)
    decode_and_print("sys8(pair(1000,'ilikephp'))", resp)
    time.sleep(0.15)

    # 7c: sys8(pair(0, "root"))
    uid0 = NConst(encode_byte_term(0))
    root_term = NConst(encode_bytes_list(b"root"))
    term = apps(g(8), scott_pair(uid0, root_term), QD)
    resp = query_named(term)
    decode_and_print("sys8(pair(0,'root'))", resp)
    time.sleep(0.15)

    # 7d: sys8(pair("gizmore", "ilikephp"))
    giz_term = NConst(encode_bytes_list(b"gizmore"))
    pwd_term2 = NConst(encode_bytes_list(b"ilikephp"))
    term = apps(g(8), scott_pair(giz_term, pwd_term2), QD)
    resp = query_named(term)
    decode_and_print("sys8(pair('gizmore','ilikephp'))", resp)
    time.sleep(0.15)

    # ============================================================
    # PART 8: Interesting — echo THEN sys8 of the same thing
    # ============================================================
    print("\n--- PART 8: echo → sys8 chain ---")

    # 8a: echo(sys8) → get Left(sys8_shifted) → what IS sys8?
    # Actually we already know echo(sys8) = Left(Var(10))
    # But what if we echo something and feed the RESULT to sys8?

    # echo(nil, λleft. sys8(left, QD))
    # This gives sys8(Left(nil))
    term = apps(
        g(14),
        NIL,
        lam(
            "result",
            apps(
                v("result"),
                lam("left_val", apps(g(8), v("left_val"), QD)),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=10)
    decode_and_print("echo(nil)→unwrap→sys8(nil)", resp)
    time.sleep(0.15)

    # 8b: echo(g(8)) → get Left(sys8) → feed that to sys8
    # sys8(Left(sys8_opaque))
    term = apps(
        g(14),
        g(8),
        lam(
            "result",
            apps(
                v("result"),
                lam("left_val", apps(g(8), v("left_val"), QD)),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=10)
    decode_and_print("echo(sys8)→unwrap→sys8(sys8)", resp)
    time.sleep(0.15)

    print("\n" + "=" * 60)
    print("ALL NAMED-TERM CHAIN TESTS COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
