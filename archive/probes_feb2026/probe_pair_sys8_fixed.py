#!/usr/bin/env python3
"""
Fix the pair extraction → sys8 chain.

The issue: pair = λx.λy.((x A) B) is a 2-arg function.
When we apply pair(selector), we get λy.((selector A) B).
Then we need to apply this to another argument to get ((selector A) B).

But the real issue is that sys8 needs TWO arguments (arg + continuation) in CPS.
So the selector must account for that.

Let me also think about what backdoor ACTUALLY returns:
backdoor(nil) returns Left(pair) where:
  Left(pair) = λl.λr.(l pair)
  pair = λx.λy.((x A) B) with A=λa.λb.(b b), B=λa.λb.(a b)

When we do: Left(pair) handler_left handler_right
  = handler_left(pair)

Then handler_left receives pair = λx.λy.((x A) B)

If we want sys8(A), we need to extract A from pair.
pair(λa.λb.a) should give A... but pair takes 2 args.
pair(λa.λb.a)(dummy) should give A.

Let me trace through:
pair = λx.λy.((x A) B)
pair(λa.λb.a) = λy.(((λa.λb.a) A) B) = λy.A
Then (λy.A)(dummy) = A

So we need: pair(fst)(dummy) = A where fst = λa.λb.a

Alternatively: pair(λa.λb.((sys8 a) QD))(dummy)
= λy.(((λa.λb.((sys8 a) QD)) A) B)
= λy.((sys8 A) QD)   [since λa.λb gets satisfied by A and B]

Wait no: pair = λx.λy.((x A) B)
pair(sel) = λy.((sel A) B)
pair(sel)(z) = (sel A) B

So: pair(λa.λb.((sys8 a) QD))(z) = ((λa.λb.((sys8 a) QD)) A) B = ((sys8 A) QD)

Actually wait — we're applying sel to A first, then the result to B.
If sel = λa.λb.((sys8 a) QD), then:
(sel A) = λb.((sys8 A) QD)
((sel A) B) = (sys8 A) QD     ← B is passed as b but b is unused, so B is discarded!

So the final result is (sys8 A) QD = ((sys8 A) QD) which is the CPS call!
But then we need to provide the dummy argument to pair to trigger the computation.
"""

from __future__ import annotations

import socket
import time

from probe_mail_focus import (
    FD,
    FE,
    FF,
    HOST,
    PORT,
    NIL,
    NConst,
    app,
    apps,
    g,
    lam,
    v,
    to_db,
    recv_all,
)
from solve_brownos_answer import (
    encode_term,
    parse_term,
    decode_either,
    decode_byte_term,
    decode_bytes_list,
    encode_byte_term,
    encode_bytes_list,
)


QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
QD_TERM = parse_term(QD_BYTES + bytes([FF]))
QD = NConst(QD_TERM)


def query_named(term: object, timeout_s: float = 10.0, retries: int = 3) -> bytes:
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


def pretty_db(term: object) -> str:
    from solve_brownos_answer import Var, Lam, App

    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{pretty_db(term.body)}"
    if isinstance(term, App):
        return f"({pretty_db(term.f)} {pretty_db(term.x)})"
    return str(term)


def decode_and_print(label: str, resp: bytes) -> str:
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
            bs = None
            try:
                bs = decode_bytes_list(payload)
            except Exception:
                pass
            if bs is not None:
                try:
                    text = bs.decode("utf-8", errors="replace")
                    print(f"  {label}: Left(string='{text}')")
                    return f"Left(str)"
                except Exception:
                    print(f"  {label}: Left(bytes={bs.hex()[:80]})")
                    return "Left(bytes)"
            else:
                print(f"  {label}: Left(term={pretty_db(payload)[:120]})")
                return "Left(term)"
        elif tag == "Right":
            errcode = decode_byte_term(payload)
            print(f"  {label}: Right({errcode})")
            return f"Right({errcode})"
        else:
            print(f"  {label}: weird={pretty_db(term)[:80]}")
            return "other"
    except Exception as e:
        print(f"  {label}: PARSE ERROR: {e}  raw={resp.hex()[:80]}")
        return "error"


def main():
    print("=" * 60)
    print("FIXED PAIR EXTRACTION → SYS8 CHAINS")
    print("=" * 60)

    # ============================================================
    # Fixed chain: backdoor(nil) → unwrap Left → pair(sel)(dummy)
    # ============================================================
    print("\n--- Pair extraction with proper 2-arg application ---")

    # 1: Extract A from pair, then sys8(A, QD)
    # CPS: ((backdoor nil)
    #   (λleft_result. (left_result
    #     (λpair. ((pair (λa.λb. ((sys8 a) QD))) nil))
    #     (λerr. nil))))
    print("\n[1] backdoor→unwrap→pair(λa.λb.sys8(a,QD))(dummy)")
    term = apps(
        g(201),
        NIL,
        lam(
            "lr",
            apps(
                v("lr"),
                lam(
                    "pair",
                    apps(
                        app(v("pair"), lam("a", lam("b", apps(g(8), v("a"), QD)))),
                        NIL,  # dummy arg to satisfy pair's 2nd parameter
                    ),
                ),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("sys8(A)", resp)
    time.sleep(0.2)

    # 2: Extract B from pair, then sys8(B, QD)
    print("\n[2] backdoor→unwrap→pair(λa.λb.sys8(b,QD))(dummy)")
    term = apps(
        g(201),
        NIL,
        lam(
            "lr",
            apps(
                v("lr"),
                lam(
                    "pair",
                    apps(
                        app(v("pair"), lam("a", lam("b", apps(g(8), v("b"), QD)))), NIL
                    ),
                ),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("sys8(B)", resp)
    time.sleep(0.2)

    # 3: Compute (A B) from pair (= ω combinator), then sys8(ω, QD)
    print("\n[3] backdoor→unwrap→pair(λa.λb.sys8(a b,QD))(dummy)")
    term = apps(
        g(201),
        NIL,
        lam(
            "lr",
            apps(
                v("lr"),
                lam(
                    "pair",
                    apps(
                        app(
                            v("pair"),
                            lam("a", lam("b", apps(g(8), app(v("a"), v("b")), QD))),
                        ),
                        NIL,
                    ),
                ),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("sys8(A B=ω)", resp)
    time.sleep(0.2)

    # 4: Compute (B A) from pair, then sys8(B A, QD)
    print("\n[4] backdoor→unwrap→pair(λa.λb.sys8(b a,QD))(dummy)")
    term = apps(
        g(201),
        NIL,
        lam(
            "lr",
            apps(
                v("lr"),
                lam(
                    "pair",
                    apps(
                        app(
                            v("pair"),
                            lam("a", lam("b", apps(g(8), app(v("b"), v("a")), QD))),
                        ),
                        NIL,
                    ),
                ),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("sys8(B A)", resp)
    time.sleep(0.2)

    # 5: Quote A to see what it actually is
    print("\n[5] backdoor→unwrap→pair(λa.λb.quote(a,QD))(dummy)")
    term = apps(
        g(201),
        NIL,
        lam(
            "lr",
            apps(
                v("lr"),
                lam(
                    "pair",
                    apps(
                        app(v("pair"), lam("a", lam("b", apps(g(4), v("a"), QD)))), NIL
                    ),
                ),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("quote(A)", resp)
    time.sleep(0.2)

    # 6: Quote B
    print("\n[6] backdoor→unwrap→pair(λa.λb.quote(b,QD))(dummy)")
    term = apps(
        g(201),
        NIL,
        lam(
            "lr",
            apps(
                v("lr"),
                lam(
                    "pair",
                    apps(
                        app(v("pair"), lam("a", lam("b", apps(g(4), v("b"), QD)))), NIL
                    ),
                ),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("quote(B)", resp)
    time.sleep(0.2)

    # 7: Quote (A B) = ω
    print("\n[7] backdoor→unwrap→pair(λa.λb.quote(a b,QD))(dummy)")
    term = apps(
        g(201),
        NIL,
        lam(
            "lr",
            apps(
                v("lr"),
                lam(
                    "pair",
                    apps(
                        app(
                            v("pair"),
                            lam("a", lam("b", apps(g(4), app(v("a"), v("b")), QD))),
                        ),
                        NIL,
                    ),
                ),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("quote(A B)", resp)
    time.sleep(0.2)

    # ============================================================
    # NEW: What about using pair components to BUILD something for sys8?
    # ============================================================
    print("\n--- Build complex terms from pair components ---")

    # 8: sys8(pair itself, QD)
    print("\n[8] sys8(pair_itself, QD)")
    term = apps(
        g(201),
        NIL,
        lam(
            "lr", apps(v("lr"), lam("pair", apps(g(8), v("pair"), QD)), lam("err", NIL))
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("sys8(pair)", resp)
    time.sleep(0.2)

    # 9: Apply pair to ITSELF: pair(pair)(dummy)
    print("\n[9] quote(pair(pair)(nil))")
    term = apps(
        g(201),
        NIL,
        lam(
            "lr",
            apps(
                v("lr"),
                lam("pair", apps(g(4), apps(app(v("pair"), v("pair")), NIL), QD)),
                lam("err", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("quote(pair(pair)(nil))", resp)
    time.sleep(0.2)

    # 10: What if sys8 needs the backdoor pair as both arg AND continuation?
    print("\n[10] ((sys8 pair) pair) — pair as both arg and continuation")
    term = apps(
        g(201),
        NIL,
        lam(
            "lr",
            apps(
                v("lr"), lam("pair", apps(g(8), v("pair"), v("pair"))), lam("err", NIL)
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("sys8(pair, pair)", resp)
    time.sleep(0.2)

    # 11: What if sys8 needs Left(something)?
    # Build Left(nil) manually: λl.λr.(l nil)
    print("\n[11] sys8(Left(nil), QD)")
    left_nil = lam("l", lam("r", app(v("l"), NIL)))
    term = apps(g(8), left_nil, QD)
    resp = query_named(term, timeout_s=8)
    decode_and_print("sys8(Left(nil))", resp)
    time.sleep(0.15)

    # 12: sys8(Left("ilikephp"), QD)
    print("\n[12] sys8(Left('ilikephp'), QD)")
    pwd = NConst(encode_bytes_list(b"ilikephp"))
    left_pwd = lam("l", lam("r", app(v("l"), pwd)))
    term = apps(g(8), left_pwd, QD)
    resp = query_named(term, timeout_s=8)
    decode_and_print("sys8(Left('ilikephp'))", resp)
    time.sleep(0.15)

    # 13: sys8(Right(0), QD) — what if it needs an error term?
    print("\n[13] sys8(Right(0), QD)")
    right_0 = lam("l", lam("r", app(v("r"), NConst(encode_byte_term(0)))))
    term = apps(g(8), right_0, QD)
    resp = query_named(term, timeout_s=8)
    decode_and_print("sys8(Right(0))", resp)
    time.sleep(0.15)

    # ============================================================
    # CRITICAL NEW IDEA: sys8 in the ?? ?? FD QD FD pattern
    # What if 08 is not the SYSCALL but the ARGUMENT?
    # "don't be too literal with the ??s"
    # Maybe: QD(sys8) or echo(sys8) → some transformation
    # ============================================================
    print("\n--- CRITICAL: sys8 as argument, not syscall ---")

    # 14: What if we use sys8 (global 8) as an ARGUMENT to other syscalls?
    # echo(sys8, QD) — we already did this, returns Left(Var(10))

    # 15: What about: g(0) applied to sys8? Var(0) is "stuck", but...
    print("\n[15] ((Var(0) sys8) QD)")
    term = apps(g(0), g(8), QD)
    resp = query_named(term, timeout_s=8)
    decode_and_print("Var(0)(sys8)", resp)
    time.sleep(0.15)

    # 16: What about applying NOTHING — just sys8 FF (no CPS)?
    # Already tested, gives EMPTY. But what about sys8 applied to QD (reversed args)?
    print("\n[16] ((sys8 QD) nil) — QD as argument, nil as continuation")
    term = apps(g(8), QD, NIL)
    resp = query_named(term, timeout_s=8)
    decode_and_print("sys8(QD, nil)", resp)
    time.sleep(0.15)

    # 17: sys8(QD, QD)
    print("\n[17] sys8(QD, QD)")
    term = apps(g(8), QD, QD)
    resp = query_named(term, timeout_s=8)
    decode_and_print("sys8(QD, QD)", resp)
    time.sleep(0.15)

    print("\n" + "=" * 60)
    print("ALL TESTS COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
