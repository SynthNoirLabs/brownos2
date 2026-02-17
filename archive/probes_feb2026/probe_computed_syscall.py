#!/usr/bin/env python3
"""
What if the SYSCALL position can be a computed term?

The cheatsheet says: BrownOS[<syscall> <argument> FD <rest> FD]
And "don't be too literal with the ??s"

What if instead of a bare Var(8) for sys8, we construct a term
that COMPUTES to some special value the VM recognizes?

For example:
- ((λx.x) sys8) — identity applied to sys8
- (backdoor_pair_applied_to_something) in syscall position

Also: what if the answer comes from using echo's output as a syscall?
echo(sys8) = Left(Var(10)) — the Left wrapper means it's under 2 lambdas.
If we could somehow USE this wrapped value as a syscall...

KEY INSIGHT: The BrownOS rewrite rule intercepts
  ((syscall arg) rest) = (rest result)
This means the VM pattern-matches on the STRUCTURE of the term.
What if it pattern-matches on something more specific than just "first Var in App position"?
What if it needs to see a specific TERM SHAPE to trigger a privileged syscall?
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
    Var,
    Lam,
    App,
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


def query_raw(payload: bytes, timeout_s: float = 8.0) -> bytes:
    delay = 0.15
    for _ in range(3):
        try:
            sock = socket.create_connection((HOST, PORT), timeout=timeout_s)
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            out = b""
            sock.settimeout(timeout_s)
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                out += chunk
            sock.close()
            return out
        except Exception:
            time.sleep(delay)
            delay *= 2
    return b""


def pretty(term: object) -> str:
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{pretty(term.body)}"
    if isinstance(term, App):
        return f"({pretty(term.f)} {pretty(term.x)})"
    return str(term)


def decode_and_print(label: str, resp: bytes) -> str:
    if not resp:
        print(f"  {label}: EMPTY")
        return "EMPTY"
    if resp.startswith(b"Invalid term!"):
        print(f"  {label}: INVALID")
        return "INVALID"
    if resp.startswith(b"Encoding failed!"):
        print(f"  {label}: ENCFAIL")
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
                text = bs.decode("utf-8", "replace")
                print(f"  {label}: Left('{text[:80]}')")
                return f"Left(str)"
            else:
                print(f"  {label}: Left(term={pretty(payload)[:80]})")
                return "Left(term)"
        elif tag == "Right":
            errcode = decode_byte_term(payload)
            print(f"  {label}: Right({errcode})")
            return f"Right({errcode})"
        else:
            print(f"  {label}: raw={resp.hex()[:60]}")
            return "other"
    except Exception as e:
        print(f"  {label}: ERROR: {e}  raw={resp.hex()[:60]}")
        return "error"


def main():
    print("=" * 60)
    print("COMPUTED SYSCALL POSITION TESTS")
    print("=" * 60)

    # ============================================================
    # PART 1: Identity-wrapped syscalls
    # Does ((λx.x)(sys8)) arg continuation == sys8 arg continuation?
    # ============================================================
    print("\n--- PART 1: Identity-wrapped syscall ---")

    # 1a: ((id sys8) nil QD) — should this produce Right(6)?
    identity = lam("x", v("x"))
    term = apps(app(identity, g(8)), NIL, QD)
    resp = query_named(term)
    decode_and_print("((id sys8) nil QD)", resp)
    time.sleep(0.15)

    # 1b: ((id echo) nil QD) — control test
    term = apps(app(identity, g(14)), NIL, QD)
    resp = query_named(term)
    decode_and_print("((id echo) nil QD)", resp)
    time.sleep(0.15)

    # ============================================================
    # PART 2: Lambda-wrapped syscall — build a term that IS the syscall
    # ============================================================
    print("\n--- PART 2: Lambda-built syscalls ---")

    # 2a: (λf. f nil QD)(sys8) — apply sys8 as argument to a CPS frame
    term = app(lam("f", apps(v("f"), NIL, QD)), g(8))
    resp = query_named(term)
    decode_and_print("(λf.f nil QD)(sys8)", resp)
    time.sleep(0.15)

    # 2b: same with echo
    term = app(lam("f", apps(v("f"), NIL, QD)), g(14))
    resp = query_named(term)
    decode_and_print("(λf.f nil QD)(echo)", resp)
    time.sleep(0.15)

    # ============================================================
    # PART 3: Use backdoor pair components in syscall position
    # A = λa.λb.(b b), B = λa.λb.(a b)
    # (A B) = ω = λx.(x x)
    # What if ω in SYSCALL position does something?
    # ============================================================
    print("\n--- PART 3: Pair components as syscalls ---")

    # Build A and B directly
    A = lam("a", lam("b", app(v("b"), v("b"))))  # λa.λb.(b b)
    B = lam("a", lam("b", app(v("a"), v("b"))))  # λa.λb.(a b)
    omega = app(A, B)  # ω = λx.(x x)

    # 3a: (A nil QD) — A as syscall
    term = apps(A, NIL, QD)
    resp = query_named(term, timeout_s=6)
    decode_and_print("(A nil QD)", resp)
    time.sleep(0.15)

    # 3b: (B nil QD)
    term = apps(B, NIL, QD)
    resp = query_named(term, timeout_s=6)
    decode_and_print("(B nil QD)", resp)
    time.sleep(0.15)

    # 3c: (ω nil QD) — ω as syscall
    # ω = λx.(x x), so ω(nil) = (nil nil), then QD applied to result
    # nil = λc.λn.n, so nil(nil) = λn.n, then (λn.n)(QD) = QD
    # Then QD reduces... interesting
    term = apps(omega, NIL, QD)
    resp = query_named(term, timeout_s=6)
    decode_and_print("(ω nil QD)", resp)
    time.sleep(0.15)

    # 3d: What about (ω sys8) — self-application on sys8?
    # ω(sys8) = (sys8 sys8) — treats sys8 as both arg and continuation!
    term = app(omega, g(8))
    resp = query_named(term, timeout_s=8)
    decode_and_print("ω(sys8)", resp)
    time.sleep(0.15)

    # 3e: (ω QD) — self-apply QD
    term = app(omega, QD)
    resp = query_named(term, timeout_s=8)
    decode_and_print("ω(QD)", resp)
    time.sleep(0.15)

    # ============================================================
    # PART 4: Build the BrownOS "kernel" rewrite manually
    # The cheatsheet says:
    #   BrownOS[syscall arg FD rest FD] -> BrownOS[rest result FD]
    # What if BrownOS is a FUNCTION and we need to apply it?
    # What if the term (syscall arg rest) reduces via normal beta
    # and the "kernel" is just the evaluator?
    # ============================================================
    print("\n--- PART 4: Manual CPS frames ---")

    # 4a: Pass sys8's result to a function that writes it directly
    # λresult. (write (quote result)) (λ_.nil)
    # This is like QD but with an explicit nil at the end
    write_quote = lam("res", apps(g(2), apps(g(4), v("res"), lam("q", v("q"))), NIL))
    term = apps(g(8), NIL, write_quote)
    resp = query_named(term, timeout_s=8)
    decode_and_print("sys8(nil, λr.write(quote(r)))", resp)
    time.sleep(0.15)

    # ============================================================
    # PART 5: What if we construct a DIFFERENT integer encoding?
    # The 9-lambda encoding is for data. But what if sys8 expects
    # a DIFFERENT kind of integer — like a Church numeral?
    # ============================================================
    print("\n--- PART 5: Church numerals as sys8 argument ---")

    # Church 0 = λf.λx.x
    church_0 = lam("f", lam("x", v("x")))
    term = apps(g(8), church_0, QD)
    resp = query_named(term)
    decode_and_print("sys8(Church 0)", resp)
    time.sleep(0.15)

    # Church 1 = λf.λx.(f x)
    church_1 = lam("f", lam("x", app(v("f"), v("x"))))
    term = apps(g(8), church_1, QD)
    resp = query_named(term)
    decode_and_print("sys8(Church 1)", resp)
    time.sleep(0.15)

    # Church 8 = λf.λx.f(f(f(f(f(f(f(f x)))))))
    def church(n: int) -> object:
        body: object = v("x")
        for _ in range(n):
            body = app(v("f"), body)
        return lam("f", lam("x", body))

    for n in [2, 3, 8, 42, 201]:
        term = apps(g(8), church(n), QD)
        resp = query_named(term)
        decode_and_print(f"sys8(Church {n})", resp)
        time.sleep(0.1)

    # ============================================================
    # PART 6: What if we need to use ALL THREE things together?
    # backdoor + echo + sys8 in one program
    # ============================================================
    print("\n--- PART 6: Three-syscall chains ---")

    # 6a: backdoor(nil) → echo(pair) → sys8(echo_result)
    # CPS: backdoor nil (λbr. br (λpair. echo pair (λer. er (λeval. sys8 eval QD) (λ_.nil))) (λ_.nil))
    term = apps(
        g(201),
        NIL,
        lam(
            "br",
            apps(
                v("br"),
                lam(
                    "pair",
                    apps(
                        g(14),
                        v("pair"),
                        lam(
                            "er",
                            apps(
                                v("er"),
                                lam("eval", apps(g(8), v("eval"), QD)),
                                lam("_err", NIL),
                            ),
                        ),
                    ),
                ),
                lam("_err2", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("backdoor→echo(pair)→sys8(echo_val)", resp)
    time.sleep(0.2)

    # 6b: echo(sys8, λleft. backdoor(nil, λbr. br (λpair. left pair QD) (λ_.nil)))
    # Get Left(sys8), unwrap, apply the "echoed sys8" to pair from backdoor
    term = apps(
        g(14),
        g(8),
        lam(
            "echo_result",
            apps(
                v("echo_result"),
                lam(
                    "sys8_echoed",
                    apps(
                        g(201),
                        NIL,
                        lam(
                            "br",
                            apps(
                                v("br"),
                                lam("pair", apps(v("sys8_echoed"), v("pair"), QD)),
                                lam("_", NIL),
                            ),
                        ),
                    ),
                ),
                lam("_", NIL),
            ),
        ),
    )
    resp = query_named(term, timeout_s=12)
    decode_and_print("echo(sys8)→backdoor→apply_echoed_sys8(pair)", resp)
    time.sleep(0.2)

    print("\n" + "=" * 60)
    print("ALL COMPUTED SYSCALL TESTS COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
