#!/usr/bin/env python3
"""
probe_llm_v18.py — Focused untested-class probes from deep analysis.

Targets:
U1) sys8(Lam(Lam(Lam(Var(n)))))(QD), n=0..5
U2) sys8(Left(int_term(n)))(QD), n=0..7
U3) sys8(Right(int_term(n)))(QD), n=0..7
U4) sys8(dirlist_nil_3way)(QD)
U5) sys8(nil)(\r. readfile(r)(QD_shifted))
U6) sys8(nil)(\r. readdir(r)(QD_shifted))
U7) sys8(App(g(5), int(0)))(QD), sys8(App(g(4), nil))(QD), sys8(App(g(1), int(6)))(QD)
"""

from __future__ import annotations

import socket
import time

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    decode_byte_term,
    decode_bytes_list,
    decode_either,
    encode_byte_term,
    encode_term,
    parse_term,
)

HOST = "wc3.wechall.net"
PORT = 61221
FF = 0xFF

QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
QD = parse_term(QD_BYTES)
NIL = Lam(Lam(Var(0)))


def shift(term, delta, cutoff=0):
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    raise TypeError(f"Unexpected term node: {type(term)}")


def g(i: int) -> Var:
    return Var(i)


def make_left(inner):
    return Lam(Lam(App(Var(1), shift(inner, 2))))


def make_right(inner):
    return Lam(Lam(App(Var(0), shift(inner, 2))))


def send(payload: bytes, timeout_s: float = 6.0) -> bytes:
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
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
                    if FF in chunk:
                        break
                except socket.timeout:
                    break
            return out
    except Exception as e:
        return b"ERR:" + str(e).encode()


def classify(resp: bytes) -> str:
    if not resp:
        return "EMPTY"
    if resp.startswith(b"ERR:"):
        return resp.decode("utf-8", "replace")
    if b"Encoding failed" in resp:
        return "EncodingFailed"
    if b"Invalid term" in resp:
        return "InvalidTerm"
    if b"Term too big" in resp:
        return "TermTooBig"

    if FF in resp:
        try:
            t = parse_term(resp[: resp.index(FF) + 1])
            tag, payload = decode_either(t)
            if tag == "Right":
                return f"Right({decode_byte_term(payload)})"
            try:
                bs = decode_bytes_list(payload)
                txt = bs.decode("utf-8", "replace")
                return f"Left(string={txt!r})"
            except Exception:
                return "Left(non-string)"
        except Exception:
            pass
    return f"HEX={resp.hex()[:100]}({len(resp)}b)"


def run(name: str, term, delay: float = 0.4):
    payload = encode_term(term) + bytes([FF])
    if len(payload) > 2000:
        print(f"[{name}] SKIP payload={len(payload)}b")
        return "TOO_LARGE"
    time.sleep(delay)
    resp = send(payload)
    result = classify(resp)
    print(f"[{name}] {result}")
    return result


def main():
    print("=" * 64)
    print("LLM v18 focused probes")
    print("=" * 64)

    print("\nU1: Lam3 body sweep")
    for n in range(6):
        arg = Lam(Lam(Lam(Var(n))))
        run(f"U1 n={n}", App(App(g(8), arg), QD))

    print("\nU2: Left(int_term(n))")
    for n in range(8):
        arg = make_left(encode_byte_term(n))
        run(f"U2 n={n}", App(App(g(8), arg), QD))

    print("\nU3: Right(int_term(n))")
    for n in range(8):
        arg = make_right(encode_byte_term(n))
        run(f"U3 n={n}", App(App(g(8), arg), QD))

    print("\nU4: 3-way list shape")
    dirlist_nil = Lam(Lam(Lam(Var(0))))
    run("U4 dirlist_nil", App(App(g(8), dirlist_nil), QD))

    print("\nU5/U6: result as resource id")
    qd_s1 = shift(QD, 1)
    cont_readfile = Lam(App(App(Var(8), Var(0)), qd_s1))
    cont_readdir = Lam(App(App(Var(6), Var(0)), qd_s1))
    run("U5 sys8(nil)->readfile(result)", App(App(g(8), NIL), cont_readfile))
    run("U6 sys8(nil)->readdir(result)", App(App(g(8), NIL), cont_readdir))

    print("\nU7: untested CBN thunk args")
    thunk_readdir0 = App(g(5), encode_byte_term(0))
    thunk_quote_nil = App(g(4), NIL)
    thunk_err6 = App(g(1), encode_byte_term(6))
    run("U7 thunk readdir(0)", App(App(g(8), thunk_readdir0), QD))
    run("U7 thunk quote(nil)", App(App(g(8), thunk_quote_nil), QD))
    run("U7 thunk error_string(6)", App(App(g(8), thunk_err6), QD))

    print("\nDone.")


if __name__ == "__main__":
    main()
