#!/usr/bin/env python3
"""
probe_pair_bytecode.py — Dump the exact bytecode of the backdoor pair
and verify pair destruction works at top level vs CPS.

Key question: Is the backdoor-returned pair IDENTICAL to the inline pair?
"""

import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE
FF = 0xFF
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


@dataclass(frozen=True)
class V:
    i: int


@dataclass(frozen=True)
class L:
    body: object


@dataclass(frozen=True)
class Ap:
    f: object
    x: object


def parse_term(data):
    stack = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            stack.append(Ap(f, x))
        elif b == FE:
            stack.append(L(stack.pop()))
        else:
            stack.append(V(b))
    return stack[0] if stack else None


def enc(term):
    if isinstance(term, V):
        if term.i > 0xFC:
            raise ValueError(f"V({term.i}) too large")
        return bytes([term.i])
    if isinstance(term, L):
        return enc(term.body) + bytes([FE])
    if isinstance(term, Ap):
        return enc(term.f) + enc(term.x) + bytes([FD])
    raise TypeError(f"Unknown: {type(term)}")


def sh(term, delta, cutoff=0):
    if isinstance(term, V):
        return V(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, L):
        return L(sh(term.body, delta, cutoff + 1))
    if isinstance(term, Ap):
        return Ap(sh(term.f, delta, cutoff), sh(term.x, delta, cutoff))
    return term


def show(term, depth=0):
    if depth > 10:
        return "..."
    if isinstance(term, V):
        return f"V{term.i}"
    if isinstance(term, L):
        return f"λ.{show(term.body, depth + 1)}"
    if isinstance(term, Ap):
        return f"({show(term.f, depth + 1)} {show(term.x, depth + 1)})"
    return "?"


def recv_all(sock, timeout_s=5.0):
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


def q(payload, timeout_s=6.0):
    delay = 0.4
    for attempt in range(3):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s)
        except Exception as e:
            if attempt == 2:
                return b""
            time.sleep(delay)
            delay *= 2
    return b""


def a2(f, x, y):
    return Ap(Ap(f, x), y)


nil_t = L(L(V(0)))
qd_t = parse_term(QD + bytes([FF]))


def main():
    print("=" * 70)
    print("PAIR BYTECODE ANALYSIS")
    print("=" * 70)

    # ===== P1: Get the raw bytecode of the backdoor pair via quote =====
    # backdoor(nil)(λr. r(λpair. quote(pair)(QD_s2))(λe. nil_s2))
    print("\n--- P1: backdoor→quote(pair)→QD ---")
    qd_s2 = sh(qd_t, 2)
    nil_s2 = sh(nil_t, 2)
    # Under 2 lambdas: quote = V(4+2) = V(6), pair = V(0)
    quote_pair = a2(V(6), V(0), qd_s2)
    left_h = L(quote_pair)
    right_h = L(nil_s2)
    dispatch = a2(V(0), left_h, right_h)
    cont = L(dispatch)
    full = a2(V(0xC9), nil_t, cont)

    try:
        payload = enc(full) + bytes([FF])
        print(f"  Payload: {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        if resp and FF in resp:
            term = parse_term(resp)
            print(f"  Result term: {show(term)}")
            # Try to decode as Either
            if isinstance(term, L) and isinstance(term.body, L):
                body = term.body.body
                if isinstance(body, Ap) and isinstance(body.f, V):
                    tag = "Left" if body.f.i == 1 else "Right"
                    print(f"  Either: {tag}")
                    if tag == "Left":
                        # Decode byte list
                        payload_term = body.x
                        bytelist = []
                        cur = payload_term
                        for _ in range(200):
                            if isinstance(cur, L) and isinstance(cur.body, L):
                                inner = cur.body.body
                                if isinstance(inner, V) and inner.i == 0:
                                    break  # nil
                                if isinstance(inner, Ap) and isinstance(inner.f, Ap):
                                    head = inner.f.x
                                    tail = inner.x
                                    # Decode byte term (9 lambdas + bitset)
                                    try:
                                        h = head
                                        for _ in range(9):
                                            h = h.body
                                        # Evaluate bitset
                                        weights = {
                                            0: 0,
                                            1: 1,
                                            2: 2,
                                            3: 4,
                                            4: 8,
                                            5: 16,
                                            6: 32,
                                            7: 64,
                                            8: 128,
                                        }

                                        def eval_bs(e):
                                            if isinstance(e, V):
                                                return weights.get(e.i, -1)
                                            if isinstance(e, Ap) and isinstance(e.f, V):
                                                w = weights.get(e.f.i, -1)
                                                if w < 0:
                                                    return -1
                                                sub = eval_bs(e.x)
                                                if sub < 0:
                                                    return -1
                                                return w + sub
                                            return -1

                                        bval = eval_bs(h)
                                        bytelist.append(bval)
                                    except:
                                        bytelist.append(-1)
                                    cur = tail
                                else:
                                    break
                            else:
                                break
                        print(
                            f"  Bytecode ({len(bytelist)} bytes): {bytes(b for b in bytelist if b >= 0).hex()}"
                        )
                        print(f"  Raw values: {bytelist}")
        elif resp:
            print(f"  Raw: {resp[:80].hex()}")
        else:
            print(f"  EMPTY")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== P2: Quote the inline pair for comparison =====
    print("\n--- P2: quote(pair_inline)(QD) ---")
    A_t = L(L(Ap(V(0), V(0))))
    B_t = L(L(Ap(V(1), V(0))))
    A_s1 = sh(A_t, 1)
    B_s1 = sh(B_t, 1)
    pair_inline = L(a2(V(0), A_s1, B_s1))

    payload = bytes([0x04]) + enc(pair_inline) + bytes([FD]) + QD + bytes([FD, FF])
    resp = q(payload)
    if resp and FF in resp:
        term = parse_term(resp)
        print(f"  Result: {show(term)}")
        # Decode the byte list
        if isinstance(term, L) and isinstance(term.body, L):
            body = term.body.body
            if isinstance(body, Ap) and isinstance(body.f, V) and body.f.i == 1:
                payload_term = body.x
                bytelist = []
                cur = payload_term
                for _ in range(200):
                    if isinstance(cur, L) and isinstance(cur.body, L):
                        inner = cur.body.body
                        if isinstance(inner, V) and inner.i == 0:
                            break
                        if isinstance(inner, Ap) and isinstance(inner.f, Ap):
                            head = inner.f.x
                            tail = inner.x
                            try:
                                h = head
                                for _ in range(9):
                                    h = h.body
                                weights = {
                                    0: 0,
                                    1: 1,
                                    2: 2,
                                    3: 4,
                                    4: 8,
                                    5: 16,
                                    6: 32,
                                    7: 64,
                                    8: 128,
                                }

                                def eval_bs2(e):
                                    if isinstance(e, V):
                                        return weights.get(e.i, -1)
                                    if isinstance(e, Ap) and isinstance(e.f, V):
                                        w = weights.get(e.f.i, -1)
                                        if w < 0:
                                            return -1
                                        sub = eval_bs2(e.x)
                                        if sub < 0:
                                            return -1
                                        return w + sub
                                    return -1

                                bval = eval_bs2(h)
                                bytelist.append(bval)
                            except:
                                bytelist.append(-1)
                            cur = tail
                        else:
                            break
                    else:
                        break
                print(
                    f"  Bytecode ({len(bytelist)} bytes): {bytes(b for b in bytelist if b >= 0).hex()}"
                )
    else:
        print(f"  Raw: {resp[:80].hex() if resp else 'EMPTY'}")
    time.sleep(0.5)

    # ===== P3: Use write to dump the raw QD output of the pair =====
    # backdoor(nil)(λr. r(λpair. quote(pair)(λquoted. write(quoted)(λ_. nil))))(λe. nil))
    # This writes the raw bytecode bytes to the socket
    print("\n--- P3: backdoor→quote(pair)→write(bytecode) ---")
    # Under 2 lambdas (result, pair): quote = V(6), pair = V(0)
    # quote(pair)(λquoted. write(quoted)(λ_.nil))
    # Under 3 lambdas (result, pair, quoted): write = V(5), quoted = V(0)
    # Under 4 lambdas (result, pair, quoted, _): nil shifted by 4
    nil_s4 = sh(nil_t, 4)
    write_k = L(nil_s4)  # λ_. nil
    write_call = a2(V(5), V(0), write_k)  # write(quoted)(λ_.nil)
    quote_k = L(write_call)  # λquoted. write(quoted)(λ_.nil)
    quote_call = a2(V(6), V(0), quote_k)  # quote(pair)(λquoted...)
    left_h3 = L(quote_call)  # λpair. quote(pair)(...)
    right_h3 = L(nil_s2)
    dispatch3 = a2(V(0), left_h3, right_h3)
    cont3 = L(dispatch3)
    full3 = a2(V(0xC9), nil_t, cont3)

    try:
        payload = enc(full3) + bytes([FF])
        print(f"  Payload ({len(payload)}b): {payload.hex()}")
        resp = q(payload, timeout_s=8.0)
        if resp:
            print(f"  Raw output ({len(resp)} bytes): {resp.hex()}")
            # This should be the bytecode of the pair
            try:
                pair_term = parse_term(resp)
                print(f"  Parsed pair: {show(pair_term)}")
            except Exception as e:
                print(f"  Parse error: {e}")
        else:
            print(f"  EMPTY")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== P4: Write the raw QD output of inline pair for comparison =====
    print("\n--- P4: quote(pair_inline)→write(bytecode) ---")
    # quote(pair_inline)(λquoted. write(quoted)(λ_.nil))
    nil_s2_v = sh(nil_t, 2)
    write_k2 = L(nil_s2_v)
    write_call2 = a2(V(3), V(0), write_k2)  # write(quoted)(λ_.nil) under 1 lambda
    quote_k2 = L(write_call2)  # λquoted. write(quoted)(λ_.nil)
    quote_call2 = a2(V(0x04), pair_inline, quote_k2)  # quote(pair)(λquoted...)

    try:
        payload = enc(quote_call2) + bytes([FF])
        resp = q(payload, timeout_s=8.0)
        if resp:
            print(f"  Raw output ({len(resp)} bytes): {resp.hex()}")
            try:
                pair_term2 = parse_term(resp)
                print(f"  Parsed pair: {show(pair_term2)}")
            except Exception as e:
                print(f"  Parse error: {e}")
        else:
            print(f"  EMPTY")
    except Exception as e:
        print(f"  ERROR: {e}")
    time.sleep(0.5)

    # ===== P5: Test pair destruction at TOP LEVEL with various destructors =====
    print("\n--- P5: Top-level pair destruction tests ---")

    # pair_inline(echo)(QD) — known to work
    test5a = a2(pair_inline, V(0x0E), qd_t)
    payload = enc(test5a) + bytes([FF])
    resp = q(payload)
    print(f"  pair(echo)(QD): {resp[:40].hex() if resp else 'EMPTY'}")
    time.sleep(0.5)

    # pair_inline(sys8)(QD)
    test5b = a2(pair_inline, V(0x08), qd_t)
    payload = enc(test5b) + bytes([FF])
    resp = q(payload)
    print(f"  pair(sys8)(QD): {resp[:40].hex() if resp else 'EMPTY'}")
    time.sleep(0.5)

    # pair_inline(λa.λb. echo(a)(QD))
    # Under 2 lambdas: echo = V(16), a = V(1)
    qd_s2_v = sh(qd_t, 2)
    destr_echo = L(L(a2(V(16), V(1), qd_s2_v)))
    test5c = Ap(pair_inline, destr_echo)
    payload = enc(test5c) + bytes([FF])
    resp = q(payload)
    print(f"  pair(λa.λb. echo(a)(QD)): {resp[:40].hex() if resp else 'EMPTY'}")
    time.sleep(0.5)

    # pair_inline(λa.λb. sys8(a)(QD))
    destr_sys8 = L(L(a2(V(10), V(1), qd_s2_v)))
    test5d = Ap(pair_inline, destr_sys8)
    payload = enc(test5d) + bytes([FF])
    resp = q(payload)
    print(f"  pair(λa.λb. sys8(a)(QD)): {resp[:40].hex() if resp else 'EMPTY'}")
    time.sleep(0.5)

    # pair_inline(λa.λb. QD(a))
    destr_qd = L(L(Ap(qd_s2_v, V(1))))
    test5e = Ap(pair_inline, destr_qd)
    payload = enc(test5e) + bytes([FF])
    resp = q(payload)
    print(f"  pair(λa.λb. QD(a)): {resp[:40].hex() if resp else 'EMPTY'}")
    time.sleep(0.5)

    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
