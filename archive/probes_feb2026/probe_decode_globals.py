#!/usr/bin/env python3
"""
Decode the structure of globals by using echo and quote.

Key findings from previous probe:
- echo(x) returns Left(x) where x appears shifted by +2 (under 2 lambdas of Left wrapper)
- quote(x) returns Left(bytes) where bytes is the wire encoding of x
- Arguments ARE evaluated before syscall receives them

This probe systematically uses quote() to extract the wire-form of each syscall global,
which will reveal whether they are ordinary lambda terms or opaque primitives.

If a global is a lambda term, quote will serialize it.
If a global is special/opaque, quote might return the Var reference or fail.

Also: echo of echo chains to explore deeper structure.
"""

from __future__ import annotations

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
class Var:
    i: int


@dataclass(frozen=True)
class Lam:
    body: object


@dataclass(frozen=True)
class App:
    f: object
    x: object


def parse_term(data: bytes) -> object:
    stack: list[object] = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    if len(stack) != 1:
        raise ValueError(f"Stack size {len(stack)}")
    return stack[0]


def pretty(term: object, depth: int = 0) -> str:
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{pretty(term.body, depth + 1)}"
    if isinstance(term, App):
        f_str = pretty(term.f, depth)
        x_str = pretty(term.x, depth)
        return f"({f_str} {x_str})"
    return str(term)


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def strip_lams(term: object, n: int) -> tuple[object, int]:
    """Strip up to n lambdas, return (body, count_stripped)."""
    cur = term
    count = 0
    for _ in range(n):
        if isinstance(cur, Lam):
            cur = cur.body
            count += 1
        else:
            break
    return cur, count


def decode_either(term: object) -> tuple[str, object]:
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        return ("NotEither", term)
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var):
        if body.f.i == 1:
            return ("Left", body.x)
        elif body.f.i == 0:
            return ("Right", body.x)
    return ("NotEither", term)


def eval_bitset_expr(expr: object) -> int:
    if isinstance(expr, Var):
        return WEIGHTS.get(expr.i, -1)
    if isinstance(expr, App):
        if not isinstance(expr.f, Var):
            return -1
        w = WEIGHTS.get(expr.f.i, -1)
        if w < 0:
            return -1
        rest = eval_bitset_expr(expr.x)
        if rest < 0:
            return -1
        return w + rest
    return -1


def decode_byte_term(term: object) -> int:
    body, n = strip_lams(term, 9)
    if n != 9:
        return -1
    return eval_bitset_expr(body)


def decode_bytes_from_list(term: object) -> bytes | None:
    """Decode a Scott list of byte-terms to bytes."""
    out = []
    cur = term
    for _ in range(100000):
        if not isinstance(cur, Lam) or not isinstance(cur.body, Lam):
            return None
        body = cur.body.body
        if isinstance(body, Var) and body.i == 0:
            return bytes(out)
        if (
            isinstance(body, App)
            and isinstance(body.f, App)
            and isinstance(body.f.f, Var)
            and body.f.f.i == 1
        ):
            head = body.f.x
            tail = body.x
            b = decode_byte_term(head)
            if b < 0:
                return None
            out.append(b)
            cur = tail
        else:
            return None
    return None


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
            delay = min(delay * 2, 1.5)
    return b""


def query_syscall_qd(syscall: int, arg_bytes: bytes) -> bytes:
    """Send ((syscall arg) QD) FF and return raw response."""
    payload = bytes([syscall]) + arg_bytes + bytes([FD]) + QD + bytes([FD, FF])
    return query_raw(payload)


def main():
    print("=" * 60)
    print("DECODING GLOBAL STRUCTURE VIA QUOTE AND ECHO")
    print("=" * 60)

    # ============================================================
    # PART 1: Use QUOTE to serialize each known global
    # quote(Var(N)) should show how the VM encodes/resolves Var(N)
    # ============================================================
    print("\n--- PART 1: quote(global) for each known global ---")
    globals_to_test = [
        (0x00, "Var(0)"),
        (0x01, "error_string"),
        (0x02, "write"),
        (0x03, "NotImpl_3"),
        (0x04, "quote"),
        (0x05, "readdir"),
        (0x06, "name"),
        (0x07, "readfile"),
        (0x08, "sys8"),
        (0x09, "NotImpl_9"),
        (0x0A, "NotImpl_10"),
        (0x0E, "echo"),
        (0x2A, "towel"),
        (0xC9, "backdoor"),
    ]

    for gid, gname in globals_to_test:
        resp = query_syscall_qd(0x04, bytes([gid]))
        if not resp:
            print(f"  quote({gname:15s}): EMPTY")
        else:
            try:
                term = parse_term(resp)
                tag, payload = decode_either(term)
                if tag == "Left":
                    bs = decode_bytes_from_list(payload)
                    if bs is not None:
                        print(
                            f"  quote({gname:15s}): Left(bytes={bs.hex()}) [{len(bs)} bytes]"
                        )
                    else:
                        print(
                            f"  quote({gname:15s}): Left(non-bytelist) = {pretty(payload)[:80]}"
                        )
                elif tag == "Right":
                    errcode = decode_byte_term(payload)
                    print(f"  quote({gname:15s}): Right({errcode})")
                else:
                    print(f"  quote({gname:15s}): {tag} raw={resp.hex()[:60]}")
            except Exception as e:
                print(f"  quote({gname:15s}): PARSE ERROR: {e}  raw={resp.hex()[:60]}")
        time.sleep(0.1)

    # ============================================================
    # PART 2: Use ECHO to see the term structure of each global
    # echo(x) = Left(x), then QD serializes Left(x)
    # ============================================================
    print("\n--- PART 2: echo(global) for each known global ---")
    for gid, gname in globals_to_test:
        resp = query_syscall_qd(0x0E, bytes([gid]))
        if not resp:
            print(f"  echo({gname:15s}): EMPTY")
        else:
            try:
                term = parse_term(resp)
                tag, payload = decode_either(term)
                if tag == "Left":
                    print(f"  echo({gname:15s}): Left({pretty(payload)[:80]})")
                elif tag == "Right":
                    errcode = decode_byte_term(payload)
                    print(f"  echo({gname:15s}): Right({errcode})")
                else:
                    print(f"  echo({gname:15s}): {tag} = {pretty(term)[:80]}")
            except Exception as e:
                print(f"  echo({gname:15s}): PARSE ERROR: {e}  raw={resp.hex()[:60]}")
        time.sleep(0.1)

    # ============================================================
    # PART 3: Use echo(echo(x)) to see double-wrapped structure
    # If echo returns Left(x), then echo(echo(x)) = echo(Left(x)) = Left(Left(x))
    # The inner Left(x) should show x shifted by +2 due to outer Left
    # ============================================================
    print("\n--- PART 3: echo(echo(global)) — double wrapping ---")
    # We need to build: ((echo ((echo Var(N)) QD_continuation)) QD)
    # But that doesn't work — echo(echo(x)) needs CPS chaining
    # Actually: echo(x, λresult. echo(result, QD))
    # Which is: ((echo x) (λresult. ((echo result) QD)))
    # Under 1 lambda: echo becomes Var(0x0F), result=Var(0)
    # QD_d1: shift all globals by 1
    QD_d1 = bytes(
        [0x06, 0x00, FD, 0x00, 0x06, 0x00, FD, 0x04, FD, FE, FD, 0x03, FD, FE, FD, FE]
    )
    cont = bytes([0x0F, 0x00, FD]) + QD_d1 + bytes([FD, FE])

    for gid, gname in [
        (0x08, "sys8"),
        (0x0E, "echo"),
        (0xC9, "backdoor"),
        (0x02, "write"),
    ]:
        payload = bytes([0x0E, gid, FD]) + cont + bytes([FD, FF])
        resp = query_raw(payload)
        if not resp:
            print(f"  echo(echo({gname:10s})): EMPTY")
        else:
            try:
                term = parse_term(resp)
                tag1, p1 = decode_either(term)
                if tag1 == "Left":
                    tag2, p2 = decode_either(p1)
                    if tag2 == "Left":
                        print(
                            f"  echo(echo({gname:10s})): Left(Left({pretty(p2)[:60]}))"
                        )
                    else:
                        print(
                            f"  echo(echo({gname:10s})): Left({tag2}({pretty(p1)[:60]}))"
                        )
                else:
                    print(f"  echo(echo({gname:10s})): {tag1} = {pretty(term)[:80]}")
            except Exception as e:
                print(f"  echo(echo({gname:10s})): PARSE ERROR: {e}")
        time.sleep(0.1)

    # ============================================================
    # PART 4: Key question — can we apply the backdoor PAIR to sys8?
    # backdoor returns Left(pair) where pair = λf. f A B
    # If we extract A and B, what happens if we feed them into sys8?
    # backdoor(nil, λpair. pair(λa.λb. sys8(a, QD)))
    # ============================================================
    print("\n--- PART 4: backdoor pair selectors → sys8 ---")

    # 4a: backdoor(nil) → extract A → sys8(A)
    # CPS chain: ((backdoor nil) (λresult.
    #   result (λa.λb. ((sys8 a) QD_d3)) (λerr. nil)))
    # result is a Left(pair), so result applied to left_handler right_handler
    # Left(pair) l r = l pair
    # So left_handler = λpair. pair(λa.λb. ((sys8 a) QD_d3))
    # Under binders: backdoor=0xC9 at top. Under 1 lam: result=Var(0)
    # Under 2 lam: pair=Var(0), Under 3 lam: a=Var(0), b=...
    # sys8 at top=Var(8), under 4 lams=Var(12)

    # This is getting complex. Let me use a simpler approach.
    # Build with named terms and convert to DB.

    # Actually let me first check: what does quote(backdoor_result) look like?
    # i.e., backdoor(nil, λresult. quote(result, QD))
    # This will show us the exact structure of the backdoor's return value

    # CPS: ((backdoor nil) (λresult. ((quote result) QD_shifted)))
    # quote at top = 4, under 1 lam = Var(5)
    cont_quote = bytes([0x05, 0x00, FD]) + QD_d1 + bytes([FD, FE])
    payload = (
        bytes([0xC9])
        + bytes([0x00, FE, FE])
        + bytes([FD])
        + cont_quote
        + bytes([FD, FF])
    )
    print(f"\n[4a] backdoor(nil) -> quote(result) -> QD")
    resp = query_raw(payload)
    if resp:
        try:
            term = parse_term(resp)
            tag, p = decode_either(term)
            if tag == "Left":
                bs = decode_bytes_from_list(p)
                if bs is not None:
                    print(f"  Left(bytes={bs.hex()}) [{len(bs)} bytes]")
                    # Parse the inner term
                    try:
                        inner = parse_term(bs)
                        print(f"  Inner term: {pretty(inner)[:200]}")
                    except Exception as e2:
                        print(f"  Inner parse error: {e2}")
                else:
                    print(f"  Left(non-bytelist): {pretty(p)[:100]}")
            else:
                print(f"  {tag}: {pretty(p)[:100]}")
        except Exception as e:
            print(f"  PARSE ERROR: {e}")
    else:
        print("  EMPTY")
    time.sleep(0.2)

    # 4b: Apply the pair to a selector, then quote the result
    # backdoor(nil, λresult. result(λleft.left, λright.right)(λpair_val. quote(pair_val, QD)))
    # Actually Left(pair) = λl.λr.(l pair)
    # So if we apply result to (λpair. quote(pair, ...)) and (λerr. ...)
    # We get (λpair. quote(pair, ...)) applied to pair

    # Simpler: backdoor(nil, λresult. result (λpair. ((quote pair) QD_d2)) (λerr. nil))
    # Under 1 lam: result=V0
    # Under 2 lam after result Left/Right dispatch: pair=V0
    # quote under 3 lams = Var(4+3)=Var(7)
    # QD under 3 lams: all globals +3
    QD_d3 = bytes(
        [0x08, 0x00, FD, 0x00, 0x08, 0x00, FD, 0x06, FD, FE, FD, 0x05, FD, FE, FD, FE]
    )

    # left handler: λpair. ((quote pair) QD_d3) = 07 00 FD QD_d3 FD FE
    left_handler = bytes([0x07, 0x00, FD]) + QD_d3 + bytes([FD, FE])
    # right handler: λerr. nil = 00 FE FE FE  (λ. λ.λ.V0 — wait, nil=λc.λn.n)
    # nil under 2 lams = Lam(Lam(Var(0))) — no shift needed since nil is closed
    right_handler = bytes([0x00, FE, FE, FE])  # λ.nil = λ.(λ.λ.V0)

    # Continuation: λresult. ((result left_handler) right_handler)
    # Under 1 lam: result=V0
    # Body: ((V0 left_handler) right_handler)
    cont_extract = (
        bytes([0x00]) + left_handler + bytes([FD]) + right_handler + bytes([FD, FE])
    )

    payload = (
        bytes([0xC9])
        + bytes([0x00, FE, FE])
        + bytes([FD])
        + cont_extract
        + bytes([FD, FF])
    )
    print(f"\n[4b] backdoor(nil) -> unwrap Left -> quote(pair) -> QD")
    resp = query_raw(payload, timeout_s=12)
    if resp:
        try:
            term = parse_term(resp)
            tag, p = decode_either(term)
            if tag == "Left":
                bs = decode_bytes_from_list(p)
                if bs is not None:
                    print(f"  Left(bytes={bs.hex()}) [{len(bs)} bytes]")
                    try:
                        inner = parse_term(bs)
                        print(f"  Pair structure: {pretty(inner)[:200]}")
                    except Exception as e2:
                        print(f"  Inner parse error: {e2}")
                else:
                    print(f"  Left(non-bytelist): {pretty(p)[:100]}")
            else:
                errcode = decode_byte_term(p)
                print(f"  {tag}({errcode})")
        except Exception as e:
            print(f"  PARSE ERROR: {e}  raw={resp.hex()[:80]}")
    else:
        print("  EMPTY")
    time.sleep(0.2)

    # 4c: Apply pair to selector that extracts A, then feed A to sys8
    # backdoor(nil, λresult. result
    #   (λpair. pair (λa.λb. ((sys8 a) QD_d4)) )
    #   (λerr. nil)
    # )
    # left_handler: λpair. ((pair (λa.λb. ((sys8 a) QD_d4))))
    # pair = λf. f A B, so pair(selector) = selector A B
    # selector = λa.λb. ((sys8 a) QD_d4)
    # Under depths: sys8 at top=8, under 4 lams=Var(12)=0x0C

    QD_d4 = bytes(
        [0x09, 0x00, FD, 0x00, 0x09, 0x00, FD, 0x07, FD, FE, FD, 0x06, FD, FE, FD, FE]
    )

    # selector: λa.λb. ((sys8_shifted a) QD_d4)
    # Under the 2 extra lams (a, b): sys8 = Var(8+4+2)=Var(14)=0x0E
    # Wait: at top level sys8=Var(8). Under 4 outer lams + 2 selector lams = 6 total
    # sys8 = Var(8+6) = Var(14) = 0x0E
    QD_d6 = bytes(
        [0x0B, 0x00, FD, 0x00, 0x0B, 0x00, FD, 0x09, FD, FE, FD, 0x08, FD, FE, FD, FE]
    )
    selector_sys8_a = bytes([0x0E, 0x01, FD]) + QD_d6 + bytes([FD, FE, FE])
    # λa.λb. ((Var(14) Var(1)) QD_d6)
    # Var(1) = a (under 2 lams, a is at index 1... wait, de Bruijn: last bound is 0)
    # λa.λb — b=Var(0), a=Var(1). We want a, so Var(1) correct.

    left_handler2 = bytes([0x00]) + selector_sys8_a + bytes([FD, FE])
    # λpair. (pair selector) — pair=Var(0)

    cont_extract2 = (
        bytes([0x00]) + left_handler2 + bytes([FD]) + right_handler + bytes([FD, FE])
    )
    payload = (
        bytes([0xC9])
        + bytes([0x00, FE, FE])
        + bytes([FD])
        + cont_extract2
        + bytes([FD, FF])
    )
    print(f"\n[4c] backdoor(nil) -> unwrap Left -> pair(λa.λb.sys8(a)) -> QD")
    print(f"  Payload ({len(payload)} bytes): {payload.hex()}")
    resp = query_raw(payload, timeout_s=12)
    if resp:
        try:
            term = parse_term(resp)
            tag, p = decode_either(term)
            if tag == "Left":
                bs = decode_bytes_from_list(p)
                if bs is not None:
                    print(f"  Left(bytes={bs.hex()}) [{len(bs)} bytes]")
                else:
                    print(f"  Left(term): {pretty(p)[:150]}")
            elif tag == "Right":
                errcode = decode_byte_term(p)
                print(f"  Right({errcode})")
            else:
                print(f"  {tag}: {pretty(term)[:100]}")
        except Exception as e:
            print(f"  PARSE ERROR: {e}  raw={resp.hex()[:80]}")
    else:
        print("  EMPTY")

    print("\n" + "=" * 60)
    print("DECODE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
