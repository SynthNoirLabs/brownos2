#!/usr/bin/env python3
import socket
import time
from dataclasses import dataclass


HOST = "wc3.wechall.net"
PORT = 61221

# Quick debug (QD) from the challenge cheat sheet.
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

FD = 0xFD  # application
FE = 0xFE  # lambda
FF = 0xFF  # end-of-code marker


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


def query(payload: bytes, retries: int = 5, timeout_s: float = 4.0) -> bytes:
    delay = 0.15
    last_err: Exception | None = None
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s=timeout_s)
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed to query {HOST}:{PORT}") from last_err


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
        raise ValueError(f"Invalid parse: stack size {len(stack)}")
    return stack[0]


def unwrap_outer(root: object) -> object:
    """
    The service returns a 2-arg wrapper that yields the actual list term as its payload.
    Pattern: λ.λ. (1 payload)
    """
    if not isinstance(root, Lam) or not isinstance(root.body, Lam):
        return root
    body = root.body.body
    if isinstance(body, App) and isinstance(body.f, Var) and body.f.i == 1:
        return body.x
    return root


def uncons_scott_list(term: object) -> tuple[object, object] | None:
    # Scott list:
    #   nil  = λc.λn. n      -> λ.λ.0
    #   cons = λc.λn. c h t  -> λ.λ.(1 h t)
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not a 2-lambda Scott list node")
    body = term.body.body
    if isinstance(body, Var) and body.i == 0:
        return None
    if (
        isinstance(body, App)
        and isinstance(body.f, App)
        and isinstance(body.f.f, Var)
        and body.f.f.i == 1
    ):
        head = body.f.x
        tail = body.x
        return head, tail
    raise ValueError("Unexpected Scott list node shape")


def decode_scott_list(term: object) -> list[object]:
    items: list[object] = []
    cur = term
    for _ in range(10000):
        res = uncons_scott_list(cur)
        if res is None:
            return items
        head, cur = res
        items.append(head)
    raise RuntimeError("List too long (possible loop)")


def strip_lams(term: object, n: int) -> object:
    cur = term
    for _ in range(n):
        if not isinstance(cur, Lam):
            raise ValueError("Not enough leading lambdas")
        cur = cur.body
    return cur


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def eval_bitset_expr(expr: object) -> int:
    """
    Character encoding used by the service:
      a 9-arg lambda where each Var index represents a bit weight.
      The body is a nested application chain like:
        V7 @(V4 @(V3 @(V2 @(V1 @ V0))))
      Interpreted as applying 'add(weight)' functions down to a 0 base.
    """
    if isinstance(expr, Var):
        return WEIGHTS[expr.i]
    if isinstance(expr, App):
        if not isinstance(expr.f, Var):
            raise ValueError("Unexpected function position (expected Var)")
        return WEIGHTS[expr.f.i] + eval_bitset_expr(expr.x)
    raise ValueError(f"Unexpected expr node: {type(expr)}")


def solve() -> str:
    # Call syscall 0x2A (42) with dummy argument, and use QD as continuation to print the result term.
    payload = bytes([0x2A, 0x00, FD]) + QD + bytes([FD, FF])
    out = query(payload)
    root = parse_term(out)
    list_term = unwrap_outer(root)
    items = decode_scott_list(list_term)
    chars = []
    for item in items:
        body = strip_lams(item, 9)
        chars.append(chr(eval_bitset_expr(body)))
    return "".join(chars)


if __name__ == "__main__":
    print(solve())
