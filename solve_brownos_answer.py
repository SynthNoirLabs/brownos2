#!/usr/bin/env python3
from __future__ import annotations

import ctypes
import ctypes.util
import socket
import time
from dataclasses import dataclass


HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD  # application
FE = 0xFE  # lambda
FF = 0xFF  # end-of-code marker

# Quick Debug continuation from the challenge cheat sheet.
# It prints (via syscall 2) the bytecode for the syscall result (via syscall 4),
# terminated by FF, so we can parse the result term on the client side.
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


def recv_until_ff(sock: socket.socket, timeout_s: float = 3.0) -> bytes:
    sock.settimeout(timeout_s)
    out = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        out += chunk
        if FF in chunk:
            break
    if FF not in out:
        raise RuntimeError("Did not receive FF-terminated output; got truncated response")
    return out[: out.index(FF) + 1]


def query(payload: bytes, retries: int = 5, timeout_s: float = 3.0) -> bytes:
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
                return recv_until_ff(sock, timeout_s=timeout_s)
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


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported term node: {type(term)}")


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def strip_lams(term: object, n: int) -> object:
    cur = term
    for _ in range(n):
        if not isinstance(cur, Lam):
            raise ValueError("Not enough leading lambdas")
        cur = cur.body
    return cur


def eval_bitset_expr(expr: object) -> int:
    if isinstance(expr, Var):
        return WEIGHTS[expr.i]
    if isinstance(expr, App):
        if not isinstance(expr.f, Var):
            raise ValueError("Unexpected function position (expected Var)")
        return WEIGHTS[expr.f.i] + eval_bitset_expr(expr.x)
    raise ValueError(f"Unexpected expr node: {type(expr)}")


def encode_byte_term(n: int) -> object:
    expr: object = Var(0)  # base 0
    for idx, weight in ((1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)):
        if n & weight:
            expr = App(Var(idx), expr)
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_bytes_list(bs: bytes) -> object:
    # Scott list of byte-terms.
    nil: object = Lam(Lam(Var(0)))

    def cons(h: object, t: object) -> object:
        return Lam(Lam(App(App(Var(1), h), t)))

    cur: object = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


def decode_either(term: object) -> tuple[str, object]:
    # Scott Either:
    # Left x  = λl.λr. l x  -> λ.λ.(1 x)
    # Right y = λl.λr. r y  -> λ.λ.(0 y)
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not an Either")
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var) and body.f.i in (0, 1):
        return ("Left" if body.f.i == 1 else "Right", body.x)
    raise ValueError("Unexpected Either shape")


def decode_byte_term(term: object) -> int:
    body = strip_lams(term, 9)
    return eval_bitset_expr(body)


def uncons_scott_list(term: object) -> tuple[object, object] | None:
    # nil  = λc.λn. n      -> λ.λ.0
    # cons = λc.λn. c h t  -> λ.λ.(1 h t)
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not a Scott list node")
    body = term.body.body
    if isinstance(body, Var) and body.i == 0:
        return None
    if (
        isinstance(body, App)
        and isinstance(body.f, App)
        and isinstance(body.f.f, Var)
        and body.f.f.i == 1
    ):
        return body.f.x, body.x
    raise ValueError("Unexpected Scott list node shape")


def decode_bytes_list(term: object) -> bytes:
    out: list[int] = []
    cur = term
    for _ in range(1_000_000):
        res = uncons_scott_list(cur)
        if res is None:
            return bytes(out)
        head, cur = res
        out.append(decode_byte_term(head))
    raise RuntimeError("List too long (possible loop)")


def call_syscall(syscall_num: int, argument: object) -> object:
    payload = bytes([syscall_num]) + encode_term(argument) + bytes([FD]) + QD + bytes([FD, FF])
    out = query(payload)
    return parse_term(out)


def libc_crypt(password: str, salt: str) -> str:
    libname = ctypes.util.find_library("crypt")
    if not libname:
        raise RuntimeError("Could not find libcrypt")
    lib = ctypes.CDLL(libname)
    crypt_fn = lib.crypt
    crypt_fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    crypt_fn.restype = ctypes.c_char_p
    out = crypt_fn(password.encode(), salt.encode())
    if not out:
        raise RuntimeError("crypt() returned NULL")
    return out.decode()


def main() -> None:
    # Read /etc/passwd-like file and find gizmore's crypt hash.
    passwd_term = call_syscall(0x07, encode_byte_term(11))
    tag, passwd_payload = decode_either(passwd_term)
    if tag != "Left":
        raise RuntimeError("Failed to read passwd file")
    passwd_text = decode_bytes_list(passwd_payload).decode("utf-8", "replace")
    giz_hash = None
    for line in passwd_text.splitlines():
        if line.startswith("gizmore:"):
            parts = line.split(":")
            if len(parts) >= 2:
                giz_hash = parts[1]
            break
    if not giz_hash:
        raise RuntimeError("Could not find gizmore hash in passwd file")

    # Read command log that leaked the password in plaintext.
    log_term = call_syscall(0x07, encode_byte_term(65))
    tag, log_payload = decode_either(log_term)
    if tag != "Left":
        raise RuntimeError("Failed to read log file")
    log_text = decode_bytes_list(log_payload).decode("utf-8", "replace")
    # heuristic: the password is a standalone token line in this file
    candidates = [ln.strip() for ln in log_text.splitlines() if ln.strip() and " " not in ln.strip()]
    if not candidates:
        raise RuntimeError("No password candidates found in log file")

    salt = giz_hash[:2]
    for cand in candidates:
        if libc_crypt(cand, salt) == giz_hash:
            print(cand)
            return
    raise RuntimeError("No candidates matched gizmore's hash")


if __name__ == "__main__":
    main()

