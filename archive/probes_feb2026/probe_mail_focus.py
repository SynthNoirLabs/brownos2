#!/usr/bin/env python3
from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from itertools import product

from solve_brownos_answer import App, Lam, Var, encode_bytes_list, encode_term


HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF


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
        try:
            return Var(env.index(term.name))
        except ValueError as exc:
            raise ValueError(f"Unbound name: {term.name}") from exc
    if isinstance(term, NGlob):
        return Var(term.index + len(env))
    if isinstance(term, NLam):
        return Lam(to_db(term.body, (term.param,) + env))
    if isinstance(term, NApp):
        return App(to_db(term.f, env), to_db(term.x, env))
    if isinstance(term, NConst):
        # Closed constants can be safely shifted by binder depth.
        return shift_db(term.term, len(env))
    raise TypeError(f"Unsupported named term node: {type(term)}")


def g(index: int) -> NGlob:
    return NGlob(index)


def v(name: str) -> NVar:
    return NVar(name)


def lam(param: str, body: object) -> NLam:
    return NLam(param, body)


def app(f: object, x: object) -> NApp:
    return NApp(f, x)


def apps(*terms: object) -> object:
    out = terms[0]
    for t in terms[1:]:
        out = app(out, t)
    return out


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


def query_named(term: object, timeout_s: float = 7.0, retries: int = 3) -> bytes:
    payload = encode_term(to_db(term)) + bytes([FF])
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


def classify(out: bytes) -> str:
    if not out:
        return "silent"
    if out.startswith(b"Invalid term!"):
        return "invalid"
    if out.startswith(b"Encoding failed!"):
        return "encfail"
    text = out.decode("latin-1", errors="replace")
    marks = "".join(ch for ch in text if ch in "LRErB")
    return marks if marks else f"other:{out[:20].hex()}"


NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)


def write_marker(ch: str) -> object:
    return apps(g(2), NConst(encode_bytes_list(ch.encode())), NIL)


def either_disc(left_char: str, right_char: str) -> object:
    return lam(
        "res",
        apps(
            v("res"),
            lam("_l", write_marker(left_char)),
            lam("_r", write_marker(right_char)),
        ),
    )


DISC8 = either_disc("L", "R")


def int_term(n: int) -> object:
    expr: object = Var(0)
    for idx, weight in ((1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)):
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def make_3leaf_selectors() -> list[tuple[str, object]]:
    sels: list[tuple[str, object]] = []
    for shape in ("left", "right"):
        for a, b, c in product(("a", "b"), repeat=3):
            if shape == "left":
                body = app(app(v(a), v(b)), v(c))
                name = f"((v{a} v{b}) v{c})"
            else:
                body = app(v(a), app(v(b), v(c)))
                name = f"(v{a} (v{b} v{c}))"
            sels.append((f"{shape}:{name}", lam("a", lam("b", body))))
    return sels


def program_stage2_backdoor(selector: object) -> object:
    # 201 nil -> Left(pair) -> 201 (pair selector) -> Left(x)? sys8(x)
    disc201_2 = lam(
        "res2",
        apps(
            v("res2"),
            lam("x", apps(g(8), v("x"), DISC8)),
            lam("err2", write_marker("r")),
        ),
    )

    first_left = lam(
        "pair",
        apps(
            g(201),
            apps(v("pair"), selector),
            disc201_2,
        ),
    )

    first_handler = lam(
        "res1",
        apps(
            v("res1"),
            first_left,
            lam("err1", write_marker("E")),
        ),
    )

    return apps(g(201), NIL, first_handler)


def program_echo_backdoor_special(echo_arg: int, mode: str) -> object:
    # echo(251/252) -> Left(vx) ; backdoor(nil)->Left(pair) ; use pair(vx) with syscall8
    if mode == "arg":
        second_left = lam(
            "pair",
            apps(g(8), apps(v("pair"), v("vx")), DISC8),
        )
    elif mode == "cont":
        second_left = lam(
            "pair",
            apps(apps(g(8), NIL), apps(v("pair"), v("vx")), DISC8),
        )
    elif mode == "stage2_201":
        disc201_2 = lam(
            "res2",
            apps(
                v("res2"),
                lam("x", apps(g(8), v("x"), DISC8)),
                lam("err2", write_marker("r")),
            ),
        )
        second_left = lam(
            "pair",
            apps(g(201), apps(v("pair"), v("vx")), disc201_2),
        )
    else:
        raise ValueError(f"Unknown mode: {mode}")

    backdoor_handler = lam(
        "res2",
        apps(
            v("res2"),
            second_left,
            lam("err2", write_marker("B")),
        ),
    )

    echo_left = lam(
        "vx",
        apps(g(201), NIL, backdoor_handler),
    )

    echo_handler = lam(
        "res1",
        apps(
            v("res1"),
            echo_left,
            lam("err1", write_marker("E")),
        ),
    )

    return apps(g(14), g(echo_arg), echo_handler)


def program_read_mail_into_sys8() -> object:
    # readfile(88) -> Left(bytes) -> syscall8(bytes)
    file88 = NConst(int_term(88))

    rf_handler = lam(
        "res",
        apps(
            v("res"),
            lam("bytes", apps(g(8), v("bytes"), DISC8)),
            lam("err", write_marker("F")),
        ),
    )
    return apps(g(7), file88, rf_handler)


def main() -> None:
    print("=== Mail-Focused BrownOS Probe ===")

    print("\n[1] Stage-2 backdoor with 3-leaf selectors")
    selectors = make_3leaf_selectors()
    stage2 = []
    for name, sel in selectors:
        out = query_named(program_stage2_backdoor(sel), timeout_s=7.0)
        stage2.append((name, classify(out), len(out)))
        time.sleep(0.05)
    for name, cls, ln in stage2:
        if cls != "R":
            print(f"  {name:26s} -> {cls:8s} len={ln}")
    print(
        "  summary:",
        {
            "total": len(stage2),
            "R": sum(1 for _, c, _ in stage2 if c == "R"),
            "non_R": sum(1 for _, c, _ in stage2 if c != "R"),
        },
    )

    print("\n[2] echo(special) + backdoor(pair) combinations")
    for mode in ("arg", "cont", "stage2_201"):
        for echo_arg in (251, 252):
            out = query_named(program_echo_backdoor_special(echo_arg, mode), timeout_s=7.0)
            print(f"  mode={mode:10s} echo({echo_arg}) -> {classify(out):8s} len={len(out)}")
            time.sleep(0.08)

    print("\n[3] Mail file content as syscall8 argument")
    out = query_named(program_read_mail_into_sys8(), timeout_s=7.0)
    print(f"  readfile(88)->sys8(bytes) -> {classify(out)} len={len(out)}")


if __name__ == "__main__":
    main()
