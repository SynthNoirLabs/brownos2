#!/usr/bin/env python3
"""
probe_ultra3.py - Follow-up experiments after ultrabrain strategy refresh.

Focus areas:
1) Continuation-centric syscall8 behavior (direct + forced observation).
2) Call-by-name thunk arguments: sys8(g(201)(nil), k) style payloads.
3) Runtime-computed arguments and backdoor-pair captured continuations.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    encode_byte_term,
    encode_bytes_list,
    encode_term,
)

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
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
        return Var(env.index(term.name))
    if isinstance(term, NGlob):
        return Var(term.index + len(env))
    if isinstance(term, NLam):
        return Lam(to_db(term.body, (term.param,) + env))
    if isinstance(term, NApp):
        return App(to_db(term.f, env), to_db(term.x, env))
    if isinstance(term, NConst):
        return shift_db(term.term, len(env))
    raise TypeError(f"Unsupported named-term node: {type(term)}")


def g(i: int) -> NGlob:
    return NGlob(i)


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


def recv_all(sock: socket.socket, timeout_s: float = 7.0) -> bytes:
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
        if FF in chunk:
            # Keep reading in case server already queued extra bytes,
            # but most responses are single FF-terminated frames.
            continue
    return out


def query(payload: bytes, retries: int = 4, timeout_s: float = 7.0) -> bytes:
    delay = 0.2
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
            delay = min(delay * 2, 2.0)
    return f"ERROR: {last_err}".encode("ascii", "replace")


def classify(out: bytes) -> str:
    if not out:
        return "EMPTY"
    if out.startswith(b"Invalid term!"):
        return "Invalid term!"
    if out.startswith(b"Encoding failed!"):
        return "Encoding failed!"
    if out.startswith(b"ERROR:"):
        return out.decode("ascii", "replace")

    try:
        text = out.decode("utf-8", "replace")
        if all((ch == "\n") or (ch == "\r") or (32 <= ord(ch) < 127) for ch in text):
            compact = text.replace("\n", "\\n")
            return f"TEXT:{compact[:120]}"
    except Exception:
        pass

    return f"HEX:{out[:80].hex()}"


NIL_DB = Lam(Lam(Var(0)))
I_DB = Lam(Var(0))
A_DB = Lam(Lam(App(Var(0), Var(0))))
B_DB = Lam(Lam(App(Var(1), Var(0))))
PAIR_AB_DB = Lam(App(App(Var(0), A_DB), B_DB))

NIL = NConst(NIL_DB)
I = NConst(I_DB)
A = NConst(A_DB)
B = NConst(B_DB)
PAIR_AB = NConst(PAIR_AB_DB)


def int_term(n: int) -> NConst:
    return NConst(encode_byte_term(n))


def int_term_wide(n: int) -> NConst:
    if n < 0:
        raise ValueError("n must be non-negative")

    expr: object = Var(0)
    remaining = n
    weights = (
        (8, 128),
        (7, 64),
        (6, 32),
        (5, 16),
        (4, 8),
        (3, 4),
        (2, 2),
        (1, 1),
    )

    while remaining > 0:
        for idx, weight in weights:
            while remaining >= weight:
                expr = App(Var(idx), expr)
                remaining -= weight

    term = expr
    for _ in range(9):
        term = Lam(term)
    return NConst(term)


def bytes_term(bs: bytes) -> NConst:
    return NConst(encode_bytes_list(bs))


def str_term(s: str) -> NConst:
    return bytes_term(s.encode("ascii", "replace"))


def write_str(s: str) -> object:
    return apps(g(2), str_term(s), NIL)


def make_observer(left_marker: str = "LEFT\n") -> object:
    right_handler = lam(
        "errcode",
        apps(
            g(1),
            v("errcode"),
            lam(
                "err_str_either",
                apps(
                    v("err_str_either"),
                    lam("errstr", apps(g(2), v("errstr"), NIL)),
                    lam("_e2", write_str("ERR_DECODE_FAIL\n")),
                ),
            ),
        ),
    )

    left_handler = lam("_left_payload", write_str(left_marker))

    return lam("result", apps(v("result"), left_handler, right_handler))


OBS = make_observer()


def make_bytes_observer(right_fallback: str = "ERR_DECODE_FAIL\n") -> object:
    right_handler = lam(
        "errcode",
        apps(
            g(1),
            v("errcode"),
            lam(
                "err_str_either",
                apps(
                    v("err_str_either"),
                    lam("errstr", apps(g(2), v("errstr"), NIL)),
                    lam("_e2", write_str(right_fallback)),
                ),
            ),
        ),
    )
    left_handler = lam("left_payload", apps(g(2), v("left_payload"), NIL))
    return lam("result", apps(v("result"), left_handler, right_handler))


def scott_pair(a: object, b: object) -> object:
    return lam("sel", apps(v("sel"), a, b))


def run_case(label: str, term: object, sleep_s: float = 0.35) -> None:
    db_term = to_db(term)
    payload = encode_term(db_term) + bytes([FF])
    out = query(payload)
    print(f"{label:62s} payload={len(payload):4d} -> {classify(out)}")
    time.sleep(sleep_s)


def section(title: str) -> None:
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def group_continuation_gate() -> None:
    section("GROUP 1: CONTINUATION-CENTRIC TESTS")

    write_k = lam("_r", write_str("K\n"))

    continuations: list[tuple[str, object]] = [
        ("OBS", OBS),
        ("I", I),
        ("A", A),
        ("B", B),
        ("PAIR_AB", PAIR_AB),
        ("g(201)", g(201)),
        ("write_K", write_k),
    ]

    for name, cont in continuations:
        direct = apps(g(8), NIL, cont)
        forced = apps(direct, OBS)
        run_case(f"G1 direct  sys8(nil)({name})", direct)
        run_case(f"G1 forced  (sys8(nil)({name}))(OBS)", forced)


def group_thunk_arguments() -> None:
    section("GROUP 2: CBN THUNK ARGUMENT TESTS")

    thunk_args: list[tuple[str, object]] = [
        ("g(201)(nil)", apps(g(201), NIL)),
        ("g(201)(g(8))", apps(g(201), g(8))),
        ("g(14)(g(8))", apps(g(14), g(8))),
        ("g(14)(g(201))", apps(g(14), g(201))),
        ("g(7)(int(11))", apps(g(7), int_term(11))),
    ]

    for name, arg in thunk_args:
        run_case(f"G2 sys8({name})(OBS)", apps(g(8), arg, OBS))


def group_runtime_and_closure() -> None:
    section("GROUP 3: RUNTIME-COMPUTED ARG + CLOSURE-CAPTURED CONT")

    # R1: quote(g8) -> if Left(bytes), feed bytes to sys8.
    r1 = apps(
        g(4),
        g(8),
        lam(
            "quote_res",
            apps(
                v("quote_res"),
                lam("qbytes", apps(g(8), v("qbytes"), OBS)),
                lam("qerr", write_str("QERR\n")),
            ),
        ),
    )
    run_case("G3 R1 quote(g8)->sys8(quoted_bytes)", r1)

    # R2: backdoor(nil) -> Left(pair) -> sys8(nil, k_pair_capture)
    # k_pair_capture references `pair` in a side position so the closure captures it.
    pair_selector_fst = lam("a", lam("b", v("a")))
    pair_token = apps(v("pair"), pair_selector_fst, NIL)

    pair_captured_observer = lam(
        "res",
        apps(
            lam(
                "_tok",
                apps(
                    v("res"),
                    lam("_left", write_str("LEFT\n")),
                    lam(
                        "err",
                        apps(
                            g(1),
                            v("err"),
                            lam(
                                "err_str_either",
                                apps(
                                    v("err_str_either"),
                                    lam("errstr", apps(g(2), v("errstr"), NIL)),
                                    lam("_e2", write_str("ERR_DECODE_FAIL\n")),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            pair_token,
        ),
    )

    r2 = apps(
        g(201),
        NIL,
        lam(
            "bd_res",
            apps(
                v("bd_res"),
                lam("pair", apps(g(8), NIL, pair_captured_observer)),
                lam("_bd_err", write_str("BDERR\n")),
            ),
        ),
    )
    run_case("G3 R2 backdoor-pair-captured continuation", r2)

    # R3: Direct CBN-shape killer test from ultrabrain:
    #     sys8(g(201)(nil))(OBS)
    r3 = apps(g(8), apps(g(201), NIL), OBS)
    run_case("G3 R3 sys8(g201(nil))(OBS) minimal CBN test", r3)


def group_stateful_chains() -> None:
    section("GROUP 4: STATEFUL MULTI-SYSCALL CHAINS")

    # S1: Feed syscall8's first result back into syscall8 as argument.
    s1 = apps(g(8), NIL, lam("r1", apps(g(8), v("r1"), OBS)))
    run_case("G4 S1 sys8(nil)->sys8(result)", s1)

    # S2: sys8 trigger first, then fetch backdoor pair, then call sys8(pair).
    s2 = apps(
        g(8),
        NIL,
        lam(
            "_r1",
            apps(
                g(201),
                NIL,
                lam(
                    "bd_res",
                    apps(
                        v("bd_res"),
                        lam("pair", apps(g(8), v("pair"), OBS)),
                        lam("_bd_err", write_str("BDERR\n")),
                    ),
                ),
            ),
        ),
    )
    run_case("G4 S2 sys8->backdoor(nil)->sys8(pair)", s2)

    # S3: Use syscall8 result as backdoor input to detect cross-syscall capability effects.
    s3 = apps(
        g(8),
        NIL,
        lam(
            "r1",
            apps(
                g(201),
                v("r1"),
                lam(
                    "bd2",
                    apps(
                        v("bd2"),
                        lam("_left", write_str("BD_LEFT\n")),
                        lam(
                            "err",
                            apps(
                                g(1),
                                v("err"),
                                lam(
                                    "err_str_either",
                                    apps(
                                        v("err_str_either"),
                                        lam("errstr", apps(g(2), v("errstr"), NIL)),
                                        lam("_e2", write_str("ERR_DECODE_FAIL\n")),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
    run_case("G4 S3 sys8(result)->backdoor(result)", s3)


def group_wide_integer_auth() -> None:
    section("GROUP 5: WIDE-INTEGER AUTH/CAPABILITY TESTS (>255)")

    bytes_obs = make_bytes_observer()

    # Validation: ensure wide encoding still reaches known id 256.
    run_case("G5 V1 name(256 wide)", apps(g(6), int_term_wide(256), bytes_obs))
    run_case("G5 V2 readfile(256 wide)", apps(g(7), int_term_wide(256), bytes_obs))

    # Compare legacy modulo-256 encoder vs true wide additive encoding.
    run_case("G5 V3 sys8(int1000 legacy byte-encoder)", apps(g(8), int_term(1000), OBS))
    run_case("G5 V4 sys8(int1000 true-wide)", apps(g(8), int_term_wide(1000), OBS))
    run_case("G5 V5 sys8(int1002 true-wide)", apps(g(8), int_term_wide(1002), OBS))

    for n in [256, 257, 511, 512, 1024, 4096]:
        run_case(f"G5 V6 sys8(int{n} true-wide)", apps(g(8), int_term_wide(n), OBS))

    pw = str_term("ilikephp")
    crypt_hash = str_term("GZKc.2/VQffio")

    pair_uid1000_pw = scott_pair(int_term_wide(1000), pw)
    pair_uid1002_pw = scott_pair(int_term_wide(1002), pw)
    pair_uid1000_hash = scott_pair(int_term_wide(1000), crypt_hash)
    pair_uid1000_uid1000 = scott_pair(int_term_wide(1000), int_term_wide(1000))

    run_case(
        "G5 V7 sys8(pair(uid1000_wide, 'ilikephp'))",
        apps(g(8), pair_uid1000_pw, OBS),
    )
    run_case(
        "G5 V8 sys8(pair(uid1002_wide, 'ilikephp'))",
        apps(g(8), pair_uid1002_pw, OBS),
    )
    run_case(
        "G5 V9 sys8(pair(uid1000_wide, crypt_hash))",
        apps(g(8), pair_uid1000_hash, OBS),
    )
    run_case(
        "G5 V10 sys8(pair(uid1000_wide, uid1000_wide))",
        apps(g(8), pair_uid1000_uid1000, OBS),
    )


def main() -> None:
    print("=" * 80)
    print("PROBE ULTRA3 - CONTINUATION/CBN/RUNTIME EXPERIMENTS")
    print("=" * 80)

    group_continuation_gate()
    group_thunk_arguments()
    group_runtime_and_closure()
    group_stateful_chains()
    group_wide_integer_auth()

    print("\n" + "=" * 80)
    print("DONE")
    print("=" * 80)


if __name__ == "__main__":
    main()
