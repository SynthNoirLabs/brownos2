#!/usr/bin/env python3
"""
probe_sys8_next.py

Runs the "next wave" of syscall 0x08 (sys8) experiments:

G1) Pass echo result directly to sys8 (NO unwrap) for g(251)/g(252) to preserve
    the +2-shifted (potentially unquotable) payload inside Left. This targets
    the "Var indices 253..255 exist at runtime but cannot be serialized" gotcha.

G2) Build unquotable runtime terms by *evaluation*, not by literal encoding:
    (λx. λ^n. x) g(251/252)  ==>  λ^n. Var(251/252 + n) at runtime.
    For n=1..3, this yields Var(253/254/255) in the reduced form.

G3) access.log challenge-response hypothesis:
    readfile(46) -> unwrap Left(bytes) -> sys8(bytes) in the same program,
    plus variants passing the Either directly.

G4) Backdoor pair A/B tests:
    sys8(A), sys8(B), sys8(pair), sys8(a(b)), sys8(a(a)), etc.
    NOTE: We FORCE the Scott-cons payload with (pair selector NIL).

G5) sys8 argument scan across all globals 0..252:
    sys8(g(i)) with adaptive backoff if we hit "Not so fast!".

G6) Sparse hidden ID scan for name(id) with wide integer encoding (>255).

Usage:
  python3 archive/probes_feb2026/probe_sys8_next.py
  python3 archive/probes_feb2026/probe_sys8_next.py --skip-globals
  python3 archive/probes_feb2026/probe_sys8_next.py --globals-start 200 --globals-end 252
"""

from __future__ import annotations

import argparse
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
FE = 0xFE
FF = 0xFF


# -----------------------------------------------------------------------------
# Named-term DSL (same idea as probe_ultra3 / probe_sys8_tracks)
# -----------------------------------------------------------------------------
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
    """Shift free de Bruijn indices by delta (standard operation)."""
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_db(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_db(term.f, delta, cutoff), shift_db(term.x, delta, cutoff))
    return term


def to_db(term: object, env: tuple[str, ...] = ()) -> object:
    """
    Convert named term into de Bruijn term.
    env is (innermost, ..., outermost)
    """
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


# -----------------------------------------------------------------------------
# Network helpers
# -----------------------------------------------------------------------------
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
            return f"TEXT:{compact[:160]}"
    except Exception:
        pass
    return f"HEX:{out[:80].hex()}"


# -----------------------------------------------------------------------------
# Term constructors
# -----------------------------------------------------------------------------
NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)


def int_term(n: int) -> NConst:
    # NOTE: solve_brownos_answer.encode_byte_term effectively covers 0..255 cleanly.
    return NConst(encode_byte_term(n))


def int_term_wide(n: int) -> NConst:
    """
    True additive encoding that supports >255 by repeating weights.
    Same strategy as probe_ultra3.
    """
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
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return NConst(term)


def bytes_term(bs: bytes) -> NConst:
    return NConst(encode_bytes_list(bs))


def str_term(s: str) -> NConst:
    return bytes_term(s.encode("ascii", "replace"))


def write_str(s: str) -> object:
    return apps(g(2), str_term(s), NIL)


def make_observer(left_marker: str = "LEFT\\n") -> object:
    """
    OBS: If Left(_) => prints left_marker (only).
         If Right(errcode) => prints decoded error string.
    """
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
                    lam("_e2", write_str("ERR_DECODE_FAIL\\n")),
                ),
            ),
        ),
    )
    left_handler = lam("_left_payload", write_str(left_marker))
    return lam("result", apps(v("result"), left_handler, right_handler))


def make_observer_left_dump(left_marker: str = "LEFT\\n") -> object:
    """
    Like OBS, but on Left(payload):
      - write(left_marker)
      - then best-effort write(payload) as bytes list (may fail silently if not bytes)
    """
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
                    lam("_e2", write_str("ERR_DECODE_FAIL\\n")),
                ),
            ),
        ),
    )
    left_handler = lam(
        "payload",
        apps(
            g(2),
            str_term(left_marker),
            lam("_w1", apps(g(2), v("payload"), NIL)),
        ),
    )
    return lam("result", apps(v("result"), left_handler, right_handler))


OBS = make_observer("LEFT\\n")
OBS_DUMP = make_observer_left_dump("LEFT\\n")


# -----------------------------------------------------------------------------
# Runner
# -----------------------------------------------------------------------------
FLAGGED: list[str] = []


def run_case(
    label: str,
    term: object,
    *,
    sleep_s: float,
    timeout_s: float,
    max_payload: int,
    retries: int,
) -> None:
    db_term = to_db(term)
    payload = encode_term(db_term) + bytes([FF])
    if len(payload) > max_payload:
        print(f"{label:70s} payload={len(payload):4d} -> SKIP(>{max_payload})")
        return

    out = query(payload, retries=retries, timeout_s=timeout_s)
    res = classify(out)

    # Flag anything that isn't the boring baseline
    if (
        ("Permission denied" not in res)
        and ("Not so fast!" not in res)
        and res not in ("EMPTY", "Invalid term!")
    ):
        FLAGGED.append(f"{label} -> {res}")

    print(f"{label:70s} payload={len(payload):4d} -> {res}")

    # Adaptive backoff on rate limit message
    if "Not so fast!" in res:
        time.sleep(max(2.0, sleep_s * 6))
    else:
        time.sleep(sleep_s)


def section(title: str) -> None:
    print("\\n" + "=" * 92)
    print(title)
    print("=" * 92)


# -----------------------------------------------------------------------------
# Groups
# -----------------------------------------------------------------------------
def group_g1_echo_result_to_sys8(args: argparse.Namespace) -> None:
    section("G1: sys8(echo(X)) WITHOUT unwrapping Either (X in {g251, g252})")
    for idx in (251, 252):
        t = apps(
            g(14),  # echo
            g(idx),
            lam("echo_res", apps(g(8), v("echo_res"), OBS)),
        )
        run_case(
            f"G1 sys8(echo(g{idx}))",
            t,
            sleep_s=args.delay,
            timeout_s=args.timeout,
            max_payload=args.max_payload,
            retries=args.retries,
        )


def _cap_under(n: int) -> object:
    """
    Returns λx. λa0. ... λa(n-1). x
    When applied to g(k), this reduces to λ^n. (shift(g(k), +n))
    """
    body: object = v("x")
    for i in range(n):
        body = lam(f"a{i}", body)
    return lam("x", body)


def group_g2_runtime_shift_unquotable(args: argparse.Namespace) -> None:
    section(
        "G2: sys8( (λx. λ^n. x) g(k) ) to create Var(k+n) at runtime (k=251/252, n=1..3)"
    )
    for k in (251, 252):
        for n in (1, 2, 3):
            u = apps(_cap_under(n), g(k))
            t = apps(g(8), u, OBS)
            run_case(
                f"G2 sys8(shift{n}(g{k}))",
                t,
                sleep_s=args.delay,
                timeout_s=args.timeout,
                max_payload=args.max_payload,
                retries=args.retries,
            )


def group_g3_access_log_nonce(args: argparse.Namespace) -> None:
    section("G3: access.log challenge-response (readfile(46) -> sys8(bytes))")

    access_id = int_term_wide(46)

    # Variant A: unwrap Left(bytes) from readfile, then sys8(bytes)
    t_unwrap = apps(
        g(7),  # readfile
        access_id,
        lam(
            "rf",
            apps(
                v("rf"),
                lam("bytes", apps(g(8), v("bytes"), OBS)),
                lam("_err", write_str("READFILE_ERR\\n")),
            ),
        ),
    )

    # Variant B: pass the Either from readfile directly into sys8
    t_either = apps(
        g(7),
        access_id,
        lam("rf", apps(g(8), v("rf"), OBS)),
    )

    # Variant C: readfile twice with sys8(bytes1) in between (prints bytes1 and bytes2)
    # (May get skipped if payload > max_payload.)
    t_chain = apps(
        g(7),
        access_id,
        lam(
            "rf1",
            apps(
                v("rf1"),
                lam(
                    "b1",
                    apps(
                        g(2),
                        v("b1"),
                        lam(
                            "_w",
                            apps(
                                g(8),
                                v("b1"),
                                lam(
                                    "_r",
                                    apps(
                                        g(7),
                                        access_id,
                                        lam(
                                            "rf2",
                                            apps(
                                                v("rf2"),
                                                lam("b2", apps(g(2), v("b2"), NIL)),
                                                lam("_e2", write_str("READ2_ERR\\n")),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
                lam("_e1", write_str("READ1_ERR\\n")),
            ),
        ),
    )

    run_case(
        "G3A readfile(46)->sys8(bytes)",
        t_unwrap,
        sleep_s=args.delay,
        timeout_s=args.timeout,
        max_payload=args.max_payload,
        retries=args.retries,
    )
    run_case(
        "G3B readfile(46)->sys8(Either)",
        t_either,
        sleep_s=args.delay,
        timeout_s=args.timeout,
        max_payload=args.max_payload,
        retries=args.retries,
    )
    run_case(
        "G3C readfile(46);print;sys8;readfile(46);print",
        t_chain,
        sleep_s=args.delay,
        timeout_s=args.timeout,
        max_payload=args.max_payload,
        retries=args.retries,
    )


def group_g4_backdoor_ab(args: argparse.Namespace) -> None:
    section("G4: Backdoor A/B tests (force cons with (pair selector NIL))")

    combos: list[tuple[str, object]] = [
        ("a", v("a")),
        ("b", v("b")),
        ("pair_as_is", v("pair")),  # note: only meaningful in the sys8(pair) case below
        ("a(a)", apps(v("a"), v("a"))),
        ("b(b)", apps(v("b"), v("b"))),
        ("a(b)", apps(v("a"), v("b"))),
        ("b(a)", apps(v("b"), v("a"))),
        ("b(a(b))", apps(v("b"), apps(v("a"), v("b")))),
    ]

    # 1) sys8(pair) where pair is the raw payload (cons A B)
    t_sys8_pair = apps(
        g(201),
        NIL,
        lam(
            "bd_res",
            apps(
                v("bd_res"),
                lam("pair", apps(g(8), v("pair"), OBS)),
                lam("_err", write_str("BD_ERR\\n")),
            ),
        ),
    )
    run_case(
        "G4.1 backdoor(nil)->sys8(pair_payload)",
        t_sys8_pair,
        sleep_s=args.delay,
        timeout_s=args.timeout,
        max_payload=args.max_payload,
        retries=args.retries,
    )

    # 2) sys8(Either) where bd_res is the Either itself
    t_sys8_either = apps(g(201), NIL, lam("bd_res", apps(g(8), v("bd_res"), OBS)))
    run_case(
        "G4.2 backdoor(nil)->sys8(Either)",
        t_sys8_either,
        sleep_s=args.delay,
        timeout_s=args.timeout,
        max_payload=args.max_payload,
        retries=args.retries,
    )

    # 3) Extract A/B via selector and force with NIL, then sys8(combo)
    for name, combo in combos:
        if name == "pair_as_is":
            continue

        selector = lam("a", lam("b", apps(g(8), combo, OBS)))

        t = apps(
            g(201),
            NIL,
            lam(
                "bd_res",
                apps(
                    v("bd_res"),
                    lam("pair", apps(v("pair"), selector, NIL)),  # FORCE cons
                    lam("_err", write_str("BD_ERR\\n")),
                ),
            ),
        )
        run_case(
            f"G4.3 backdoor->sys8({name})",
            t,
            sleep_s=args.delay,
            timeout_s=args.timeout,
            max_payload=args.max_payload,
            retries=args.retries,
        )


def group_g5_sys8_global_scan(args: argparse.Namespace) -> None:
    section(
        f"G5: sys8(g(i)) scan for globals i={args.globals_start}..{args.globals_end}"
    )

    for i in range(args.globals_start, args.globals_end + 1):
        t = apps(g(8), g(i), OBS)
        run_case(
            f"G5 sys8(g{i})",
            t,
            sleep_s=args.delay_scan,
            timeout_s=args.timeout,
            max_payload=args.max_payload,
            retries=args.retries,
        )


def group_g6_sparse_id_scan(args: argparse.Namespace) -> None:
    section("G6: Sparse hidden-ID scan via name(id) with wide integer encoding")

    # Targets: powers of two + common CTF-ish numbers + a few hex patterns.
    targets = [
        1025,
        1337,
        2048,
        31337,
        4096,
        4242,
        8192,
        9001,
        16384,
        32768,
        48879,  # 0xBEEF
        57005,  # 0xDEAD
    ]

    # Use OBS_DUMP so we get LEFT marker and then attempt to print the payload bytes
    # (name() returns bytes list on success, so this is usually perfect).
    for n in targets:
        t = apps(g(6), int_term_wide(n), OBS_DUMP)
        run_case(
            f"G6 name({n})",
            t,
            sleep_s=args.delay,
            timeout_s=args.timeout,
            max_payload=args.max_payload,
            retries=args.retries,
        )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=7.0)
    ap.add_argument("--retries", type=int, default=4)
    ap.add_argument("--max-payload", type=int, default=1900)
    ap.add_argument(
        "--delay", type=float, default=0.40, help="Delay between non-scan cases."
    )
    ap.add_argument(
        "--delay-scan", type=float, default=0.25, help="Delay between scan cases."
    )
    ap.add_argument("--skip-globals", action="store_true")
    ap.add_argument("--skip-id-scan", action="store_true")
    ap.add_argument("--globals-start", type=int, default=0)
    ap.add_argument("--globals-end", type=int, default=252)
    args = ap.parse_args()

    print("=" * 92)
    print(
        "PROBE SYS8 NEXT - unquotable terms + access.log nonce + backdoor A/B + scans"
    )
    print("=" * 92)
    print(f"HOST={HOST} PORT={PORT}")
    print()

    group_g1_echo_result_to_sys8(args)
    group_g2_runtime_shift_unquotable(args)
    group_g3_access_log_nonce(args)
    group_g4_backdoor_ab(args)

    if not args.skip_globals:
        group_g5_sys8_global_scan(args)

    if not args.skip_id_scan:
        group_g6_sparse_id_scan(args)

    print("\\n" + "=" * 92)
    if FLAGGED:
        print(f"FLAGGED RESULTS ({len(FLAGGED)}):")
        for f in FLAGGED:
            print(f"  {f}")
    else:
        print("No non-baseline results flagged.")
    print("=" * 92)


if __name__ == "__main__":
    main()
