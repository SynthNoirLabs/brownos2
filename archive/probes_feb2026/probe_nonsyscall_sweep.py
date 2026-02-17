#!/usr/bin/env python3
from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import App, Lam, Var, FF, encode_bytes_list, encode_term

HOST = "wc3.wechall.net"
PORT = 61221
TIMEOUT_S = 6.0
REQUEST_DELAY_S = 0.2
MAX_PAYLOAD = 2000


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
    raise TypeError(f"Unsupported term type: {type(term)}")


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


NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)


def recv_all(sock: socket.socket, timeout_s: float = TIMEOUT_S) -> bytes:
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


def query_named(term: object, timeout_s: float = TIMEOUT_S) -> tuple[bytes, float, int]:
    payload = encode_term(to_db(term)) + bytes([FF])
    plen = len(payload)
    if plen > MAX_PAYLOAD:
        return b"", 0.0, plen
    start = time.monotonic()
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            out = recv_all(sock, timeout_s)
        elapsed = time.monotonic() - start
        time.sleep(REQUEST_DELAY_S)
        return out, elapsed, plen
    except Exception:
        elapsed = time.monotonic() - start
        time.sleep(REQUEST_DELAY_S)
        return b"", elapsed, plen


def classify(out: bytes) -> str:
    if not out:
        return "EMPTY"
    txt = out.decode("latin-1", errors="replace")
    if "Permission denied" in txt:
        return "RIGHT_6"
    if "Not implemented" in txt:
        return "RIGHT_1"
    if txt.startswith("R:"):
        return "RIGHT_OTHER"
    if txt.startswith("L:"):
        return "LEFT"
    if out.startswith(b"Invalid term!"):
        return "INVALID"
    if out.startswith(b"Encoding failed!"):
        return "ENCFAIL"
    if out.startswith(b"Term too big!"):
        return "TOOBIG"
    return "OTHER"


def write_str(s: bytes) -> object:
    return NConst(encode_bytes_list(s))


def obs_detailed() -> object:
    right_handler = lam(
        "err_code",
        apps(
            g(2),
            write_str(b"R:"),
            lam(
                "_w",
                apps(
                    g(1),
                    v("err_code"),
                    lam(
                        "err_res",
                        apps(
                            v("err_res"),
                            lam("errstr", apps(g(2), v("errstr"), NIL)),
                            lam("_e2", apps(g(2), write_str(b"?"), NIL)),
                        ),
                    ),
                ),
            ),
        ),
    )
    left_handler = lam(
        "payload",
        apps(g(2), write_str(b"L:"), lam("_w", NIL)),
    )
    return lam("res", apps(v("res"), left_handler, right_handler))


OBS = obs_detailed()


def selector_a() -> object:
    return lam("a", lam("b", v("a")))


def selector_b() -> object:
    return lam("a", lam("b", v("b")))


def from_backdoor(builder) -> object:
    return apps(
        g(201),
        NIL,
        lam(
            "bd_res",
            apps(
                v("bd_res"),
                lam("pair", builder(v("pair"))),
                lam("_bd_err", apps(g(2), write_str(b"BDF"), NIL)),
            ),
        ),
    )


def run_case(label: str, term: object) -> tuple[str, float, str]:
    out, elapsed, plen = query_named(term)
    bucket = classify(out)
    print(label)
    print(f"  payload_len: {plen}")
    print(f"  elapsed: {elapsed:.3f}s")
    print(f"  bucket: {bucket}")
    print(f"  raw_hex: {out.hex() if out else '(empty)'}")
    print(f"  text: {out.decode('latin-1', errors='replace') if out else ''!r}")
    print()
    return bucket, elapsed, out.hex() if out else ""


def main() -> None:
    print("=" * 80)
    print("probe_nonsyscall_sweep.py")
    print("Sweep active globals with kernel-minted pair/A/B values")
    print("=" * 80)
    print()

    active = [1, 2, 4, 5, 6, 7, 8, 14, 42]
    results: list[tuple[str, str, float, str]] = []
    anomalies: list[int] = []

    # Group H baseline and pair round
    for i in active:
        b_bucket, b_t, b_hex = run_case(
            f"H{i}-BASE: g({i})(nil)(OBS)", apps(g(i), NIL, OBS)
        )
        results.append((f"H{i}-BASE", b_bucket, b_t, b_hex))

        p_bucket, p_t, p_hex = run_case(
            f"H{i}-PAIR: backdoor->g({i})(pair)(OBS)",
            from_backdoor(lambda p, idx=i: apps(g(idx), p, OBS)),
        )
        results.append((f"H{i}-PAIR", p_bucket, p_t, p_hex))

        if p_bucket != b_bucket:
            anomalies.append(i)

    if not anomalies:
        print("ABORT_EARLY: No pair-vs-baseline anomalies across active globals.")
    else:
        print(f"Anomalies detected on globals: {anomalies}")
        print("Running A/B rounds only for anomalous globals.")
        print()
        for i in anomalies:
            a_bucket, a_t, a_hex = run_case(
                f"I{i}-A: backdoor->g({i})(A)(OBS)",
                from_backdoor(
                    lambda p, idx=i: apps(g(idx), apps(p, selector_a(), NIL), OBS)
                ),
            )
            results.append((f"I{i}-A", a_bucket, a_t, a_hex))

            b_bucket, b_t, b_hex = run_case(
                f"I{i}-B: backdoor->g({i})(B)(OBS)",
                from_backdoor(
                    lambda p, idx=i: apps(g(idx), apps(p, selector_b(), NIL), OBS)
                ),
            )
            results.append((f"I{i}-B", b_bucket, b_t, b_hex))

    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"{'LABEL':28s} {'BUCKET':12s} {'TIME':>8s}")
    print("-" * 80)
    for label, bucket, elapsed, _ in results:
        print(f"{label:28.28s} {bucket:12s} {elapsed:8.3f}")


if __name__ == "__main__":
    main()
