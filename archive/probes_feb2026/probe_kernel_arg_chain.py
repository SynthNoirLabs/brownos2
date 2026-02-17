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


def run_case(label: str, term: object, rows: list[tuple[str, str, float, str]]) -> None:
    out, elapsed, plen = query_named(term)
    bucket = classify(out)
    rows.append((label, bucket, elapsed, out.hex() if out else ""))
    print(label)
    print(f"  payload_len: {plen}")
    print(f"  elapsed: {elapsed:.3f}s")
    print(f"  bucket: {bucket}")
    print(f"  raw_hex: {out.hex() if out else '(empty)'}")
    print(f"  text: {out.decode('latin-1', errors='replace') if out else ''!r}")
    print()


def main() -> None:
    print("=" * 80)
    print("probe_kernel_arg_chain.py")
    print("Inline chain: backdoor runtime values -> sys8 arg/continuation")
    print("=" * 80)
    print()

    rows: list[tuple[str, str, float, str]] = []

    run_case("CTRL: g(8)(nil)(OBS)", apps(g(8), NIL, OBS), rows)

    # Group E: direct inline args
    run_case(
        "E1: backdoor -> sys8(pair)(OBS)",
        from_backdoor(lambda p: apps(g(8), p, OBS)),
        rows,
    )
    run_case(
        "E2: backdoor -> sys8(A)(OBS)",
        from_backdoor(lambda p: apps(g(8), apps(p, selector_a(), NIL), OBS)),
        rows,
    )
    run_case(
        "E3: backdoor -> sys8(B)(OBS)",
        from_backdoor(lambda p: apps(g(8), apps(p, selector_b(), NIL), OBS)),
        rows,
    )
    run_case(
        "E4: backdoor -> sys8(A(B))(OBS)",
        from_backdoor(
            lambda p: apps(
                g(8),
                apps(apps(p, selector_a(), NIL), apps(p, selector_b(), NIL)),
                OBS,
            )
        ),
        rows,
    )
    run_case(
        "E5: backdoor -> sys8(B(A))(OBS)",
        from_backdoor(
            lambda p: apps(
                g(8),
                apps(apps(p, selector_b(), NIL), apps(p, selector_a(), NIL)),
                OBS,
            )
        ),
        rows,
    )

    # Group F: continuation capability
    run_case(
        "F1: backdoor -> sys8(nil)(pair)",
        from_backdoor(lambda p: apps(g(8), NIL, p)),
        rows,
    )
    run_case(
        "F2: backdoor -> sys8(nil)(A)",
        from_backdoor(lambda p: apps(g(8), NIL, apps(p, selector_a(), NIL))),
        rows,
    )
    run_case(
        "F3: backdoor -> sys8(nil)(B)",
        from_backdoor(lambda p: apps(g(8), NIL, apps(p, selector_b(), NIL))),
        rows,
    )

    # Group G: password + capability
    pw = NConst(encode_bytes_list(b"ilikephp"))
    run_case(
        "G1: backdoor -> sys8(ilikephp)(OBS)",
        from_backdoor(lambda _p: apps(g(8), pw, OBS)),
        rows,
    )
    run_case(
        "G2: backdoor -> sys8(pair(ilikephp))(OBS)",
        from_backdoor(lambda p: apps(g(8), apps(p, pw), OBS)),
        rows,
    )

    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"{'LABEL':45s} {'BUCKET':12s} {'TIME':>8s}")
    print("-" * 80)
    for label, bucket, elapsed, _ in rows:
        print(f"{label:45.45s} {bucket:12s} {elapsed:8.3f}")

    signals = [
        r
        for r in rows
        if (not r[0].startswith("CTRL")) and r[1] in {"LEFT", "RIGHT_OTHER"}
    ]
    if signals:
        print("\nSIGNALS:")
        for label, bucket, _elapsed, hx in signals:
            print(f"  {label}: {bucket} hex={hx}")
    else:
        print("\nNo behavioral change detected (no LEFT/RIGHT_OTHER).")


if __name__ == "__main__":
    main()
