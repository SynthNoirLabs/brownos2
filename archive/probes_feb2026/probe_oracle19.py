#!/usr/bin/env python3
"""
probe_oracle19.py - syscall 8 hypothesis probes (Oracle #19).

Focus:
- Test whether syscall 8 can be unlocked by backdoor context (g(201)).
- Test whether syscall 8 requires kernel-minted byte payloads.
- Test non-standard continuations and g(0) exception-handler context.

Observation strategy:
- Use a quote-free tag continuation that writes "LEFT\n" on Left and "RIGHT\n" on Right.
- Send exactly one term per TCP connection.
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FF,
    encode_term,
    encode_byte_term,
    encode_bytes_list,
    parse_term,
    decode_either,
    decode_byte_term,
    decode_bytes_list,
)


HOST = "wc3.wechall.net"
PORT = 61221
TIMEOUT_S = 6.0
REQUEST_DELAY_S = 0.3
MAX_PAYLOAD = 2000

LEFT_MARKER = b"LEFT\n"
RIGHT_MARKER = b"RIGHT\n"


@dataclass(frozen=True)
class Experiment:
    code: str
    group: str
    label: str
    term: object


@dataclass(frozen=True)
class ProbeResult:
    code: str
    group: str
    label: str
    payload_len: int
    elapsed: float
    bucket: str
    decoded: str


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


def query_raw(payload: bytes, timeout_s: float = TIMEOUT_S) -> tuple[bytes, float]:
    start = time.monotonic()
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            out = recv_all(sock, timeout_s=timeout_s)
        elapsed = time.monotonic() - start
        return out, elapsed
    except Exception:
        elapsed = time.monotonic() - start
        return b"", elapsed


def shift_free_vars(term: object, delta: int, cutoff: int = 0) -> object:
    if isinstance(term, Var):
        if term.i >= cutoff:
            return Var(term.i + delta)
        return term
    if isinstance(term, Lam):
        return Lam(shift_free_vars(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(
            shift_free_vars(term.f, delta, cutoff),
            shift_free_vars(term.x, delta, cutoff),
        )
    return term


def build_tag_cont(left_marker: bytes, right_marker: bytes) -> object:
    """
    λresult.
      result
        (λpayload. write(left_marker, g(0)))
        (λerrcode. write(right_marker, g(0)))
    """
    left_marker_term = encode_bytes_list(left_marker)
    right_marker_term = encode_bytes_list(right_marker)

    # Under λresult.λpayload: g(2)=Var(4), g(0)=Var(2)
    left_handler = Lam(App(App(Var(4), shift_free_vars(left_marker_term, 2)), Var(2)))

    # Under λresult.λerrcode: g(2)=Var(4), g(0)=Var(2)
    right_handler = Lam(App(App(Var(4), shift_free_vars(right_marker_term, 2)), Var(2)))

    # Under λresult: result=Var(0)
    return Lam(App(App(Var(0), left_handler), right_handler))


def classify_response(
    out: bytes,
    elapsed: float,
    timeout_s: float,
    left_marker: bytes,
    right_marker: bytes,
) -> tuple[str, str]:
    if not out:
        if elapsed >= timeout_s - 0.5:
            return "OTHER", "TIMEOUT"
        return "OTHER", f"EMPTY({elapsed:.1f}s)"

    has_left = left_marker in out
    has_right = right_marker in out
    if has_left and not has_right:
        return "LEFT", f"LEFT_MARKER:{left_marker!r}"
    if has_right and not has_left:
        return "RIGHT", f"RIGHT_MARKER:{right_marker!r}"
    if has_left and has_right:
        return "OTHER", "BOTH_MARKERS"

    text = out.decode("latin-1", errors="replace")
    if text.startswith("Encoding failed"):
        return "OTHER", "ENC_FAIL"
    if text.startswith("Invalid term"):
        return "OTHER", "INVALID_TERM"
    if text.startswith("Term too big"):
        return "OTHER", "TOO_BIG"

    if FF in out:
        try:
            parsed = parse_term(out)
            tag, payload_data = decode_either(parsed)
            if tag == "Left":
                try:
                    bs = decode_bytes_list(payload_data)
                    return "LEFT", f"Left:{bs.decode('latin-1', errors='replace')!r}"
                except Exception:
                    return "LEFT", f"Left({payload_data})"

            try:
                err = decode_byte_term(payload_data)
                return "RIGHT", f"Right({err})"
            except Exception:
                return "RIGHT", f"Right({payload_data})"
        except Exception:
            return "OTHER", f"FF_DATA:{out[:40].hex()}"

    return "OTHER", f"DATA:{text!r}"


def build_experiments(tag_cont: object) -> list[Experiment]:
    nil_term = Lam(Lam(Var(0)))

    tag_cont_shift_1 = shift_free_vars(tag_cont, 1)
    tag_cont_shift_2 = shift_free_vars(tag_cont, 2)
    tag_cont_shift_3 = shift_free_vars(tag_cont, 3)

    fail_marker = encode_bytes_list(b"FAIL")

    experiments: list[Experiment] = []

    # ------------------------------------------------------------------
    # Group A: Backdoor-gated permission (highest priority)
    # ------------------------------------------------------------------
    experiments.append(
        Experiment(
            code="A1",
            group="A",
            label="g(201)(nil)(λp. g(8)(nil)(TAG_CONT_shifted))",
            term=App(
                App(Var(201), nil_term),
                Lam(App(App(Var(9), nil_term), tag_cont_shift_1)),
            ),
        )
    )

    experiments.append(
        Experiment(
            code="A2",
            group="A",
            label="g(201)(nil)(λp. g(8)(p)(TAG_CONT_shifted))",
            term=App(
                App(Var(201), nil_term),
                Lam(App(App(Var(9), Var(0)), tag_cont_shift_1)),
            ),
        )
    )

    experiments.append(
        Experiment(
            code="A3",
            group="A",
            label="g(201)(nil)(λp. p(λa.λb. g(8)(App(a,b))(TAG_CONT_shifted)))",
            term=App(
                App(Var(201), nil_term),
                Lam(
                    App(
                        Var(0),
                        Lam(
                            Lam(
                                App(
                                    App(Var(11), App(Var(1), Var(0))),
                                    tag_cont_shift_3,
                                )
                            )
                        ),
                    )
                ),
            ),
        )
    )

    experiments.append(
        Experiment(
            code="A4",
            group="A",
            label="g(201)(nil)(λp. p(λa.λb. g(8)(a)(TAG_CONT_shifted)))",
            term=App(
                App(Var(201), nil_term),
                Lam(
                    App(
                        Var(0),
                        Lam(Lam(App(App(Var(11), Var(1)), tag_cont_shift_3))),
                    )
                ),
            ),
        )
    )

    experiments.append(
        Experiment(
            code="A5",
            group="A",
            label="g(201)(nil)(λp. p(λa.λb. g(8)(b)(TAG_CONT_shifted)))",
            term=App(
                App(Var(201), nil_term),
                Lam(
                    App(
                        Var(0),
                        Lam(Lam(App(App(Var(11), Var(0)), tag_cont_shift_3))),
                    )
                ),
            ),
        )
    )

    # ------------------------------------------------------------------
    # Group B: Kernel-produced bytes as sys8 argument
    # ------------------------------------------------------------------
    experiments.append(
        Experiment(
            code="B1",
            group="B",
            label="g(1)(int(6))(λs. g(8)(s)(TAG_CONT_shifted))",
            term=App(
                App(Var(1), encode_byte_term(6)),
                Lam(App(App(Var(9), Var(0)), tag_cont_shift_1)),
            ),
        )
    )

    b2_left_handler = Lam(App(App(Var(10), Var(0)), tag_cont_shift_2))
    b2_right_handler = Lam(App(App(Var(4), shift_free_vars(fail_marker, 2)), Var(2)))
    b2_cont = Lam(App(App(Var(0), b2_left_handler), b2_right_handler))
    experiments.append(
        Experiment(
            code="B2",
            group="B",
            label=(
                "g(7)(int(11))(λresult. result"
                "(λbytes. g(8)(bytes)(TAG_CONT_shifted))"
                '(λerr. write("FAIL", g(0))))'
            ),
            term=App(App(Var(7), encode_byte_term(11)), b2_cont),
        )
    )

    experiments.append(
        Experiment(
            code="B3",
            group="B",
            label="g(14)(int(8))(λecho_result. g(8)(echo_result)(TAG_CONT_shifted))",
            term=App(
                App(Var(14), encode_byte_term(8)),
                Lam(App(App(Var(9), Var(0)), tag_cont_shift_1)),
            ),
        )
    )

    # ------------------------------------------------------------------
    # Group C: Non-standard continuations
    # ------------------------------------------------------------------
    experiments.append(
        Experiment(
            code="C1",
            group="C",
            label="g(8)(nil)(g(0))",
            term=App(App(Var(8), nil_term), Var(0)),
        )
    )
    experiments.append(
        Experiment(
            code="C2",
            group="C",
            label="g(8)(nil)(g(201))",
            term=App(App(Var(8), nil_term), Var(201)),
        )
    )
    experiments.append(
        Experiment(
            code="C3",
            group="C",
            label="g(8)(nil)(g(8))",
            term=App(App(Var(8), nil_term), Var(8)),
        )
    )
    experiments.append(
        Experiment(
            code="C4",
            group="C",
            label="g(8)(nil)(g(2))",
            term=App(App(Var(8), nil_term), Var(2)),
        )
    )

    # ------------------------------------------------------------------
    # Group D: Exception handler context
    # ------------------------------------------------------------------
    failing_term = App(App(Var(250), nil_term), nil_term)
    d1_handler = Lam(App(App(Var(9), nil_term), tag_cont_shift_1))
    experiments.append(
        Experiment(
            code="D1",
            group="D",
            label="g(0)(λex. g(8)(nil)(TAG_CONT_shifted))(g(250)(nil)(nil))",
            term=App(App(Var(0), d1_handler), failing_term),
        )
    )

    return experiments


def run_request(
    exp: Experiment,
    left_marker: bytes,
    right_marker: bytes,
    timeout_s: float = TIMEOUT_S,
) -> ProbeResult:
    payload = encode_term(exp.term) + bytes([FF])
    payload_len = len(payload)

    print(f"{exp.code} [{exp.group}] {exp.label}")
    print(f"  payload_len: {payload_len}")

    if payload_len > MAX_PAYLOAD:
        print("  elapsed: 0.000s")
        print("  raw_hex: (skipped)")
        print(f"  decoded: SKIPPED: too big ({payload_len} > {MAX_PAYLOAD})")
        print("  bucket: SKIPPED")
        print()
        return ProbeResult(
            code=exp.code,
            group=exp.group,
            label=exp.label,
            payload_len=payload_len,
            elapsed=0.0,
            bucket="SKIPPED",
            decoded=f"SKIPPED: too big ({payload_len} > {MAX_PAYLOAD})",
        )

    out, elapsed = query_raw(payload, timeout_s=timeout_s)
    bucket, decoded = classify_response(
        out,
        elapsed,
        timeout_s=timeout_s,
        left_marker=left_marker,
        right_marker=right_marker,
    )

    print(f"  elapsed: {elapsed:.3f}s")
    print(f"  raw_hex: {out.hex() if out else '(empty)'}")
    print(f"  decoded: {decoded}")
    print(f"  bucket: {bucket}")
    print()

    time.sleep(REQUEST_DELAY_S)

    return ProbeResult(
        code=exp.code,
        group=exp.group,
        label=exp.label,
        payload_len=payload_len,
        elapsed=elapsed,
        bucket=bucket,
        decoded=decoded,
    )


def print_summary(results: list[ProbeResult]) -> None:
    counts = {
        "LEFT": 0,
        "RIGHT": 0,
        "OTHER": 0,
        "SKIPPED": 0,
    }
    for r in results:
        counts[r.bucket] = counts.get(r.bucket, 0) + 1

    print("=" * 72)
    print("Summary")
    print("=" * 72)
    print(f"LEFT    : {counts['LEFT']}")
    print(f"RIGHT   : {counts['RIGHT']}")
    print(f"OTHER   : {counts['OTHER']}")
    print(f"SKIPPED : {counts['SKIPPED']}")
    print("-" * 72)
    for r in results:
        print(f"{r.code} [{r.group}] -> {r.bucket} | {r.decoded}")
    print("=" * 72)


def main() -> None:
    print("=" * 72)
    print("probe_oracle19.py - syscall 8 hypothesis probes")
    print(f"Target: {HOST}:{PORT}")
    print(
        f"Timeout: {TIMEOUT_S:.1f}s | Delay: {REQUEST_DELAY_S:.1f}s | Max payload: {MAX_PAYLOAD}"
    )
    print(f"Markers: LEFT={LEFT_MARKER!r} RIGHT={RIGHT_MARKER!r}")
    print("=" * 72)
    print()

    tag_cont = build_tag_cont(LEFT_MARKER, RIGHT_MARKER)
    experiments = build_experiments(tag_cont)

    group_title = {
        "A": "Group A - Backdoor-gated permission",
        "B": "Group B - Kernel-produced bytes",
        "C": "Group C - Non-standard continuations",
        "D": "Group D - Exception handler context",
    }

    results: list[ProbeResult] = []
    current_group = ""
    for exp in experiments:
        if exp.group != current_group:
            current_group = exp.group
            print("-" * 72)
            print(group_title.get(exp.group, f"Group {exp.group}"))
            print("-" * 72)
        results.append(run_request(exp, LEFT_MARKER, RIGHT_MARKER, timeout_s=TIMEOUT_S))

    print_summary(results)


if __name__ == "__main__":
    main()
