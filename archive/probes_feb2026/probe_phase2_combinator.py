#!/usr/bin/env python3
"""
probe_phase2_combinator.py — Phase 2 combinator probe: construct terms from
the backdoor basis (A,B) and test novel approaches to sys8 / sys3.

Categories:
  C1: S/K/I from A,B basis — classic combinators as sys8 arg
  C2: Backdoor pair as raw entity — pass unwrapped pair to sys8
  C3: Backdoor-derived compositions — A(B), B(A), B(B)(A), etc.
  C4: sys8 with kernel-provenance terms — use backdoor output within CPS chain
  C5: Chained syscalls with backdoor continuations
  C6: g(0) exception capture — catch sys8 error, inspect/reuse
  C7: sys3 exploration — "not implemented" may respond to specific args
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
DELAY = 0.45

FD = 0xFD
FF = 0xFF

# ---------------------------------------------------------------------------
# Named-term DSL (reused from previous probes)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------


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
    if out.startswith(b"Term too big!"):
        return "Term too big!"
    if out.startswith(b"ERROR:"):
        return out.decode("ascii", "replace")
    try:
        text = out.decode("utf-8", "replace")
        if all((ch == "\n") or (ch == "\r") or (32 <= ord(ch) < 127) for ch in text):
            compact = text.replace("\n", "\\n")
            return f"TEXT:{compact[:120]}"
        # Check if it ends with FF — might be QD output
        if out[-1:] == bytes([FF]):
            return f"HEX:{out[:80].hex()}"
    except Exception:
        pass
    return f"HEX:{out[:80].hex()}"


# ---------------------------------------------------------------------------
# Term constructors
# ---------------------------------------------------------------------------

NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)

# Standard combinators
I = NConst(Lam(Var(0)))  # λx.x
K = NConst(Lam(Lam(Var(1))))  # λx.λy.x
S = NConst(Lam(Lam(Lam(App(App(Var(2), Var(0)), App(Var(1), Var(0)))))))

# Backdoor components (known)
A_DB = Lam(Lam(App(Var(0), Var(0))))  # λa.λb. b b
B_DB = Lam(Lam(App(Var(1), Var(0))))  # λa.λb. a b
A = NConst(A_DB)
B = NConst(B_DB)

# Church false = λx.λy.y = same as A ignoring first, but A self-applies
KI = NConst(Lam(Lam(Var(0))))  # λx.λy.y (Church false / K*)


def church(n: int) -> NConst:
    body: object = Var(0)
    for _ in range(n):
        body = App(Var(1), body)
    return NConst(Lam(Lam(body)))


def scott_pair(x: object, y: object) -> object:
    return lam("f", apps(v("f"), x, y))


def int_term(n: int) -> NConst:
    return NConst(encode_byte_term(n))


def str_term(s: str) -> NConst:
    return NConst(encode_bytes_list(s.encode("ascii", "replace")))


# ---------------------------------------------------------------------------
# Observer: Either unwrap that writes error text or LEFT marker
# ---------------------------------------------------------------------------


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


# QD-style observer: quotes the Left payload for raw byte inspection
def make_qd_observer() -> object:
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
                    lam("_e2", write_str("ERR\n")),
                ),
            ),
        ),
    )
    left_handler = lam(
        "payload",
        apps(
            g(4),
            v("payload"),
            lam(
                "qr",
                apps(
                    v("qr"),
                    lam("qbytes", apps(g(2), v("qbytes"), NIL)),
                    lam("_qerr", write_str("QFAIL\n")),
                ),
            ),
        ),
    )
    return lam("result", apps(v("result"), left_handler, right_handler))


QD_OBS = make_qd_observer()


# ---------------------------------------------------------------------------
# Execution helpers
# ---------------------------------------------------------------------------

RESULTS: list[tuple[str, str]] = []
FLAGGED: list[str] = []
_request_count = 0
MAX_REQUESTS = 38


def run_case(
    label: str, term: object, sleep_s: float = DELAY, timeout_s: float = 7.0
) -> str | None:
    global _request_count
    if _request_count >= MAX_REQUESTS:
        print(f"  [{label}] SKIPPED — rate limit ({MAX_REQUESTS} reached)")
        return None
    db_term = to_db(term)
    payload = encode_term(db_term) + bytes([FF])
    if len(payload) > 1500:
        result = f"SKIPPED (payload={len(payload)} > 1500)"
        print(f"  {label:58s} -> {result}")
        RESULTS.append((label, result))
        return result
    _request_count += 1
    out = query(payload, timeout_s=timeout_s)
    result = classify(out)
    flag = ""
    # Flag anything that's NOT Permission denied / EMPTY / error
    if (
        "Permission denied" not in result
        and result
        not in (
            "EMPTY",
            "Invalid term!",
            "Encoding failed!",
            "Term too big!",
        )
        and not result.startswith("ERROR:")
        and "Not implemented" not in result
    ):
        flag = " *** BREAKTHROUGH ***"
        FLAGGED.append(f"{label} -> {result}")
    print(f"  {label:58s} -> {result}{flag}")
    RESULTS.append((label, result))
    time.sleep(sleep_s)
    return result


def section(title: str) -> None:
    print(f"\n{'=' * 78}")
    print(f"  {title}")
    print(f"{'=' * 78}")


# ---------------------------------------------------------------------------
# C1: S/K/I constructed from A,B basis
# ---------------------------------------------------------------------------


def group_c1_sk_from_basis() -> None:
    section("C1: S/K/I from A,B — combinators as sys8 arg")

    # K = λx.λy.x — already known, but test as "constructed" emphasis
    run_case("C1 sys8(K=λx.λy.x)", apps(g(8), K, OBS))

    # S = λx.λy.λz.xz(yz)
    run_case("C1 sys8(S)", apps(g(8), S, OBS))

    # I = SKK: (S K K) — applicatively construct I
    # S(K)(K) = λz. K(z)(K(z)) = λz.z = I
    SKK = apps(S, K, K)
    run_case("C1 sys8(I=SKK)", apps(g(8), SKK, OBS))

    # B(A)(B) = apply(A)(B) = A(B) = λb.bb (since A ignores first arg)
    # Actually: A = λa.λb.bb, so A(B) = λb.bb
    run_case("C1 sys8(B(A)(B))=A(B)=λb.bb", apps(g(8), apps(B, A, B), OBS))


# ---------------------------------------------------------------------------
# C2: Backdoor pair as raw entity passed to sys8
# ---------------------------------------------------------------------------


def group_c2_backdoor_pair_raw() -> None:
    section("C2: Backdoor pair raw — unwrapped pair → sys8")

    # backdoor(nil) -> Left(pair) -> unwrap Left -> pass pair to sys8
    # pair = λf.f(A)(B) — this is the KERNEL-MINTED pair
    run_case(
        "C2 backdoor→unwrap→sys8(pair)",
        apps(
            g(201),
            NIL,
            lam(
                "bd_either",
                apps(
                    v("bd_either"),
                    # Left handler: pair is the payload
                    lam("pair", apps(g(8), v("pair"), OBS)),
                    lam("_err", write_str("BDERR\n")),
                ),
            ),
        ),
    )

    # Extract A from kernel pair, pass to sys8
    run_case(
        "C2 backdoor→extract_A→sys8(A)",
        apps(
            g(201),
            NIL,
            lam(
                "bd_either",
                apps(
                    v("bd_either"),
                    lam(
                        "pair",
                        # pair(λa.λb.a) extracts first = A
                        apps(
                            g(8),
                            apps(v("pair"), lam("a", lam("b", v("a")))),
                            OBS,
                        ),
                    ),
                    lam("_err", write_str("BDERR\n")),
                ),
            ),
        ),
    )

    # Extract B from kernel pair, pass to sys8
    run_case(
        "C2 backdoor→extract_B→sys8(B)",
        apps(
            g(201),
            NIL,
            lam(
                "bd_either",
                apps(
                    v("bd_either"),
                    lam(
                        "pair",
                        # pair(λa.λb.b) extracts second = B
                        apps(
                            g(8),
                            apps(v("pair"), lam("a", lam("b", v("b")))),
                            OBS,
                        ),
                    ),
                    lam("_err", write_str("BDERR\n")),
                ),
            ),
        ),
    )

    # Pass the ENTIRE Either (not unwrapped) to sys8
    run_case(
        "C2 backdoor→sys8(entire_either)",
        apps(
            g(201),
            NIL,
            lam("bd_either", apps(g(8), v("bd_either"), OBS)),
        ),
    )


# ---------------------------------------------------------------------------
# C3: Backdoor-derived compositions
# ---------------------------------------------------------------------------


def group_c3_compositions() -> None:
    section("C3: Backdoor compositions — A/B combinator algebra")

    # B(B) = (λa.λb.ab)(λa.λb.ab) = λb.(λa.λb.ab)(b) = λb.λb'.bb'
    # That's interesting — it's like a delayed application
    run_case("C3 sys8(B(B))", apps(g(8), app(B, B), OBS))

    # A(A) = (λa.λb.bb)(λa.λb.bb) = λb.bb
    # A ignores its arg, so A(A) = λb.bb = A without outer lambda
    run_case("C3 sys8(A(A))", apps(g(8), app(A, A), OBS))

    # B(A) = (λa.λb.ab)(λa.λb.bb) = λb.(λa.λb.bb)(b) = λb.λb'.b'b'
    # Which is just λb.A (since A ignores its arg) — actually λb.(λb'.b'b')
    run_case("C3 sys8(B(A))", apps(g(8), app(B, A), OBS))

    # A(B)(B) = (λa.λb.bb)(B)(B) = (λb.bb)(B) = B(B) = λb'.B(b')
    run_case("C3 sys8(A(B)(B))", apps(g(8), apps(A, B, B), OBS))

    # B(B)(A) = (λb'.B(b'))(A)? No: B(B) = λb. B(b) = λb.λb'.b(b')
    # So B(B)(A) = λb'.A(b') = λb'.λb''.b''b'' (since A ignores arg)
    run_case("C3 sys8(B(B)(A))", apps(g(8), apps(B, B, A), OBS))

    # Scott pair(A,B) manually — same structure as backdoor output
    run_case("C3 sys8(pair(A,B))", apps(g(8), scott_pair(A, B), OBS))


# ---------------------------------------------------------------------------
# C4: sys8 with kernel-provenance terms in CPS chain
# ---------------------------------------------------------------------------


def group_c4_kernel_provenance() -> None:
    section("C4: kernel-provenance CPS — backdoor result as continuation")

    # sys8(nil) with A as continuation: A(result) = λb.bb
    run_case(
        "C4 sys8(nil)(A_cont)",
        apps(g(8), NIL, A),
    )

    # sys8(nil) with B as continuation: B(result) = λb.result(b)
    run_case(
        "C4 sys8(nil)(B_cont)",
        apps(g(8), NIL, B),
    )

    # sys8(nil) with kernel-extracted A as continuation
    run_case(
        "C4 backdoor→A_cont→sys8(nil)(A)",
        apps(
            g(201),
            NIL,
            lam(
                "bd",
                apps(
                    v("bd"),
                    lam(
                        "pair",
                        # Extract A from pair, use as sys8 continuation
                        apps(
                            v("pair"),
                            lam(
                                "ka",
                                lam(
                                    "_kb",
                                    # ka = kernel A; use as sys8 arg
                                    apps(g(8), v("ka"), OBS),
                                ),
                            ),
                        ),
                    ),
                    lam("_err", write_str("BDERR\n")),
                ),
            ),
        ),
    )

    # Use kernel-B as continuation for sys8
    run_case(
        "C4 backdoor→B_cont→sys8(nil)(B)",
        apps(
            g(201),
            NIL,
            lam(
                "bd",
                apps(
                    v("bd"),
                    lam(
                        "pair",
                        apps(
                            v("pair"),
                            lam(
                                "_ka",
                                lam(
                                    "kb",
                                    # kb = kernel B; use as sys8 arg
                                    apps(g(8), v("kb"), OBS),
                                ),
                            ),
                        ),
                    ),
                    lam("_err", write_str("BDERR\n")),
                ),
            ),
        ),
    )


# ---------------------------------------------------------------------------
# C5: Chained syscalls with backdoor
# ---------------------------------------------------------------------------


def group_c5_chained() -> None:
    section("C5: Chained syscalls — sys8→sys8, backdoor→sys8→write")

    # sys8(nil)(λr. sys8(r)(OBS)) — chain: feed sys8 result back into sys8
    run_case(
        "C5 sys8(nil)→sys8(result)",
        apps(g(8), NIL, lam("r1", apps(g(8), v("r1"), OBS))),
    )

    # backdoor → extract A → apply A to itself → sys8(A(A))
    # A(A) should reduce to λb.bb
    run_case(
        "C5 backdoor→A→A(A)→sys8",
        apps(
            g(201),
            NIL,
            lam(
                "bd",
                apps(
                    v("bd"),
                    lam(
                        "pair",
                        apps(
                            v("pair"),
                            lam(
                                "ka",
                                lam(
                                    "_kb",
                                    apps(g(8), apps(v("ka"), v("ka")), OBS),
                                ),
                            ),
                        ),
                    ),
                    lam("_err", write_str("BDERR\n")),
                ),
            ),
        ),
    )

    # echo(pair(A,B)) → unwrap → sys8(echoed_pair)
    # echo returns Left(input), so this tests if echo-provenance matters
    run_case(
        "C5 echo(pair(A,B))→sys8",
        apps(
            g(14),
            scott_pair(A, B),
            lam(
                "echo_either",
                apps(
                    v("echo_either"),
                    lam("echoed", apps(g(8), v("echoed"), OBS)),
                    lam("_err", write_str("ECHOERR\n")),
                ),
            ),
        ),
    )


# ---------------------------------------------------------------------------
# C6: g(0) exception capture — catch sys8 error, inspect/reuse
# ---------------------------------------------------------------------------


def group_c6_exception() -> None:
    section("C6: g(0) exception capture around sys8")

    # g(0)(handler)(sys8(nil)(I)) — catch sys8 exception, write it
    run_case(
        "C6 g(0)(handler)(sys8(nil)(I))",
        apps(
            g(0),
            lam(
                "exc",
                apps(
                    g(2),
                    str_term("CAUGHT:"),
                    lam(
                        "_",
                        apps(
                            g(4),
                            v("exc"),
                            lam(
                                "qr",
                                apps(
                                    v("qr"),
                                    lam("qb", apps(g(2), v("qb"), NIL)),
                                    lam("_e", write_str("QFAIL\n")),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            apps(g(8), NIL, I),
        ),
    )

    # sys8 with g(0) itself as argument — exception handler as auth token?
    run_case("C6 sys8(g(0))", apps(g(8), g(0), OBS))

    # Wrap sys8 call in g(0), use QD_OBS to see what g(0) returns
    run_case(
        "C6 g(0)(QD_handler)(sys8(nil)(I))",
        apps(
            g(0),
            lam(
                "exc",
                apps(
                    g(4),
                    v("exc"),
                    lam(
                        "qr",
                        apps(
                            v("qr"),
                            lam("qb", apps(g(2), v("qb"), NIL)),
                            lam("_e", write_str("QFAIL\n")),
                        ),
                    ),
                ),
            ),
            apps(g(8), NIL, I),
        ),
    )


# ---------------------------------------------------------------------------
# C7: sys3 exploration — test if it responds to specific args
# ---------------------------------------------------------------------------


def group_c7_sys3() -> None:
    section("C7: sys3 exploration with specific arguments")

    # sys3(A) — backdoor component A
    run_case("C7 sys3(A)", apps(g(3), A, OBS))

    # sys3(B) — backdoor component B
    run_case("C7 sys3(B)", apps(g(3), B, OBS))

    # sys3(pair(A,B)) — backdoor pair
    run_case("C7 sys3(pair(A,B))", apps(g(3), scott_pair(A, B), OBS))

    # sys3(g(8)) — pass sys8 itself to sys3
    run_case("C7 sys3(g(8))", apps(g(3), g(8), OBS))

    # sys3(nil) — simplest arg
    run_case("C7 sys3(nil)", apps(g(3), NIL, OBS))

    # sys3("ilikephp") — password string
    run_case("C7 sys3('ilikephp')", apps(g(3), str_term("ilikephp"), OBS))

    # sys3(int(8)) — numeric 8
    run_case("C7 sys3(int(8))", apps(g(3), int_term(8), OBS))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 78)
    print("  PROBE PHASE 2 COMBINATOR — A,B basis constructions + sys3/sys8")
    print(f"  Target: {HOST}:{PORT}")
    print(f"  Max requests: {MAX_REQUESTS}, delay: {DELAY}s")
    print("=" * 78)

    start = time.time()

    group_c1_sk_from_basis()
    group_c2_backdoor_pair_raw()
    group_c3_compositions()
    group_c4_kernel_provenance()
    group_c5_chained()
    group_c6_exception()
    group_c7_sys3()

    elapsed = time.time() - start

    print(f"\n{'=' * 78}")
    print(f"  SUMMARY — {_request_count} requests in {elapsed:.1f}s")
    print(f"{'=' * 78}")

    if FLAGGED:
        print(f"\n  *** BREAKTHROUGHS ({len(FLAGGED)}) ***:")
        for f in FLAGGED:
            print(f"    {f}")
    else:
        print("\n  No breakthroughs — all denied/empty/error/not-implemented.")

    # Categorize results
    cats: dict[str, int] = {}
    for _, r in RESULTS:
        key = r.split(":")[0] if ":" in r else r[:30]
        cats[key] = cats.get(key, 0) + 1
    print(f"\n  Result categories:")
    for k, cnt in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"    {k:40s} x{cnt}")

    print(f"\n{'=' * 78}")
    print("  DONE")
    print(f"{'=' * 78}")


if __name__ == "__main__":
    main()
