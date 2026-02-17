#!/usr/bin/env python3
"""
probe_extended_ids.py - Sweep filesystem IDs using extended integer encoding.

Var(9) = weight 256 is CONFIRMED WORKING. This means IDs 253-511 are potentially
accessible (253-255 were unreachable with standard 0-252 byte encoding).

Also: sweep for hidden syscalls using extended IDs as the syscall argument.
"""

from __future__ import annotations
import socket, time
from dataclasses import dataclass
from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FF,
    FD,
    FE,
    QD,
    encode_term,
    encode_byte_term,
    encode_bytes_list,
)

HOST = "wc3.wechall.net"
PORT = 61221


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


def shift_db(term, delta, cutoff=0):
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_db(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_db(term.f, delta, cutoff), shift_db(term.x, delta, cutoff))
    return term


def to_db(term, env=()):
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
    raise TypeError(f"Unsupported: {type(term)}")


def g(i):
    return NGlob(i)


def v(n):
    return NVar(n)


def lam(p, b):
    return NLam(p, b)


def app(f, x):
    return NApp(f, x)


def apps(*t):
    out = t[0]
    for x in t[1:]:
        out = app(out, x)
    return out


NIL_DB = Lam(Lam(Var(0)))
NIL = NConst(NIL_DB)


def recv_all(sock, timeout_s=5.0):
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


def query_named_timed(term, timeout_s=5.0):
    payload = encode_term(to_db(term)) + bytes([FF])
    try:
        start = time.monotonic()
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            result = recv_all(sock, timeout_s=timeout_s)
        elapsed = time.monotonic() - start
        return result, elapsed
    except Exception as e:
        elapsed = time.monotonic() - start
        return f"ERR:{e}".encode(), elapsed


def write_str(s):
    return apps(g(2), NConst(encode_bytes_list(s.encode("latin-1"))), NIL)


# Full observer that shows Left content or Right error string
def obs_full():
    """Writes file content for Left, error string for Right."""
    right_handler = lam(
        "err_code",
        apps(
            g(1),
            v("err_code"),
            lam(
                "err_res",
                apps(
                    v("err_res"),
                    lam("errstr", apps(g(2), v("errstr"), NIL)),
                    lam("_e2", write_str("?")),
                ),
            ),
        ),
    )
    left_handler = lam("payload", apps(g(2), v("payload"), NIL))
    return lam("res", apps(v("res"), left_handler, right_handler))


# Observer that writes Left payload as string (for readfile/name)
def obs_left_write():
    right_handler = lam(
        "err_code",
        apps(
            g(1),
            v("err_code"),
            lam(
                "err_res",
                apps(
                    v("err_res"),
                    lam("errstr", apps(g(2), v("errstr"), NIL)),
                    lam("_e2", write_str("ERR:?")),
                ),
            ),
        ),
    )
    left_handler = lam("payload", apps(g(2), v("payload"), NIL))
    return lam("res", apps(v("res"), left_handler, right_handler))


OBS_FULL = obs_left_write()


# Observer for sys8 that shows Left or error
def obs_sys8():
    right_handler = lam(
        "err_code",
        apps(
            g(1),
            v("err_code"),
            lam(
                "err_res",
                apps(
                    v("err_res"),
                    lam("errstr", apps(g(2), v("errstr"), NIL)),
                    lam("_e2", write_str("ERR:?")),
                ),
            ),
        ),
    )
    left_handler = lam("_payload", write_str("LEFT!!!"))
    return lam("res", apps(v("res"), left_handler, right_handler))


OBS_SYS8 = obs_sys8()


def make_extended_int(val):
    """Build integer term supporting values 0-511 using Var(0)-Var(9) weights."""
    weights = [
        (9, 256),
        (8, 128),
        (7, 64),
        (6, 32),
        (5, 16),
        (4, 8),
        (3, 4),
        (2, 2),
        (1, 1),
    ]
    expr = Var(0)  # base 0
    remaining = val
    for idx, w in weights:
        if remaining >= w:
            expr = App(Var(idx), expr)
            remaining -= w
    if remaining != 0:
        return None
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def classify(raw, elapsed):
    if not raw:
        if elapsed >= 4.5:
            return "TIMEOUT"
        return f"EMPTY({elapsed:.2f}s)"
    text = raw.decode("latin-1", errors="replace")
    if "Permission denied" in text:
        return f"PERM_DENIED({elapsed:.2f}s)"
    if "Not implemented" in text:
        return f"NOT_IMPL({elapsed:.2f}s)"
    if "No such directory" in text:
        return f"NO_SUCH({elapsed:.2f}s)"
    if "Invalid" in text:
        return f"INVALID({elapsed:.2f}s)"
    if "Encoding failed" in text:
        return f"ENC_FAIL({elapsed:.2f}s)"
    if "LEFT!!!" in text:
        return f"LEFT!!!({elapsed:.2f}s)"
    return f"OTHER({text[:60]!r},{elapsed:.2f}s)"


def phase_1_sweep_names():
    """Sweep name() for IDs 253-280 and 500-511 using extended encoding."""
    print("=" * 72)
    print("PHASE 1: name() sweep with extended integer encoding")
    print("=" * 72)

    # Critical range: 253-255 (previously unreachable)
    for fid in range(253, 260):
        int_term = make_extended_int(fid)
        if int_term is None:
            print(f"  name({fid}): can't encode")
            continue
        term = apps(g(6), NConst(int_term), OBS_FULL)
        out, elapsed = query_named_timed(term, timeout_s=5.0)
        result = classify(out, elapsed)
        print(f"  name({fid}) -> {result}")
        if out and "OTHER" in result:
            text = out.decode("latin-1", errors="replace")
            print(f"    content: {text!r}")
        time.sleep(0.3)

    # Also check 256 for reference
    int_term = make_extended_int(256)
    term = apps(g(6), NConst(int_term), OBS_FULL)
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  name(256) -> {classify(out, elapsed)}")
    if out:
        text = out.decode("latin-1", errors="replace")
        print(f"    content: {text!r}")
    time.sleep(0.3)

    # Sparse check: 300-511
    for fid in [300, 400, 500, 510, 511]:
        int_term = make_extended_int(fid)
        if int_term is None:
            print(f"  name({fid}): can't encode")
            continue
        term = apps(g(6), NConst(int_term), OBS_FULL)
        out, elapsed = query_named_timed(term, timeout_s=5.0)
        result = classify(out, elapsed)
        if "NO_SUCH" not in result:
            print(f"  name({fid}) -> {result}")
        time.sleep(0.2)


def phase_2_sweep_readfile():
    """readfile() for IDs 253-256 with extended encoding."""
    print("\n" + "=" * 72)
    print("PHASE 2: readfile() sweep (253-256)")
    print("=" * 72)

    for fid in [253, 254, 255, 256]:
        int_term = make_extended_int(fid)
        if int_term is None:
            print(f"  readfile({fid}): can't encode")
            continue
        term = apps(g(7), NConst(int_term), OBS_FULL)
        out, elapsed = query_named_timed(term, timeout_s=5.0)
        result = classify(out, elapsed)
        print(f"  readfile({fid}) -> {result}")
        if out and "NO_SUCH" not in result and "EMPTY" not in result:
            text = out.decode("latin-1", errors="replace")
            print(f"    content: {text[:200]!r}")
        time.sleep(0.3)


def phase_3_sweep_readdir():
    """readdir() for IDs 253-256 with extended encoding."""
    print("\n" + "=" * 72)
    print("PHASE 3: readdir() sweep (253-256)")
    print("=" * 72)

    for fid in [253, 254, 255, 256]:
        int_term = make_extended_int(fid)
        if int_term is None:
            print(f"  readdir({fid}): can't encode")
            continue
        # For readdir, we need a more complex observer that decodes the list
        # Let's just use QD for raw output
        qd_bytes = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
        # readdir(N, QD) in raw wire
        int_enc = encode_term(int_term)
        payload = bytes([0x05]) + int_enc + bytes([FD]) + qd_bytes + bytes([FD, FF])
        try:
            start = time.monotonic()
            with socket.create_connection((HOST, PORT), timeout=5.0) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                result = recv_all(sock, timeout_s=5.0)
            elapsed = time.monotonic() - start
        except Exception as e:
            elapsed = time.monotonic() - start
            result = f"ERR:{e}".encode()

        result_class = classify(result, elapsed)
        print(f"  readdir({fid}) -> {result_class}")
        if result and "NO_SUCH" not in result_class and len(result) > 0:
            print(f"    raw hex: {result[:40].hex()}")
        time.sleep(0.3)


def phase_4_sys8_with_extended_ids():
    """Test sys8 with extended integer values as arguments."""
    print("\n" + "=" * 72)
    print("PHASE 4: sys8 with extended integer arguments")
    print("=" * 72)

    for val in [253, 254, 255, 256, 257, 511]:
        int_term = make_extended_int(val)
        if int_term is None:
            continue
        term = apps(g(8), NConst(int_term), OBS_SYS8)
        out, elapsed = query_named_timed(term, timeout_s=5.0)
        result = classify(out, elapsed)
        print(f"  sys8({val}, OBS) -> {result}")
        time.sleep(0.3)


def phase_5_extended_syscall_sweep():
    """
    What if there are syscalls at IDs > 252 that we can reach via extended encoding?
    The wire format only allows Var(0-252) directly, but what if we compute
    g(253)(nil, QD) via a lambda trick?

    Method: ((λ. Var(9+253))(dummy) nil FD QD FD) — shift globals to reach 253+
    Actually no. Inside a lambda, Var(N) with N > 0 refers to global N-1.
    Var(252) inside 1 lambda = global 251. We can't go HIGHER.

    Alternative: use the integer term AS the function.
    If val = encode_byte_term(253), then val is a 9-lambda term.
    val(arg1)(arg2)... applies it like a function.
    But this doesn't call g(253) — it destructs the 9-lambda term.

    Actually, there's NO WAY to call g(253+) through the wire format.
    The wire format constrains us to Var(0-252). Period.

    Unless we can somehow manufacture a reference to g(253+) at runtime.
    Echo does this: echo(g(251)) creates Var(253) internally.
    But when we unwrap it, it resolves back to g(251).

    So let's try using echo's result AS A SYSCALL (calling it as a function).
    echo(g(251)) → Left(Var(253)). If we extract the payload (Var(253)) and
    then apply it as (Var(253) nil QD), that's g(253)(nil)(QD) = g(251)(nil)(QD).
    De Bruijn resolution means it's just calling g(251) again.

    The only way to truly call g(253) is if the VM has a mechanism where
    Var(253) at the top level (0 lambdas deep) means something special.
    And we CAN'T create that through the wire format.

    UNLESS: beta-reduction can increase a variable's index.
    Standard beta: ((λ.body) arg) → body[0:=arg], then shift_down(body, 1).
    shift_down DECREASES free variable indices. Can't go up.

    OK, this avenue is closed for now. Let me test something different.
    """
    print("\n" + "=" * 72)
    print("PHASE 5: Call echo's internal Var(253) as a function directly")
    print("=" * 72)

    # echo(g(251)) → Left(Var(253))
    # Left(Var(253)) = λl.λr.(l Var(253))
    # To extract Var(253): Left(Var(253))(λx.x)(λy.y) = (λx.x)(Var(253)) = Var(253)
    # But after the lambdas are stripped, Var(253) becomes Var(251) = g(251).
    # De Bruijn semantics: Var(253) under 2 lambdas IS g(251).

    # What if we DON'T unwrap but instead call the raw Left as a syscall?
    # echo(g(251)) → Left_result. Left_result(nil)(QD)
    # Left_result = λl.λr.l(Var(253)).
    # Left_result(nil) = λr.nil(Var(253-1)) = λr.nil(Var(252))
    # Wait, no. Beta: (λl.λr.l(Var(253)))(nil) = λr.nil[l:=nil](Var(253-1))
    # Actually: (λl. body)(nil) → body[l:=nil] then shift_down(1).
    # body = λr.l(Var(253)) = λr.(Var(1))(Var(254))   [l=Var(1) under 1 lambda r]
    # After substitution: λr.(nil)(Var(254))
    # After shift_down(1): λr.(nil)(Var(253))
    # Then (λr.(nil)(Var(253)))(QD) → nil(Var(253))[r:=QD] shift_down(1)
    # nil(Var(253)) at depth 1: nil = λa.λb.Var(0), applied to Var(253).
    # nil(Var(253)) = λb.Var(0) (nil ignores its argument).
    # Then shift_down(1) and substitute QD: λb.Var(0)[r:=QD] = Var(0) stays.
    # Final: (λb.Var(0)) after removing r. Applied to QD: Var(0) which is QD's bound var.
    # Wait this is getting confused. Let's just test empirically.

    # Use echo result as a "syscall-like" function
    # echo(g(251)) → raw → raw(nil)(QD_observer)
    term = apps(g(14), g(251), lam("raw", apps(v("raw"), NIL, OBS_SYS8)))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  echo(251)_raw(nil, OBS) -> {classify(out, elapsed)}")
    if out:
        text = out.decode("latin-1", errors="replace")
        if text:
            print(f"    text: {text[:80]!r}")
    time.sleep(0.3)

    # echo(g(252)) → raw → raw(nil)(OBS)
    term = apps(g(14), g(252), lam("raw", apps(v("raw"), NIL, OBS_SYS8)))
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  echo(252)_raw(nil, OBS) -> {classify(out, elapsed)}")
    if out:
        text = out.decode("latin-1", errors="replace")
        if text:
            print(f"    text: {text[:80]!r}")
    time.sleep(0.3)

    # Double echo: echo(echo(251)) → Left(Left(Var(255)))
    # Then call this compound thing as function(nil)(OBS)
    term = apps(
        g(14),
        g(251),
        lam("r1", apps(g(14), v("r1"), lam("r2", apps(v("r2"), NIL, OBS_SYS8)))),
    )
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  echo(echo(251))_raw(nil, OBS) -> {classify(out, elapsed)}")
    if out:
        text = out.decode("latin-1", errors="replace")
        if text:
            print(f"    text: {text[:80]!r}")
    time.sleep(0.3)


def phase_6_verify_256_content():
    """Verify file 256 content with our new observer."""
    print("\n" + "=" * 72)
    print("PHASE 6: Verify known data with extended encoding")
    print("=" * 72)

    # name(256)
    int_256 = make_extended_int(256)
    term = apps(g(6), NConst(int_256), OBS_FULL)
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  name(256) -> {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')!r}")
    time.sleep(0.3)

    # readfile(256) with content-printing observer
    term = apps(g(7), NConst(int_256), OBS_FULL)
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  readfile(256) -> {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')!r}")
    time.sleep(0.3)

    # Try file 8 with extended encoding (just to be thorough)
    int_8 = make_extended_int(8)
    term = apps(g(6), NConst(int_8), OBS_FULL)
    out, elapsed = query_named_timed(term, timeout_s=5.0)
    print(f"  name(8) extended -> {classify(out, elapsed)}")
    if out:
        print(f"    text: {out.decode('latin-1', errors='replace')!r}")
    time.sleep(0.3)


def main():
    print("=" * 72)
    print("probe_extended_ids.py - Extended integer encoding sweep")
    print(f"target: {HOST}:{PORT}")
    print("=" * 72)

    phase_1_sweep_names()
    phase_2_sweep_readfile()
    phase_3_sweep_readdir()
    phase_4_sys8_with_extended_ids()
    phase_5_extended_syscall_sweep()
    phase_6_verify_256_content()

    print("\nAll phases complete.")


if __name__ == "__main__":
    main()
