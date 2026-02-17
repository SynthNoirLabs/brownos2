#!/usr/bin/env python3
"""
probe_echo_special_attack.py — Echo-manufactured special-byte attack on sys8.

HYPOTHESIS: Echo (syscall 0x0E) exists to manufacture terms containing
Var indices that collide with bytecode markers (FD=253, FE=254, FF=255).
When these runtime-only terms are fed to sys8, internal serialization
or comparison might break, bypassing the permission gate.

The key constraint: QD uses quote internally, and quote CANNOT serialize
Var(253+).  So we need ALTERNATIVE observation methods (write, errorString,
or just observe raw socket output).

Tests S1-S10 cover:
- Unwrapped special-byte args to sys8 with QD observer (S1, S2, S4)
- Whole Left wrapper to sys8 (S3)
- Bare extraction (S5)
- Write-based observer (S6)
- Thunk/unevaluated arg (S7)
- Lambda-wrapped special bytes (S8, S9)
- Minimal 3-leaf echo→sys8 chain (S10)
"""

import socket
import sys
import time
from dataclasses import dataclass


HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD  # application
FE = 0xFE  # lambda
FF = 0xFF  # end-of-code marker

QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


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


# ---------------------------------------------------------------------------
# Term utilities
# ---------------------------------------------------------------------------


def enc(term):
    """Encode a term to bytecode (without trailing FF)."""
    if isinstance(term, Var):
        if term.i > 0xFC:
            raise ValueError(f"Var({term.i}) cannot be encoded in bytecode")
        return bytes([term.i])
    if isinstance(term, Lam):
        return enc(term.body) + bytes([FE])
    if isinstance(term, App):
        return enc(term.f) + enc(term.x) + bytes([FD])
    raise TypeError(f"Unsupported: {type(term)}")


def sh(term, delta, cutoff=0):
    """Shift free variables by delta (de Bruijn shift)."""
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(sh(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(sh(term.f, delta, cutoff), sh(term.x, delta, cutoff))
    raise TypeError


def parse_term(data):
    """Parse bytecode to a term (stops at FF)."""
    stack = []
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


def g(n):
    """Global variable reference (top-level Var(n))."""
    return Var(n)


# Standard terms
nil = Lam(Lam(Var(0)))
QD = parse_term(QD_BYTES + bytes([FF]))

# Syscall numbers (as global indices)
SYS8 = 8
ECHO = 14
WRITE = 2
ERRORSTR = 1
QUOTE = 4


def encode_byte_term(n):
    """Encode an integer 0-255 as a 9-lambda additive bitset term."""
    expr = Var(0)
    for idx, weight in (
        (1, 1),
        (2, 2),
        (3, 4),
        (4, 8),
        (5, 16),
        (6, 32),
        (7, 64),
        (8, 128),
    ):
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_bytes_list(bs):
    """Scott list of byte-terms."""
    cur = nil

    def cons(h, t):
        return Lam(Lam(App(App(Var(1), h), t)))

    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

novel_results = []


def send_raw(payload_bytes, timeout_s=8.0):
    """Send raw bytes, receive all output."""
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload_bytes)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            sock.settimeout(timeout_s)
            out = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    out += chunk
                except socket.timeout:
                    break
            return out
    except Exception as e:
        return f"ERROR: {e}".encode()


def classify(label, resp):
    """Classify and print a response."""
    resp_hex = resp.hex() if resp else "EMPTY"
    resp_text = resp.decode("utf-8", "replace") if resp else ""

    # Try to parse as Either
    parsed_info = ""
    if resp and len(resp) > 0 and FF in resp:
        try:
            term = parse_term(resp)
            tag, val = _decode_either(term)
            if tag == "Left":
                try:
                    bs = _decode_bytes_list(val)
                    parsed_info = f" -> Left({bs!r})"
                except Exception:
                    parsed_info = " -> Left(<complex>)"
            else:
                try:
                    code = _decode_byte_val(val)
                    parsed_info = f" -> Right({code})"
                except Exception:
                    parsed_info = f" -> Right(<complex>)"
        except Exception:
            if resp_text:
                parsed_info = f" [{resp_text[:60].strip()}]"

    is_perm = "Permission denied" in resp_text
    is_right6 = "-> Right(6)" in parsed_info
    is_empty = len(resp) == 0
    is_invalid = "Invalid term" in resp_text
    is_enc = "Encoding failed" in resp_text
    is_toobig = "Term too big" in resp_text

    if is_right6 or is_perm:
        status = "RIGHT(6)"
    elif "-> Right(2)" in parsed_info:
        status = "RIGHT(2)"
    elif "-> Right(1)" in parsed_info:
        status = "RIGHT(1)"
    elif "-> Right(" in parsed_info:
        status = "RIGHT(?)"
    elif "-> Left(" in parsed_info:
        status = "LEFT"
    elif is_empty:
        status = "EMPTY"
    elif is_invalid:
        status = "INVALID"
    elif is_enc:
        status = "ENC_FAIL"
    elif is_toobig:
        status = "TOO_BIG"
    else:
        status = "OTHER"

    marker = (
        "  *** NOVEL ***"
        if status
        not in (
            "RIGHT(6)",
            "EMPTY",
            "ENC_FAIL",
            "INVALID",
            "RIGHT(1)",
            "RIGHT(2)",
            "TOO_BIG",
        )
        else ""
    )
    print(f"  [{status:10s}] {label}{parsed_info}{marker}")
    if marker:
        print(f"    hex: {resp_hex[:120]}")
        if resp_text and not resp_text.startswith("\x00"):
            print(f"    text: {repr(resp_text[:120])}")
        novel_results.append((label, status, resp_hex, resp_text))
    elif status == "OTHER":
        print(f"    hex: {resp_hex[:120]}")
        print(f"    text: {repr(resp_text[:120])}")
        novel_results.append((label, status, resp_hex, resp_text))
    sys.stdout.flush()
    return status


def _decode_either(term):
    """Decode Scott Either: Left x = λl.λr.l(x), Right y = λl.λr.r(y)."""
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not an Either")
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var) and body.f.i in (0, 1):
        return ("Left" if body.f.i == 1 else "Right", body.x)
    raise ValueError("Unexpected Either shape")


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def _decode_byte_val(term):
    """Decode a 9-lambda additive bitset integer."""
    cur = term
    for _ in range(9):
        if not isinstance(cur, Lam):
            raise ValueError("Not enough lambdas")
        cur = cur.body
    return _eval_bitset(cur)


def _eval_bitset(expr):
    if isinstance(expr, Var):
        return WEIGHTS.get(expr.i, -1)
    if isinstance(expr, App) and isinstance(expr.f, Var):
        return WEIGHTS.get(expr.f.i, 0) + _eval_bitset(expr.x)
    raise ValueError(f"Not bitset: {expr}")


def _decode_bytes_list(term):
    out = []
    cur = term
    for _ in range(100000):
        if not isinstance(cur, Lam) or not isinstance(cur.body, Lam):
            break
        body = cur.body.body
        if isinstance(body, Var) and body.i == 0:
            return bytes(out)
        if (
            isinstance(body, App)
            and isinstance(body.f, App)
            and isinstance(body.f.f, Var)
            and body.f.f.i == 1
        ):
            out.append(_decode_byte_val(body.f.x))
            cur = body.x
            continue
        break
    return bytes(out)


def run_test(label, term):
    """Encode, send, classify. Returns status string."""
    try:
        payload = enc(term) + bytes([FF])
    except ValueError as e:
        print(f"  [ENC_ERROR ] {label}  ({e})")
        sys.stdout.flush()
        return "ENC_ERROR"
    if len(payload) > 2000:
        print(f"  [TOO_BIG   ] {label}  ({len(payload)} bytes)")
        sys.stdout.flush()
        return "TOO_BIG"
    time.sleep(0.5)
    resp = send_raw(payload)
    return classify(label, resp)


# ---------------------------------------------------------------------------
# Build test terms
# ---------------------------------------------------------------------------


def build_s1():
    """S1: echo(g(251)) → unwrap Left → pass payload to sys8 → QD observer.

    echo(g(251))(λr. r(λp. sys8(p)(QD_s2))(λe. nil_s2))

    Depth 0 (top): echo=V(14), arg=V(251)
    Depth 1 (λr): r=V(0)
    Depth 2 (λp, inside left handler): p=V(0), sys8=V(8+2)=V(10), QD shifted by 2
    Depth 2 (λe, inside right handler): nil shifted by 2
    """
    qd_s2 = sh(QD, 2)
    nil_s2 = sh(nil, 2)
    # λp. sys8(p)(QD_s2)  — depth 2
    left_handler = Lam(App(App(Var(10), Var(0)), qd_s2))
    # λe. nil  — depth 2
    right_handler = Lam(nil_s2)
    # λr. r(left_handler)(right_handler)
    cont = Lam(App(App(Var(0), left_handler), right_handler))
    return App(App(g(ECHO), g(251)), cont)


def build_s2():
    """S2: Same as S1 but with g(252) → creates Var(254) = 0xFE = Lam marker."""
    qd_s2 = sh(QD, 2)
    nil_s2 = sh(nil, 2)
    left_handler = Lam(App(App(Var(10), Var(0)), qd_s2))
    right_handler = Lam(nil_s2)
    cont = Lam(App(App(Var(0), left_handler), right_handler))
    return App(App(g(ECHO), g(252)), cont)


def build_s3():
    """S3: Pass entire Left(Var(253)) wrapper to sys8 (don't unwrap).

    echo(g(251))(λr. sys8(r)(QD_s1))

    Under λr (1 lam): r=Var(0), sys8=g(8)+1=Var(9), QD shifted by 1
    """
    qd_s1 = sh(QD, 1)
    cont = Lam(App(App(Var(9), Var(0)), qd_s1))
    return App(App(g(ECHO), g(251)), cont)


def build_s4():
    """S4: Double echo: echo(g(249)) → unwrap → echo(payload) → unwrap → sys8.

    echo(g(249))(λr1.
      r1(λp1.                    # p1 = g(249) at runtime (shift cancels)
        echo(p1)(λr2.
          r2(λp2.                # p2 is echo's Left payload at runtime
            sys8(p2)(QD)
          )(λe. nil)
        )
      )(λe. nil)
    )

    Lambda depth tracking:
    - Top (depth 0): echo=V(14), arg=V(249)
    - λr1 (depth 1): r1=V(0)
    - λp1 (depth 2): p1=V(0), echo=V(14+2)=V(16)
    - λr2 (depth 3): r2=V(0)
    - λp2 (depth 4): p2=V(0), sys8=V(8+4)=V(12), QD shifted by 4
    - inner right λe (depth 4): nil shifted by 4
    - outer right λe (depth 2): nil shifted by 2
    """
    qd_s4 = sh(QD, 4)
    nil_s4 = sh(nil, 4)
    nil_s2 = sh(nil, 2)
    # λp2. sys8(p2)(QD_s4) — depth 4
    inner_left = Lam(App(App(Var(12), Var(0)), qd_s4))
    # λe. nil — depth 4
    inner_right = Lam(nil_s4)
    # λr2. r2(inner_left)(inner_right) — depth 3
    inner_cont = Lam(App(App(Var(0), inner_left), inner_right))
    # λp1. echo(p1)(inner_cont) — depth 2, echo=V(16)
    outer_left = Lam(App(App(Var(16), Var(0)), inner_cont))
    # λe. nil — depth 2
    outer_right = Lam(nil_s2)
    # λr1. r1(outer_left)(outer_right) — depth 1
    cont = Lam(App(App(Var(0), outer_left), outer_right))
    return App(App(g(ECHO), g(249)), cont)


def build_s5():
    """S5: Just extract Var(253) and return it.

    echo(g(251))(λr. r(λp. p)(λe. nil_s2))

    Bare extraction — no sys8. See if Var(253) produces any output.
    Under λr (1 lam): r=V(0)
    Under λr.r.λp (2 lams): p=V(0)
    Under λr.λe (2 lams): nil shifted by 2
    """
    nil_s2 = sh(nil, 2)
    left_handler = Lam(Var(0))  # λp. p (identity)
    right_handler = Lam(nil_s2)
    cont = Lam(App(App(Var(0), left_handler), right_handler))
    return App(App(g(ECHO), g(251)), cont)


def build_s6():
    """S6: Use errorString→write observer instead of QD.

    echo(g(251))(λr.                               # depth 1
      r(λp.                                         # depth 2
        sys8(p)(λsys_res.                           # depth 3
          sys_res(λleft_val.                        # depth 4
            write(left_val)(λ_. nil)                # depth 5
          )(λerr_code.                              # depth 4
            errorString(err_code)(λestr_res.        # depth 5
              estr_res(λestr.                       # depth 6
                write(estr)(λ_. nil)                # depth 7
              )(λ_. nil)                            # depth 6
            )
          )
        )
      )(λe. nil)                                    # depth 2
    )

    Globals: write=g(2), errorString=g(1), sys8=g(8), echo=g(14)
    """
    # Build inside-out:

    # depth 7: λ_. nil(shifted by 7)
    write_done_d7 = Lam(sh(nil, 7))
    # depth 6: λestr. write(estr)(write_done_d7), write=g(2)+6=V(8)
    write_estr_d6 = Lam(App(App(Var(8), Var(0)), write_done_d7))
    # depth 6: λ_. nil(shifted by 6)
    estr_right_d6 = Lam(sh(nil, 6))
    # depth 5: λestr_res. estr_res(write_estr_d6)(estr_right_d6)
    estr_dispatch_d5 = Lam(App(App(Var(0), write_estr_d6), estr_right_d6))
    # depth 4: λerr_code. errorString(err_code)(estr_dispatch_d5), errorStr=g(1)+4=V(5)
    err_handler_d4 = Lam(App(App(Var(5), Var(0)), estr_dispatch_d5))

    # depth 5: λ_. nil(shifted by 5)
    write_done_d5 = Lam(sh(nil, 5))
    # depth 4: λleft_val. write(left_val)(write_done_d5), write=g(2)+4=V(6)
    left_handler_d4 = Lam(App(App(Var(6), Var(0)), write_done_d5))

    # depth 3: λsys_res. sys_res(left_handler_d4)(err_handler_d4)
    sys_dispatch_d3 = Lam(App(App(Var(0), left_handler_d4), err_handler_d4))

    # depth 2: λp. sys8(p)(sys_dispatch_d3), sys8=g(8)+2=V(10)
    left_d2 = Lam(App(App(Var(10), Var(0)), sys_dispatch_d3))

    # depth 2: λe. nil(shifted by 2)
    right_d2 = Lam(sh(nil, 2))

    # depth 1: λr. r(left_d2)(right_d2)
    cont = Lam(App(App(Var(0), left_d2), right_d2))

    return App(App(g(ECHO), g(251)), cont)


def build_s7():
    """S7: Pass echo as a THUNK — sys8 gets unevaluated App(echo, g(251)).

    sys8(App(g(14), g(251)))(QD)

    This is just: ((g(8) (g(14) g(251) FD)) QD FD) FF
    """
    return App(App(g(SYS8), App(g(ECHO), g(251))), QD)


def build_s8():
    """S8: Echo a lambda containing Var(252).

    echo(Lam(Var(252)))(λr. r(λp. sys8(p)(QD_s2))(λe. nil_s2))

    Lam(Var(252)) at top: V(252) is free (references g(251)).
    Inside echo's Left wrapper (+2 lambdas): becomes Lam(Var(254)).
    Var(254) = 0xFE = Lam marker inside a Lam — type confusion!

    Same continuation structure as S1:
    Depth 1 (λr): r=V(0)
    Depth 2 (λp): p=V(0), sys8=V(10), QD shifted by 2
    """
    qd_s2 = sh(QD, 2)
    nil_s2 = sh(nil, 2)
    arg = Lam(Var(252))
    left_handler = Lam(App(App(Var(10), Var(0)), qd_s2))
    right_handler = Lam(nil_s2)
    cont = Lam(App(App(Var(0), left_handler), right_handler))
    return App(App(g(ECHO), arg), cont)


def build_s9():
    """S9: Echo an application containing Var(251).

    echo(App(Var(0), Var(251)))(λr. r(λp. sys8(p)(QD_s2))(λe. nil_s2))

    App(V(0), V(251)) at top: both are free vars (g(0), g(251)).
    Inside Left's 2 lambdas: V(0)→V(2), V(251)→V(253).
    So internally: Left(App(V(2), V(253))) — contains FD-colliding index.

    When unwrapped via Left(payload)(handler)(rhandler), de Bruijn shift
    should cancel, giving handler App(V(0), V(251)) again. But if the
    runtime representation has V(253) before substitution completes...

    Same continuation structure as S1.
    """
    qd_s2 = sh(QD, 2)
    nil_s2 = sh(nil, 2)
    arg = App(Var(0), Var(251))
    left_handler = Lam(App(App(Var(10), Var(0)), qd_s2))
    right_handler = Lam(nil_s2)
    cont = Lam(App(App(Var(0), left_handler), right_handler))
    return App(App(g(ECHO), arg), cont)


def build_s10():
    """S10: Minimal echo→sys8 chain.

    echo(g(251))(sys8)(QD)

    3+QD leaves. echo(g(251)) returns Left(Var(253)).
    Left(Var(253))(sys8) = (λl.λr. l(Var(253)))(sys8) = λr. sys8(Var(253))
    Then applied to QD: sys8(Var(253))(QD)
    But wait — when Left's lambda is consumed, Var(253) shifts to Var(252)
    after one lambda, then Var(251) after the second. So it's sys8(g(251))(QD).
    Still, let's test — the runtime path is different.
    """
    return App(App(App(g(ECHO), g(251)), g(SYS8)), QD)


# Additional interesting variants
def build_s1_v2():
    """S1-v2: Same as S1 but with shift-by-3 QD and Var(11) for sys8.

    This is an intentional "off-by-one" variant to test if the server
    handles misaligned indices differently.
    """
    qd_s3 = sh(QD, 3)
    nil_s2 = sh(nil, 2)
    left_handler = Lam(App(App(Var(11), Var(0)), qd_s3))
    right_handler = Lam(nil_s2)
    cont = Lam(App(App(Var(0), left_handler), right_handler))
    return App(App(g(ECHO), g(251)), cont)


def build_s3_252():
    """S3 variant with g(252) → Var(254) = FE marker."""
    qd_s1 = sh(QD, 1)
    cont = Lam(App(App(Var(9), Var(0)), qd_s1))
    return App(App(g(ECHO), g(252)), cont)


def build_s10_252():
    """S10 variant with g(252)."""
    return App(App(App(g(ECHO), g(252)), g(SYS8)), QD)


def build_direct_left_sys8():
    """Pass a hand-built Left(g(251)) directly to sys8, without using echo.

    Left(x) = λl.λr. l(x)
    Left(g(251)) = Lam(Lam(App(Var(1), Var(253)))) — but Var(253) not encodable!

    So we build Left(g(251)) as: Lam(Lam(App(Var(1), Var(251+2=253))))
    Can't encode. This test should fail at encoding. Just confirming.
    """
    return None  # Can't encode — skip


def build_echo_chain_sys8():
    """Chain: echo(g(251)) → echo result → sys8(double-Left).

    echo(g(251))(λr1. echo(r1)(λr2. sys8(r2)(QD_s2)))

    λr1 (depth 1): r1=V(0), echo=V(15)
    λr2 (depth 2): r2=V(0), sys8=V(10)
    QD at depth 2: shift by 2
    """
    qd_s2 = sh(QD, 2)
    inner = Lam(App(App(Var(10), Var(0)), qd_s2))  # λr2. sys8(r2)(QD_s2)
    outer = Lam(App(App(Var(15), Var(0)), inner))  # λr1. echo(r1)(inner)
    return App(App(g(ECHO), g(251)), outer)


def build_echo_nil_then_sys8():
    """echo(nil)(λr. sys8(r)(QD_s1)) — echo(nil) as baseline/control."""
    qd_s1 = sh(QD, 1)
    cont = Lam(App(App(Var(9), Var(0)), qd_s1))
    return App(App(g(ECHO), nil), cont)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    print("=" * 72)
    print("probe_echo_special_attack.py")
    print("Testing echo-manufactured special-byte terms against sys8")
    print("=" * 72)
    print()

    # Control test first
    print("--- CONTROL: echo(nil)(λr. sys8(r)(QD)) ---")
    run_test("CTRL: echo(nil) → sys8 (baseline)", build_echo_nil_then_sys8())

    print()
    print("--- CATEGORY S: Simplified echo→sys8 attack vectors ---")
    print()

    tests = [
        (
            "S1  echo(g251)→unwrap→sys8(V253)(QD_s2)",
            build_s1,
            "Unwrap Left, pass Var(253) to sys8, QD shifted by 2",
        ),
        (
            "S1v2 echo(g251)→unwrap→sys8(V253)(QD_s3)",
            build_s1_v2,
            "Same but QD shifted by 3 (alt indexing)",
        ),
        (
            "S2  echo(g252)→unwrap→sys8(V254)(QD_s2)",
            build_s2,
            "Var(254)=FE marker to sys8",
        ),
        (
            "S3  echo(g251)→whole-Left→sys8(QD_s1)",
            build_s3,
            "Pass entire Left(Var(253)) to sys8",
        ),
        (
            "S3b echo(g252)→whole-Left→sys8(QD_s1)",
            build_s3_252,
            "Pass entire Left(Var(254)) to sys8",
        ),
        (
            "S4  double-echo(g249)→unwrap²→sys8(V253)",
            build_s4,
            "Double echo: g(249)→V(251)→V(253)",
        ),
        ("S5  echo(g251)→extract-V253→return", build_s5, "Bare extraction, no sys8"),
        (
            "S6  echo(g251)→sys8→errStr→write observer",
            build_s6,
            "Write-based observer, no QD",
        ),
        (
            "S7  sys8(thunk:echo(g251))(QD)",
            build_s7,
            "Pass echo as unevaluated thunk to sys8",
        ),
        (
            "S8  echo(Lam(V252))→sys8 [Lam(V254) inside]",
            build_s8,
            "Lambda with FE-colliding var",
        ),
        (
            "S9  echo(App(V0,V251))→sys8 [App w/ V253]",
            build_s9,
            "Application with FD-colliding var",
        ),
        (
            "S10 echo(g251)(sys8)(QD) [minimal chain]",
            build_s10,
            "Minimal: echo→sys8→QD",
        ),
        ("S10b echo(g252)(sys8)(QD)", build_s10_252, "Minimal with g(252)"),
        (
            "S-chain echo(g251)→echo→sys8(double-Left)",
            build_echo_chain_sys8,
            "Echo the echo result, then sys8",
        ),
    ]

    for label, builder, desc in tests:
        print(f"  # {desc}")
        term = builder()
        if term is None:
            print(f"  [SKIP      ] {label}  (cannot encode)")
            continue
        try:
            payload = enc(term)
            print(
                f"  # payload: {len(payload) + 1}B  hex: {(payload + bytes([FF])).hex()[:80]}"
            )
        except ValueError as e:
            print(f"  [ENC_ERROR ] {label}  ({e})")
            continue
        run_test(label, term)
        print()

    # --- Additional: raw bytecode experiments ---
    print()
    print("--- RAW BYTECODE EXPERIMENTS ---")
    print("  Testing unusual byte patterns that can't be built with the term API")
    print()

    # What if we embed 0xFD mid-stream where the parser might misinterpret?
    # App(echo, g(251)) then app with sys8, then app with QD
    # Standard: 0E FB FD 08 FD QD FD FF
    # This is echo(g(251))(sys8)(QD) = S10
    raw_tests = [
        (
            "RAW-1: 0E FB FD 08 FD " + QD_BYTES.hex() + " FD FF (=S10 raw)",
            bytes([0x0E, 0xFB, FD, 0x08, FD]) + QD_BYTES + bytes([FD, FF]),
        ),
        # What if sys8 gets the echo APPLICATION as a reducible thunk?
        # Build: sys8(App(echo, g(251)))(QD) = 08 (0E FB FD) FD QD FD FF
        (
            "RAW-2: sys8(echo(g251))(QD) raw",
            bytes([0x08, 0x0E, 0xFB, FD, FD]) + QD_BYTES + bytes([FD, FF]),
        ),
        # Triple application: ((echo g251) sys8 QD) — same as S10 structurally
        # But what about: (echo (sys8 g251)) QD — echo applied to sys8(g251)?
        # = echo(sys8(g251))(QD) = 0E (08 FB FD) FD QD FD FF
        (
            "RAW-3: echo(sys8(g251))(QD)",
            bytes([0x0E, 0x08, 0xFB, FD, FD]) + QD_BYTES + bytes([FD, FF]),
        ),
        # What about: echo(g(251))(λr. r(λp. p(nil)(QD)))(nil)
        # Unwrap Left, then apply Var(253) as if it were a syscall: V253(nil)(QD)
        # This is built as a term above (S5-like but with application)
        # Under λr(1).r.λp(2): p=V(0), nil=V(2)+shift... complex
        # Let's try: echo(g(251))(I) where I=identity — returns Left(V253) unchanged
        (
            "RAW-4: echo(g251)(I) [identity cont]",
            bytes([0x0E, 0xFB, FD, 0x00, FE, FD, FF]),
        ),
        # echo(g(251))(nil) — nil as continuation (nil = λc.λn.n = just returns second arg)
        ("RAW-5: echo(g251)(nil)", bytes([0x0E, 0xFB, FD, 0x00, FE, FE, FD, FF])),
    ]

    for label, payload in raw_tests:
        time.sleep(0.5)
        resp = send_raw(payload)
        classify(label, resp)
        print()

    # --- Summary ---
    print()
    print("=" * 72)
    print(f"SUMMARY: {len(novel_results)} non-standard results")
    print("=" * 72)
    if novel_results:
        for label, status, hex_resp, text_resp in novel_results:
            print(f"  !!! [{status}] {label}")
            print(f"      hex: {hex_resp[:120]}")
            if text_resp:
                print(f"      text: {repr(text_resp[:120])}")
    else:
        print("  All results were standard (RIGHT(6), EMPTY, ENC_FAIL, INVALID).")
        print("  No breakthrough found in this batch.")
    print()


if __name__ == "__main__":
    main()
