#!/usr/bin/env python3
"""
probe_fake_globals.py — Build FAKE globals with modified sentinel bytes.

BREAKTHROUGH: We discovered that each global g(N) has the internal structure:
  g(N) = λa.λb. a(cons(int(N), cons(int(255), nil)))
       = λa.λb. a([N, 255])

The VM intercepts this pattern and dispatches to syscall N.
The 255 appears to be a sentinel/marker byte.

HYPOTHESIS: If we build λa.λb. a([8, X]) where X != 255, the VM might:
1. Still dispatch to syscall 8 but with different permissions
2. Bypass the permission check entirely
3. Dispatch to a different/hidden syscall

We also test:
- Building fake globals from scratch (not from the global table)
- Modifying the byte list structure
- Using echo to manufacture the sentinel byte
"""

import socket
import sys
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
DELAY = 0.5


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


def enc(term):
    """Encode term to bytecode (without trailing FF)."""
    if isinstance(term, Var):
        if term.i > 0xFC:
            raise ValueError(f"Var({term.i}) cannot be encoded")
        return bytes([term.i])
    if isinstance(term, Lam):
        return enc(term.body) + bytes([FE])
    if isinstance(term, App):
        return enc(term.f) + enc(term.x) + bytes([FD])
    raise TypeError(f"Unsupported: {type(term)}")


def encode_int(n):
    """Encode integer n as 9-lambda additive bitset term."""
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


def scott_nil():
    """nil = λc.λn. n"""
    return Lam(Lam(Var(0)))


def scott_cons(head, tail):
    """cons h t = λc.λn. c(h)(t)"""
    # Under 2 lambdas, head and tail need to be shifted by 2
    return Lam(Lam(App(App(Var(1), sh(head, 2)), sh(tail, 2))))


def sh(term, delta, cutoff=0):
    """Shift free variables by delta."""
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(sh(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(sh(term.f, delta, cutoff), sh(term.x, delta, cutoff))
    raise TypeError


def build_byte_list(byte_values):
    """Build a Scott byte list from a list of integer values."""
    cur = scott_nil()
    for b in reversed(byte_values):
        cur = scott_cons(encode_int(b), cur)
    return cur


def build_fake_global(syscall_id, sentinel):
    """Build λa.λb. a([syscall_id, sentinel])

    Under 2 lambdas: a=V1, b=V0
    The byte list [syscall_id, sentinel] needs to be shifted by 2 for the enclosing lambdas.
    """
    byte_list = build_byte_list([syscall_id, sentinel])
    # Shift the byte list by 2 for the enclosing λa.λb.
    shifted_list = sh(byte_list, 2)
    return Lam(Lam(App(Var(1), shifted_list)))


def send_raw(payload_bytes, timeout_s=5.0):
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
        return f"ERROR:{e}".encode()


def parse_term(data):
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
    return stack[0] if len(stack) == 1 else None


def decode_either(term):
    """Decode Scott Either."""
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        return None
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var):
        if body.f.i == 1:
            return ("Left", body.x)
        elif body.f.i == 0:
            return ("Right", body.x)
    return None


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def decode_int(term):
    """Decode 9-lambda additive bitset integer."""
    cur = term
    for _ in range(9):
        if not isinstance(cur, Lam):
            return None
        cur = cur.body
    return _eval_bits(cur)


def _eval_bits(expr):
    if isinstance(expr, Var):
        return WEIGHTS.get(expr.i, -1)
    if isinstance(expr, App) and isinstance(expr.f, Var):
        rest = _eval_bits(expr.x)
        if rest is None:
            return None
        return WEIGHTS.get(expr.f.i, 0) + rest
    return None


def classify(resp):
    """Classify response."""
    if not resp:
        return "EMPTY", None
    if resp.startswith(b"ERROR:"):
        return resp.decode(), None
    if b"Invalid term" in resp:
        return "INVALID", None
    if b"Encoding failed" in resp:
        return "ENC_FAIL", None
    if b"Term too big" in resp:
        return "TOO_BIG", None
    if b"Not so fast" in resp:
        return "RATE_LIMIT", None

    # Try to parse as term
    term = parse_term(resp)
    if term:
        either = decode_either(term)
        if either:
            tag, val = either
            code = decode_int(val)
            if code is not None:
                return f"{tag}({code})", term
            return f"{tag}(<complex>)", term

    return f"RAW:{resp.hex()[:60]}", None


def test_fake_global(label, fake_global, arg, cont_bytes=QD_BYTES):
    """Test a fake global: fake_global(arg)(cont)."""
    try:
        payload = enc(
            App(App(fake_global, arg), parse_term(cont_bytes + bytes([FF])))
        ) + bytes([FF])
    except ValueError as e:
        print(f"  [ENC_ERROR] {label}: {e}")
        return "ENC_ERROR"

    if len(payload) > 2000:
        print(f"  [TOO_BIG ] {label}: {len(payload)} bytes")
        return "TOO_BIG"

    time.sleep(DELAY)
    resp = send_raw(payload)
    status, term = classify(resp)

    marker = ""
    if status not in (
        "Right(6)",
        "Right(1)",
        "Right(2)",
        "EMPTY",
        "ENC_ERROR",
        "TOO_BIG",
        "RATE_LIMIT",
    ):
        marker = "  *** NOVEL ***"

    print(f"  [{status:20s}] {label}{marker}")
    if marker:
        print(f"    hex: {resp.hex()[:120]}")
        if resp:
            try:
                print(f"    text: {resp.decode('utf-8', 'replace')[:120]}")
            except:
                pass

    sys.stdout.flush()
    return status


def main():
    print("=" * 72)
    print("probe_fake_globals.py")
    print("Testing FAKE globals with modified sentinel bytes")
    print("=" * 72)
    print()

    nil = scott_nil()
    QD = parse_term(QD_BYTES + bytes([FF]))

    # ===== PHASE 1: Verify fake global dispatch =====
    print("--- PHASE 1: Verify fake global construction ---")
    print("  Build λa.λb. a([N, 255]) from scratch and test if VM dispatches")
    print()

    # Test: fake g(42) should return towel
    print("  Testing fake g(42) = λa.λb. a([42, 255]):")
    fg42 = build_fake_global(42, 255)
    test_fake_global("fake_g42(nil)(QD)", fg42, nil)

    # Test: fake g(14) should return Left(nil) = echo
    print("  Testing fake g(14) = λa.λb. a([14, 255]):")
    fg14 = build_fake_global(14, 255)
    test_fake_global("fake_g14(nil)(QD)", fg14, nil)

    # Test: fake g(8) should return Right(6) = PermDenied
    print("  Testing fake g(8) = λa.λb. a([8, 255]):")
    fg8 = build_fake_global(8, 255)
    test_fake_global("fake_g8(nil)(QD)", fg8, nil)

    # Test: fake g(201) should return Left(pair)
    print("  Testing fake g(201) = λa.λb. a([201, 255]):")
    fg201 = build_fake_global(201, 255)
    test_fake_global("fake_g201(nil)(QD)", fg201, nil)

    print()

    # ===== PHASE 2: Sentinel fuzzing for syscall 8 =====
    print("--- PHASE 2: Sentinel fuzzing — λa.λb. a([8, X]) for X=0..254 ---")
    print("  If any X != 255 changes the behavior, we found the bypass!")
    print()

    novel_sentinels = []
    for x in range(256):
        if x == 255:
            continue  # Skip the normal sentinel
        if x in (0xFD, 0xFE, 0xFF):
            continue  # Can't encode these as Var indices

        fg = build_fake_global(8, x)
        status = test_fake_global(f"fake_g8_sentinel_{x}(nil)(QD)", fg, nil)

        if status not in (
            "Right(6)",
            "Right(1)",
            "EMPTY",
            "ENC_ERROR",
            "TOO_BIG",
            "RATE_LIMIT",
        ):
            novel_sentinels.append((x, status))
            print(f"    !!! NOVEL SENTINEL {x} → {status}")

    print()

    # ===== PHASE 3: Different byte list structures =====
    print("--- PHASE 3: Modified byte list structures ---")
    print()

    # Test: [8] alone (no sentinel)
    print("  Testing λa.λb. a([8]):")
    bl_8 = build_byte_list([8])
    fg_8only = Lam(Lam(App(Var(1), sh(bl_8, 2))))
    test_fake_global("fake_g8_no_sentinel(nil)(QD)", fg_8only, nil)

    # Test: [8, 0]
    print("  Testing λa.λb. a([8, 0]):")
    fg_80 = build_fake_global(8, 0)
    test_fake_global("fake_g8_sentinel_0(nil)(QD)", fg_80, nil)

    # Test: [8, 8]
    print("  Testing λa.λb. a([8, 8]):")
    fg_88 = build_fake_global(8, 8)
    test_fake_global("fake_g8_sentinel_8(nil)(QD)", fg_88, nil)

    # Test: [8, 255, 255] (extra sentinel)
    print("  Testing λa.λb. a([8, 255, 255]):")
    bl_8255255 = build_byte_list([8, 255, 255])
    fg_extra = Lam(Lam(App(Var(1), sh(bl_8255255, 2))))
    test_fake_global("fake_g8_double_sentinel(nil)(QD)", fg_extra, nil)

    # Test: [255, 8] (reversed)
    print("  Testing λa.λb. a([255, 8]):")
    bl_2558 = build_byte_list([255, 8])
    fg_rev = Lam(Lam(App(Var(1), sh(bl_2558, 2))))
    test_fake_global("fake_g8_reversed(nil)(QD)", fg_rev, nil)

    # Test: empty list
    print("  Testing λa.λb. a([]):")
    fg_empty = Lam(Lam(App(Var(1), sh(scott_nil(), 2))))
    test_fake_global("fake_g_empty_list(nil)(QD)", fg_empty, nil)

    # Test: [0, 0] (exception with sentinel 0)
    print("  Testing λa.λb. a([0, 0]):")
    fg_00 = build_fake_global(0, 0)
    test_fake_global("fake_g0_sentinel_0(nil)(QD)", fg_00, nil)

    print()

    # ===== PHASE 4: Use real g(8) but pass fake capability =====
    print("--- PHASE 4: Pass fake capability objects to real g(8) ---")
    print()

    # What if sys8 expects a specific TERM as its argument?
    # Try passing the byte list [8, 255] directly
    print("  Testing g(8)([8, 255])(QD):")
    bl_8_255 = build_byte_list([8, 255])
    payload = enc(App(App(Var(8), bl_8_255), QD)) + bytes([FF])
    time.sleep(DELAY)
    resp = send_raw(payload)
    status, _ = classify(resp)
    print(f"  [{status:20s}] g(8)([8,255])(QD)")

    # Try passing [8, 0]
    print("  Testing g(8)([8, 0])(QD):")
    bl_8_0 = build_byte_list([8, 0])
    payload = enc(App(App(Var(8), bl_8_0), QD)) + bytes([FF])
    time.sleep(DELAY)
    resp = send_raw(payload)
    status, _ = classify(resp)
    print(f"  [{status:20s}] g(8)([8,0])(QD)")

    # Try passing the fake global TERM itself as argument to real g(8)
    print("  Testing g(8)(fake_g8_term)(QD):")
    fg8_term = build_fake_global(8, 255)
    payload = enc(App(App(Var(8), fg8_term), QD)) + bytes([FF])
    time.sleep(DELAY)
    resp = send_raw(payload)
    status, _ = classify(resp)
    print(f"  [{status:20s}] g(8)(fake_g8)(QD)")

    print()

    # ===== SUMMARY =====
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    if novel_sentinels:
        print(f"  NOVEL SENTINELS FOUND: {len(novel_sentinels)}")
        for x, status in novel_sentinels:
            print(f"    sentinel={x}: {status}")
    else:
        print("  No novel sentinels found in range 0-254.")
    print()


if __name__ == "__main__":
    main()
