#!/usr/bin/env python3
"""
probe_3leaf_exhaustive.py — Exhaustive 3-leaf term enumeration.

Tests ALL meaningful 3-Var-node programs formed from key syscall globals.
The hint from dloser (challenge author): "My record is 3 leafs IIRC."

CRITICAL INSIGHT: Without QD (Quick Debug) as continuation, syscalls produce
no visible output. So we test each EXPR with QD appended: EXPR(QD).

The 3-leaf EXPR shapes applied to QD:
  A1. g(a)(g(b))(g(c))(QD)         — left-associated 3-leaf chain
  A2. g(a)(g(b)(g(c)))(QD)         — right-associated arg
  A3. (λ.V)(g(b))(g(c))(QD)        — lambda in function position
  A4. g(a)((λ.V)(g(c)))(QD)        — lambda in arg
  A5. g(a)(g(b))(λ.V)(QD)          — lambda as 2nd arg
  A6. (λ.λ.V)(g(b))(g(c))(QD)     — double-lambda prefix
  A8. (λ.V(m)(V(n)))(g(c))(QD)    — internal App in lambda
  B1. g(a)(g(b))(g(c)) raw         — self-contained (no QD)
"""

import socket
import time
import itertools

HOST = "wc3.wechall.net"
PORT = 61221
FF = 0xFF
FD = 0xFD
FE = 0xFE

# Quick Debug continuation — prints bytecode of syscall result
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def send_raw(payload, timeout_s=5.0):
    """Send raw bytecode to BrownOS, return raw response."""
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
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


# Key globals to test — all known syscalls + backdoor
GLOBALS = [0, 2, 4, 5, 7, 8, 14, 42, 201]

# Under 1 lambda: g(N) = Var(N+1), Var(0) = bound variable
UNDER_1_LAM = [0, 1, 3, 5, 6, 8, 9, 15, 43]

# Under 2 lambdas: g(N) = Var(N+2), Var(0)=inner, Var(1)=outer
UNDER_2_LAM = [0, 1, 2, 4, 6, 7, 9, 10, 16, 44]

# Known Right(6) response for sys8 — 19 bytes
RIGHT6_HEX = "00030200fdfdfefefefefefefefefefdfefeff"

results = []
test_count = 0


def classify_response(resp):
    """Classify a raw response into a status category."""
    if len(resp) == 0:
        return "EMPTY"
    if resp.startswith(b"ERROR:"):
        return "CONN_ERR"

    rhex = resp.hex()

    # Right(6) = Permission denied — the known sys8 failure response
    if rhex == RIGHT6_HEX:
        return "RIGHT6"

    # Check for text-based errors
    try:
        text = resp.decode("utf-8", "replace")
        if "Permission denied" in text:
            return "DENIED"
        if "Invalid" in text:
            return "INVALID"
        if "Term too big" in text:
            return "TOO_BIG"
        if "Rate" in text:
            return "RATE_LIM"
    except Exception:
        pass

    return "*** NOVEL ***"


def test(label, payload_bytes):
    """Send a payload, classify response, log results."""
    global test_count
    test_count += 1
    if len(payload_bytes) > 500:
        return None

    time.sleep(0.35)
    resp = send_raw(payload_bytes)
    resp_hex = resp.hex() if resp else "EMPTY"

    status = classify_response(resp)

    # Always print novel; print first 20 + every 200th for progress
    if status == "*** NOVEL ***":
        print(f"  [{test_count:4d}] [{status:10s}] {label}")
        print(f"         Payload: {payload_bytes.hex()}")
        print(f"         Response({len(resp)}b): {resp_hex[:160]}")
        try:
            print(f"         Text: {resp.decode('utf-8', 'replace')[:80]}")
        except Exception:
            pass
    elif test_count <= 20 or test_count % 200 == 0:
        print(f"  [{test_count:4d}] [{status:10s}] {label}")

    results.append((status, label, payload_bytes.hex(), resp_hex[:120]))
    return status


def ev(n):
    """Encode Var(n) as single byte. Rejects n >= 0xFD."""
    if n >= FD:
        raise ValueError(f"Var({n}) collides with special byte")
    return bytes([n])


def make_qd_payload(expr_bytes):
    """Wrap: EXPR(QD) sent as expr_bytes + QD + FD + FF."""
    return expr_bytes + QD + bytes([FD, FF])


# ================================================================
def run_all():
    """Run all test shapes."""
    global test_count

    c_names = {
        0: "bound",
        1: "g(0)=exc",
        3: "g(2)=write",
        5: "g(4)=quote",
        6: "g(5)=readdir",
        8: "g(7)=readfile",
        9: "g(8)=sys8",
        15: "g(14)=echo",
        43: "g(42)=towel",
    }

    d2_names = {
        0: "inner",
        1: "outer",
        2: "g(0)=exc",
        4: "g(2)=write",
        6: "g(4)=quote",
        7: "g(5)=readdir",
        9: "g(7)=readfile",
        10: "g(8)=sys8",
        16: "g(14)=echo",
        44: "g(42)=towel",
    }

    # ------------------------------------------------------------------
    # A1: g(a)(g(b))(g(c))(QD)
    # ------------------------------------------------------------------
    print("=" * 70)
    print("A1: g(a)(g(b))(g(c))(QD) — left-associated 3-leaf + QD")
    n_combos = len(GLOBALS) ** 3
    print(f"  Testing {n_combos} combinations...")
    print("=" * 70)

    for a, b, c in itertools.product(GLOBALS, repeat=3):
        expr = ev(a) + ev(b) + bytes([FD]) + ev(c) + bytes([FD])
        test(f"g({a})(g({b}))(g({c}))(QD)", make_qd_payload(expr))

    # ------------------------------------------------------------------
    # A2: g(a)(g(b)(g(c)))(QD)
    # ------------------------------------------------------------------
    print(f"\n{'=' * 70}")
    print("A2: g(a)(g(b)(g(c)))(QD) — right-assoc arg + QD")
    print(f"  Testing {n_combos} combinations...")
    print("=" * 70)

    for a, b, c in itertools.product(GLOBALS, repeat=3):
        expr = ev(a) + ev(b) + ev(c) + bytes([FD, FD])
        test(f"g({a})(g({b})(g({c})))(QD)", make_qd_payload(expr))

    # ------------------------------------------------------------------
    # A3: (λ.V)(g(b))(g(c))(QD)
    # ------------------------------------------------------------------
    print(f"\n{'=' * 70}")
    print("A3: (λ.V)(g(b))(g(c))(QD) — lambda fn + QD")
    print(f"  Testing {len(UNDER_1_LAM) * len(GLOBALS) ** 2} combinations...")
    print("=" * 70)

    for m in UNDER_1_LAM:
        for b in GLOBALS:
            for c in GLOBALS:
                expr = bytes([m, FE]) + ev(b) + bytes([FD]) + ev(c) + bytes([FD])
                m_label = c_names.get(m, f"V{m}")
                test(f"(λ.{m_label})(g({b}))(g({c}))(QD)", make_qd_payload(expr))

    # ------------------------------------------------------------------
    # A4: g(a)((λ.V)(g(c)))(QD)
    # ------------------------------------------------------------------
    print(f"\n{'=' * 70}")
    print("A4: g(a)((λ.V)(g(c)))(QD) — lambda in arg + QD")
    print(f"  Testing {len(GLOBALS) * len(UNDER_1_LAM) * len(GLOBALS)} combinations...")
    print("=" * 70)

    for a in GLOBALS:
        for m in UNDER_1_LAM:
            for c in GLOBALS:
                expr = ev(a) + bytes([m, FE]) + ev(c) + bytes([FD, FD])
                m_label = c_names.get(m, f"V{m}")
                test(f"g({a})((λ.{m_label})(g({c})))(QD)", make_qd_payload(expr))

    # ------------------------------------------------------------------
    # A5: g(a)(g(b))(λ.V)(QD)
    # ------------------------------------------------------------------
    print(f"\n{'=' * 70}")
    print("A5: g(a)(g(b))(λ.V)(QD) — lambda as 2nd arg + QD")
    print(f"  Testing {len(GLOBALS) ** 2 * len(UNDER_1_LAM)} combinations...")
    print("=" * 70)

    for a in GLOBALS:
        for b in GLOBALS:
            for m in UNDER_1_LAM:
                expr = ev(a) + ev(b) + bytes([FD, m, FE, FD])
                m_label = c_names.get(m, f"V{m}")
                test(f"g({a})(g({b}))(λ.{m_label})(QD)", make_qd_payload(expr))

    # ------------------------------------------------------------------
    # A6: (λ.λ.V)(g(b))(g(c))(QD)
    # ------------------------------------------------------------------
    print(f"\n{'=' * 70}")
    print("A6: (λ.λ.V)(g(b))(g(c))(QD) — double-lambda + QD")
    print(f"  Testing {len(UNDER_2_LAM) * len(GLOBALS) ** 2} combinations...")
    print("=" * 70)

    for n in UNDER_2_LAM:
        for b in GLOBALS:
            for c in GLOBALS:
                expr = bytes([n, FE, FE]) + ev(b) + bytes([FD]) + ev(c) + bytes([FD])
                n_label = d2_names.get(n, f"V{n}")
                test(f"(λ.λ.{n_label})(g({b}))(g({c}))(QD)", make_qd_payload(expr))

    # ------------------------------------------------------------------
    # A8: (λ.V(m)(V(n)))(g(c))(QD)
    # ------------------------------------------------------------------
    print(f"\n{'=' * 70}")
    print("A8: (λ.V(m)(V(n)))(g(c))(QD) — internal App + QD")
    print(f"  Testing {len(UNDER_1_LAM) ** 2 * len(GLOBALS)} combinations...")
    print("=" * 70)

    for m in UNDER_1_LAM:
        for n in UNDER_1_LAM:
            for c in GLOBALS:
                expr = bytes([m, n, FD, FE]) + ev(c) + bytes([FD])
                m_label = c_names.get(m, f"V{m}")
                n_label = c_names.get(n, f"V{n}")
                test(f"(λ.{m_label}({n_label}))(g({c}))(QD)", make_qd_payload(expr))

    # ------------------------------------------------------------------
    # B1: g(a)(g(b))(g(c)) raw — only with output-producing continuations
    # ------------------------------------------------------------------
    print(f"\n{'=' * 70}")
    print("B1: g(a)(g(b))(g(c)) raw — self-contained CPS (no QD)")
    print("  Only testing with c ∈ {write(2), echo(14)} as continuation")
    print("=" * 70)

    for a in GLOBALS:
        for b in GLOBALS:
            for c in [2, 14]:
                payload = ev(a) + ev(b) + bytes([FD]) + ev(c) + bytes([FD, FF])
                test(f"g({a})(g({b}))(g({c})) RAW", payload)

    # ==================================================================
    # SUMMARY
    # ==================================================================
    print(f"\n{'=' * 70}")
    print(f"SUMMARY: {test_count} tests total")
    print("=" * 70)

    novel = [r for r in results if r[0] == "*** NOVEL ***"]
    if novel:
        print(f"\n!!! FOUND {len(novel)} NOVEL RESPONSES !!!")
        for status, label, phex, rhex in novel:
            print(f"  {label}")
            print(f"    Payload: {phex}")
            print(f"    Response: {rhex}")
    else:
        print("\nNo novel responses found.")

    counts = {}
    for status, _, _, _ in results:
        counts[status] = counts.get(status, 0) + 1
    print("\nResponse distribution:")
    for status, count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {status:15s}: {count}")

    # Save full results
    with open("probe_3leaf_results.txt", "w") as f:
        f.write(f"Total tests: {test_count}\n\n")
        if novel:
            f.write(f"NOVEL RESPONSES: {len(novel)}\n")
            for status, label, phex, rhex in novel:
                f.write(f"  {label}\n    Payload: {phex}\n    Response: {rhex}\n\n")
        f.write("\nResponse distribution:\n")
        for status, count in sorted(counts.items(), key=lambda x: -x[1]):
            f.write(f"  {status:15s}: {count}\n")
        f.write("\nAll results:\n")
        for status, label, phex, rhex in results:
            f.write(f"[{status:15s}] {label} | {phex} | {rhex}\n")
    print(f"\nFull results saved to probe_3leaf_results.txt")


if __name__ == "__main__":
    run_all()
