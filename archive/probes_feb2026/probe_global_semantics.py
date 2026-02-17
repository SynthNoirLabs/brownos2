#!/usr/bin/env python3
"""
probe_global_semantics.py — Systematically map the lambda-term semantics of ALL BrownOS globals.

The challenge author says "figuring out the meaning of the input codes is probably the most
important thing to do." The second cheat sheet example (?? ?? FD QD FD) reveals "crucial
properties" and "core structures" through "different outputs."

Phase 1: quote(g(a)) for all a in 0..252 — see raw structure
Phase 2: g(a)(nil)(QD) for all a — see what each global does with nil
Phase 3: g(a)(g(b))(QD) for strategic pairs — see interactions
Phase 4: Identify combinators (I, K, S, True, False, Pair, fst, snd)
"""

import socket
import sys
import time
from collections import defaultdict

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

DELAY = 0.45  # seconds between requests


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


def classify_response(resp):
    """Return a short classification string."""
    if not resp:
        return "EMPTY"
    if resp.startswith(b"ERROR:"):
        return resp.decode("utf-8", "replace")
    if b"Invalid term" in resp:
        return "INVALID"
    if b"Encoding failed" in resp:
        return "ENC_FAIL"
    if b"Term too big" in resp:
        return "TOO_BIG"
    if b"Not so fast" in resp:
        return "RATE_LIMIT"
    return resp.hex()


def make_quote_global(a):
    """quote(g(a))(QD) — see raw bytecode of global a.
    Bytecode: 04 <a> FD QD FD FF
    """
    return bytes([0x04, a, FD]) + QD_BYTES + bytes([FD, FF])


def make_apply_nil(a):
    """g(a)(nil)(QD) — apply global a to nil, observe via QD.
    nil = 00 FE FE
    Bytecode: <a> 00 FE FE FD QD FD FF
    """
    return bytes([a, 0x00, FE, FE, FD]) + QD_BYTES + bytes([FD, FF])


def make_apply_pair(a, b):
    """g(a)(g(b))(QD) — apply global a to global b, observe via QD.
    Bytecode: <a> <b> FD QD FD FF
    """
    return bytes([a, b, FD]) + QD_BYTES + bytes([FD, FF])


def make_apply_two_args(a, b, c):
    """g(a)(g(b))(g(c))(QD) — apply global a to two args, observe via QD.
    Bytecode: <a> <b> FD <c> FD QD FD FF
    """
    return bytes([a, b, FD, c, FD]) + QD_BYTES + bytes([FD, FF])


def run_phase(label, payloads_dict):
    """Run a batch of tests. payloads_dict = {label: payload_bytes}."""
    results = {}
    total = len(payloads_dict)
    for i, (test_label, payload) in enumerate(payloads_dict.items()):
        time.sleep(DELAY)
        resp = send_raw(payload)
        result = classify_response(resp)
        results[test_label] = result
        # Print progress
        if (i + 1) % 20 == 0 or (i + 1) == total:
            print(f"  [{label}] {i + 1}/{total} done", flush=True)
    return results


def main():
    print("=" * 72)
    print("probe_global_semantics.py")
    print("Mapping lambda-term semantics of ALL BrownOS globals (0-252)")
    print("=" * 72)
    print()

    # ===== PHASE 1: Quote all globals =====
    print("--- PHASE 1: quote(g(a)) for a=0..252 ---")
    print("  This shows the raw bytecode structure of each global.")
    print()

    phase1_payloads = {}
    for a in range(253):
        phase1_payloads[f"quote(g({a}))"] = make_quote_global(a)

    phase1_results = run_phase("P1", phase1_payloads)

    # Analyze Phase 1
    quote_clusters = defaultdict(list)
    for label, result in phase1_results.items():
        quote_clusters[result].append(label)

    print()
    print(f"  Phase 1 complete: {len(phase1_results)} globals quoted")
    print(f"  Unique quote outputs: {len(quote_clusters)}")
    print()

    # Show non-trivial results (anything that's NOT just "<a>ff")
    print("  Non-trivial quote results (globals with internal structure):")
    for result, labels in sorted(quote_clusters.items()):
        # Expected: quote(g(N)) = "<N_hex>ff"
        # Check if any result is NOT just a single-byte + ff
        if result not in (
            "EMPTY",
            "INVALID",
            "ENC_FAIL",
            "RATE_LIMIT",
        ) and not result.startswith("ERROR"):
            if len(result) > 4:  # More than 2 hex chars (1 byte + ff)
                print(f"    {result}: {labels[:5]}{'...' if len(labels) > 5 else ''}")
    print()

    # ===== PHASE 2: Apply all globals to nil =====
    print("--- PHASE 2: g(a)(nil)(QD) for a=0..252 ---")
    print("  This shows what each global does when applied to nil.")
    print()

    phase2_payloads = {}
    for a in range(253):
        phase2_payloads[f"g({a})(nil)"] = make_apply_nil(a)

    phase2_results = run_phase("P2", phase2_payloads)

    # Analyze Phase 2
    nil_clusters = defaultdict(list)
    for label, result in phase2_results.items():
        nil_clusters[result].append(label)

    print()
    print(f"  Phase 2 complete: {len(phase2_results)} globals applied to nil")
    print(f"  Unique outputs: {len(nil_clusters)}")
    print()

    # Show all clusters
    print("  Behavior clusters (g(a)(nil) output → which globals):")
    for result, labels in sorted(nil_clusters.items(), key=lambda x: -len(x[1])):
        # Extract just the numbers
        nums = [l.replace("g(", "").replace(")(nil)", "") for l in labels]
        if len(nums) <= 15:
            print(f"    [{result[:60]:60s}] ({len(labels):3d}): {', '.join(nums)}")
        else:
            print(
                f"    [{result[:60]:60s}] ({len(labels):3d}): {', '.join(nums[:10])}... +{len(nums) - 10} more"
            )
    print()

    # ===== PHASE 3: Apply globals to each other (strategic pairs) =====
    print("--- PHASE 3: g(a)(g(b))(QD) for strategic pairs ---")
    print("  Testing known syscalls and interesting globals against each other.")
    print()

    # Key globals to test as arguments
    key_globals = [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]

    # Also find globals that had INTERESTING Phase 2 results
    # (not the most common result, not EMPTY, not error)
    interesting_globals = set(key_globals)

    # Add globals with unique/rare Phase 2 behaviors
    for result, labels in nil_clusters.items():
        if len(labels) <= 5 and result not in ("EMPTY", "INVALID", "ENC_FAIL"):
            for l in labels:
                num = int(l.replace("g(", "").replace(")(nil)", ""))
                interesting_globals.add(num)

    interesting_globals = sorted(interesting_globals)[:30]  # Cap at 30

    phase3_payloads = {}
    # Test all key globals against all key globals
    for a in key_globals:
        for b in key_globals:
            phase3_payloads[f"g({a})(g({b}))"] = make_apply_pair(a, b)

    # Test interesting globals against a few probes
    probe_args = [0, 8, 14, 42]
    for a in interesting_globals:
        if a not in key_globals:
            for b in probe_args:
                phase3_payloads[f"g({a})(g({b}))"] = make_apply_pair(a, b)

    phase3_results = run_phase("P3", phase3_payloads)

    # Analyze Phase 3
    pair_clusters = defaultdict(list)
    for label, result in phase3_results.items():
        pair_clusters[result].append(label)

    print()
    print(f"  Phase 3 complete: {len(phase3_results)} pairs tested")
    print(f"  Unique outputs: {len(pair_clusters)}")
    print()

    print("  Pair interaction clusters:")
    for result, labels in sorted(pair_clusters.items(), key=lambda x: -len(x[1])):
        if len(labels) <= 10:
            print(f"    [{result[:60]:60s}] ({len(labels):3d}): {', '.join(labels)}")
        else:
            print(
                f"    [{result[:60]:60s}] ({len(labels):3d}): {', '.join(labels[:5])}... +{len(labels) - 5} more"
            )
    print()

    # ===== PHASE 4: Combinator identification =====
    print("--- PHASE 4: Combinator identification ---")
    print("  Testing for I, K, True, False patterns.")
    print()

    # Test: g(a)(X)(Y)(QD) for candidate identity/constant globals
    # If g(a)(X)(Y) = X → g(a) is K (or True)
    # If g(a)(X)(Y) = Y → g(a) is K* (or False)
    # Use X=g(42), Y=g(201) as distinguishable markers

    phase4_payloads = {}
    # Test all globals with two args
    for a in interesting_globals:
        phase4_payloads[f"g({a})(g(42))(g(201))"] = make_apply_two_args(a, 42, 201)
        phase4_payloads[f"g({a})(g(201))(g(42))"] = make_apply_two_args(a, 201, 42)

    phase4_results = run_phase("P4", phase4_payloads)

    print()
    print(f"  Phase 4 complete: {len(phase4_results)} tests")
    print()

    # Identify combinators
    # If g(a)(g(42))(g(201)) produces quote of g(42) AND g(a)(g(201))(g(42)) produces quote of g(201)
    # → g(a) is K (selects first arg)
    # If g(a)(g(42))(g(201)) produces quote of g(201) AND g(a)(g(201))(g(42)) produces quote of g(42)
    # → g(a) is K* / False (selects second arg)

    # Get reference: what does QD show for g(42) and g(201)?
    ref_42 = phase1_results.get("quote(g(42))", "?")
    ref_201 = phase1_results.get("quote(g(201))", "?")
    print(f"  Reference: quote(g(42)) = {ref_42}")
    print(f"  Reference: quote(g(201)) = {ref_201}")
    print()

    for a in interesting_globals:
        r1 = phase4_results.get(f"g({a})(g(42))(g(201))", "?")
        r2 = phase4_results.get(f"g({a})(g(201))(g(42))", "?")

        role = "?"
        if r1 == ref_42 and r2 == ref_201:
            role = "K / True (selects 1st arg)"
        elif r1 == ref_201 and r2 == ref_42:
            role = "K* / False (selects 2nd arg)"
        elif r1 == r2 and r1 != "EMPTY" and r1 != "?":
            role = f"Constant (always returns {r1[:30]})"
        elif r1 == "EMPTY" and r2 == "EMPTY":
            role = "Diverges or no output"
        else:
            role = f"Other: ({r1[:30]}) vs ({r2[:30]})"

        if role != "Diverges or no output" and role != "?":
            print(f"  g({a:3d}): {role}")
        elif role == "Diverges or no output":
            print(f"  g({a:3d}): {role}")

    # ===== SUMMARY =====
    print()
    print("=" * 72)
    print("FULL RESULTS DUMP")
    print("=" * 72)
    print()

    print("--- Phase 1: quote(g(a)) ---")
    for a in range(253):
        label = f"quote(g({a}))"
        result = phase1_results.get(label, "?")
        print(f"  g({a:3d}): {result}")

    print()
    print("--- Phase 2: g(a)(nil) ---")
    for a in range(253):
        label = f"g({a})(nil)"
        result = phase2_results.get(label, "?")
        print(f"  g({a:3d})(nil): {result}")

    print()
    print("--- Phase 3: g(a)(g(b)) ---")
    for label in sorted(phase3_results.keys()):
        print(f"  {label}: {phase3_results[label]}")

    print()
    print("--- Phase 4: g(a)(X)(Y) ---")
    for label in sorted(phase4_results.keys()):
        print(f"  {label}: {phase4_results[label]}")

    print()
    print("=" * 72)
    print("DONE")
    print("=" * 72)


if __name__ == "__main__":
    main()
