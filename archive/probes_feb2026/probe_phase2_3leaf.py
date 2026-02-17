#!/usr/bin/env python3
"""
probe_phase2_3leaf.py — Systematic 3-leaf program probe for BrownOS.

A "3-leaf" program has exactly 3 variable bytes (0x00-0xFC) in its bytecode.
The rest are structural: FD=App, FE=Lam, FF=End.

Tests all meaningful 3-leaf bytecode shapes against the BrownOS service,
focusing on sys8 (g(8)) and backdoor (g(201)).

Key shapes:
  Shape 1: a b FD c FD FF  = App(App(g(a), g(b)), g(c)) = g(a)(g(b))(g(c))
  Shape 2: a b c FD FD FF  = App(g(a), App(g(b), g(c))) = g(a)(g(b)(g(c)))
  Shape 3: a b FD c FE FD FF = App(App(g(a), g(b)), Lam(Var(c)))
  Shape 4: a FE b c FD FD FF = App(Lam(g(a)), App(g(b), g(c)))  [let-style]
  Shape 5: 00 FE FE prefix variants (the mail hint)
"""

from __future__ import annotations

import hashlib
import socket
import time
from datetime import datetime

HOST = "wc3.wechall.net"
PORT = 61221
TARGET = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ROUNDS = 56154

FD = 0xFD
FE = 0xFE
FF = 0xFF

total_requests = 0
results: list[dict] = []
breakthroughs: list[dict] = []


def send_raw(payload: bytes) -> bytes:
    """Send raw bytes, return response."""
    global total_requests
    total_requests += 1
    try:
        with socket.create_connection((HOST, PORT), timeout=6) as s:
            s.sendall(payload)
            try:
                s.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            chunks = []
            s.settimeout(5)
            while True:
                try:
                    d = s.recv(4096)
                    if not d:
                        break
                    chunks.append(d)
                except (socket.timeout, OSError):
                    break
        return b"".join(chunks)
    except Exception as e:
        return f"ERR:{e}".encode()


def check_hash(candidate: str) -> bool:
    cur = candidate.encode("utf-8")
    for _ in range(ROUNDS):
        cur = hashlib.sha1(cur).hexdigest().encode("ascii")
    return cur.decode("ascii") == TARGET


def classify(resp: bytes) -> str:
    if not resp:
        return "EMPTY"
    try:
        text = resp.decode("utf-8", errors="replace")
        if "Permission denied" in text:
            return "DENIED"
        if "Invalid term" in text:
            return "INVALID"
        if "Invalid argument" in text:
            return "INVAL_ARG"
        if "Not implemented" in text:
            return "NOT_IMPL"
        if "Encoding failed" in text:
            return "ENC_FAIL"
        if "Term too big" in text:
            return "TOO_BIG"
        if "Not so fast" in text:
            return "RATE_LIMIT"
        if text.startswith("ERR:"):
            return f"CONN_ERR:{text[4:60]}"
        return f"TEXT:{text[:100]}"
    except Exception:
        return f"RAW:{resp.hex()[:100]}"


KNOWN_BORING = {
    "EMPTY",
    "DENIED",
    "INVALID",
    "INVAL_ARG",
    "NOT_IMPL",
    "ENC_FAIL",
    "TOO_BIG",
    "RATE_LIMIT",
}


def is_breakthrough(cls: str) -> bool:
    if cls in KNOWN_BORING:
        return False
    if cls.startswith("CONN_ERR"):
        return False
    return True


def test(label: str, payload: bytes, desc: str):
    """Send payload, classify, record, flag breakthroughs."""
    resp = send_raw(payload)
    cls = classify(resp)
    bt = is_breakthrough(cls)

    entry = {
        "label": label,
        "desc": desc,
        "payload_hex": payload.hex(),
        "cls": cls,
        "breakthrough": bt,
        "raw_hex": resp.hex()[:160] if resp else "",
    }
    results.append(entry)

    flag = " *** BREAKTHROUGH ***" if bt else ""
    print(f"  [{total_requests:02d}] {label}: {cls}{flag}")
    if bt:
        print(f"       payload: {payload.hex()}")
        print(f"       raw: {resp.hex()[:160]}")
        breakthroughs.append(entry)

        # Try hash check on text responses
        if cls.startswith("TEXT:"):
            text = resp.decode("utf-8", errors="replace").strip()
            for candidate in [text, text.strip("\x00"), text.rstrip("\xff")]:
                if candidate and check_hash(candidate):
                    print(f"  !!! HASH MATCH: '{candidate}' !!!")

    time.sleep(0.4)


def main():
    start_time = time.time()
    print(f"=== probe_phase2_3leaf.py — {datetime.now().isoformat()} ===")
    print(f"Target: {HOST}:{PORT}")
    print()

    # ─── CATEGORY 1: Shape 1 — g(a)(g(b))(g(c)) = a b FD c FD FF ───
    # This is THE key test: sys8 with raw globals for BOTH arg AND continuation.
    # CPS: ((sys8 arg) continuation) = g(8)(g(n))(g(m))
    print("=== Cat 1: sys8(g(n))(g(m)) — CPS sys8 with raw globals ===")

    # Most promising first — backdoor as arg
    cat1_tests = [
        (8, 201, 2, "sys8(backdoor)(write)"),
        (8, 201, 14, "sys8(backdoor)(echo)"),
        (8, 201, 4, "sys8(backdoor)(quote)"),
        (8, 201, 7, "sys8(backdoor)(readfile)"),
        (8, 201, 0, "sys8(backdoor)(exception)"),
        (8, 201, 1, "sys8(backdoor)(error)"),
        (8, 201, 8, "sys8(backdoor)(sys8)"),
        (8, 201, 201, "sys8(backdoor)(backdoor)"),
        # Echo as arg
        (8, 14, 2, "sys8(echo)(write)"),
        (8, 14, 14, "sys8(echo)(echo)"),
        # Exception handler as arg
        (8, 0, 2, "sys8(exception)(write)"),
        # Other interesting
        (8, 42, 2, "sys8(towel)(write)"),
        (8, 2, 2, "sys8(write)(write)"),
        (8, 5, 2, "sys8(readdir)(write)"),
        (8, 7, 2, "sys8(readfile)(write)"),
    ]
    for a, b, c, desc in cat1_tests:
        payload = bytes([a, b, FD, c, FD, FF])
        test(f"C1:{a},{b},{c}", payload, desc)

    # ─── CATEGORY 2: backdoor(g(n))(g(m)) ───
    print("\n=== Cat 2: backdoor(g(n))(g(m)) — CPS backdoor with raw globals ===")

    cat2_tests = [
        (201, 0, 2, "backdoor(exception)(write)"),
        (201, 8, 2, "backdoor(sys8)(write)"),
        (201, 14, 2, "backdoor(echo)(write)"),
        (201, 201, 2, "backdoor(backdoor)(write)"),
        (201, 1, 2, "backdoor(error)(write)"),
        (201, 42, 2, "backdoor(towel)(write)"),
        (201, 0, 14, "backdoor(exception)(echo)"),
        (201, 8, 8, "backdoor(sys8)(sys8)"),
    ]
    for a, b, c, desc in cat2_tests:
        payload = bytes([a, b, FD, c, FD, FF])
        test(f"C2:{a},{b},{c}", payload, desc)

    # ─── CATEGORY 3: echo(g(n))(g(m)) ───
    print("\n=== Cat 3: echo(g(n))(g(m)) — CPS echo with raw globals ===")

    cat3_tests = [
        (14, 8, 2, "echo(sys8)(write)"),
        (14, 201, 2, "echo(backdoor)(write)"),
        (14, 8, 8, "echo(sys8)(sys8)"),
        (14, 201, 14, "echo(backdoor)(echo)"),
        (14, 14, 2, "echo(echo)(write)"),
    ]
    for a, b, c, desc in cat3_tests:
        payload = bytes([a, b, FD, c, FD, FF])
        test(f"C3:{a},{b},{c}", payload, desc)

    # ─── CATEGORY 4: Shape 2 — g(a)(g(b)(g(c))) = a b c FD FD FF ───
    print("\n=== Cat 4: g(a)(g(b)(g(c))) — right-associated 3-leaf ===")

    cat4_tests = [
        (8, 201, 0, "sys8(backdoor(exception))"),
        (8, 14, 8, "sys8(echo(sys8))"),
        (8, 14, 201, "sys8(echo(backdoor))"),
        (201, 8, 0, "backdoor(sys8(exception))"),
        (2, 8, 201, "write(sys8(backdoor))"),
        (8, 201, 2, "sys8(backdoor(write))"),
        (8, 201, 201, "sys8(backdoor(backdoor))"),
        (8, 0, 0, "sys8(exception(exception))"),
        (14, 8, 201, "echo(sys8(backdoor))"),
        (201, 0, 0, "backdoor(exception(exception))"),
    ]
    for a, b, c, desc in cat4_tests:
        payload = bytes([a, b, c, FD, FD, FF])
        test(f"C4:{a},{b},{c}", payload, desc)

    # ─── CATEGORY 5: Shape 3 — g(a)(g(b))(λx.Var(c)) = a b FD c FE FD FF ───
    print("\n=== Cat 5: g(a)(g(b))(λx.Var(c)) — 3-leaf with lambda cont ===")

    cat5_tests = [
        (8, 201, 0, "sys8(backdoor)(identity)"),  # Lam(Var(0)) = identity
        (8, 201, 1, "sys8(backdoor)(λx.g(0))"),  # under 1 lam, Var(1)=g(0)
        (8, 201, 2, "sys8(backdoor)(λx.g(1))"),  # Var(2) = g(1) = error
        (8, 201, 3, "sys8(backdoor)(λx.g(2))"),  # Var(3) = g(2) = write!
        (8, 201, 9, "sys8(backdoor)(λx.g(8))"),  # Var(9) = g(8) under 1 lam
        (8, 0, 0, "sys8(exception)(identity)"),
        (201, 0, 0, "backdoor(exception)(identity)"),
        (14, 8, 0, "echo(sys8)(identity)"),
    ]
    for a, b, c, desc in cat5_tests:
        payload = bytes([a, b, FD, c, FE, FD, FF])
        test(f"C5:{a},{b},{c}", payload, desc)

    # ─── CATEGORY 6: "00 FE FE" prefix — the mail hint ───
    # Bytecode literally starting with 00 FE FE
    # 00 FE FE = Lam(Lam(Var(0))) = nil — 1 leaf
    # To get exactly 3 leaves total, need 2 more Var bytes in the rest
    print("\n=== Cat 6: 00 FE FE prefix — mail hint literal bytecode ===")

    cat6_tests = [
        # 00 FE FE n FD m FD FF = nil(g(n))(g(m)) — nil applied to two args selects first → g(n)
        # But the PROGRAM itself has 3 leaves: 0, n, m
        (8, 2, "nil(g(8))(g(2)) = g(8)"),  # reduces to g(8)
        (201, 2, "nil(g(201))(g(2)) = g(201)"),  # reduces to g(201) = backdoor
        (8, 201, "nil(g(8))(g(201)) = g(8)"),  # reduces to g(8)
        (201, 8, "nil(g(201))(g(8)) = g(201)"),
        (14, 2, "nil(g(14))(g(2)) = g(14)"),
        (8, 14, "nil(g(8))(g(14)) = g(8)"),
    ]
    for n, m, desc in cat6_tests:
        # nil(g(n))(g(m)): 00 FE FE n FD m FD FF — 3 leaves (0, n, m)
        payload = bytes([0x00, FE, FE, n, FD, m, FD, FF])
        test(f"C6:nil,{n},{m}", payload, desc)

    # Shape: 00 FE FE FE n m FD FD FF = Lam(Lam(Lam(Var(0))))(g(n))(g(m)) — not 3 leaves (Var(0) is 1 leaf, but we only have 3 total? Wait: 00 = Var(0), n, m → 3 leaves: 00, n, m)
    # Actually 00 FE FE FE is Lam(Lam(Lam(Var(0)))) = 4 structural bytes + 1 leaf byte. Adding n m FD FD gives us App(App(..., g(n)), g(m)): total = 1+1+1 = 3 leaves.
    # But wait, 00 FE FE FE n m FD FD FF: parse → push 0, FE→Lam(0), FE→Lam(Lam(0)), FE→Lam(Lam(Lam(0))), push n, push m, FD→App(n,m), FD→App(Lam(Lam(Lam(0))),App(n,m))
    # That's only 2 items left (after the FDs): Lam3(0) and App(n,m). Need another FD.
    # 00 FE FE FE n FD m FD FF = App(App(Lam(Lam(Lam(Var(0)))), g(n)), g(m))
    cat6b_tests = [
        (8, 2, "Lam3(0)(g(8))(g(2))"),
        (201, 2, "Lam3(0)(g(201))(g(2))"),
    ]
    for n, m, desc in cat6b_tests:
        payload = bytes([0x00, FE, FE, FE, n, FD, m, FD, FF])
        test(f"C6b:{n},{m}", payload, desc)

    # ─── SUMMARY ───
    elapsed = time.time() - start_time
    print(f"\n{'=' * 60}")
    print(f"TOTAL: {total_requests} requests in {elapsed:.1f}s")
    print(f"BREAKTHROUGHS: {len(breakthroughs)}")

    # Classify all results by category
    cats = {}
    for r in results:
        cat = r["label"].split(":")[0]
        cats.setdefault(cat, []).append(r)

    print(f"\n--- Results by category ---")
    for cat, entries in cats.items():
        classes = {}
        for e in entries:
            classes[e["cls"]] = classes.get(e["cls"], 0) + 1
        print(f"  {cat} ({len(entries)} tests): {dict(classes)}")

    if breakthroughs:
        print(f"\n--- BREAKTHROUGHS ---")
        for bt in breakthroughs:
            print(f"  {bt['label']}: {bt['desc']}")
            print(f"    class: {bt['cls']}")
            print(f"    payload: {bt['payload_hex']}")
            print(f"    raw: {bt['raw_hex']}")
    else:
        print("\nNo breakthroughs detected.")

    # Deduplicate check
    payloads_seen = set()
    dupes = 0
    for r in results:
        if r["payload_hex"] in payloads_seen:
            dupes += 1
        payloads_seen.add(r["payload_hex"])
    if dupes:
        print(f"\nWARNING: {dupes} duplicate payloads detected")

    print(f"\nDone.")


if __name__ == "__main__":
    main()
