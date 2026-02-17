#!/usr/bin/env python3
"""
probe_enum_env.py - Enumerate the BrownOS environment by quoting every global.

For each n in 0..252, send:
    g(4)(Var(n))(continuation) FF

where continuation unwraps the Either result from quote:
    λresult. result
        (λbytes. g(2)(bytes)(g(0)))     -- Left: write the raw quoted bytes
        (λerr.   g(2)("R:")(g(0)))      -- Right: write "R:" marker

The raw quoted bytes give us the internal structure of each Var(n).
If Var(n) is a simple global referencing index n, quote returns just byte [n, FF].
If it's been reduced to something else (lambda, application, etc.), we see that structure.

"Encoding failed!" means the term contains bytes 0xFD/0xFE/0xFF which can't be serialized.
"""

from __future__ import annotations

import json
import socket
import sys
import time

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FF,
    FD,
    FE,
    encode_term,
    encode_bytes_list,
    parse_term,
)

HOST = "wc3.wechall.net"
PORT = 61221
TIMEOUT_S = 6.0
REQUEST_DELAY_S = 0.40  # be gentle with shared service
MAX_RETRIES = 3


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


def shift(term: object, delta: int, cutoff: int = 0) -> object:
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    return term


def build_quote_write_cont() -> object:
    """
    λresult. result
        (λbytes. g(2)(bytes)(g(0)))     -- Left: write bytes, halt
        (λerr.   g(2)("R:")(g(0)))      -- Right: write marker "R:", halt

    Depth analysis:
      λresult (depth 1): result=Var(0)
        Left handler: λbytes (depth 2): bytes=Var(0), g(2)=Var(4), g(0)=Var(2)
        Right handler: λerr (depth 2): g(2)=Var(4), g(0)=Var(2)
    """
    # Left handler at depth 2: write(bytes, g(0))
    left_h = Lam(App(App(Var(4), Var(0)), Var(2)))
    # Right handler at depth 2: write("R:", g(0))
    r_marker = encode_bytes_list(b"R:")
    right_h = Lam(App(App(Var(4), shift(r_marker, 2)), Var(2)))
    # result(left_h)(right_h)
    return Lam(App(App(Var(0), left_h), right_h))


def build_quote_term(n: int, cont: object) -> object:
    """
    g(4)(Var(n))(cont)

    At depth 0: g(4) = Var(4), target = Var(n)
    """
    return App(App(Var(4), Var(n)), cont)


def classify_quoted_bytes(raw: bytes) -> dict:
    """Classify the raw quoted bytes (before FF terminator)."""
    if not raw:
        return {"type": "empty", "detail": "no data"}

    # Strip FF terminator if present
    data = raw
    if data and data[-1] == FF:
        data = data[:-1]

    if len(data) == 0:
        return {"type": "empty_after_ff", "detail": "only FF"}

    if len(data) == 1:
        b = data[0]
        if b < FD:
            return {"type": "var", "index": b, "detail": f"Var({b})"}
        elif b == FD:
            return {"type": "special", "detail": "bare FD (App marker)"}
        elif b == FE:
            return {"type": "special", "detail": "bare FE (Lam marker)"}
        else:
            return {"type": "special", "detail": f"bare 0x{b:02X}"}

    # Try to parse as a term
    try:
        term = parse_term(data + bytes([FF]))
        return {"type": "term", "detail": repr(term), "term_bytes": data.hex()}
    except Exception as e:
        return {"type": "parse_error", "detail": str(e), "raw_hex": data.hex()}


def run_quote_probe(n: int, cont: object) -> dict:
    """Quote Var(n) and return classification."""
    term = build_quote_term(n, cont)
    payload = encode_term(term) + bytes([FF])

    for attempt in range(MAX_RETRIES):
        out, elapsed = query_raw(payload)

        if not out and elapsed >= TIMEOUT_S - 0.5:
            # Timeout — retry
            if attempt < MAX_RETRIES - 1:
                time.sleep(1.0)
                continue
            return {
                "var": n,
                "status": "timeout",
                "elapsed": round(elapsed, 3),
                "classification": {
                    "type": "timeout",
                    "detail": f"timeout after {elapsed:.1f}s",
                },
            }

        if not out:
            # Empty but fast — could be meaningful
            return {
                "var": n,
                "status": "empty",
                "elapsed": round(elapsed, 3),
                "classification": {
                    "type": "empty_response",
                    "detail": f"empty after {elapsed:.1f}s",
                },
            }

        text = out.decode("latin-1", errors="replace")

        # Check for error messages from the server
        if text.startswith("Encoding failed"):
            return {
                "var": n,
                "status": "encoding_failed",
                "elapsed": round(elapsed, 3),
                "classification": {
                    "type": "encoding_failed",
                    "detail": "Term contains unserializable bytes (0xFD/FE/FF)",
                },
            }
        if text.startswith("Invalid term"):
            return {
                "var": n,
                "status": "invalid_term",
                "elapsed": round(elapsed, 3),
                "classification": {"type": "invalid_term", "detail": text.strip()},
            }
        if text.startswith("Term too big"):
            return {
                "var": n,
                "status": "too_big",
                "elapsed": round(elapsed, 3),
                "classification": {"type": "too_big", "detail": text.strip()},
            }

        # Check if response starts with "R:" — Right branch (error from quote)
        if out.startswith(b"R:"):
            return {
                "var": n,
                "status": "quote_error",
                "elapsed": round(elapsed, 3),
                "raw_hex": out.hex(),
                "classification": {
                    "type": "quote_error",
                    "detail": "quote returned Right (error)",
                },
            }

        # Otherwise it's raw quoted bytes from the Left branch
        classification = classify_quoted_bytes(out)
        return {
            "var": n,
            "status": "ok",
            "elapsed": round(elapsed, 3),
            "raw_hex": out.hex(),
            "classification": classification,
        }

    return {
        "var": n,
        "status": "failed",
        "classification": {"type": "failed", "detail": "all retries failed"},
    }


def main() -> None:
    start_n = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    end_n = int(sys.argv[2]) if len(sys.argv) > 2 else 252

    print(f"BrownOS Environment Enumeration: Var({start_n}) to Var({end_n})")
    print(f"Target: {HOST}:{PORT}")
    print(f"Delay: {REQUEST_DELAY_S}s between requests")
    print("=" * 80)

    cont = build_quote_write_cont()
    results: list[dict] = []

    # Summary counters
    counts: dict[str, int] = {}

    for n in range(start_n, end_n + 1):
        result = run_quote_probe(n, cont)
        results.append(result)

        cls_type = result["classification"]["type"]
        counts[cls_type] = counts.get(cls_type, 0) + 1

        # Print progress
        raw_hex = result.get("raw_hex", "")
        status = result["status"]
        detail = result["classification"]["detail"]
        elapsed = result.get("elapsed", 0)
        print(f"  Var({n:3d}): [{status:18s}] {elapsed:.2f}s | {detail}")
        if raw_hex and status == "ok":
            print(f"           raw: {raw_hex}")

        time.sleep(REQUEST_DELAY_S)

    # Summary
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total probed: {len(results)}")
    for cls_type, count in sorted(counts.items()):
        print(f"  {cls_type}: {count}")

    # Find interesting entries (not simple single-byte Var(n) = n)
    print()
    print("INTERESTING ENTRIES (not simple Var(n)=byte(n)):")
    print("-" * 80)
    for r in results:
        cls = r["classification"]
        n = r["var"]
        # A simple global just quotes to its own byte
        if cls["type"] == "var" and cls.get("index") == n:
            continue  # boring — Var(n) quotes to byte n, it's just a reference
        # Everything else is interesting
        print(f"  Var({n:3d}): {cls['type']} — {cls['detail']}")
        if "raw_hex" in r:
            print(f"           raw: {r['raw_hex']}")

    # Save full results to JSON
    outfile = f"env_map_{start_n}_{end_n}.json"
    with open(outfile, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nFull results saved to {outfile}")


if __name__ == "__main__":
    main()
