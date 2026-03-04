#!/usr/bin/env python3
"""
probe_3leaf_exhaustive.py

Generates all possible 3-leaf Lambda Calculus ASTs containing at least `Var(201)`
and up to 3 Lambda nodes, and tests them against the live server.
"""
from dataclasses import dataclass
import socket
import time
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import socket
import time
import sys

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE
FF = 0xFF


@dataclass(frozen=True)
class Var:
    i: int

    def __repr__(self):
        return f"V{self.i}"


@dataclass(frozen=True)
class Lam:
    body: object

    def __repr__(self):
        return f"λ.{self.body}"


@dataclass(frozen=True)
class App:
    f: object
    x: object

    def __repr__(self):
        return f"({self.f} {self.x})"


def encode_term(term) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])


def has_var(term, val):
    if isinstance(term, Var):
        return term.i == val
    if isinstance(term, Lam):
        return has_var(term.body, val)
    if isinstance(term, App):
        return has_var(term.f, val) or has_var(term.x, val)


def generate_asts_exact(leaves, lams, allowed_vars):
    if leaves == 1:
        if lams == 0:
            for v in allowed_vars:
                yield Var(v)
        else:
            for t in generate_asts_exact(leaves, lams - 1, allowed_vars):
                yield Lam(t)
    else:
        if lams > 0:
            for t in generate_asts_exact(leaves, lams - 1, allowed_vars):
                yield Lam(t)

        for left_leaves in range(1, leaves):
            right_leaves = leaves - left_leaves
            for left_lams in range(lams + 1):
                right_lams = lams - left_lams
                for l in generate_asts_exact(left_leaves, left_lams, allowed_vars):
                    for r in generate_asts_exact(
                        right_leaves, right_lams, allowed_vars
                    ):
                        yield App(l, r)


def query(payload: bytes, timeout_s=4.0) -> bytes:
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
        return b"ERROR"


def classify(out: bytes) -> str:
    if not out:
        return "EMPTY"
    known = [
        "Invalid term!",
        "Encoding failed!",
        "Term too big!",
        "Permission denied",
        "Not implemented",
        "ERR_DECODE_FAIL",
        "LEFT\n",
        "QUOTE_FAIL\n",
        "Unexpected exception",
        "Invalid argument",
        "Not so fast!",
    ]
    for t in known:
        if out.startswith(t.encode("ascii")):
            return f"TEXT:{t!r}"
    try:
        text = out.decode("utf-8", "replace")
        if all((ch == "\n") or (ch == "\r") or (32 <= ord(ch) < 127) for ch in text):
            return f"TEXT:{text.strip()!r}"
    except Exception:
        pass
    return f"HEX:{out[:40].hex()}"


def main():
    allowed_vars = [0, 8, 201]  # The most important globals to combine

    print("Generating 3-leaf ASTs...")
    all_asts = []
    for lams in range(0, 4):  # 0 to 3 lambdas
        for ast in generate_asts_exact(3, lams, allowed_vars):
            if has_var(ast, 201):
                all_asts.append(ast)

    # Also generate 4-leaf ASTs just in case "3 leafs" meant something else,
    # but we'll stick to 3 leaves for now to be exhaustive.
    print(
        f"Found {len(all_asts)} structurally distinct 3-leaf ASTs containing Var(201)."
    )

    # We want to see if any return something other than EMPTY or Permission denied or Invalid argument or Not implemented
    boring = [
        "EMPTY",
        "TEXT:'Permission denied'",
        "TEXT:'Invalid argument'",
        "TEXT:'Not implemented'",
        "ERROR",
    ]

    anomalies = []

    print(f"Testing {len(all_asts)} payloads on live server...")
    t0 = time.monotonic()

    def test_ast(item):
        i, ast = item
        payload = encode_term(ast) + bytes([FF])
        out = query(payload)
        c = classify(out)
        return i, ast, payload.hex(), c

    with ThreadPoolExecutor(max_workers=5) as executor:
        for i, ast, hex_str, c in executor.map(test_ast, enumerate(all_asts)):
            if c not in boring:
                anomalies.append((ast, hex_str, c))
                print(f"[{i + 1}/{len(all_asts)}] AST: {ast} -> {c} *** ANOMALY ***")
            else:
                if (i + 1) % 100 == 0:
                    print(f"[{i + 1}/{len(all_asts)}] Tested...")
    t1 = time.monotonic()
    print(f"Finished in {t1 - t0:.1f}s. Found {len(anomalies)} anomalies.")

    if anomalies:
        print("\n--- ANOMALIES ---")
        for ast, hex_str, c in anomalies:
            print(f"AST: {ast}")
            print(f"Hex: {hex_str}")
            print(f"Out: {c}")
            print("-" * 40)


if __name__ == "__main__":
    main()
