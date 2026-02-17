#!/usr/bin/env python3
"""
Alternative probe strategies for syscall 8 using combinator applications.

Hypothesis: Maybe we need to use the backdoor combinators (A, B) to
construct syscall calls in unusual ways that bypass permission checks.
"""
from __future__ import annotations

import argparse
import json
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FF,
    QD,
    decode_byte_term,
    decode_bytes_list,
    decode_either,
    encode_byte_term,
    encode_term,
    parse_term,
)


HOST = "wc3.wechall.net"
PORT = 61221

NIL_TERM: object = Lam(Lam(Var(0)))
QD_TERM: object = parse_term(QD)

SYSCALL_RESTRICTED = 0x08
SYSCALL_ECHO = 0x0E
SYSCALL_BACKDOOR = 0xC9

OMEGA_A: object = Lam(Lam(App(Var(0), Var(0))))  # λa.λb. b b
FLIP_B: object = Lam(Lam(App(Var(1), Var(0))))   # λa.λb. a b


def shift_term(term: object, delta: int, cutoff: int = 0) -> object:
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_term(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_term(term.f, delta, cutoff), shift_term(term.x, delta, cutoff))
    raise TypeError(f"Unsupported: {type(term)}")


def recv_until_close_or_ff(sock: socket.socket, timeout_s: float) -> bytes:
    sock.settimeout(timeout_s)
    out = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
            if FF in chunk:
                break
    except socket.timeout:
        pass
    return out


def query_raw(payload: bytes, timeout_s: float = 3.0, retries: int = 3) -> bytes:
    delay_s = 0.15
    last_err: Exception | None = None
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_until_close_or_ff(sock, timeout_s)
        except Exception as exc:
            last_err = exc
            time.sleep(delay_s)
            delay_s = min(delay_s * 2.0, 2.0)
    raise RuntimeError(f"Failed to query {HOST}:{PORT}") from last_err


@dataclass
class ProbeResult:
    name: str
    description: str
    payload_hex: str
    response_hex: str
    response_ascii: str
    classification: str
    detail: str
    interesting: bool = False
    
    def to_dict(self) -> dict[str, Any]:
        return self.__dict__


def classify_response(resp: bytes) -> tuple[str, str, bool]:
    if not resp:
        return "silent", "No response", False
    
    if resp.startswith(b"Invalid term!"):
        return "invalid", "Invalid term!", False
    
    if resp.startswith(b"Encoding failed!"):
        return "encoding_failed", "Encoding failed!", True
    
    if resp.startswith(b"Term too big!"):
        return "too_big", "Term too big!", False
    
    if FF not in resp:
        preview = resp[:200].decode("utf-8", "replace")
        return "no_ff", preview, True
    
    try:
        term = parse_term(resp)
    except Exception as e:
        return "parse_error", str(e)[:100], True
    
    try:
        tag, payload = decode_either(term)
    except Exception:
        return "non_either", str(term)[:200], True
    
    if tag == "Right":
        try:
            code = decode_byte_term(payload)
            is_interesting = code != 6
            return "either_right", f"Right({code})", is_interesting
        except Exception:
            return "either_right", "Right(<non-int>)", True
    
    try:
        bs = decode_bytes_list(payload)
        preview = bs[:120].decode("utf-8", "replace")
        return "either_left", f"Left(bytes:{len(bs)}:{preview!r})", True
    except Exception:
        return "either_left", "Left(<non-bytes>)", True


def run_probe(name: str, description: str, term: object) -> ProbeResult:
    payload = encode_term(term) + bytes([FF])
    
    try:
        resp = query_raw(payload)
    except Exception as e:
        return ProbeResult(
            name=name, description=description, payload_hex=payload.hex(),
            response_hex="", response_ascii=str(e),
            classification="error", detail=str(e), interesting=False,
        )
    
    classification, detail, interesting = classify_response(resp)
    
    return ProbeResult(
        name=name, description=description, payload_hex=payload.hex(),
        response_hex=resp.hex(), response_ascii=resp[:200].decode("utf-8", "replace"),
        classification=classification, detail=detail, interesting=interesting,
    )


def generate_probes() -> list[tuple[str, str, object]]:
    probes: list[tuple[str, str, object]] = []
    
    # Strategy 1: Apply backdoor combinators TO syscall 8
    # Maybe (A 8 arg) or (B 8 arg) bypasses something?
    
    # (A syscall8) nil QD - A takes 2 args, so (A 8) = λb. b b, then ((λb.bb) nil) = nil nil
    probes.append((
        "A_applied_to_8_nil",
        "(A 8 nil) then QD - A(8) = λb.bb, so (λb.bb nil) = nil nil",
        App(App(App(OMEGA_A, Var(SYSCALL_RESTRICTED)), NIL_TERM), QD_TERM),
    ))
    
    # (B syscall8 nil) QD - B takes 2 args, so (B 8 nil) = 8 nil
    probes.append((
        "B_applied_to_8_nil",
        "(B 8 nil) then QD - B(8)(nil) = 8(nil)",
        App(App(App(FLIP_B, Var(SYSCALL_RESTRICTED)), NIL_TERM), QD_TERM),
    ))
    
    # Strategy 2: Backdoor pair application to each other
    # A A, A B, B A, B B
    probes.append((
        "A_A_nil_qd",
        "((A A) nil) QD",
        App(App(App(OMEGA_A, OMEGA_A), NIL_TERM), QD_TERM),
    ))
    
    probes.append((
        "A_B_nil_qd",
        "((A B) nil) QD",
        App(App(App(OMEGA_A, FLIP_B), NIL_TERM), QD_TERM),
    ))
    
    probes.append((
        "B_A_nil_qd",
        "((B A) nil) QD",
        App(App(App(FLIP_B, OMEGA_A), NIL_TERM), QD_TERM),
    ))
    
    probes.append((
        "B_B_nil_qd",
        "((B B) nil) QD",
        App(App(App(FLIP_B, FLIP_B), NIL_TERM), QD_TERM),
    ))
    
    # Strategy 3: Use backdoor result in application position
    # Get (A,B) from backdoor, then apply it to syscall 8
    def backdoor_then_apply_to_8() -> object:
        qd_shifted = shift_term(QD_TERM, 1, 0)
        # pair is at Var(0), apply it to syscall 8 (shifted by 1 = Var(9))
        inner = App(App(App(Var(0), Var(SYSCALL_RESTRICTED + 1)), NIL_TERM), qd_shifted)
        return App(App(Var(SYSCALL_BACKDOOR), NIL_TERM), Lam(inner))
    
    probes.append((
        "backdoor_pair_applied_to_8",
        "Get (A,B) from backdoor, then (pair 8 nil) QD",
        backdoor_then_apply_to_8(),
    ))
    
    # Strategy 4: Triple echo (3 layers of shifting)
    def triple_echo_then_8(payload: object) -> object:
        qd_shifted_3 = shift_term(QD_TERM, 3, 0)
        innermost = App(App(Var(SYSCALL_RESTRICTED + 3), Var(0)), qd_shifted_3)
        cont3 = Lam(innermost)
        
        middle = App(App(Var(SYSCALL_ECHO + 2), Var(0)), cont3)
        cont2 = Lam(middle)
        
        outer = App(App(Var(SYSCALL_ECHO + 1), Var(0)), cont2)
        cont1 = Lam(outer)
        
        return App(App(Var(SYSCALL_ECHO), payload), cont1)
    
    for idx in [247, 248, 249, 250]:
        target = idx + 6
        probes.append((
            f"triple_echo_v{idx}",
            f"Triple-echo V{idx} -> Var({target}) then syscall 8",
            triple_echo_then_8(Var(idx)),
        ))
    
    # Strategy 5: Different 3-leaf tree shape: (Va (Vb Vc))
    for a, b, c in [(251, 252, 251), (252, 251, 252), (250, 251, 252)]:
        payload: object = App(Var(a), App(Var(b), Var(c)))
        
        def echo_then_8(p: object) -> object:
            qd_shifted = shift_term(QD_TERM, 1, 0)
            inner = App(App(Var(SYSCALL_RESTRICTED + 1), Var(0)), qd_shifted)
            return App(App(Var(SYSCALL_ECHO), p), Lam(inner))
        
        probes.append((
            f"3leaf_alt_echo_{a}_{b}_{c}",
            f"Echo (V{a} (V{b} V{c})) then syscall 8",
            echo_then_8(payload),
        ))
    
    # Strategy 6: Syscall 8 with A and B directly (not extracted from backdoor)
    probes.append((
        "syscall8_with_omega_A",
        "Syscall 8 with (λa.λb. b b) argument",
        App(App(Var(SYSCALL_RESTRICTED), OMEGA_A), QD_TERM),
    ))
    
    probes.append((
        "syscall8_with_flip_B",
        "Syscall 8 with (λa.λb. a b) argument",
        App(App(Var(SYSCALL_RESTRICTED), FLIP_B), QD_TERM),
    ))
    
    # Strategy 7: Syscall 8 with (A B) and (B A) as arguments
    probes.append((
        "syscall8_with_A_B",
        "Syscall 8 with (A B) argument",
        App(App(Var(SYSCALL_RESTRICTED), App(OMEGA_A, FLIP_B)), QD_TERM),
    ))
    
    probes.append((
        "syscall8_with_B_A",
        "Syscall 8 with (B A) argument",
        App(App(Var(SYSCALL_RESTRICTED), App(FLIP_B, OMEGA_A)), QD_TERM),
    ))
    
    # Strategy 8: Echo the identity (I = λx.x), then syscall 8
    I_TERM = Lam(Var(0))
    
    def echo_then_8(p: object) -> object:
        qd_shifted = shift_term(QD_TERM, 1, 0)
        inner = App(App(Var(SYSCALL_RESTRICTED + 1), Var(0)), qd_shifted)
        return App(App(Var(SYSCALL_ECHO), p), Lam(inner))
    
    probes.append((
        "echo_identity",
        "Echo (λx.x) then syscall 8",
        echo_then_8(I_TERM),
    ))
    
    # Strategy 9: Use echoed backdoor head/tail
    def backdoor_extract_and_echo_then_8(use_head: bool) -> object:
        selector = Lam(Lam(Var(1))) if use_head else Lam(Lam(Var(0)))
        
        qd_shifted_2 = shift_term(QD_TERM, 2, 0)
        innermost = App(App(Var(SYSCALL_RESTRICTED + 2), Var(0)), qd_shifted_2)
        cont2 = Lam(innermost)
        
        sel_shifted = shift_term(selector, 1, 0)
        nil_shifted = shift_term(NIL_TERM, 1, 0)
        extract = App(App(Var(0), sel_shifted), nil_shifted)
        middle = App(App(Var(SYSCALL_ECHO + 1), extract), cont2)
        cont1 = Lam(middle)
        
        return App(App(Var(SYSCALL_BACKDOOR), NIL_TERM), cont1)
    
    probes.append((
        "backdoor_head_echoed_8",
        "Backdoor -> extract head -> echo -> syscall 8",
        backdoor_extract_and_echo_then_8(use_head=True),
    ))
    
    probes.append((
        "backdoor_tail_echoed_8",
        "Backdoor -> extract tail -> echo -> syscall 8",
        backdoor_extract_and_echo_then_8(use_head=False),
    ))
    
    # Strategy 10: Maybe syscall 3 is actually implemented with specific args?
    SYSCALL_3 = 0x03
    
    probes.append((
        "syscall3_nil",
        "Syscall 3 with nil",
        App(App(Var(SYSCALL_3), NIL_TERM), QD_TERM),
    ))
    
    probes.append((
        "syscall3_backdoor_result",
        "Syscall 3 with backdoor result",
        App(App(Var(SYSCALL_BACKDOOR), NIL_TERM), 
            Lam(App(App(Var(SYSCALL_3 + 1), Var(0)), shift_term(QD_TERM, 1, 0)))),
    ))
    
    return probes


def main() -> None:
    parser = argparse.ArgumentParser(description="Alternative syscall 8 probes")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--delay", type=float, default=0.3)
    parser.add_argument("--out", type=Path, default=Path("syscall8_combinator_results.json"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--filter", type=str, default="")
    args = parser.parse_args()
    
    probes = generate_probes()
    
    if args.filter:
        probes = [(n, d, t) for n, d, t in probes if args.filter in n]
    
    print(f"Generated {len(probes)} probes")
    print("=" * 70)
    
    if args.dry_run:
        for name, desc, term in probes:
            payload = encode_term(term) + bytes([FF])
            print(f"\n{name}")
            print(f"  {desc}")
            print(f"  Payload ({len(payload)} bytes): {payload[:60].hex()}...")
        return
    
    results: list[dict[str, Any]] = []
    interesting_results: list[ProbeResult] = []
    
    for i, (name, desc, term) in enumerate(probes):
        print(f"\n[{i+1}/{len(probes)}] {name}")
        print(f"  {desc}")
        
        result = run_probe(name, desc, term)
        results.append(result.to_dict())
        
        status = "INTERESTING!" if result.interesting else "normal"
        print(f"  -> {result.classification}: {result.detail} [{status}]")
        
        if result.interesting:
            interesting_results.append(result)
            print(f"  *** Response hex: {result.response_hex[:100]}...")
        
        args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        time.sleep(args.delay)
    
    print("\n" + "=" * 70)
    print(f"SUMMARY: {len(interesting_results)} interesting out of {len(results)}")
    
    if interesting_results:
        print("\nInteresting results:")
        for r in interesting_results:
            print(f"  - {r.name}: {r.classification} - {r.detail}")
    
    print(f"\nResults saved to {args.out}")


if __name__ == "__main__":
    main()
