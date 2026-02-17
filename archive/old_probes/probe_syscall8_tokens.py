#!/usr/bin/env python3
"""
Probe syscall 0x08 with "unforgeable token" strategies.

Hypothesis: syscall 0x08 is gated by terms containing variable indices 253-255
(reserved bytes FD/FE/FF) which cannot be transmitted directly. Echo (0x0E)
shifts de Bruijn indices, allowing manufacture of these "illegal" terms.
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
I_TERM: object = Lam(Var(0))
QD_TERM: object = parse_term(QD)

SYSCALL_ERROR = 0x01
SYSCALL_WRITE = 0x02
SYSCALL_QUOTE = 0x04
SYSCALL_READDIR = 0x05
SYSCALL_NAME = 0x06
SYSCALL_READFILE = 0x07
SYSCALL_RESTRICTED = 0x08
SYSCALL_ECHO = 0x0E
SYSCALL_TOWEL = 0x2A
SYSCALL_BACKDOOR = 0xC9


def shift_term(term: object, delta: int, cutoff: int = 0) -> object:
    """De Bruijn shift: increase free vars >= cutoff by delta."""
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_term(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_term(term.f, delta, cutoff), shift_term(term.x, delta, cutoff))
    raise TypeError(f"Unsupported term node: {type(term)}")


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
        return {
            "name": self.name,
            "description": self.description,
            "payload_hex": self.payload_hex,
            "response_hex": self.response_hex,
            "response_ascii": self.response_ascii,
            "classification": self.classification,
            "detail": self.detail,
            "interesting": self.interesting,
        }


def classify_response(resp: bytes) -> tuple[str, str, bool]:
    """Returns: (classification, detail, is_interesting)"""
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
            is_interesting = code != 6  # Right(6) = Permission denied is expected
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
            name=name,
            description=description,
            payload_hex=payload.hex(),
            response_hex="",
            response_ascii=str(e),
            classification="error",
            detail=str(e),
            interesting=False,
        )
    
    classification, detail, interesting = classify_response(resp)
    
    return ProbeResult(
        name=name,
        description=description,
        payload_hex=payload.hex(),
        response_hex=resp.hex(),
        response_ascii=resp[:200].decode("utf-8", "replace"),
        classification=classification,
        detail=detail,
        interesting=interesting,
    )


def make_cps_call(syscall: int, arg: object, cont: object) -> object:
    """Build ((syscall arg) continuation)"""
    return App(App(Var(syscall), arg), cont)


def make_syscall8_with_qd(arg: object) -> object:
    return make_cps_call(SYSCALL_RESTRICTED, arg, QD_TERM)


def make_echo_then_syscall8(payload: object) -> object:
    """
    ((0x0E payload) (λresult. ((0x08 result) QD)))
    
    Echo payload, pass RAW result (with Either wrapper) to syscall 8.
    DO NOT unwrap - we want the shifted indices!
    """
    qd_shifted = shift_term(QD_TERM, 1, 0)
    inner_call = App(App(Var(SYSCALL_RESTRICTED + 1), Var(0)), qd_shifted)
    cont = Lam(inner_call)
    return App(App(Var(SYSCALL_ECHO), payload), cont)


def make_double_echo_then_syscall8(payload: object) -> object:
    """
    ((0x0E payload) (λr1. ((0x0E r1) (λr2. ((0x08 r2) QD)))))
    
    Double-echo for higher shifted indices.
    """
    qd_shifted_2 = shift_term(QD_TERM, 2, 0)
    innermost_call = App(App(Var(SYSCALL_RESTRICTED + 2), Var(0)), qd_shifted_2)
    inner_cont = Lam(innermost_call)
    
    middle_call = App(App(Var(SYSCALL_ECHO + 1), Var(0)), inner_cont)
    outer_cont = Lam(middle_call)
    
    return App(App(Var(SYSCALL_ECHO), payload), outer_cont)


def make_backdoor_then_syscall8() -> object:
    """((0xC9 nil) (λbackdoor_result. ((0x08 backdoor_result) QD)))"""
    qd_shifted = shift_term(QD_TERM, 1, 0)
    inner_call = App(App(Var(SYSCALL_RESTRICTED + 1), Var(0)), qd_shifted)
    cont = Lam(inner_call)
    return App(App(Var(SYSCALL_BACKDOOR), NIL_TERM), cont)


def make_backdoor_extract_head_then_syscall8() -> object:
    """
    ((0xC9 nil) (λpair. ((0x08 (pair (λh.λt.h) nil)) QD)))
    
    Extract head (first component) from backdoor, pass to syscall 8.
    """
    head_sel: object = Lam(Lam(Var(1)))  # λh.λt.h
    
    head_sel_shifted = shift_term(head_sel, 1, 0)
    nil_shifted = shift_term(NIL_TERM, 1, 0)
    
    extract_head = App(App(Var(0), head_sel_shifted), nil_shifted)
    
    qd_shifted = shift_term(QD_TERM, 1, 0)
    inner_call = App(App(Var(SYSCALL_RESTRICTED + 1), extract_head), qd_shifted)
    cont = Lam(inner_call)
    
    return App(App(Var(SYSCALL_BACKDOOR), NIL_TERM), cont)


def make_backdoor_extract_tail_then_syscall8() -> object:
    """
    ((0xC9 nil) (λpair. ((0x08 (pair (λh.λt.t) nil)) QD)))
    
    Extract tail (second component) from backdoor, pass to syscall 8.
    """
    tail_sel: object = Lam(Lam(Var(0)))  # λh.λt.t
    
    tail_sel_shifted = shift_term(tail_sel, 1, 0)
    nil_shifted = shift_term(NIL_TERM, 1, 0)
    
    extract_tail = App(App(Var(0), tail_sel_shifted), nil_shifted)
    
    qd_shifted = shift_term(QD_TERM, 1, 0)
    inner_call = App(App(Var(SYSCALL_RESTRICTED + 1), extract_tail), qd_shifted)
    cont = Lam(inner_call)
    
    return App(App(Var(SYSCALL_BACKDOOR), NIL_TERM), cont)


def make_echo_backdoor_then_syscall8() -> object:
    """((0xC9 nil) (λbd. ((0x0E bd) (λechoed. ((0x08 echoed) QD)))))"""
    qd_shifted_2 = shift_term(QD_TERM, 2, 0)
    innermost = App(App(Var(SYSCALL_RESTRICTED + 2), Var(0)), qd_shifted_2)
    inner_cont = Lam(innermost)
    
    middle = App(App(Var(SYSCALL_ECHO + 1), Var(0)), inner_cont)
    outer_cont = Lam(middle)
    
    return App(App(Var(SYSCALL_BACKDOOR), NIL_TERM), outer_cont)


def encode_bytes_list_term(bs: bytes) -> object:
    nil: object = Lam(Lam(Var(0)))
    
    def cons(h: object, t: object) -> object:
        return Lam(Lam(App(App(Var(1), h), t)))
    
    cur: object = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


def generate_probes() -> list[tuple[str, str, object]]:
    probes: list[tuple[str, str, object]] = []
    
    # Category 1: Baseline
    probes.append((
        "baseline_nil",
        "Syscall 8 with nil argument (baseline)",
        make_syscall8_with_qd(NIL_TERM),
    ))
    
    probes.append((
        "baseline_int0",
        "Syscall 8 with int(0) argument",
        make_syscall8_with_qd(encode_byte_term(0)),
    ))
    
    probes.append((
        "baseline_password",
        "Syscall 8 with 'ilikephp' string",
        make_syscall8_with_qd(encode_bytes_list_term(b"ilikephp")),
    ))
    
    # Category 2: Single-echo illegal-var tokens (V251+2=253, V252+2=254)
    for base_idx in [251, 252]:
        target = base_idx + 2
        probes.append((
            f"echo_v{base_idx}",
            f"Echo V{base_idx} -> Var({target}) inside Either, then syscall 8",
            make_echo_then_syscall8(Var(base_idx)),
        ))
    
    # Category 3: Double-echo to reach Var(255) (V251+4=255)
    for base_idx in [249, 250, 251]:
        target = base_idx + 4
        probes.append((
            f"double_echo_v{base_idx}",
            f"Double-echo V{base_idx} -> Var({target}) deep inside, then syscall 8",
            make_double_echo_then_syscall8(Var(base_idx)),
        ))
    
    # Category 4: 3-leaf payloads - ((Va Vb) Vc)
    three_leaf_combos = [
        (251, 252, 251),
        (251, 251, 252),
        (252, 251, 251),
        (250, 251, 252),
        (251, 252, 250),
        (249, 250, 251),
    ]
    
    for a, b, c in three_leaf_combos:
        payload: object = App(App(Var(a), Var(b)), Var(c))
        probes.append((
            f"3leaf_echo_{a}_{b}_{c}",
            f"Echo ((V{a} V{b}) V{c}), then syscall 8",
            make_echo_then_syscall8(payload),
        ))
        
        probes.append((
            f"3leaf_double_echo_{a}_{b}_{c}",
            f"Double-echo ((V{a} V{b}) V{c}), then syscall 8",
            make_double_echo_then_syscall8(payload),
        ))
    
    # Category 5: Backdoor result as capability
    probes.append((
        "backdoor_direct",
        "Backdoor result passed directly to syscall 8",
        make_backdoor_then_syscall8(),
    ))
    
    probes.append((
        "backdoor_head",
        "Backdoor head (first component) to syscall 8",
        make_backdoor_extract_head_then_syscall8(),
    ))
    
    probes.append((
        "backdoor_tail",
        "Backdoor tail (second component) to syscall 8",
        make_backdoor_extract_tail_then_syscall8(),
    ))
    
    probes.append((
        "backdoor_echoed",
        "Echo backdoor result, then syscall 8",
        make_echo_backdoor_then_syscall8(),
    ))
    
    # Category 6: Direct high-index vars (comparison baseline)
    for idx in [251, 252]:
        probes.append((
            f"direct_v{idx}",
            f"Direct V{idx} to syscall 8 (no echo)",
            make_syscall8_with_qd(Var(idx)),
        ))
    
    # Category 7: Lambda-wrapped payloads (maybe "3 leafs" = 3 lambdas?)
    for depth in [1, 2, 3]:
        inner: object = Var(depth)
        for _ in range(depth):
            inner = Lam(inner)
        probes.append((
            f"lambda_depth_{depth}",
            f"{depth}-deep lambda wrapping Var({depth}), then syscall 8",
            make_syscall8_with_qd(inner),
        ))
    
    # Category 8: Echo backdoor components directly
    probes.append((
        "echo_backdoor_omega",
        "Echo backdoor's omega-like component (λa.λb. b b)",
        make_echo_then_syscall8(Lam(Lam(App(Var(0), Var(0))))),
    ))
    
    probes.append((
        "echo_backdoor_flip",
        "Echo backdoor's flip-like component (λa.λb. a b)",
        make_echo_then_syscall8(Lam(Lam(App(Var(1), Var(0))))),
    ))
    
    return probes


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Probe syscall 0x08 with unforgeable token strategies",
    )
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between probes")
    parser.add_argument("--out", type=Path, default=Path("syscall8_probe_results.json"))
    parser.add_argument("--dry-run", action="store_true", help="Show probes without running")
    parser.add_argument("--filter", type=str, default="", help="Only run probes matching this substring")
    parser.add_argument("--stop-on-success", action="store_true", help="Stop on first interesting result")
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
            
            if args.stop_on_success:
                print("\n*** STOPPING ON INTERESTING RESULT ***")
                break
        
        args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        
        time.sleep(args.delay)
    
    print("\n" + "=" * 70)
    print(f"SUMMARY: {len(interesting_results)} interesting results out of {len(results)} probes")
    
    if interesting_results:
        print("\nInteresting results:")
        for r in interesting_results:
            print(f"  - {r.name}: {r.classification} - {r.detail}")
    
    print(f"\nResults saved to {args.out}")


if __name__ == "__main__":
    main()
