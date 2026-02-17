#!/usr/bin/env python3
"""
Final probe attempts: backdoor pair with unusual selectors, recursive backdoor.
"""
from __future__ import annotations

import json
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from solve_brownos_answer import (
    App, Lam, Var, FF, QD,
    decode_byte_term, decode_bytes_list, decode_either,
    encode_byte_term, encode_term, parse_term,
)


HOST = "wc3.wechall.net"
PORT = 61221

NIL_TERM: object = Lam(Lam(Var(0)))
QD_TERM: object = parse_term(QD)

SYSCALL_RESTRICTED = 0x08
SYSCALL_ECHO = 0x0E
SYSCALL_BACKDOOR = 0xC9


def shift_term(term: object, delta: int, cutoff: int = 0) -> object:
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_term(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_term(term.f, delta, cutoff), shift_term(term.x, delta, cutoff))
    raise TypeError(f"Unsupported: {type(term)}")


def query_raw(payload: bytes, timeout_s: float = 3.0) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
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


def classify_response(resp: bytes) -> tuple[str, str, bool]:
    if not resp:
        return "silent", "No response", False
    if resp.startswith(b"Invalid term!"):
        return "invalid", "Invalid term!", False
    if resp.startswith(b"Encoding failed!"):
        return "encoding_failed", "Encoding failed!", True
    if FF not in resp:
        return "no_ff", resp[:100].decode("utf-8", "replace"), True
    try:
        term = parse_term(resp)
        tag, payload = decode_either(term)
        if tag == "Right":
            code = decode_byte_term(payload)
            return "either_right", f"Right({code})", code != 6
        bs = decode_bytes_list(payload)
        return "either_left", f"Left({len(bs)}b:{bs[:80].decode('utf-8','replace')!r})", True
    except Exception as e:
        return "other", str(e)[:100], True


def run_probe(name: str, desc: str, term: object) -> dict:
    payload = encode_term(term) + bytes([FF])
    try:
        resp = query_raw(payload)
    except Exception as e:
        return {"name": name, "desc": desc, "result": f"error: {e}", "interesting": False}
    
    cls, detail, interesting = classify_response(resp)
    status = "INTERESTING!" if interesting else "normal"
    print(f"  {name}: {cls} - {detail} [{status}]")
    if interesting:
        print(f"    Response: {resp[:80].hex()}")
    return {"name": name, "desc": desc, "result": f"{cls}: {detail}", "interesting": interesting, "hex": resp.hex()}


def main():
    results = []
    
    print("=" * 70)
    print("Strategy 1: Backdoor pair with syscall 8 as selector")
    print("=" * 70)
    
    # (backdoor_pair syscall8) - use syscall 8 reference as the selector
    # pair = λf. f A B, so (pair 8) = 8 A B
    def backdoor_with_syscall8_selector():
        qd_shifted = shift_term(QD_TERM, 1, 0)
        inner = App(App(Var(0), Var(SYSCALL_RESTRICTED + 1)), qd_shifted)
        return App(App(Var(SYSCALL_BACKDOOR), NIL_TERM), Lam(inner))
    
    results.append(run_probe(
        "backdoor_syscall8_selector",
        "Get backdoor pair, apply syscall 8 as selector: (pair 8)",
        backdoor_with_syscall8_selector(),
    ))
    
    print("\n" + "=" * 70)
    print("Strategy 2: Recursive backdoor (backdoor applied to backdoor result)")
    print("=" * 70)
    
    # Call backdoor, then call backdoor again with the result
    def backdoor_of_backdoor():
        qd_shifted_2 = shift_term(QD_TERM, 2, 0)
        innermost = App(App(Var(0), Var(SYSCALL_RESTRICTED + 2)), qd_shifted_2)
        inner_cont = Lam(innermost)
        
        middle = App(App(Var(SYSCALL_BACKDOOR + 1), Var(0)), inner_cont)
        outer_cont = Lam(middle)
        
        return App(App(Var(SYSCALL_BACKDOOR), NIL_TERM), outer_cont)
    
    results.append(run_probe(
        "backdoor_of_backdoor_then_8",
        "Backdoor -> backdoor(result) -> syscall 8",
        backdoor_of_backdoor(),
    ))
    
    print("\n" + "=" * 70)
    print("Strategy 3: Apply backdoor head (A) to syscall 8 directly")
    print("=" * 70)
    
    # Get A from backdoor, then (A syscall8)
    def backdoor_head_apply_to_8():
        head_sel = Lam(Lam(Var(1)))
        qd_shifted_2 = shift_term(QD_TERM, 2, 0)
        
        head_sel_s1 = shift_term(head_sel, 1, 0)
        nil_s1 = shift_term(NIL_TERM, 1, 0)
        extract_A = App(App(Var(0), head_sel_s1), nil_s1)
        
        inner = App(App(App(Var(0), Var(SYSCALL_RESTRICTED + 2)), NIL_TERM), qd_shifted_2)
        inner_cont = Lam(inner)
        
        middle = App(extract_A, inner_cont)
        outer_cont = Lam(middle)
        
        return App(App(Var(SYSCALL_BACKDOOR), NIL_TERM), outer_cont)
    
    results.append(run_probe(
        "backdoor_A_applied_to_8",
        "Backdoor -> get A -> (A syscall8 nil) QD",
        backdoor_head_apply_to_8(),
    ))
    
    print("\n" + "=" * 70)
    print("Strategy 4: Small leaf counts with backdoor")
    print("=" * 70)
    
    # 1-leaf: just the backdoor result itself
    # 2-leaf: (backdoor_result backdoor_result)
    # 3-leaf variations
    
    def backdoor_applied_to_self():
        qd_shifted = shift_term(QD_TERM, 1, 0)
        inner = App(App(App(Var(0), Var(0)), NIL_TERM), qd_shifted)
        return App(App(Var(SYSCALL_BACKDOOR), NIL_TERM), Lam(inner))
    
    results.append(run_probe(
        "backdoor_applied_to_self",
        "Backdoor -> (result result nil) QD - 2 leaves from result",
        backdoor_applied_to_self(),
    ))
    
    print("\n" + "=" * 70)
    print("Strategy 5: Maybe the answer is from a file we can't read normally?")
    print("=" * 70)
    
    # Try reading file IDs that might be protected
    SYSCALL_READFILE = 0x07
    for file_id in [100, 128, 200, 255, 257, 300]:
        term = App(App(Var(SYSCALL_READFILE), encode_byte_term(file_id)), QD_TERM)
        results.append(run_probe(
            f"readfile_{file_id}",
            f"Try to read file ID {file_id}",
            term,
        ))
    
    print("\n" + "=" * 70)
    print("Strategy 6: What if syscall 8 needs a PAIR argument matching backdoor format?")
    print("=" * 70)
    
    # Construct our own pair like the backdoor returns
    # pair = λf. f A B
    OMEGA_A = Lam(Lam(App(Var(0), Var(0))))
    FLIP_B = Lam(Lam(App(Var(1), Var(0))))
    OUR_PAIR = Lam(App(App(Var(0), OMEGA_A), FLIP_B))
    
    results.append(run_probe(
        "syscall8_with_constructed_pair",
        "Syscall 8 with manually constructed (A,B) pair",
        App(App(Var(SYSCALL_RESTRICTED), OUR_PAIR), QD_TERM),
    ))
    
    # Or echo the constructed pair first
    def echo_our_pair_then_8():
        qd_shifted = shift_term(QD_TERM, 1, 0)
        inner = App(App(Var(SYSCALL_RESTRICTED + 1), Var(0)), qd_shifted)
        return App(App(Var(SYSCALL_ECHO), OUR_PAIR), Lam(inner))
    
    results.append(run_probe(
        "echo_constructed_pair_then_8",
        "Echo constructed (A,B) pair, then syscall 8",
        echo_our_pair_then_8(),
    ))
    
    print("\n" + "=" * 70)
    print("Strategy 7: Try some unusual syscall numbers")
    print("=" * 70)
    
    for syscall in [0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F, 0x10, 0xFF]:
        term = App(App(Var(syscall), NIL_TERM), QD_TERM)
        results.append(run_probe(
            f"syscall_{syscall:02x}_nil",
            f"Syscall 0x{syscall:02X} with nil",
            term,
        ))
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    
    interesting = [r for r in results if r.get("interesting")]
    print(f"Found {len(interesting)} interesting results out of {len(results)}")
    for r in interesting:
        print(f"  {r['name']}: {r['result']}")
    
    Path("syscall8_key_results.json").write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
