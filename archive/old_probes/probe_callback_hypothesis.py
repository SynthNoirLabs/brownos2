#!/usr/bin/env python3
"""
CALLBACK HYPOTHESIS PROBE

Oracle insight: Syscall 8 might not be checking its argument as DATA.
Instead, it might be APPLYING the argument as a callback to hidden capabilities.

If syscall8(f) = check(f(hidden_cap)), then:
- syscall8(I) where I=λx.x should return the hidden capability
- syscall8(K_nil) where K_nil=λx.nil should return nil
- syscall8(π1) and syscall8(π2) would extract components if there are 2 hidden args

This is the key test to determine syscall 8's semantics.
"""
from __future__ import annotations

import socket
import sys
import time

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    decode_byte_term,
    decode_bytes_list,
    decode_either,
    encode_term,
    parse_term,
    call_syscall,
)
from solve_brownos_answer import QD as QD_BYTES

FF = 0xFF
QD_TERM = parse_term(QD_BYTES)


def shift(term, delta, cutoff=0):
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    return term


def short_show(term, depth=12):
    if depth <= 0:
        return "..."
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"(λ.{short_show(term.body, depth-1)})"
    if isinstance(term, App):
        return f"({short_show(term.f, depth-1)} {short_show(term.x, depth-1)})"
    return repr(term)


def unwrap_either(term):
    if isinstance(term, Lam) and isinstance(term.body, Lam):
        body = term.body.body
        if isinstance(body, App) and isinstance(body.f, Var):
            if body.f.i == 1:
                return ("Left", body.x)
            elif body.f.i == 0:
                return ("Right", body.x)
    return (None, term)


def main():
    print("=" * 70)
    print("CALLBACK HYPOTHESIS PROBE")
    print("=" * 70)
    print()
    print("Testing if syscall 8 APPLIES its argument as a callback...")
    print()
    
    I = Lam(Var(0))
    nil = Lam(Lam(Var(0)))
    K_nil = Lam(nil)
    pi1 = Lam(Lam(Var(1)))
    pi2 = Lam(Lam(Var(0)))
    K_I = Lam(I)
    
    omega = Lam(App(Var(0), Var(0)))
    
    cases = [
        ("I (λ.0) - identity, returns what it receives", I),
        ("K_nil (λ.(λλ.0)) - constant nil", K_nil),
        ("pi1 (λλ.1) - first projection", pi1),
        ("pi2 (λλ.0) - second projection (= nil)", pi2),
        ("K_I (λ.(λ.0)) - constant identity", K_I),
        ("nil (λλ.0) - used as callback?", nil),
    ]
    
    results = []
    
    for name, cb in cases:
        print(f"\n{'='*60}")
        print(f"TEST: syscall8({name})")
        print(f"{'='*60}")
        
        try:
            out = call_syscall(0x08, cb)
            tag, payload = unwrap_either(out)
            
            print(f"  Response tag: {tag}")
            
            if tag == "Right":
                try:
                    code = decode_byte_term(payload)
                    print(f"  Error code: {code}")
                    results.append((name, f"Right({code})"))
                except:
                    print(f"  Payload shape: {short_show(payload)}")
                    results.append((name, f"Right(non-int)"))
            elif tag == "Left":
                print(f"  SUCCESS! Left payload shape: {short_show(payload)}")
                try:
                    bs = decode_bytes_list(payload)
                    print(f"  As bytes: {bs!r}")
                    results.append((name, f"Left(bytes:{bs!r})"))
                except:
                    print(f"  (Not a bytes list)")
                    results.append((name, f"Left({short_show(payload)})"))
            else:
                print(f"  Raw term: {short_show(out)}")
                results.append((name, f"raw:{short_show(out)}"))
                
        except Exception as e:
            print(f"  ERROR: {e}")
            results.append((name, f"error:{e}"))
        
        time.sleep(0.2)
    
    print("\n" + "=" * 70)
    print("ANALYSIS")
    print("=" * 70)
    
    unique_results = set(r[1] for r in results)
    
    if len(unique_results) == 1:
        print("\nAll callbacks returned the SAME result.")
        print("This suggests syscall 8 is NOT applying the callback.")
        print("It's likely doing a data/structure check instead.")
    else:
        print("\nCallbacks returned DIFFERENT results!")
        print("This suggests syscall 8 IS applying the argument!")
        print("\nResults summary:")
        for name, result in results:
            print(f"  {name[:30]:30} -> {result}")
    
    print("\n" + "=" * 70)
    print("ADDITIONAL TESTS: Multi-arg callbacks")
    print("=" * 70)
    
    cb_3arg = Lam(Lam(Lam(Var(2))))
    cb_4arg = Lam(Lam(Lam(Lam(Var(3)))))
    
    for name, cb in [("3-arg (λλλ.2)", cb_3arg), ("4-arg (λλλλ.3)", cb_4arg)]:
        print(f"\nTEST: syscall8({name})")
        try:
            out = call_syscall(0x08, cb)
            tag, payload = unwrap_either(out)
            if tag == "Right":
                try:
                    code = decode_byte_term(payload)
                    print(f"  Result: Right({code})")
                except:
                    print(f"  Result: Right(non-int)")
            elif tag == "Left":
                print(f"  Result: Left({short_show(payload)})")
            else:
                print(f"  Result: {short_show(out)}")
        except Exception as e:
            print(f"  ERROR: {e}")
        time.sleep(0.2)
    
    print("\n" + "=" * 70)
    print("TEST: What if we need to OUTPUT the hidden capability?")
    print("=" * 70)
    
    write_syscall = Var(2)
    quote_syscall = Var(4)
    
    cb_reveal = Lam(App(App(write_syscall, App(quote_syscall, Var(0))), Var(0)))
    
    print("\nBuilding: λx. ((write (quote x)) x)")
    print("This would output whatever syscall 8 passes to our callback")
    
    try:
        out = call_syscall(0x08, cb_reveal)
        tag, payload = unwrap_either(out)
        print(f"  Result: {tag}({short_show(payload) if tag else short_show(out)})")
    except Exception as e:
        print(f"  ERROR: {e}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
