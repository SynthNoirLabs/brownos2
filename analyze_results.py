#!/usr/bin/env python3
from solve_brownos_answer import parse_term, decode_either, decode_byte_term, App, Lam, Var

def term_to_str(t):
    if isinstance(t, Var): return f"V{t.i}"
    if isinstance(t, Lam): return f"λ.{term_to_str(t.body)}"
    if isinstance(t, App): return f"({term_to_str(t.f)} {term_to_str(t.x)})"
    return str(t)

def analyze(hex_str):
    try:
        data = bytes.fromhex(hex_str)
        term = parse_term(data)
        print(f"Term: {term_to_str(term)}")
        try:
            tag, val = decode_either(term)
            print(f"Either: {tag}")
            if tag == "Right":
                err = decode_byte_term(val)
                print(f"Error Code: {err}")
            else:
                print(f"Payload: {term_to_str(val)}")
        except:
            print("Not a standard Either")
    except Exception as e:
        print(f"Error parsing: {e}")

print("--- Syscall 8(A)(QD) ---")
analyze("00030200fdfdfefefefefefefefefefdfefeff")

print("\n--- Syscall 14(A)(QD) ---")
analyze("010000fdfefefdfefeff")
