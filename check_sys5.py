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
        try:
            tag, val = decode_either(term)
            if tag == "Right":
                err = decode_byte_term(val)
                return f"Right({err})"
            else:
                return f"Left({term_to_str(val)})"
        except:
            return f"Term({term_to_str(term)})"
    except Exception as e:
        return f"Error: {e}"

print(f"sys5(A)(QD): {analyze('000200fdfefefefefefefefefefdfefeff')}")
