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
        # Term structure might be Either Left(...) Right(...)
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

results = {
    1: "010000fdfefefd0100fdfefefdfefe01fdff",
    2: "010000fdfefefd0100fdfefefdfefe02fdff",
    4: "010000fdfefefd0100fdfefefdfefe04fdff",
    5: "010000fdfefefd0100fdfefefdfefe05fdff",
    6: "010000fdfefefd0100fdfefefdfefe06fdff",
    7: "010000fdfefefd0100fdfefefdfefe07fdff",
    8: "010000fdfefefd0100fdfefefdfefe08fdff",
    14: "010000fdfefefd0100fdfefefdfefe0efdff",
    42: "010000fdfefefd0100fdfefefdfefe2afdff",
    201: "010000fdfefefd0100fdfefefdfefec9fdff"
}

for k, v in results.items():
    print(f"{k:<5}: {analyze(v)}")
