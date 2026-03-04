#!/usr/bin/env python3
from solve_brownos_answer import encode_term, Lam, App, Var

# A = λa.λb. b b
A = Lam(Lam(App(Var(0), Var(0))))
# B = λa.λb. a b
B = Lam(Lam(App(Var(1), Var(0))))
# pair(A,B) = λs. s A B
pair = Lam(App(App(Var(0), A), B))

print(f"A: {encode_term(A).hex()}")
print(f"B: {encode_term(B).hex()}")
print(f"pair(A,B): {encode_term(pair).hex()}")

# Try pair(V1)
pair_v1 = App(pair, Var(1))
print(f"pair(V1): {encode_term(pair_v1).hex()}")
