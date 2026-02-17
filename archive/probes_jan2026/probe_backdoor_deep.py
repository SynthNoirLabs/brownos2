#!/usr/bin/env python3
"""
Deep analysis of the backdoor (syscall 201).

What we know:
- Backdoor returns Left(pair) where pair = λλ((V1 A) B)
- A = λλ(V0 V0) - self-apply second arg
- B = λλ(V1 V0) - apply first to second

What if the "answer" is hidden in how we USE this pair?
"""

import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE
FF = 0xFF

def query(payload, timeout_s=5.0):
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            out = b""
            start = time.time()
            while time.time() - start < timeout_s:
                try:
                    sock.settimeout(1.0)
                    chunk = sock.recv(4096)
                    if not chunk: break
                    out += chunk
                except socket.timeout:
                    continue
            return out
    except:
        return b""

def Var(i): return bytes([i])
def App(f, x): return f + x + bytes([FD])
def Lam(body): return body + bytes([FE])

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

def call_syscall(num, arg):
    """Standard syscall pattern: syscall arg FD QD FD FF"""
    return Var(num) + arg + bytes([FD]) + QD + bytes([FD, FF])

print("=" * 60)
print("1. Analyze backdoor output structure")
print("=" * 60)

resp = query(call_syscall(201, Var(0)))
print(f"Backdoor raw: {resp.hex()}")

# Parse the Left structure
# The output should be: Left(pair) = λλ(V1 pair) in postfix

# Let's just decode what we get
print("Decoding the term...")

# Actually let's use the solve script's parser
from dataclasses import dataclass

@dataclass(frozen=True)
class VarT:
    i: int
    def __repr__(self): return f"V{self.i}"

@dataclass(frozen=True)  
class LamT:
    body: object
    def __repr__(self): return f"λ.{self.body}"

@dataclass(frozen=True)
class AppT:
    f: object
    x: object
    def __repr__(self): return f"({self.f} {self.x})"

def parse_term(data):
    stack = []
    for b in data:
        if b == FF: break
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            stack.append(AppT(f, x))
        elif b == FE:
            body = stack.pop()
            stack.append(LamT(body))
        else:
            stack.append(VarT(b))
    return stack[0] if stack else None

term = parse_term(resp)
print(f"Parsed: {term}")

print("\n" + "=" * 60)
print("2. What if we apply the pair to specific arguments?")
print("=" * 60)

# The pair is λλ((V1 A) B)
# If we apply it to X then Y:
# (pair X Y) = ((X A) B)
# So X gets applied to A, then to B

# What if X is the "key" that, when applied to A and B, produces the answer?

# Let's build: ((backdoor_result X) Y) 
# Where backdoor_result is ((201 V0) V0) - unwrap the Left

# Actually, to "unwrap" the Left, we need to apply it to a continuation
# Left(x) = λl.λr. l x = when applied to 'k', gives (k x)

# So: ((((201 V0) id) id) write_output)
# This would:
# 1. Call backdoor -> Left(pair)
# 2. Apply to id -> (id pair) = pair  (assuming Left's structure)
# Wait, Left = λλ(V1 x), so (Left k) = λ.(k x), then ((Left k) _) = (k x)

# Simpler: call backdoor, pass a continuation that extracts and uses the pair
# ((201 V0) λ.use_V0_which_is_pair)

# Use the pair: apply it to V8 (syscall 8) and see what happens
# (pair V8) = ((V8 A) B) = ?

# Let's test: ((201 V0) λ.(((V0 V8) V14) QD))
# This applies the pair to V8 and V14, then outputs via QD

# Build: ((201 V0) λ.(...))
# The continuation is: λ.(...) where ... uses V0 (the pair)

# (V0 V8) = apply pair to V8 -> λ.((V8 A) B)
# Then apply to V14 -> ((V8 A) B)
# Hmm, that would try to call syscall 8 with A as argument...

for first_arg, second_arg in [(8, 0), (8, 14), (14, 8), (201, 8), (8, 201)]:
    # Continuation: λ.(((V0 Vfirst) Vsecond) QD)
    # In postfix: 00 first FD second FD QD FD FE
    cont = Var(0) + Var(first_arg) + bytes([FD]) + Var(second_arg) + bytes([FD]) + QD + bytes([FD, FE])
    
    # Full program: ((201 V0) cont)
    prog = Var(201) + Var(0) + bytes([FD]) + cont + bytes([FD, FF])
    
    resp = query(prog)
    if resp:
        print(f"((pair V{first_arg}) V{second_arg}): {resp.hex()[:60]}")
        try:
            text = resp.decode('latin-1')
            if any(c.isalpha() for c in text):
                print(f"  Text: {text[:40]}")
        except:
            pass
    else:
        print(f"((pair V{first_arg}) V{second_arg}): EMPTY")
    time.sleep(0.3)

print("\n" + "=" * 60)
print("3. Extract A and B from the pair and test them separately")
print("=" * 60)

# Pair = λλ((V1 A) B)
# To extract A: (pair (λλV1) anything) = (((λλV1) A) B) = ((λV1) B) = V1... wait
# This is getting complex

# Actually, (pair sel1 sel2) = ((sel1 A) B)
# If sel1 = K = λλV1, then ((K A) B) = (λV1 B) = A
# If sel1 = K' = λλV0, then ((K' A) B) = (λV0 B) = B

# So to get A: ((pair K) anything)
# To get B: ((pair K') anything)

K = Lam(Lam(Var(1)))   # λλV1 - select first
KP = Lam(Lam(Var(0)))  # λλV0 - select second

# Extract A and pass to syscall 8
# Continuation: λ.(((V0 K) dummy) -> A, then ((8 A) QD))
# This is getting complex, let me build it step by step

# We want: ((201 V0) λ.((8 ((V0 K) dummy)) QD))
# V0 is the pair from backdoor
# ((V0 K) dummy) extracts A
# Then ((8 A) QD) calls syscall 8 with A

# Build the continuation body:
# ((V0 K) dummy) in postfix: 00 K FD dummy FD
extract_A = Var(0) + K + bytes([FD]) + Var(0) + bytes([FD])  # ((V0 K) V0)
# ((8 extract_A) QD) in postfix: 08 extract_A FD QD FD
syscall8_A = Var(8) + extract_A + bytes([FD]) + QD + bytes([FD])
# λ.(...) 
cont_A = syscall8_A + bytes([FE])
# ((201 V0) cont)
prog_A = Var(201) + Var(0) + bytes([FD]) + cont_A + bytes([FD, FF])

print(f"Program to pass A to syscall 8:")
print(f"  Payload: {prog_A.hex()}")
resp = query(prog_A)
print(f"  Response: {resp.hex() if resp else 'EMPTY'}")

# Similarly for B
extract_B = Var(0) + KP + bytes([FD]) + Var(0) + bytes([FD])  # ((V0 K') V0)
syscall8_B = Var(8) + extract_B + bytes([FD]) + QD + bytes([FD])
cont_B = syscall8_B + bytes([FE])
prog_B = Var(201) + Var(0) + bytes([FD]) + cont_B + bytes([FD, FF])

print(f"\nProgram to pass B to syscall 8:")
print(f"  Payload: {prog_B.hex()}")
resp = query(prog_B)
print(f"  Response: {resp.hex() if resp else 'EMPTY'}")

print("\n" + "=" * 60)
print("4. What about the pair ITSELF as a syscall?")
print("=" * 60)

# What if pair(x, cont) behaves like a syscall?
# ((pair x) cont) = ((x A) B) cont... no that doesn't work

# Actually wait, the pair is λλ((V1 A) B)
# So (pair x cont) = ((pair x) cont) = ((x A) B)
# Hmm, it applies x to A and B

# What if x = 8 (the syscall)?
# Then ((8 A) B) = syscall 8 with argument A and continuation B
# But B = λλ(V1 V0), which doesn't output anything

# Let's try with x = 8 and see what happens when B is the continuation
# Actually the pair structure makes B be the "argument" position...

# Let me re-read: pair = λλ((V1 A) B)
# (pair x) = λ((x A) B) with x substituted for V1
# Wait, De Bruijn indices shift when we go under lambdas

# Actually in λλ((V1 A) B):
# V1 refers to the FIRST lambda's parameter (0-indexed from innermost)
# So (pair x) = λ((x A') B') where A' and B' are shifted

# This is complex. Let me just test various combinations

for x in [0, 2, 8, 14, 201]:
    # Build: ((pair Vx) cont) using backdoor
    # Continuation after backdoor: λ.((V0 Vx) QD)
    cont = Var(0) + Var(x) + bytes([FD]) + QD + bytes([FD, FE])
    prog = Var(201) + Var(0) + bytes([FD]) + cont + bytes([FD, FF])
    
    resp = query(prog)
    if resp:
        print(f"(pair V{x}): {resp.hex()[:60]}")
    else:
        print(f"(pair V{x}): EMPTY")
    time.sleep(0.2)

print("\nDone!")
