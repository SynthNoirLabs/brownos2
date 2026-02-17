#!/usr/bin/env python3
"""
Correctly structured probing - syscall(arg, QD) format.
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
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk: break
                    out += chunk
                except socket.timeout: break
            return out
    except Exception as e:
        return f"ERROR: {e}".encode()

# Postfix encoding
def Var(i): return bytes([i])
def App(f, x): return f + x + bytes([FD])
def Lam(body): return body + bytes([FE])

# QD continuation
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

def call_syscall(syscall_num, arg_bytes):
    """
    Build: ((syscall_num arg) QD) + END
    In postfix: syscall_num arg FD QD FD FF
    """
    payload = Var(syscall_num) + arg_bytes + bytes([FD]) + QD + bytes([FD, FF])
    return query(payload)

def parse_either_term(data):
    """Parse the Either response."""
    # Text error
    try:
        text = data.decode('ascii')
        return ("TEXT", text, data)
    except:
        pass
    
    if not data or len(data) < 5:
        return ("EMPTY", "", data)
    
    # Parse the structure:
    # Left(x)  = λλ(V1 x) -> in postfix: 01 x FD FE FE
    # Right(x) = λλ(V0 x) -> in postfix: 00 x FD FE FE
    
    # Actually we receive the term in postfix, so let's check pattern
    if data[-1] == FF:
        data = data[:-1]  # strip FF
    
    if len(data) >= 2 and data[-2:] == bytes([FE, FE]):
        # Two lambdas at end - this is Either
        # The byte before those tells us Left (01) or Right (00) applied
        # But we need to find where the (V0/V1 x FD) is
        pass
    
    # Simpler: just check first few bytes pattern
    # For Left: starts with 01 ... 
    # For Right: starts with 00 03 (V0 applied to V3 for error index)
    
    if data.startswith(bytes([0x01])):
        return ("Left", "", data)
    elif data.startswith(bytes([0x00, 0x03])):
        return ("Right", "V3 (permission denied)", data)
    elif data.startswith(bytes([0x00])):
        return ("Right?", "", data)
    
    return ("Unknown", "", data)

print("=" * 60)
print("Test 1: Verify with syscall 1 (error lookup)")
print("=" * 60)

# syscall 1(V6) should return "Permission denied" as bytes
resp = call_syscall(1, Var(6))
print(f"syscall 1(V6): {resp.hex()}")
typ, msg, _ = parse_either_term(resp)
print(f"  Type: {typ}")

print("\n" + "=" * 60)
print("Test 2: Backdoor (201)")
print("=" * 60)

resp = call_syscall(201, Var(0))
print(f"syscall 201(V0): {resp.hex()}")
typ, msg, _ = parse_either_term(resp)
print(f"  Type: {typ}")

print("\n" + "=" * 60)
print("Test 3: syscall 8 with simple Vars")
print("=" * 60)

for i in [0, 1, 2, 6, 8, 14, 42, 201, 251, 252]:
    resp = call_syscall(8, Var(i))
    typ, msg, _ = parse_either_term(resp)
    
    if typ == "Left":
        print(f"[SUCCESS!] syscall 8(V{i}): Left!")
        print(f"  Raw: {resp.hex()}")
    elif typ == "Right":
        print(f"syscall 8(V{i}): Right (permission denied)")
    else:
        print(f"syscall 8(V{i}): {typ} -> {resp.hex()[:60]}...")
    time.sleep(0.3)

print("\n" + "=" * 60)
print("Test 4: syscall 8 with lambda-wrapped values")
print("=" * 60)

# λ.V0 (identity)
identity = Lam(Var(0))
resp = call_syscall(8, identity)
typ, msg, _ = parse_either_term(resp)
print(f"syscall 8(λ.V0): {typ} -> {resp.hex()[:60]}")

# λλ.V0 (K combinator that returns second)
k2 = Lam(Lam(Var(0)))
resp = call_syscall(8, k2)
typ, msg, _ = parse_either_term(resp)
print(f"syscall 8(λλ.V0): {typ} -> {resp.hex()[:60]}")

# λλ.V1 (K combinator that returns first)
k1 = Lam(Lam(Var(1)))
resp = call_syscall(8, k1)
typ, msg, _ = parse_either_term(resp)
print(f"syscall 8(λλ.V1): {typ} -> {resp.hex()[:60]}")

print("\n" + "=" * 60)
print("Test 5: syscall 8 with result of other syscalls")
print("=" * 60)

# We can't directly chain syscalls with this encoding...
# But we can build complex arguments

# A combinator: λλ(V0 V0) = 00 00 FD FE FE
A = bytes([0x00, 0x00, FD, FE, FE])
# B combinator: λλ(V1 V0) = 01 00 FD FE FE  
B = bytes([0x01, 0x00, FD, FE, FE])

resp = call_syscall(8, A)
typ, msg, _ = parse_either_term(resp)
print(f"syscall 8(A=λλ(V0 V0)): {typ}")

resp = call_syscall(8, B)
typ, msg, _ = parse_either_term(resp)
print(f"syscall 8(B=λλ(V1 V0)): {typ}")

# Pair: λλ((V1 A) B) 
# In postfix: 01 A FD B FD FE FE
pair = bytes([0x01]) + A + bytes([FD]) + B + bytes([FD, FE, FE])
resp = call_syscall(8, pair)
typ, msg, _ = parse_either_term(resp)
print(f"syscall 8(pair): {typ}")

print("\n" + "=" * 60)  
print("Test 6: More structured arguments")
print("=" * 60)

# Try some specific structures that might match "3 leafs"

# ((V8 V14) V201) - 3 special syscall indices
three_leaf1 = App(App(Var(8), Var(14)), Var(201))
resp = call_syscall(8, three_leaf1)
typ, _, _ = parse_either_term(resp)
print(f"syscall 8(((V8 V14) V201)): {typ}")

# (V8 (V14 V201))
three_leaf2 = App(Var(8), App(Var(14), Var(201)))
resp = call_syscall(8, three_leaf2)
typ, _, _ = parse_either_term(resp)
print(f"syscall 8((V8 (V14 V201))): {typ}")

# ((V201 V8) V14)
three_leaf3 = App(App(Var(201), Var(8)), Var(14))
resp = call_syscall(8, three_leaf3)
typ, _, _ = parse_either_term(resp)
print(f"syscall 8(((V201 V8) V14)): {typ}")

print("\n" + "=" * 60)
print("Test 7: Chained syscalls as argument")
print("=" * 60)

# What if we need to call another syscall INSIDE the argument?
# Like: 8(14(N)) meaning "call echo first, then pass result to 8"
# But in lambda calculus, we'd need to structure this as a term...

# Actually, let's try: 8(λ.((14 V0) V0))
# This wraps the echo call in a lambda
echo_wrapped = Lam(App(App(Var(14), Var(0)), Var(0)))
resp = call_syscall(8, echo_wrapped)
typ, _, _ = parse_either_term(resp)
print(f"syscall 8(λ.((14 V0) V0)): {typ}")

# 8(λ.((201 V0) V0)) - backdoor wrapped in lambda
bd_wrapped = Lam(App(App(Var(201), Var(0)), Var(0)))
resp = call_syscall(8, bd_wrapped)
typ, _, _ = parse_either_term(resp)
print(f"syscall 8(λ.((201 V0) V0)): {typ}")

print("\nDone!")
