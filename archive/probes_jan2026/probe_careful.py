#!/usr/bin/env python3
"""
Careful probing - using only valid program structures.
Based on working examples from solve_brownos_answer.py
"""

import socket
import time

def query(payload, timeout_s=5.0):
    """Send payload and receive response."""
    try:
        with socket.create_connection(("wc3.wechall.net", 61221), timeout=timeout_s) as sock:
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

# Wire format
def Var(i):  return bytes([i])
def App(f, x): return b'\xfd' + f + x
def Lam(body): return b'\xfe' + body
def End(): return b'\xff'

# QD: λ.(syscall_2 (syscall_4 V0))
# This takes a result and outputs it serialized
QD = Lam(App(App(Var(2), App(App(Var(4), Var(0)), Var(0))), Var(0)))

def call_syscall_with_qd(syscall_num, arg):
    """Properly call syscall with argument and use QD to output result.
    
    Program structure: (QD ((syscall_num arg) continuation))
    Where continuation is V0 (identity/pass-through)
    """
    # Inner: ((syscall_num arg) V0)
    inner = App(App(Var(syscall_num), arg), Var(0))
    # Outer: (QD inner)
    program = App(QD, inner) + End()
    return query(program)

def parse_either(data):
    """Parse Either Left/Right response."""
    if not data or len(data) < 3:
        return ("EMPTY", data)
    # Left = 00 01 00 fd ... (V0 applied to something)
    # Right = 00 03 02 00 fd ... (V3 applied to (V2 V0) and something)
    if data[:3] == bytes([0x00, 0x01, 0x00]):
        return ("Left", data)
    elif data[:3] == bytes([0x00, 0x03, 0x02]):
        return ("Right", data)
    else:
        return ("Unknown", data)

def decode_if_text(data):
    """Try to decode as ASCII text."""
    try:
        return data.decode('ascii', errors='ignore')
    except:
        return None

print("=" * 60)
print("Test 1: Verify protocol works - syscall 1 (error string)")
print("=" * 60)

# syscall 1 with V6 should give "Permission denied"
resp = call_syscall_with_qd(1, Var(6))
typ, data = parse_either(resp)
print(f"syscall 1(V6): {typ} -> {resp.hex()}")
text = decode_if_text(resp)
if text:
    print(f"  Text: {text!r}")

print("\n" + "=" * 60)
print("Test 2: syscall 8 with simple Vars")
print("=" * 60)

for i in [0, 1, 2, 6, 8, 14, 42, 201, 251, 252, 253]:
    resp = call_syscall_with_qd(8, Var(i))
    typ, data = parse_either(resp)
    
    # Check if NOT standard "Right(6)"
    is_right6 = (typ == "Right" and len(data) > 10 and data[-2] == 0x06)
    
    if typ != "Right" or not is_right6:
        print(f"[!!] syscall 8(V{i}): {typ} -> {resp.hex()}")
    else:
        print(f"syscall 8(V{i}): Right(6) - Permission denied")
    time.sleep(0.3)

print("\n" + "=" * 60)
print("Test 3: Using backdoor - get the pair, then test with it")
print("=" * 60)

# First, get the backdoor result and analyze it
resp_bd = call_syscall_with_qd(201, Var(0))
typ, data = parse_either(resp_bd)
print(f"Backdoor (201) with V0: {typ}")
print(f"  Raw: {resp_bd.hex()}")

print("\n" + "=" * 60)
print("Test 4: Testing if syscall 8 checks its continuation")
print("=" * 60)

# What if syscall 8 checks what continuation it gets?
# Normal: ((8 arg) V0) - V0 is identity
# Try: ((8 arg) V1), ((8 arg) V2), etc.

for cont_idx in [0, 1, 2, 3, 201, 14]:
    inner = App(App(Var(8), Var(0)), Var(cont_idx))
    program = App(QD, inner) + End()
    resp = query(program)
    typ, data = parse_either(resp)
    
    if typ != "Right":
        print(f"[!!] ((8 V0) V{cont_idx}): {typ} -> {resp.hex()}")
    else:
        print(f"((8 V0) V{cont_idx}): Right(6)")
    time.sleep(0.3)

print("\n" + "=" * 60)
print("Test 5: Syscall 8 with result of other syscalls")
print("=" * 60)

# Build: ((8 ((other_syscall arg) id)) cont)
# This passes the result of another syscall to syscall 8

other_syscalls = [
    (14, 0, "echo(V0) -> V2"),
    (14, 6, "echo(V6) -> V8"),
    (14, 199, "echo(V199) -> V201"),
    (201, 0, "backdoor -> pair"),
]

for sc, arg, desc in other_syscalls:
    # ((sc Varg) V0) = result of syscall
    sc_result = App(App(Var(sc), Var(arg)), Var(0))
    # Now pass to syscall 8
    inner = App(App(Var(8), sc_result), Var(0))
    program = App(QD, inner) + End()
    resp = query(program)
    typ, data = parse_either(resp)
    
    if typ != "Right":
        print(f"[!!] 8({desc}): {typ} -> {resp.hex()}")
    else:
        print(f"8({desc}): Right(6)")
    time.sleep(0.3)

print("\n" + "=" * 60)
print("Test 6: What about applying syscall 8 partially?")
print("=" * 60)

# (8 arg) without continuation - partial application
# Then apply QD to that
partial = App(Var(8), Var(0))
program = App(QD, partial) + End()
resp = query(program)
print(f"QD(8 V0) partial: {resp.hex()}")
text = decode_if_text(resp)
if text:
    print(f"  Text: {text!r}")

print("\n" + "=" * 60)
print("Test 7: Lambda-wrapped syscall 8 calls")
print("=" * 60)

# λ.((8 V0) V0) - shift everything up by 1
wrapped = Lam(App(App(Var(8), Var(0)), Var(0)))
program = App(QD, wrapped) + End()
resp = query(program)
print(f"QD(λ.((8 V0) V0)): {resp.hex()}")

# λλ.((8 V0) V1) - two lambdas
wrapped2 = Lam(Lam(App(App(Var(8), Var(0)), Var(1))))
program = App(QD, wrapped2) + End()
resp = query(program)
print(f"QD(λλ.((8 V0) V1)): {resp.hex()}")

print("\n" + "=" * 60)
print("Test 8: Interesting - what if we DON'T use QD?")
print("=" * 60)

# What if the solution is a program that directly outputs without QD?
# Try: ((8 arg) (λ.(2 V0))) - where continuation does the output

output_cont = Lam(App(App(Var(2), Var(0)), Var(0)))

for arg_idx in [0, 1, 8, 201]:
    program = App(App(Var(8), Var(arg_idx)), output_cont) + End()
    resp = query(program)
    
    # This should output something if syscall 8 succeeds
    if resp:
        print(f"((8 V{arg_idx}) output_cont): {resp.hex()}")
        text = decode_if_text(resp)
        if text:
            print(f"  Text: {text!r}")
    else:
        print(f"((8 V{arg_idx}) output_cont): EMPTY")
    time.sleep(0.3)

print("\nDone!")
