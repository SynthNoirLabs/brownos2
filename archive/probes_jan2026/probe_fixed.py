#!/usr/bin/env python3
"""
Fixed probing - using POSTFIX encoding (like the actual BrownOS VM).
"""

import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD  # Application marker
FE = 0xFE  # Lambda marker  
FF = 0xFF  # End marker

def query(payload, timeout_s=5.0):
    """Send payload and receive response."""
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

# POSTFIX encoding: build bottom-up on stack
def Var(i):
    """Variable with De Bruijn index i."""
    return bytes([i])

def App(f, x):
    """Application (f x) in postfix = f x FD"""
    return f + x + bytes([FD])

def Lam(body):
    """Lambda in postfix = body FE"""
    return body + bytes([FE])

def End():
    return bytes([FF])

# Quick Debug continuation from challenge
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

def make_program(inner):
    """Wrap inner with QD and end marker: (QD inner) + END"""
    return App(QD, inner) + End()

def parse_either(data):
    """Parse Either Left/Right response from hex."""
    if not data or len(data) < 3:
        return ("EMPTY", data)
    
    # Check for text error
    try:
        text = data.decode('ascii', errors='strict')
        return ("TEXT", text)
    except:
        pass
    
    # Left pattern: starts with something that parses to (V0 ...)
    # Right pattern: starts with something that parses to (V3 ...)
    if data[0] == 0x00 and len(data) > 1:
        if data[1] == 0x01:  # V0 V1 FD pattern
            return ("Left", data)
        elif data[1] == 0x03:  # V0 V3 ... pattern  
            return ("Right", data)
    
    return ("Unknown", data)

print("=" * 60)
print("Test 1: Verify encoding - simple syscall 3 (filesystem)")
print("=" * 60)

# ((3 V0) V0) - filesystem syscall with V0
inner = App(App(Var(3), Var(0)), Var(0))
program = make_program(inner)
print(f"Program bytes: {program.hex()}")
resp = query(program)
print(f"Response: {resp.hex()}")
typ, _ = parse_either(resp)
print(f"Type: {typ}")

print("\n" + "=" * 60)
print("Test 2: Backdoor syscall (201)")
print("=" * 60)

inner = App(App(Var(201), Var(0)), Var(0))
program = make_program(inner)
print(f"Program bytes: {program.hex()}")
resp = query(program)
print(f"Response: {resp.hex()}")
typ, _ = parse_either(resp)
print(f"Type: {typ}")

print("\n" + "=" * 60)
print("Test 3: syscall 8 with various arguments")
print("=" * 60)

test_indices = [0, 1, 2, 6, 8, 14, 42, 201, 251, 252]

for i in test_indices:
    inner = App(App(Var(8), Var(i)), Var(0))
    program = make_program(inner)
    resp = query(program)
    typ, data = parse_either(resp)
    
    if typ == "Left":
        print(f"[SUCCESS!] syscall 8(V{i}): Left!")
        print(f"  Response: {resp.hex()}")
    elif typ == "Right":
        # Check if it's Right(6) = permission denied
        print(f"syscall 8(V{i}): Right (Permission denied)")
    else:
        print(f"syscall 8(V{i}): {typ} -> {resp[:50].hex()}...")
    time.sleep(0.3)

print("\n" + "=" * 60)
print("Test 4: syscall 8 with result of echo syscall")
print("=" * 60)

# echo(N) returns Left(V(N+2))
# Build: ((8 ((14 VN) V0)) V0)
# This should pass V(N+2) to syscall 8

for n in [0, 6, 12, 199]:  # Creates V2, V8, V14, V201
    echo_result = App(App(Var(14), Var(n)), Var(0))  # ((14 VN) V0)
    inner = App(App(Var(8), echo_result), Var(0))
    program = make_program(inner)
    resp = query(program)
    typ, _ = parse_either(resp)
    
    expected_var = n + 2
    if typ == "Left":
        print(f"[SUCCESS!] 8(echo({n})->V{expected_var}): Left!")
        print(f"  Response: {resp.hex()}")
    elif typ == "Right":
        print(f"8(echo({n})->V{expected_var}): Right (Permission denied)")
    else:
        print(f"8(echo({n})->V{expected_var}): {typ}")
    time.sleep(0.3)

print("\n" + "=" * 60)
print("Test 5: syscall 8 with backdoor result")
print("=" * 60)

# Backdoor returns Left(pair) where pair = λλ((V1 A) B)
# Let's pass the backdoor result to syscall 8

backdoor_result = App(App(Var(201), Var(0)), Var(0))  # ((201 V0) V0)
inner = App(App(Var(8), backdoor_result), Var(0))
program = make_program(inner)
resp = query(program)
typ, _ = parse_either(resp)
print(f"8(backdoor_result): {typ}")
print(f"  Response: {resp.hex()}")

print("\n" + "=" * 60)
print("Test 6: What if syscall 8's continuation matters?")
print("=" * 60)

# Instead of V0 as continuation, try other things
continuations = [
    ("V0", Var(0)),
    ("V1", Var(1)),
    ("V2 (write)", Var(2)),
    ("V8", Var(8)),
    ("V201 (backdoor)", Var(201)),
]

for label, cont in continuations:
    inner = App(App(Var(8), Var(0)), cont)
    program = make_program(inner)
    resp = query(program)
    typ, _ = parse_either(resp)
    
    if typ == "Left":
        print(f"[SUCCESS!] ((8 V0) {label}): Left!")
        print(f"  Response: {resp.hex()}")
    else:
        print(f"((8 V0) {label}): {typ}")
    time.sleep(0.3)

print("\n" + "=" * 60)
print("Test 7: 3-leaf patterns with special indices")
print("=" * 60)

# "3 leafs IIRC" - try patterns with exactly 3 Var nodes
# ((Va Vb) Vc) or (Va (Vb Vc))

special = [8, 14, 201]

for a in special:
    for b in special:
        for c in special:
            # Left associative: ((Va Vb) Vc)
            prog1 = App(App(Var(a), Var(b)), Var(c))
            # Right associative: (Va (Vb Vc))
            prog2 = App(Var(a), App(Var(b), Var(c)))
            
            for label, prog in [("left", prog1), ("right", prog2)]:
                full_prog = make_program(prog)
                resp = query(full_prog)
                typ, _ = parse_either(resp)
                
                if typ == "Left":
                    print(f"[SUCCESS!] (V{a}, V{b}, V{c})-{label}: Left!")
                    print(f"  Response: {resp.hex()}")
                elif typ != "Right":
                    print(f"(V{a}, V{b}, V{c})-{label}: {typ}")
            time.sleep(0.2)

print("\nDone!")
