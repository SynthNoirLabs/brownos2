#!/usr/bin/env python3
"""
Testing minimal programs with exactly 3 Var nodes (3 leafs).
The "3 leafs IIRC" hint might mean the ENTIRE solution program has 3 Var nodes.
"""

import socket
import time
import itertools

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE
FF = 0xFF

def query_raw(payload, timeout_s=5.0):
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            out = b""
            while True:
                try:
                    sock.settimeout(2.0)
                    chunk = sock.recv(4096)
                    if not chunk: break
                    out += chunk
                except socket.timeout:
                    break
            return out
    except Exception as e:
        return b""

def Var(i): return bytes([i])
def App(f, x): return f + x + bytes([FD])
def Lam(body): return body + bytes([FE])

def count_vars(term_bytes):
    """Count number of Var nodes (bytes < FD)."""
    return sum(1 for b in term_bytes if b < FD)

print("=" * 60)
print("Testing 3-Var minimal programs")
print("=" * 60)

# All possible 3-var programs with one or two applications:
# ((Va Vb) Vc) - left associative, 2 apps
# (Va (Vb Vc)) - right associative, 2 apps
# These have exactly 3 Vars

# Key indices to try
key_indices = [0, 1, 2, 8, 14, 42, 201]

found_interesting = []

print("\nPattern: ((Va Vb) Vc) + FF")
count = 0
for a, b, c in itertools.product(key_indices, repeat=3):
    # ((Va Vb) Vc) in postfix: a b FD c FD
    prog = bytes([a, b, FD, c, FD, FF])
    resp = query_raw(prog, timeout_s=3)
    
    if resp and len(resp) > 0:
        # Check if NOT the typical "no output" or error
        hex_resp = resp.hex()
        if hex_resp not in ['', 'ff']:
            # Try to decode as text
            try:
                text = resp.decode('latin-1')
                if any(c.isalpha() for c in text):
                    print(f"[!!] ({a},{b},{c}): {hex_resp} -> {text[:40]}")
                    found_interesting.append((a, b, c, "left", resp))
            except:
                if len(resp) > 1:
                    print(f"[?] ({a},{b},{c}): {hex_resp[:60]}")
    
    count += 1
    if count % 50 == 0:
        print(f"  Tested {count} left-associative patterns...")
        time.sleep(0.5)

print("\nPattern: (Va (Vb Vc)) + FF")
count = 0
for a, b, c in itertools.product(key_indices, repeat=3):
    # (Va (Vb Vc)) in postfix: a b c FD FD
    prog = bytes([a, b, c, FD, FD, FF])
    resp = query_raw(prog, timeout_s=3)
    
    if resp and len(resp) > 0:
        hex_resp = resp.hex()
        if hex_resp not in ['', 'ff']:
            try:
                text = resp.decode('latin-1')
                if any(c.isalpha() for c in text):
                    print(f"[!!] ({a},{b},{c}): {hex_resp} -> {text[:40]}")
                    found_interesting.append((a, b, c, "right", resp))
            except:
                if len(resp) > 1:
                    print(f"[?] ({a},{b},{c}): {hex_resp[:60]}")
    
    count += 1
    if count % 50 == 0:
        print(f"  Tested {count} right-associative patterns...")
        time.sleep(0.5)

print("\n" + "=" * 60)
print("Testing with one lambda wrapping: λ.((Va Vb) Vc)")
print("=" * 60)

# Maybe the solution needs a lambda to close over free variables
# λ.((Va Vb) Vc) - this still has 3 Var nodes

for a, b, c in itertools.product([0, 1, 2, 8], repeat=3):
    # λ.((Va Vb) Vc) in postfix: a b FD c FD FE
    prog = bytes([a, b, FD, c, FD, FE, FF])
    resp = query_raw(prog, timeout_s=3)
    
    if resp and len(resp) > 0:
        hex_resp = resp.hex()
        if hex_resp not in ['', 'ff']:
            try:
                text = resp.decode('latin-1')
                if any(c.isalpha() for c in text):
                    print(f"[!!] λ.({a},{b},{c}): {hex_resp} -> {text[:40]}")
                    found_interesting.append((a, b, c, "lambda-left", resp))
            except:
                if len(resp) > 1:
                    print(f"[?] λ.({a},{b},{c}): {hex_resp[:60]}")

print("\n" + "=" * 60)
print("Now testing THE EXACT backdoor pattern")
print("=" * 60)

# The backdoor output is λλ((V1 A) B) where A and B are combinators
# The "answer" might be to somehow use this structure

# What if we send: ((201 arg) write_continuation)
# And the "arg" is special?

# Let's test with the write syscall as continuation
# ((201 V0) V2) - call backdoor, pass result to write syscall

for arg_idx in [0, 1, 2, 8, 14]:
    prog = bytes([201, arg_idx, FD, 2, FD, FF])  # ((201 Varg) V2) in postfix
    resp = query_raw(prog, timeout_s=3)
    if resp:
        print(f"((201 V{arg_idx}) V2): {resp.hex()[:60]}")
        try:
            print(f"  Text: {resp.decode('latin-1')[:40]}")
        except:
            pass

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
if found_interesting:
    print(f"Found {len(found_interesting)} interesting patterns!")
    for item in found_interesting:
        print(f"  {item}")
else:
    print("No interesting patterns found in 3-Var minimal programs")

print("\nDone!")
