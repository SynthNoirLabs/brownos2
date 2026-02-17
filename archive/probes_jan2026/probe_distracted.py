#!/usr/bin/env python3
"""
Hypothesis: "too busy casting its dark magic"

Syscall 8 might evaluate its argument. If we give it something that:
1. Takes a long time to evaluate (Omega, Y combinator, etc.)
2. Or never terminates

Then while syscall 8 is "distracted", we can run ANOTHER syscall
in the same program that bypasses the check.

Key insight: In a CPS program structure, multiple syscalls can be chained.
If syscall 8 is stuck evaluating, maybe another part of the program runs.
"""

import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE  
FF = 0xFF

def query(payload, timeout_s=10.0):
    """Extended timeout to see if something takes longer."""
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            out = b""
            start = time.time()
            while time.time() - start < timeout_s:
                try:
                    sock.settimeout(2.0)
                    chunk = sock.recv(4096)
                    if not chunk: break
                    out += chunk
                except socket.timeout:
                    continue
            return out, time.time() - start
    except Exception as e:
        return b"", 0

@dataclass(frozen=True)
class Var:
    i: int
@dataclass(frozen=True)
class Lam:
    body: object
@dataclass(frozen=True)
class App:
    f: object
    x: object

def encode(term):
    if isinstance(term, Var): return bytes([term.i])
    if isinstance(term, Lam): return encode(term.body) + bytes([FE])
    if isinstance(term, App): return encode(term.f) + encode(term.x) + bytes([FD])
    raise TypeError

def parse(data):
    stack = []
    for b in data:
        if b == FF: break
        if b == FD:
            x, f = stack.pop(), stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            stack.append(Lam(stack.pop()))
        else:
            stack.append(Var(b))
    return stack[0] if stack else None

def to_str(t):
    if isinstance(t, Var): return f"V{t.i}"
    if isinstance(t, Lam): return f"λ.{to_str(t.body)}"
    if isinstance(t, App): return f"({to_str(t.f)} {to_str(t.x)})"
    return str(t)

QD = parse(bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe"))
nil = Lam(Lam(Var(0)))

# Omega = (λx.xx)(λx.xx) - infinite loop
omega_half = Lam(App(Var(0), Var(0)))  # λ.(V0 V0)
OMEGA = App(omega_half, omega_half)     # ((λ.(V0 V0)) (λ.(V0 V0)))

# Y combinator - also causes infinite recursion when applied
# Y = λf.(λx.f(xx))(λx.f(xx))
Y = Lam(App(
    Lam(App(Var(1), App(Var(0), Var(0)))),
    Lam(App(Var(1), App(Var(0), Var(0))))
))

print("=" * 60)
print("Test 1: Baseline timing")
print("=" * 60)

# Normal syscall 8 - should be fast (~0.5s)
prog = App(App(Var(8), Var(0)), QD)
payload = encode(prog) + bytes([FF])
resp, elapsed = query(payload)
print(f"((8 V0) QD): {elapsed:.2f}s -> {resp.hex()[:30] if resp else 'EMPTY'}")

print("\n" + "=" * 60)
print("Test 2: syscall 8 with Omega (infinite loop) as argument")
print("=" * 60)

# ((8 Omega) QD)
prog = App(App(Var(8), OMEGA), QD)
payload = encode(prog) + bytes([FF])
print(f"Sending: ((8 Ω) QD)")
resp, elapsed = query(payload, timeout_s=15)
print(f"  Time: {elapsed:.2f}s")
print(f"  Response: {resp.hex()[:40] if resp else 'EMPTY'}")

if elapsed > 5:
    print("  [!!] Took longer than normal - might be evaluating!")

print("\n" + "=" * 60)
print("Test 3: Omega BEFORE syscall 8 in same program")
print("=" * 60)

# What if Omega runs first, then syscall 8?
# ((Omega) ((8 V0) QD)) - Omega applied to the syscall result handler
# This might cause Omega to run, never terminating, and syscall 8 never runs

# Actually let's try: (Omega (8 V0 QD)) in different ways
# We want syscall 8 to run while Omega is "distracting" something

# Try: pass Omega as continuation to syscall 8
# ((8 V0) Omega) - syscall 8, then pass result to Omega
prog = App(App(Var(8), Var(0)), OMEGA)
payload = encode(prog) + bytes([FF])
print(f"Sending: ((8 V0) Ω)")
resp, elapsed = query(payload, timeout_s=15)
print(f"  Time: {elapsed:.2f}s")
print(f"  Response: {resp.hex()[:40] if resp else 'EMPTY'}")

print("\n" + "=" * 60)
print("Test 4: Run syscall 8 and backdoor 'simultaneously'")
print("=" * 60)

# What if the "distraction" is another syscall?
# Structure: ((8 ((201 nil) something)) QD)
# This calls backdoor first, passes its result to something, then to syscall 8

# ((8 ((201 nil) V0)) QD) - backdoor result applied to V0, then to syscall 8
inner = App(App(Var(201), nil), Var(0))
prog = App(App(Var(8), inner), QD)
payload = encode(prog) + bytes([FF])
print(f"((8 ((201 nil) V0)) QD)")
resp, elapsed = query(payload)
print(f"  Time: {elapsed:.2f}s -> {resp.hex()[:40] if resp else 'EMPTY'}")

print("\n" + "=" * 60)
print("Test 5: Backdoor with syscall 8 as argument")
print("=" * 60)

# What if we give syscall 8 TO the backdoor?
# ((201 ((8 V0) something)) QD)

# Actually the backdoor needs 'nil' as argument...
# But what if we pass syscall 8's index (V8)?

# ((201 V8) QD) - backdoor with V8 as argument (instead of nil)
prog = App(App(Var(201), Var(8)), QD)
payload = encode(prog) + bytes([FF])
print(f"((201 V8) QD) - backdoor with syscall 8 as arg")
resp, elapsed = query(payload)
print(f"  Time: {elapsed:.2f}s -> {resp.hex()[:40] if resp else 'EMPTY'}")

# ((201 ((8 nil) nil)) QD) - pass syscall 8's result to backdoor... but that's weird
prog = App(App(Var(201), App(App(Var(8), nil), nil)), QD)
payload = encode(prog) + bytes([FF])
print(f"\n((201 ((8 nil) nil)) QD) - pass syscall 8 result to backdoor")
resp, elapsed = query(payload)
print(f"  Time: {elapsed:.2f}s -> {resp.hex()[:40] if resp else 'EMPTY'}")

print("\n" + "=" * 60)
print("Test 6: Use the backdoor pair AS the continuation for syscall 8")
print("=" * 60)

# Backdoor returns Left(pair) where pair = λλ((V1 A) B)
# If we use this pair as the CONTINUATION for syscall 8...
# ((8 arg) pair) = (pair result) = (result A) B? 

# But we need to GET the pair first from backdoor
# Structure: ((8 arg) ((201 nil) extractor))
# Where extractor = λ.V0 (identity) to get the pair

# Actually let's build: the result of ((201 nil) V0) is (Left(pair) V0)
# which pattern-matches Left and gives (V0 pair)... but V0 is the continuation

# This is getting complex. Let's try a simpler structure:
# What if pair itself is a valid continuation?

# Build pair directly (from the backdoor)
A = Lam(Lam(App(Var(0), Var(0))))
B = Lam(Lam(App(Var(1), Var(0))))
pair = Lam(Lam(App(App(Var(1), A), B)))

# ((8 V0) pair)
prog = App(App(Var(8), Var(0)), pair)
payload = encode(prog) + bytes([FF])
print(f"((8 V0) pair)")
resp, elapsed = query(payload)
print(f"  Time: {elapsed:.2f}s -> {resp.hex()[:40] if resp else 'EMPTY'}")

# ((8 pair) QD)
prog = App(App(Var(8), pair), QD)
payload = encode(prog) + bytes([FF])
print(f"\n((8 pair) QD)")
resp, elapsed = query(payload)
print(f"  Time: {elapsed:.2f}s -> {resp.hex()[:40] if resp else 'EMPTY'}")

print("\n" + "=" * 60)
print("Test 7: What if we pass a term that 'looks like' Left()?")
print("=" * 60)

# Left(x) = λλ(V1 x)
# What if we construct a fake Left that passes the permission check?

# Fake Left with nil inside
fake_left_nil = Lam(Lam(App(Var(1), nil)))
prog = App(App(Var(8), fake_left_nil), QD)
payload = encode(prog) + bytes([FF])
print(f"((8 λλ(V1 nil)) QD) - fake Left(nil)")
resp, elapsed = query(payload)
print(f"  Time: {elapsed:.2f}s -> {resp.hex()[:40] if resp else 'EMPTY'}")

# Fake Left with the pair inside
fake_left_pair = Lam(Lam(App(Var(1), pair)))
prog = App(App(Var(8), fake_left_pair), QD)
payload = encode(prog) + bytes([FF])
print(f"\n((8 λλ(V1 pair)) QD) - fake Left(pair)")
resp, elapsed = query(payload)
print(f"  Time: {elapsed:.2f}s -> {resp.hex()[:40] if resp else 'EMPTY'}")

print("\nDone!")
