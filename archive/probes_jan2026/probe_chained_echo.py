#!/usr/bin/env python3
"""
Chain echo to reach Var(255) - the forbidden END marker.

Strategy:
1. echo(Var(251)) -> Left(Var(253)) [FD byte]
2. Extract Var(253), call echo(Var(253)) -> Left(Var(255)) [FF byte!]
3. Extract Var(255), call it as syscall
"""

import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221
FD, FE, FF = 0xFD, 0xFE, 0xFF
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


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


def recv_all(sock, timeout_s=5.0):
    sock.settimeout(timeout_s)
    out = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
    return out


def query(payload, timeout_s=5.0):
    start = time.time()
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        result = recv_all(sock, timeout_s=timeout_s)
        return result, time.time() - start


def encode_term(term):
    if isinstance(term, Var):
        if term.i > 252:
            raise ValueError(f"Cannot encode Var({term.i})")
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Bad term: {type(term)}")


def shift_term(term, delta, cutoff=0):
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift_term(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift_term(term.f, delta, cutoff), shift_term(term.x, delta, cutoff))
    return term


def parse_term(data):
    stack = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x, f = stack.pop(), stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            stack.append(Lam(stack.pop()))
        else:
            stack.append(Var(b))
    return stack[0] if len(stack) == 1 else None


def pp(term):
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{pp(term.body)}"
    if isinstance(term, App):
        return f"({pp(term.f)} {pp(term.x)})"
    return str(term)


def fmt(data):
    if not data:
        return "(empty)"
    if b"Invalid" in data or b"Encoding" in data or b"Term too" in data:
        return data.decode('ascii', 'replace')[:60]
    return data.hex()[:80]


nil = Lam(Lam(Var(0)))
identity = Lam(Var(0))
QD_term = parse_term(QD)

print("="*70)
print("CHAINED ECHO TO REACH Var(255)")
print("="*70)

# First, verify we can call echo on a runtime value
# We'll build a program that:
# 1. Gets Left(Var(253)) from echo(Var(251))
# 2. In the Left handler, calls echo again on Var(253)
# 3. This should produce Left(Var(255))!
# 4. Then we call Var(255) as syscall

# Program structure:
# ((echo V251) handler1)
# handler1 = λe1. (e1 leftH1 rightH1)  
# leftH1 = λx. ((echo x) handler2)    ; x = V253, call echo(V253)
# handler2 = λe2. (e2 leftH2 rightH2)
# leftH2 = λy. ((y nil) QD)           ; y = V255, call as syscall

# De Bruijn depth tracking:
# Top level: echo = V14
# handler1 (1 lambda): e1 = V0, echo = V15
# leftH1 (2 lambdas): x = V0, e1 = V1, echo = V16
# handler2 (3 lambdas): e2 = V0, x = V1, e1 = V2, echo = V17
# leftH2 (4 lambdas): y = V0, e2 = V1, x = V2, e1 = V3, echo = V18

# Build from inside out:

# leftH2: λy. ((y nil) QD)
# y = V0, nil = closed, QD needs +4 shift
QD_shifted4 = shift_term(QD_term, 4)
leftH2_body = App(App(Var(0), nil), QD_shifted4)
leftH2 = Lam(leftH2_body)
print(f"leftH2 = {pp(leftH2)}")

# rightH2: λ_. nil (dummy, shouldn't be called)
rightH2 = Lam(nil)
print(f"rightH2 = {pp(rightH2)}")

# handler2: λe2. ((e2 leftH2) rightH2)
# e2 = V0, leftH2/rightH2 need +3 shift (under 3 lambdas going into handler2's body)
leftH2_in_h2 = shift_term(leftH2, 1)  # +1 because handler2 adds 1 lambda
rightH2_in_h2 = shift_term(rightH2, 1)
handler2_body = App(App(Var(0), leftH2_in_h2), rightH2_in_h2)
handler2 = Lam(handler2_body)
print(f"handler2 = {pp(handler2)}")

# leftH1: λx. ((echo x) handler2)
# Under leftH1 (2 lambdas from top): echo = V16
# x = V0
# handler2 needs shift: when we move it under leftH1's lambda, add +1
handler2_in_leftH1 = shift_term(handler2, 1)
echo_in_leftH1 = Var(16)  # echo syscall shifted by 2
leftH1_body = App(App(echo_in_leftH1, Var(0)), handler2_in_leftH1)
leftH1 = Lam(leftH1_body)
print(f"leftH1 = {pp(leftH1)}")

# rightH1: λ_. nil
rightH1 = Lam(nil)
print(f"rightH1 = {pp(rightH1)}")

# handler1: λe1. ((e1 leftH1) rightH1)
leftH1_in_h1 = shift_term(leftH1, 1)
rightH1_in_h1 = shift_term(rightH1, 1)
handler1_body = App(App(Var(0), leftH1_in_h1), rightH1_in_h1)
handler1 = Lam(handler1_body)
print(f"handler1 = {pp(handler1)}")

# Full program: ((echo V251) handler1)
# echo = V14 at top level
try:
    prog = App(App(Var(14), Var(251)), handler1)
    print(f"\nFull program: {pp(prog)}")
    
    prog_bytes = encode_term(prog) + bytes([FF])
    print(f"Encoded ({len(prog_bytes)} bytes): {prog_bytes.hex()}")
    
    print("\nSending to server...")
    resp, elapsed = query(prog_bytes, timeout_s=8.0)
    print(f"Response: {fmt(resp)} [{elapsed:.1f}s]")
    
    if resp and b"Encoding" not in resp and b"Invalid" not in resp:
        print(f"Raw: {resp.hex()}")
        try:
            p = parse_term(resp)
            if p:
                print(f"Parsed: {pp(p)}")
        except:
            pass

except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()


print("\n" + "="*70)
print("SIMPLER: Just try to call echo(V253) using a minimal extraction")  
print("="*70)

# What if we use the Either eliminator pattern more directly?
# 3-leaf eliminator: λe.λl.λr. ((e l) r) = λλλ.((V2 V1) V0)
# This has body: (V2 V1) V0 = App(App(V2, V1), V0)

# Actually let me try an even simpler approach:
# Apply the echo result directly to handlers without extra wrapper

# echo(V251) returns Left(V253) = λl.λr.(l V253)
# If we apply this to (λx. ((echo x) QD)) and some_dummy:
# (Left(V253) (λx.((echo x) QD)) dummy) = (λx.((echo x) QD)) V253 = ((echo V253) QD)

# But wait - ((echo V253) QD) would try to serialize Left(V255)!
# We need another level of handler to avoid serialization.

# Let me try: extract V253, then extract V255, then call it
# But without nesting - use continuation passing:

# ((echo V251) (λe1. (e1 (λv253. ((echo v253) (λe2. (e2 (λv255. ((v255 nil) QD)) nil)))) nil)))

# Hmm this is the same as above but flattened. Let me just try calling V253 directly:

print("\n--- Direct call to extracted V253 ---")

# ((echo V251) (λe. (e (λx. ((x nil) QD_shifted)) rightH)))
# Under λe (1 deep), under λx (2 deep): QD needs +2 shift

QD_s2 = shift_term(QD_term, 2)
leftH_direct = Lam(App(App(Var(0), nil), QD_s2))
rightH_direct = Lam(nil)
handler_direct_body = App(App(Var(0), shift_term(leftH_direct, 1)), shift_term(rightH_direct, 1))
handler_direct = Lam(handler_direct_body)

try:
    prog2 = App(App(Var(14), Var(251)), handler_direct)
    print(f"Program: {pp(prog2)}")
    
    prog2_bytes = encode_term(prog2) + bytes([FF])
    print(f"Encoded ({len(prog2_bytes)} bytes)")
    
    resp2, elapsed2 = query(prog2_bytes, timeout_s=6.0)
    print(f"Response: {fmt(resp2)} [{elapsed2:.1f}s]")
    
except Exception as e:
    print(f"ERROR: {e}")


print("\n" + "="*70)
print("EVEN SIMPLER: Just extract V253 and try to print 'OK' to show we got it")
print("="*70)

# ((echo V251) (λe. (e (λx. ((write 'OK') QD)) rightH)))
# This always prints 'OK' in the Left branch, proving we entered it

# Building the string 'OK' as bytes list is complex. Let's just use nil
# and see if we get any response vs empty

# λx. nil
left_trivial = Lam(nil)
handler_trivial_body = App(App(Var(0), shift_term(left_trivial, 1)), shift_term(Lam(nil), 1))
handler_trivial = Lam(handler_trivial_body)

try:
    prog3 = App(App(Var(14), Var(251)), handler_trivial)
    print(f"Program (returns nil from Left branch): {pp(prog3)}")
    
    prog3_bytes = encode_term(prog3) + bytes([FF])
    resp3, elapsed3 = query(prog3_bytes, timeout_s=6.0)
    print(f"Response: {fmt(resp3)} [{elapsed3:.1f}s]")

except Exception as e:
    print(f"ERROR: {e}")

print("\n" + "="*70)
print("DONE")  
print("="*70)
