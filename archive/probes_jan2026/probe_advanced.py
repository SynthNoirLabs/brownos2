#!/usr/bin/env python3
"""
Advanced probing of syscall 8 based on all collected hints:
- "3 leafs IIRC" - minimal solution has 3 Var nodes
- "the mail points to the way" - backdoor (201) is key
- Backdoor returns Left(pair) where pair = λλ((V1 A) B)
- A = λλ(V0 V0), B = λλ(V1 V0)
"""

import socket
import time

def query(payload, timeout_s=5.0):
    """Send payload and receive response with proper socket handling."""
    try:
        with socket.create_connection(("wc3.wechall.net", 61221), timeout=timeout_s) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)  # CRITICAL!
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

# Wire format builders
def Var(i):  return bytes([i])
def App(f, x): return b'\xfd' + f + x  # APP marker
def Lam(body): return b'\xfe' + body   # LAM marker
def End(): return b'\xff'

# Helper to build syscall with argument
def syscall(n, arg):
    """Build ((syscall_n arg) output_continuation)"""
    # syscall is Var(n), apply to arg, then to V0 (continuation)
    return App(App(Var(n), arg), Var(0))

# QD = λ.(syscall_2 (syscall_4 V0))
QD = Lam(App(App(Var(2), App(App(Var(4), Var(0)), Var(0))), Var(0)))

def test_with_qd(label, arg_bytes, desc=""):
    """Apply QD to syscall 8 with given argument"""
    # Program: (QD (syscall_8 arg))
    inner = App(App(Var(8), arg_bytes), Var(0))
    program = App(QD, inner) + End()
    resp = query(program)
    
    # Check if different from standard "Permission denied"
    if resp and b'\x06' not in resp[-10:]:  # V6 = Permission denied
        print(f"[INTERESTING] {label}: {resp.hex()}")
        if desc: print(f"  {desc}")
        return True
    return False

# Pre-built terms
A = Lam(Lam(App(Var(0), Var(0))))        # λλ(V0 V0)
B = Lam(Lam(App(Var(1), Var(0))))        # λλ(V1 V0)
PAIR = Lam(Lam(App(App(Var(1), A), B)))  # λλ((V1 A) B)

print("=" * 60)
print("PHASE 1: Testing syscall 8 with backdoor-derived terms")
print("=" * 60)

tests = [
    ("A combinator", A, "λλ(V0 V0)"),
    ("B combinator", B, "λλ(V1 V0)"),
    ("PAIR", PAIR, "λλ((V1 A) B)"),
    ("(A B)", App(A, B), "Apply A to B"),
    ("(B A)", App(B, A), "Apply B to A"),
    ("(A A)", App(A, A), "Apply A to itself"),
    ("(B B)", App(B, B), "Apply B to itself"),
    ("λ.A", Lam(A), "Wrap A in lambda"),
    ("λ.B", Lam(B), "Wrap B in lambda"),
    ("((A B) A)", App(App(A, B), A), "3 leafs with A,B,A"),
    ("((A A) B)", App(App(A, A), B), "3 leafs with A,A,B"),
    ("((B A) B)", App(App(B, A), B), "3 leafs with B,A,B"),
    ("((B B) A)", App(App(B, B), A), "3 leafs with B,B,A"),
]

interesting = []
for label, term, desc in tests:
    if test_with_qd(label, term, desc):
        interesting.append(label)
    time.sleep(0.3)

print("\n" + "=" * 60)
print("PHASE 2: Testing without QD (direct program execution)")
print("=" * 60)

# What if the solution is a minimal program that doesn't use QD?
# Try: ((8 X) continuation) where X is special

def test_direct(label, program_bytes, desc=""):
    """Test a program directly without QD wrapper"""
    resp = query(program_bytes + End())
    
    # Look for anything other than "Permission denied" pattern
    # Standard error: 00030200fd...06... (Right(6))
    if resp:
        hex_resp = resp.hex()
        if not hex_resp.startswith("00030200fd") and len(resp) > 0:
            print(f"[INTERESTING] {label}: {hex_resp}")
            if desc: print(f"  {desc}")
            return True
    return False

# Try minimal programs
direct_tests = [
    ("((8 A) 0)", App(App(Var(8), A), Var(0)), "syscall 8 with A"),
    ("((8 B) 0)", App(App(Var(8), B), Var(0)), "syscall 8 with B"),
    ("((8 (201 0)) 0)", App(App(Var(8), App(App(Var(201), Var(0)), Var(0))), Var(0)), 
     "syscall 8 with result of backdoor"),
    # Try "3 leafs" interpretations
    ("(8 (A B))", App(Var(8), App(A, B)), "Just 8 applied to (A B)"),
    ("(8 (B A))", App(Var(8), App(B, A)), "Just 8 applied to (B A)"),
]

for label, prog, desc in direct_tests:
    if test_direct(label, prog, desc):
        interesting.append(label)
    time.sleep(0.3)

print("\n" + "=" * 60)
print("PHASE 3: Special indices with 3-leaf structure")
print("=" * 60)

# Maybe "3 leafs" is exactly 3 Var nodes in specific order
# Try all 3-leaf patterns with indices: 8, 14, 201
special_indices = [8, 14, 201, 0, 1]

count = 0
for a in special_indices:
    for b in special_indices:
        for c in special_indices:
            # Pattern 1: ((Va Vb) Vc)
            prog1 = App(App(Var(a), Var(b)), Var(c))
            # Pattern 2: (Va (Vb Vc))
            prog2 = App(Var(a), App(Var(b), Var(c)))
            
            for pattern, prog in [("left", prog1), ("right", prog2)]:
                label = f"({a},{b},{c})-{pattern}"
                if test_direct(label, prog, f"3-leaf with {a},{b},{c}"):
                    interesting.append(label)
            count += 1
            if count % 10 == 0:
                print(f"  Tested {count} combinations...")
            time.sleep(0.2)

print("\n" + "=" * 60)
print("PHASE 4: echo-based approaches")
print("=" * 60)

# Echo shifts indices by +2
# echo(6) = V8, echo(12) = V14, echo(199) = V201
# What if we use echo output as input to syscall 8?

echo_tests = [
    ("echo(6)->V8", 6, "Create V8 via echo"),
    ("echo(12)->V14", 12, "Create V14 via echo"),  
    ("echo(199)->V201", 199, "Create V201 via echo"),
]

for label, n, desc in echo_tests:
    # Build: ((8 (echo n)) cont)
    echo_n = App(App(Var(14), Var(n)), Var(0))  # ((14 Vn) V0) = Left(V(n+2))
    prog = App(QD, App(App(Var(8), echo_n), Var(0)))
    resp = query(prog + End())
    
    if resp and b'\x06' not in resp[-10:]:
        print(f"[INTERESTING] {label}: {resp.hex()}")
        interesting.append(label)
    time.sleep(0.3)

print("\n" + "=" * 60)
print("PHASE 5: Combining backdoor result with syscall 8")
print("=" * 60)

# What if we need to extract A or B from backdoor and pass to 8?
# Backdoor returns λλ((V1 A) B)
# Applying it to X and Y gives ((X A) B)
# If X selects first (like K = λλ.V1), we get A
# If X selects second (like K' = λλ.V0), we get B

K = Lam(Lam(Var(1)))   # λλV1 - select first
KI = Lam(Lam(Var(0)))  # λλV0 - select second

# ((((201 0) K) K) I) should reduce to A
# But we need to do this symbolically...

# Simpler: pass the backdoor pair directly to syscall 8
# Or: use backdoor to get A, then pass A to 8

combo_tests = [
    # The backdoor itself as argument
    ("8(201)", App(App(Var(8), App(App(Var(201), Var(0)), Var(0))), Var(0))),
    # Apply backdoor to K to try to extract A
    ("8(((201 0) K))", App(App(Var(8), App(App(App(Var(201), Var(0)), K), Var(0))), Var(0))),
    # Apply backdoor to KI to try to extract B  
    ("8(((201 0) KI))", App(App(Var(8), App(App(App(Var(201), Var(0)), KI), Var(0))), Var(0))),
]

for label, prog in combo_tests:
    resp = query(App(QD, prog) + End())
    if resp and b'\x06' not in resp[-10:]:
        print(f"[INTERESTING] {label}: {resp.hex()}")
        interesting.append(label)
    time.sleep(0.3)

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
if interesting:
    print(f"Found {len(interesting)} interesting responses:")
    for i in interesting:
        print(f"  - {i}")
else:
    print("No interesting responses found (all Permission denied)")

print("\nDone!")
