#!/usr/bin/env python3
"""
Radical probing - testing wild hypotheses:
1. NOT using QD continuation (avoid serialization)
2. Using syscall 2 directly as continuation for syscall 8
3. Multi-syscall chains where syscall 8 is NOT the target
4. Testing if "permission denied" can be bypassed by passing the right continuation
"""

import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221
FD = 0xFD
FE = 0xFE
FF = 0xFF

def query_raw(payload, timeout_s=8.0):
    """Send and receive raw, no assumptions about response format."""
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
                    if FF in chunk:
                        break  # Got end marker
                except socket.timeout:
                    continue
            return out
    except Exception as e:
        return f"ERROR: {e}".encode()

def Var(i): return bytes([i])
def App(f, x): return f + x + bytes([FD])
def Lam(body): return body + bytes([FE])

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

def decode_ascii_safe(data):
    """Try to extract ASCII text from response."""
    try:
        # Filter printable ASCII
        text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        return text
    except:
        return ""

print("=" * 60)
print("HYPOTHESIS 1: syscall 8's continuation IS the unlock")
print("=" * 60)

# What if syscall 8 doesn't check its argument, but checks its CONTINUATION?
# And passing certain continuations triggers success?

# Normal call: ((8 arg) cont) 
# Try various continuations

continuations_to_test = [
    ("QD", QD),
    ("V0 (identity)", Var(0)),
    ("V8 (syscall 8 itself)", Var(8)),
    ("V201 (backdoor syscall)", Var(201)),
    ("V14 (echo syscall)", Var(14)),
    ("λ.V0 (λ identity)", Lam(Var(0))),
    # What about a continuation that ignores the error?
    # λ.(2 'hello') - always output 'hello'
    # Actually: λ.((2 "ok") V0) - output "ok" regardless of input
]

for label, cont in continuations_to_test:
    # ((8 V0) cont) + FF
    payload = Var(8) + Var(0) + bytes([FD]) + cont + bytes([FD, FF])
    resp = query_raw(payload)
    
    ascii_text = decode_ascii_safe(resp)
    if resp and len(resp) > 0:
        # Check if it's different from standard permission denied
        if b"Permission" not in resp and "Permission" not in ascii_text:
            print(f"[!!] Cont={label}: {resp.hex()[:60]}")
            if ascii_text.strip('.'):
                print(f"      ASCII: {ascii_text[:50]}")
        else:
            print(f"Cont={label}: Permission denied")
    else:
        print(f"Cont={label}: EMPTY")
    time.sleep(0.3)

print("\n" + "=" * 60)
print("HYPOTHESIS 2: Chain syscalls differently")
print("=" * 60)

# What if the program should be structured differently?
# Instead of ((8 arg) QD), what about ((something) (8 arg))?

# Try: ((201 V0) (8 V0)) - pass syscall 8 result to backdoor?
# Actually that doesn't make sense for syscall semantics...

# What about: (8 ((201 V0) V0)) but without extra lambda?
# This would be: pass the RESULT of backdoor (after unwrapping) to syscall 8

# Let's think about this: backdoor returns Left(pair)
# If we call ((201 V0) k) where k is a continuation,
# k gets the pair as argument
# So: ((201 V0) (λ.((8 V0) QD))) would:
#   1. Call backdoor with V0
#   2. Pass result to continuation λ.((8 V0) QD)
#   3. That continuation binds result to V0 and calls syscall 8 with it

inner_cont = Lam(Var(8) + Var(0) + bytes([FD]) + QD + bytes([FD]))
# That's: λ.((8 V0) QD) in postfix = 08 00 FD QD FD FE

# Wait, need to be careful about nesting. Let me rebuild:
# We want: ((201 V0) λ.((8 V0) QD))
# In postfix: 201 V0 FD [λ.((8 V0) QD)] FD FF

# First build λ.((8 V0) QD):
syscall8_with_v0 = Var(8) + Var(0) + bytes([FD])  # 08 00 FD
then_qd = syscall8_with_v0 + QD + bytes([FD])  # (8 V0) QD FD = ((8 V0) QD)
lambda_wrap = then_qd + bytes([FE])  # λ.((8 V0) QD)

# Now: ((201 V0) λ.((8 V0) QD))
backdoor_call = Var(201) + Var(0) + bytes([FD])  # (201 V0)
full = backdoor_call + lambda_wrap + bytes([FD, FF])

print(f"Test: ((201 V0) λ.((8 V0) QD))")
print(f"  Payload: {full.hex()}")
resp = query_raw(full)
print(f"  Response: {resp.hex() if resp else 'EMPTY'}")
ascii_text = decode_ascii_safe(resp)
if ascii_text.strip('.'):
    print(f"  ASCII: {ascii_text[:80]}")

print("\n" + "=" * 60)
print("HYPOTHESIS 3: What if syscall 8 needs a specific TERM shape?")
print("=" * 60)

# Maybe syscall 8 checks if the argument has a specific structure
# Like: must be a closed term, or must be a lambda, or must be a pair

# Scott pair: λf. f a b = Lam(App(App(Var(0), a), b))
# Try passing a Scott pair to syscall 8

# Pair(V8, V14) = λ.((V0 V8) V14)
pair_8_14 = Lam(App(App(Var(0), Var(8)), Var(14)))
payload = Var(8) + pair_8_14 + bytes([FD]) + QD + bytes([FD, FF])
print(f"Test: ((8 pair(V8,V14)) QD)")
resp = query_raw(payload)
print(f"  Response: {resp.hex()[:60] if resp else 'EMPTY'}")

# Pair(V201, V8)
pair_201_8 = Lam(App(App(Var(0), Var(201)), Var(8)))
payload = Var(8) + pair_201_8 + bytes([FD]) + QD + bytes([FD, FF])
print(f"Test: ((8 pair(V201,V8)) QD)")
resp = query_raw(payload)
print(f"  Response: {resp.hex()[:60] if resp else 'EMPTY'}")

print("\n" + "=" * 60)
print("HYPOTHESIS 4: Echo something, then syscall 8 with the echo result")
print("=" * 60)

# Chain: ((14 something) λ.((8 V0) QD))
# This would echo 'something', then pass the echo result to syscall 8

for something_label, something in [("V6", Var(6)), ("V8", Var(8)), ("V199", Var(199)), ("V201", Var(201))]:
    echo_call = Var(14) + something + bytes([FD])  # (14 something)
    cont = Lam(Var(8) + Var(0) + bytes([FD]) + QD + bytes([FD, FE]))  # λ.((8 V0) QD)
    
    full = echo_call + cont + bytes([FD, FF])
    resp = query_raw(full)
    
    # Check if different from permission denied
    if resp:
        # Standard "Right(6)" for permission denied has pattern
        is_permission_denied = (len(resp) > 3 and resp[0] == 0x00 and resp[1] == 0x03)
        if not is_permission_denied:
            print(f"[!!] echo({something_label}) -> 8: {resp.hex()[:60]}")
        else:
            print(f"echo({something_label}) -> 8: Permission denied")
    else:
        print(f"echo({something_label}) -> 8: EMPTY")
    time.sleep(0.3)

print("\n" + "=" * 60)
print("HYPOTHESIS 5: The 'key' is a term that, when applied to 8's callback, unlocks")
print("=" * 60)

# What if we need to pass a term that "tricks" syscall 8's internal check?
# Maybe it checks if the continuation has a certain property?

# Let's try some exotic terms as argument:
# - Y combinator (fixpoint)
# - Omega (infinite loop)

# Omega = (λx.x x)(λx.x x) = ((λ.(V0 V0)) (λ.(V0 V0)))
omega_half = Lam(App(Var(0), Var(0)))  # λ.(V0 V0) = 00 00 FD FE
omega = App(omega_half, omega_half)
payload = Var(8) + omega + bytes([FD]) + QD + bytes([FD, FF])
print(f"Test: ((8 Ω) QD) - passing Omega (infinite loop)")
resp = query_raw(payload, timeout_s=5)
print(f"  Response: {resp.hex()[:60] if resp else 'EMPTY/TIMEOUT'}")

# Y combinator is more complex, skip for now

print("\n" + "=" * 60)
print("HYPOTHESIS 6: What if we bypass QD entirely?")
print("=" * 60)

# QD serializes the result. What if syscall 8 checks for QD specifically
# and denies access if it detects serialization attempt?

# Try: ((8 V0) (λ.(2 "test")))
# Where (2 "test") outputs literal text without serializing anything

# Actually, let's try the simplest: output nothing, just run syscall 8
payload = Var(8) + Var(0) + bytes([FD]) + Var(0) + bytes([FD, FF])
print("Test: ((8 V0) V0) - no output, just execute")
resp = query_raw(payload)
print(f"  Response: {resp.hex() if resp else 'EMPTY'}")
# This should produce no output, but maybe there's a side effect?

# Or try outputting a fixed string regardless of syscall 8's result
# ((8 V0) (λ.((2 ...) ...)))
# This is complex because we need to encode a string...

print("\nDone!")
