#!/usr/bin/env python3
"""
Basic verification of echo + handler pattern.
Start simple and verify each step works.
"""

import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221
FD, FE, FF = 0xFD, 0xFE, 0xFF
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def query(payload, timeout_s=5.0):
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        sock.settimeout(timeout_s)
        out = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                out += chunk
            except socket.timeout:
                break
        return out


def fmt(data):
    if not data:
        return "(empty)"
    if b"Invalid" in data or b"Encoding" in data:
        return data.decode('ascii', 'replace')[:50]
    return data.hex()[:60]


print("="*70)
print("BASIC VERIFICATION OF ECHO HANDLER PATTERN")
print("="*70)

# Test 1: Verify basic echo works
print("\n1. Basic echo(V0) with QD:")
payload = bytes([0x0E, 0x00, FD]) + QD + bytes([FD, FF])
resp = query(payload)
print(f"   ((echo V0) QD): {fmt(resp)}")
# Expected: Left(V2) encoded

# Test 2: Verify we can pattern match an Either
print("\n2. Echo result applied to handlers:")
# echo(V0) returns Left(V2)
# Left(x) = λl.λr. l x
# (Left f g) = f x
# So ((Left(V2)) identity identity) = identity V2 = V2
# Then QD(V2) should work

# Build: (((echo V0) identity) identity) applied to QD
# In postfix: echo V0 FD identity FD identity FD QD FD FF
# identity = λ.V0 = 00 FE

identity = bytes([0x00, FE])
payload = bytes([0x0E, 0x00, FD]) + identity + bytes([FD]) + identity + bytes([FD]) + QD + bytes([FD, FF])
resp = query(payload)
print(f"   ((((echo V0) id) id) QD): {fmt(resp)}")
# This extracts V2 from Left, then applies QD to it
# Should show V2 encoded... or maybe something else

# Test 3: Even simpler - what if we just use identity as continuation?
print("\n3. Echo with identity continuation:")
payload = bytes([0x0E, 0x00, FD]) + identity + bytes([FD, FF])
resp = query(payload)
print(f"   ((echo V0) identity): {fmt(resp)}")
# This applies identity to Left(V2), giving Left(V2)
# But then what? No output without QD

# Test 4: Use a handler that prints something observable
print("\n4. Echo with write handler:")
# ((echo V0) (λresult. ((write "X") QD)))
# Under λresult: write = V3, result = V0
# "X" as bytes list is complex, but let's try with empty list (nil)
# nil = λλ.V0 = 00 FE FE
nil = bytes([0x00, FE, FE])
# handler = λ. ((V3 nil) QD) = nil V3 FD QD FD FE
handler = nil + bytes([0x03, FD]) + QD + bytes([FD, FE])
payload = bytes([0x0E, 0x00, FD]) + handler + bytes([FD, FF])
resp = query(payload)
print(f"   ((echo V0) (λ_.((write nil) QD))): {fmt(resp)}")
# Should print empty string then the QD output

# Test 5: What if echo result IS the continuation's argument?
print("\n5. Verify handler receives the Either:")
# ((echo V0) (λe. e)) should give back the Either
# Then we can't print it without QD, but let's chain with QD

# ((echo V0) (λe. (e l r))) where l and r are identity
# Under λe: e = V0
# identity = λ.V0
# l = identity shifted +1 under λe = λ.V1
# Actually identity in de Bruijn doesn't shift - it's closed!
# λ.V0 under another lambda is still λ.V0 (the inner V0 refers to its own binder)

# ((echo V0) (λe. ((e id) id)))
# = ((e id) id) where e = Left(V2)
# = ((Left(V2) id) id) = (id V2) = V2
# Then we need to do something with V2...

# Let me try: (((echo V0) (λe. ((e id) id))) QD)
# This should give us V2, then apply QD to it
handler_extract = identity + identity + bytes([0x00, FD, FD, FE])  # λ.((V0 id) id)
payload = bytes([0x0E, 0x00, FD]) + handler_extract + bytes([FD]) + QD + bytes([FD, FF])
resp = query(payload)
print(f"   (((echo V0) extract) QD): {fmt(resp)}")

# Test 6: What about applying syscall directly?
print("\n6. Direct syscall with extracted value as arg:")
# Can we make: ((syscall (extract echo)) QD)?
# Let's try ((error_str V2) QD) which should print "Invalid argument"
# error_str = syscall 1, V2 = integer 2
# If we extract V2 from echo(V0):
# (((echo V0) (λe. ((e (λx. ((V3 x) QD')) (λy. dummy))))) 
# Under λe, under λx: V0 = x, error_str = V3
# QD needs +2 shift... 

# Actually this is getting complicated. Let me verify a known working pattern.

print("\n7. Direct error string call for reference:")
# ((error_str int2) QD) where int2 is Church 2
# int2 = λλ.λλ.λλ.λλ.λλ.V2 V0 = ... complex
# Let's use int 0 instead: λ^9.V0
int0_body = bytes([0x00])
for _ in range(9):
    int0_body += bytes([FE])
payload = bytes([0x01]) + int0_body + bytes([FD]) + QD + bytes([FD, FF])
resp = query(payload)
print(f"   ((error_str int0) QD): {fmt(resp)}")

# Test 8: Let's verify the Scott Either pattern
print("\n8. Manual Left creation and extraction:")
# Left(42) = λl.λr. l 42
# left_42 = 42 01 FD FE FE (postfix: body=01 42 FD, then FE FE)
# No wait, de Bruijn: under λl.λr, l = V1, r = V0
# Left(x) body = (V1 x)
# So Left(V42) = 42 01 FD FE FE
left_42 = bytes([42, 0x01, FD, FE, FE])
# Apply to identity twice: ((left_42 id) id)
# = (id V42) = V42
# Then apply QD
payload = left_42 + identity + bytes([FD]) + identity + bytes([FD]) + QD + bytes([FD, FF])
resp = query(payload)
print(f"   (((Left(42) id) id) QD): {fmt(resp)}")

# Test 9: What does echo actually return for V249?
print("\n9. Echo V249 behavior check:")
# echo(V249) = Left(V251) which IS serializable
# Let's extract it: (((echo V249) id) id) should give V251
# Then QD(V251) = quote(V251) = ... ?
payload = bytes([0x0E, 249, FD]) + identity + bytes([FD]) + identity + bytes([FD]) + QD + bytes([FD, FF])
resp = query(payload)
print(f"   (((echo V249) id) id) via QD: {fmt(resp)}")

print("\n" + "="*70)
print("DONE")
print("="*70)
