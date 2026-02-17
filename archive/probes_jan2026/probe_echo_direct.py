#!/usr/bin/env python3
"""
Direct probes of echo behavior without complex de Bruijn manipulation.
Test basic interactions to understand what echo actually gives us.
"""

import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def recv_all(sock: socket.socket, timeout_s: float = 4.0) -> bytes:
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


def query(payload: bytes, timeout_s: float = 4.0) -> tuple[bytes, float]:
    start = time.time()
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        result = recv_all(sock, timeout_s=timeout_s)
        return result, time.time() - start


def fmt(data: bytes) -> str:
    if not data:
        return "(empty)"
    if b"Invalid" in data or b"Encoding" in data:
        return data.decode('ascii', 'replace')[:50]
    return data.hex()


print("="*70)
print("DIRECT ECHO PROBES")
print("="*70)

# Test 1: What does echo return for various inputs?
print("\n--- Echo with different var indices ---")
for v in [0, 1, 2, 8, 14, 100, 200, 249, 250, 251, 252]:
    payload = bytes([0x0E, v, FD]) + QD + bytes([FD, FF])
    try:
        resp, t = query(payload)
        print(f"echo(V{v}): {fmt(resp)} [{t:.1f}s]")
    except Exception as e:
        print(f"echo(V{v}): ERROR {e}")
    time.sleep(0.2)


print("\n--- Echo with lambda terms ---")

# echo(identity) where identity = λ.0
# identity = 00 FE
identity = bytes([0x00, FE])
payload = bytes([0x0E]) + identity + bytes([FD]) + QD + bytes([FD, FF])
resp, t = query(payload)
print(f"echo(λ.0): {fmt(resp)} [{t:.1f}s]")

# echo(nil) where nil = λλ.0
nil = bytes([0x00, FE, FE])
payload = bytes([0x0E]) + nil + bytes([FD]) + QD + bytes([FD, FF])
resp, t = query(payload)
print(f"echo(λλ.0): {fmt(resp)} [{t:.1f}s]")

# echo(ω) where ω = λ.(0 0)
omega = bytes([0x00, 0x00, FD, FE])
payload = bytes([0x0E]) + omega + bytes([FD]) + QD + bytes([FD, FF])
resp, t = query(payload)
print(f"echo(λ.(0 0)): {fmt(resp)} [{t:.1f}s]")


print("\n--- Try to use echo result without QD (direct write) ---")

# ((echo V251) (λe. ((write e) QD)))
# This tries to write the echo result directly
# write = syscall 2, and we're 1 lambda deep so write = V3

# Handler: λ. ((V3 V0) QD_shifted)
# Actually, let's build this carefully:
# At top level: write = V2
# Under λe: write = V3, e = V0
# So handler body: ((V3 V0) QD)

# QD is a closed term, doesn't need shifting
# Actually QD references syscalls internally - let me check what QD is:
# QD = write(quote(result)) pattern

# Let's try: ((echo V249) (λe. ((write e) (λ_. 0 FE FF))))
# This writes the echo result and then returns identity

# Actually simpler - just print a constant when echo succeeds:
# ((echo V249) (λ_. ((write "OK") QD)))

# Build "OK" as bytes list - but that's complex
# Let's try even simpler: just use a constant continuation

# ((echo V249) (λe. e))  - just return the echo result
# This should give us Left(V251) which CAN be encoded

payload = bytes([0x0E, 249, FD, 0x00, FE, FD, FF])  # ((echo V249) identity)
resp, t = query(payload)
print(f"((echo V249) identity) direct output: {fmt(resp)} [{t:.1f}s]")


print("\n--- What if we apply the Either result to something? ---")

# echo returns Left(V+2)
# Left(x) = λl.λr. l x
# If we apply Left to two args: (Left f g) = f x
# 
# Let's try: ((echo V249) (λe. ((e identity) identity)))
# e = Left(V251)
# (e identity identity) = (identity V251) = V251
# Then we try to output V251 somehow

# Actually this still hits encoding issues if V251 gets into the output path
# Let's try: ((echo V249) (λe. ((e (λx. nil)) (λy. nil))))
# This discards the payload and returns nil regardless

# handler = λe. ((e (λx. nil)) (λy. nil))
# Under λe: V0 = e
# Under λx (2 deep): nil
# Under λy (2 deep): nil
# handler = λ. ((V0 (λ. nil)) (λ. nil))

# nil = λλ.V0 = 00 FE FE
# λ.nil = 00 FE FE FE
# handler body = left_h right_h V0 FD FD
# But we need to adjust vars... let's just try raw:

# ((0x0E V249) handler) where handler = λ.((V0 (λ.nil)) (λ.nil))
# postfix: 0E F9 FD handler FD FF
# handler: λ. ((V0 left) right) = left right 00 FD FD FE
# left = λ. nil = 00 FE FE FE
# right = λ. nil = 00 FE FE FE

left_handler = bytes([0x00, FE, FE, FE])  # λ.nil
right_handler = bytes([0x00, FE, FE, FE])  # λ.nil
handler_body = left_handler + right_handler + bytes([0x00, FD, FD])
handler = handler_body + bytes([FE])

payload = bytes([0x0E, 249, FD]) + handler + bytes([FD, FF])
resp, t = query(payload)
print(f"((echo V249) (λe. ((e (λ.nil)) (λ.nil)))): {fmt(resp)} [{t:.1f}s]")


print("\n--- Test: does calling extracted var as syscall produce anything? ---")

# Let's see if V251 (or V253 inside) can be called
# ((echo V249) (λe. ((e (λx. ((x nil) QD))) (λy. nil))))
#
# If Left branch succeeds: x = V251 (the +2 shifted var)
# Then ((V251 nil) QD) - this treats V251 as syscall

# Under λe (1 deep), under λx (2 deep):
# x = V0
# nil = closed term
# QD needs adjustment - its internal refs are syscall 2,3,4,5
# Under 2 lambdas, those become V4,5,6,7

# Actually QD structure: write(quote(arg))
# QD = λarg. ((write (quote arg)) QD)... wait let me parse QD

# QD bytes: 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
# Let's trace through:
# 05 -> V5 (stack: V5)
# 00 -> V0 (stack: V5 V0)
# FD -> App (stack: (V5 V0))
# 00 -> V0 (stack: (V5 V0) V0)
# 05 -> V5 (stack: (V5 V0) V0 V5)
# 00 -> V0 (stack: (V5 V0) V0 V5 V0)
# FD -> App (stack: (V5 V0) V0 (V5 V0))
# 03 -> V3 (stack: (V5 V0) V0 (V5 V0) V3)
# FD -> App (stack: (V5 V0) V0 ((V5 V0) V3))
# FE -> Lam (stack: (V5 V0) V0 λ.((V5 V0) V3))
# FD -> App (stack: (V5 V0) (V0 λ.((V5 V0) V3)))
# 02 -> V2 (stack: (V5 V0) (V0 λ.((V5 V0) V3)) V2)
# FD -> App (stack: (V5 V0) ((V0 λ.((V5 V0) V3)) V2))
# FE -> Lam (stack: (V5 V0) λ.((V0 λ.((V5 V0) V3)) V2))
# FD -> App (stack: ((V5 V0) λ.((V0 λ.((V5 V0) V3)) V2)))
# FE -> Lam (stack: λ.((V5 V0) λ.((V0 λ.((V5 V0) V3)) V2)))

# So QD = λ.((V5 V0) λ.((V0 λ.((V5 V0) V3)) V2))
# At top level, V5 = syscall 5, V4 = syscall 4, etc.
# Under QD's lambda: V5 = syscall 4 (shifted), V0 = arg
# Hmm, actually I think QD references its own internal vars correctly

# Let's try a simpler approach: just call the extracted var as a syscall
# and see if we get "Not implemented" vs empty

# Build: ((echo V249) (λe. (e call_as_syscall ignore)))
# call_as_syscall = λx. ((x nil) QD)
# Under λe, λx: x = V0, nil = closed, QD = closed but has internal refs

# I think the issue is QD's internal syscall refs get shifted wrong
# Let me try without QD - just call and see if it produces direct output

# ((echo V249) (λe. (e (λx. (x nil)) (λy. y))))
# Left branch: call V251 with nil, no continuation - will produce nothing visible
# But if V251 = "not implemented" it might just return that

# Actually let's try calling V251 directly with normal QD flow:
# ((V251 nil) QD)
# V251 at top level = syscall 251

payload = bytes([251]) + bytes([0x00, FE, FE, FD]) + QD + bytes([FD, FF])
resp, t = query(payload)
print(f"((V251 nil) QD) directly: {fmt(resp)} [{t:.1f}s]")


print("\n--- Test backdoor ---")
# Backdoor = syscall 201 with nil argument
payload = bytes([201]) + bytes([0x00, FE, FE, FD]) + QD + bytes([FD, FF])
resp, t = query(payload)
print(f"((backdoor nil) QD): {fmt(resp)} [{t:.1f}s]")


print("\n" + "="*70)
print("DONE")
print("="*70)
