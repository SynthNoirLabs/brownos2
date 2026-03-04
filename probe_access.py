import socket
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

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

def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    return term # already bytes

def query(payload: bytes) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        out = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            out += chunk
        return out

# int encoding helper
def encode_int(n: int):
    # weights: 0:0, 1:1, 2:2, 3:4, 4:8, 5:16, 6:32, 7:64, 8:128
    expr = Var(0)
    for i in range(1, 9):
        if n & (1 << (i-1)):
            expr = App(Var(i), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
NIL = bytes.fromhex("00fefe")

# Test 1: (201 nil (λ_. 7 8 QD))
# Call 201, then read file 8.
# (C9 00 FE FE FD) (Lam(7 8 FD QD FD)) FD FF
test1 = bytes([0xC9]) + NIL + bytes([FD]) + encode_term(Lam(App(App(Var(9), encode_int(8)), QD))) + bytes([FD, FF])

print("Testing 201 -> readfile(8)...")
res1 = query(test1)
print(f"Result: {res1.hex()}")

# Test 2: (201 nil (λ_. 6 8 QD))
# Call 201, then get name of ID 8.
test2 = bytes([0xC9]) + NIL + bytes([FD]) + encode_term(Lam(App(App(Var(8), encode_int(8)), QD))) + bytes([FD, FF])
print("Testing 201 -> name(8)...")
res2 = query(test2)
print(f"Result: {res2.hex()}")

# Wait, indices shift under lambda!
# 7 at top level is 7.
# Inside Lam, it becomes 8? Or 9?
# Environment: [V0:arg, V1:ls, V2:write, V3:not_impl, V4:quote, V5:readdir, V6:name, V7:readfile, V8:sys8, ...]
# Wait, let's look at syscall mapping.
# 0: unbound/silent
# 1: error string
# 2: write
# 4: quote
# 5: readdir
# 6: name
# 7: readfile
# 8: sys8
# 14: echo
# 201: backdoor
#
# Inside one Lam:
# 0 -> V0 (arg)
# 1 -> V1 (unbound?)
# 2 -> V2 (error string)
# 3 -> V3 (write)
# 4 -> V4 (not_impl)
# 5 -> V5 (quote)
# 6 -> V6 (readdir)
# 7 -> V7 (name)
# 8 -> V8 (readfile)
# 9 -> V9 (sys8)
#
# So inside one Lam:
# name is Var(8)
# readfile is Var(9)
# sys8 is Var(10)
