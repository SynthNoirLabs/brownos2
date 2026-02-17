#!/usr/bin/env python3
"""
Probe Var(253/254/255) as potential hidden syscalls/globals.

Theory: The global namespace is indexed by bytes. Bytes 253-255 are reserved
in wire encoding (FD/FE/FF), making them unreachable by normal source.
Echo is the capability mint that lets us access these forbidden globals.

We test if these minted vars behave like callable syscalls.
"""

from __future__ import annotations
import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

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


def recv_all(sock: socket.socket, timeout_s: float = 3.0) -> bytes:
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


def query(payload: bytes, retries: int = 3, timeout_s: float = 4.0) -> tuple[bytes, float]:
    delay = 0.2
    last_err: Exception | None = None
    for _ in range(retries):
        try:
            start = time.time()
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                result = recv_all(sock, timeout_s=timeout_s)
                elapsed = time.time() - start
                return result, elapsed
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed to query") from last_err


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported: {type(term)}")


def encode_byte_term(n: int) -> object:
    expr: object = Var(0)
    for idx, weight in ((1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)):
        if n & weight:
            expr = App(Var(idx), expr)
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_bytes_list(bs: bytes) -> object:
    nil: object = Lam(Lam(Var(0)))
    def cons(h: object, t: object) -> object:
        return Lam(Lam(App(App(Var(1), h), t)))
    cur: object = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


def nil() -> object:
    return Lam(Lam(Var(0)))


def identity() -> object:
    return Lam(Var(0))


def format_response(data: bytes) -> str:
    if not data:
        return "(empty)"
    if b"Invalid term!" in data:
        return "Invalid term!"
    if b"Encoding failed!" in data:
        return "Encoding failed!"
    try:
        text = data.decode('utf-8', errors='replace')
        if len(text) < 50 and text.isprintable():
            return repr(text)
    except:
        pass
    return data[:40].hex() + ("..." if len(data) > 40 else "")


print("="*70)
print("PROBING HIDDEN GLOBALS (Var 253/254/255) AS POTENTIAL SYSCALLS")
print("="*70)

# K_print_ok: continuation that writes "OK" and ignores its argument
# K = λresult. ((write "OK") QD)
# write = syscall 2, takes bytes list, returns via continuation
# We need: λresult. ((2 ok_bytes) QD)
# But syscall refs are globals... let's build this carefully.

# Actually, let's use a simpler approach:
# We'll build the program to:
# 1. Call echo(Var(251)) to get Left(Var(253))
# 2. Extract Var(253) from the Either
# 3. Try to call Var(253) as a syscall with nil argument
# 4. Use a continuation that prints observable output

# The tricky part is extracting from Either and then calling as syscall.
# Let's think about this step by step.

# echo returns: Left(Var(253)) = λl.λr. l Var(253)
# To extract, we apply it to (λx.x) and (λy.y):
#   (Left(Var253) identity ignore) = identity Var253 = Var253

# Then we want: ((Var253 nil) continuation)
# But Var253 is a runtime value we can't directly reference.

# Full program structure:
# ((echo Var251) (λechoResult. 
#    ((echoResult identity (λ_.nil)) nil) 
#    (λsyscallResult. ((write "OK") QD))))

# Wait, that's getting complex. Let me simplify.

# Let's use the fact that Left(x) = λl.λr. l x
# So (Left(Var253) f g) = f Var253
# 
# If f = λx. ((x nil) continuation), then:
# f Var253 = ((Var253 nil) continuation)
#
# This treats Var253 as a syscall!

print("\n--- Test 1: Probe if echo(Var(251)) result can be called as syscall ---")

# Build: ((echo Var251) handler)
# where handler = λe. (e (λx. ((x nil) K)) (λerr. ((write "ERR") QD)))
# This extracts Left's payload and calls it as syscall

# Actually simpler: if Var253 IS a syscall-like global:
# ((Var253 arg) cont) should work
# But we need to GET Var253 first.

# The cleanest way:
# ((echo Var251) (λresult. 
#     (result 
#         (λpayload. ((payload nil) QD))    ; Left handler: call payload as syscall
#         (λerr. ((write "LEFT_FAILED") QD))  ; Right handler
#     )))

# Let's encode this step by step:

# payload_call = λpayload. ((payload nil) QD)
# This is: λ. ((0 nil) QD) where nil and QD are globals/known terms
# Actually we need to be careful about de Bruijn here...

# Let me think about scoping:
# Under the outer lambda (result), index 0 = result
# Under the Left handler lambda (payload), index 0 = payload, index 1 = result
# So ((payload nil) QD) = ((0 nil_term) QD_term)

# Let's build it in code:
def build_probe_hidden_syscall(seed_var: int, arg: object) -> bytes:
    """
    Build a program that:
    1. Calls echo(Var(seed_var)) to get Left(Var(seed_var+2))
    2. Extracts the payload (the minted var)
    3. Treats it as a syscall: ((minted_var arg) QD)
    
    Structure: ((echo Var(seed)) handler)
    handler = λresult. (result left_handler right_handler)
    left_handler = λpayload. ((payload arg) QD_adjusted)
    right_handler = λerr. ((write "ERR") QD)
    """
    
    # Build from inside out, tracking de Bruijn indices
    
    # At deepest level (inside left_handler):
    # Var(0) = payload (the minted var we want to call)
    # Var(1) = result (the Either)
    # Global syscalls are at higher indices...
    
    # Actually, for this to work, we need the continuation (QD) to be accessible.
    # QD is a global constant. In de Bruijn terms at the program level,
    # it would be encoded directly, not as a variable reference.
    
    # Let me try a different approach: inline QD directly.
    
    # Left handler: λpayload. ((payload arg_encoded) QD_encoded)
    # In postfix: arg_encoded 0 FD QD_encoded FD FE
    # where 0 = Var(0) = payload
    
    # Wait, this is confusing. Let me just build the raw bytes manually.
    
    # Program structure in postfix:
    # syscall_echo Var(seed) FD handler FD FF
    # = 0x0E seed FD handler FD FF
    
    # handler needs to:
    # 1. Receive the Either result
    # 2. Pattern match: if Left, extract and call as syscall
    # 3. Print something observable
    
    # For simplicity, let's just try: 
    # ((echo Var(seed)) (λe. ((e identity const_nil) nil) QD))
    # This applies the Either to identity (for Left) and const_nil (for Right)
    # If Left: result is (identity Var253) = Var253
    # Then we apply that to nil: (Var253 nil)
    # Then apply to QD: ((Var253 nil) QD)
    
    # Hmm, that's treating Var253 as syscall directly.
    
    # Actually wait - the Either selectors work like this:
    # (Left(x) l r) = l x
    # So (Left(Var253) identity _) = identity Var253 = Var253
    # That gives us the raw Var253.
    # Then ((Var253 nil) QD) treats it as syscall.
    
    # But we need the application structure: ((...) QD)
    # Let's encode:
    
    # Full: ((echo Var251) (λe. (((e (λx.x) (λx.nil)) nil) QD)))
    #                            ^^^^^^^^^^^^^^^^^^^^^^^ extracts payload or nil
    #                       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ applies to nil
    #                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ applies to QD
    
    # In de Bruijn under λe:
    # Var(0) = e
    # identity = λ.0
    # const_nil = λ.nil where nil = λ.λ.0 so const_nil = λ.λ.λ.0
    # nil (argument) = λ.λ.0
    # QD = the known bytes
    
    # This is getting complex. Let me just write it directly in postfix bytes.
    
    pass

# Simpler approach: Just try calling the echo syscall and see what we can observe

print("\n--- Test 2: Multiple echo levels to reach Var(254) and Var(255) ---")

# If echo(Var(251)) gives Left(Var(253))
# What about echo(Var(252))? Should give Left(Var(254))
# And can we echo the result of echo to go higher?

for seed in [251, 252]:
    payload = bytes([0x0E, seed, FD]) + QD + bytes([FD, FF])
    try:
        resp, elapsed = query(payload, timeout_s=3.0)
        print(f"  echo(Var({seed})): {format_response(resp)} [{elapsed:.2f}s]")
    except Exception as e:
        print(f"  echo(Var({seed})): ERROR: {e}")
    time.sleep(0.3)


print("\n--- Test 3: Direct variable probes at edge of encoding ---")

# What if we try to reference Var(252) directly in various contexts?
# Var(252) = 0xFC is still encodable!

# Test: λ.Var(252) applied to nil
# (λ.252 nil) = 252 (but 252 is a free variable)
# If 252 is a global, this would produce its value

for idx in [250, 251, 252]:
    # ((λ.idx nil) QD)
    # λ.idx = idx FE
    # ((λ.idx nil) QD) = idx FE nil FD QD FD FF
    nil_enc = encode_term(nil())
    payload = bytes([idx, FE]) + nil_enc + bytes([FD]) + QD + bytes([FD, FF])
    try:
        resp, elapsed = query(payload, timeout_s=3.0)
        print(f"  ((λ.{idx} nil) QD): {format_response(resp)} [{elapsed:.2f}s]")
    except Exception as e:
        print(f"  ((λ.{idx} nil) QD): ERROR: {e}")
    time.sleep(0.3)


print("\n--- Test 4: Call Var(252) directly as if it were a syscall ---")

# What if Var(252) IS a hidden syscall at the edge?
# Try: ((252 nil) QD)
# In postfix: FC nil FD QD FD FF

nil_enc = encode_term(nil())
payload = bytes([252]) + nil_enc + bytes([FD]) + QD + bytes([FD, FF])
try:
    resp, elapsed = query(payload, timeout_s=3.0)
    print(f"  ((Var(252) nil) QD): {format_response(resp)} [{elapsed:.2f}s]")
except Exception as e:
    print(f"  ((Var(252) nil) QD): ERROR: {e}")


print("\n--- Test 5: Nested echo to reach higher vars ---")

# echo(echo(Var(251))) - but we need to handle the Either wrapping
# This is complex because echo returns Either, not raw var

# Simpler: echo(Var(250)) should give Left(Var(252))
# Then echo(Var(249)) gives Left(Var(251))
# etc.

for seed in [249, 250]:
    payload = bytes([0x0E, seed, FD]) + QD + bytes([FD, FF])
    try:
        resp, elapsed = query(payload, timeout_s=3.0)
        print(f"  echo(Var({seed})): {format_response(resp)} [{elapsed:.2f}s]")
    except Exception as e:
        print(f"  echo(Var({seed})): ERROR: {e}")
    time.sleep(0.3)


print("\n--- Test 6: Apply minted var to write syscall (check if callable) ---")

# Complex: We want to extract Var253 from echo result and USE it
# 
# Program: 
# ((echo 251) (λe. 
#     (e 
#         (λx. ((write "WORKS") (λ_. x)))  ; if Left: print "WORKS", then return x  
#         (λy. ((write "RIGHT") (λ_. y)))  ; if Right: print "RIGHT"
#     )
# )) 
#
# This uses write (syscall 2) to produce observable output before dealing with minted var

# Build the "WORKS" string as bytes list
works_bytes = encode_bytes_list(b"WORKS")
works_enc = encode_term(works_bytes)

# Actually let's simplify: just print what we get from the Left branch
# ((echo 251) (λe. ((write "GOT") QD)))
# This always prints "GOT" regardless of what echo returns

msg = encode_bytes_list(b"GOT_LEFT")
msg_enc = encode_term(msg)

# Structure: ((echo 251) (λe. ((write msg) QD)))
# = ((0x0E 251) (λ. ((0x02 msg) QD)))
# Postfix: 0E FB FD handler FD FF
# handler = λ. ((2 msg) QD) = msg 02 FD QD FD FE

handler = msg_enc + bytes([0x02, FD]) + QD + bytes([FD, FE])
payload = bytes([0x0E, 251, FD]) + handler + bytes([FD, FF])
try:
    resp, elapsed = query(payload, timeout_s=3.0)
    print(f"  Test write in echo cont: {format_response(resp)} [{elapsed:.2f}s]")
except Exception as e:
    print(f"  Test write in echo cont: ERROR: {e}")


print("\n--- Test 7: Extract Left payload and try to call as function ---")

# Full program to extract Var253 and call it:
# ((echo 251) handler)
# handler = λresult. (result left_handler right_handler)
# left_handler = λpayload. ((payload nil) QD)  ; treat payload as syscall
# right_handler = λerr. ((write "ERR") QD)

# Build left_handler: λ. ((0 nil) QD)
# In postfix: nil 00 FD QD FD FE
nil_enc = encode_term(nil())
left_handler = nil_enc + bytes([0x00, FD]) + QD + bytes([FD, FE])

# Build right_handler: λ. ((write "ERR") QD)
err_msg = encode_bytes_list(b"ERR")
err_enc = encode_term(err_msg)
right_handler = err_enc + bytes([0x02, FD]) + QD + bytes([FD, FE])

# Build handler: λresult. ((result left_handler) right_handler)
# In postfix (under λresult where Var0=result):
# left_handler_adjusted right_handler_adjusted 00 FD FD FE
# But wait - left/right handlers need de Bruijn adjustment since they're under another lambda!

# This is getting very complex. Let me try a more direct approach.

print("\n--- Test 8: Simpler - use Identity continuation to see what echo gives us ---")

# ((echo 251) identity) should give us (identity Left(Var253)) = Left(Var253)
# Then QD tries to print it -> "Encoding failed!" because it contains Var253

# But what if we use a continuation that doesn't try to print the var?
# ((echo 251) (λx. ((write "SAW") QD)))
# This ignores the echo result entirely and just prints "SAW"

saw_msg = encode_bytes_list(b"SAW")
saw_enc = encode_term(saw_msg)

# λx. ((write saw) QD) = saw 02 FD QD FD FE
cont = saw_enc + bytes([0x02, FD]) + QD + bytes([FD, FE])

payload = bytes([0x0E, 251, FD]) + cont + bytes([FD, FF])
try:
    resp, elapsed = query(payload, timeout_s=3.0)
    print(f"  ((echo 251) (λ_. write 'SAW')): {format_response(resp)} [{elapsed:.2f}s]")
except Exception as e:
    print(f"  ((echo 251) (λ_. write 'SAW')): ERROR: {e}")


print("\n--- Test 9: Check if extracting from Left and calling succeeds ---")

# The key question: can Var(253) be called as a function?
# Let's build:
# ((echo 251) (λe. ((e (λx. ((x nil) QD)) (λy. ((write "R") QD))))))
#
# This:
# 1. Gets e = Left(Var253)
# 2. Pattern matches: e leftHandler rightHandler
# 3. leftHandler = λx. ((x nil) QD) - treats x as syscall with nil arg
# 4. If it works, we'd see QD output; if Var253 isn't callable, we'd get stuck (empty)

# leftHandler: λ. ((0 nil) QD)
# In postfix: nil 00 FD QD FD FE
nil_enc = encode_term(nil())
left_h = nil_enc + bytes([0x00, FD]) + QD + bytes([FD, FE])

# rightHandler: λ. ((write "R") QD)  
r_msg = encode_bytes_list(b"R")
r_enc = encode_term(r_msg)
right_h = r_enc + bytes([0x02, FD]) + QD + bytes([FD, FE])

# handler: λe. ((e left_h) right_h)
# Under λe, Var0 = e
# But left_h and right_h need to be encoded as terms, not var refs
# This is where it gets tricky - they're lambda terms that need to be inlined

# Actually the handler needs to be:
# λe. ((Var0 left_h_term) right_h_term)
# Postfix: left_h right_h 00 FD FD FE

# But left_h and right_h are already postfix-encoded lambdas...
# They need de Bruijn adjustment because we're putting them under another lambda

# Hmm, this requires proper term construction. Let me just build it programmatically:

# leftHandler term: Lam(App(App(Var(0), nil), QD_term)) 
# rightHandler term: Lam(App(App(Var(2), r_bytes), QD_term))  # 2 = write syscall

# Actually QD is already a term... let me parse it first
def parse_term(data: bytes) -> object:
    stack: list[object] = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    if len(stack) != 1:
        raise ValueError(f"Invalid: {len(stack)}")
    return stack[0]

QD_term = parse_term(QD)

# leftHandler: λx. ((x nil) QD)
# Under the handler's λ, x is Var(0)
left_handler_term = Lam(App(App(Var(0), nil()), QD_term))

# rightHandler: λy. ((write "R") QD) where write is global Var(2)
# Under handler's λ then rightHandler's λ, write would be Var(3)
# But actually globals don't shift... wait, in this VM syscalls are globals.
# Var(2) at top level = write syscall (global index 2)
# Under one λ, what was Var(2) at top level is still... hmm.

# Actually in pure de Bruijn, if you're under N lambdas, you need to add N 
# to reference the same global. So Var(2) at top level becomes Var(3) under 1 lambda.

# For rightHandler inside handler (2 lambdas deep from top):
# write = Var(2) at top, so inside it's Var(2+2) = Var(4)
right_handler_term = Lam(App(App(Var(4), encode_bytes_list(b"R")), 
                             # But QD_term also needs adjustment...
                             # This is getting really messy.
                             QD_term))  

# Let's try a much simpler probe:
# Just see if sending a minimal program that references syscall-like indices works

print("\n--- Test 10: Direct syscall-style call at indices 250-252 ---")

for idx in range(250, 253):
    # Try ((idx nil) QD) - treating idx as syscall global
    payload = bytes([idx]) + encode_term(nil()) + bytes([FD]) + QD + bytes([FD, FF])
    try:
        resp, elapsed = query(payload, timeout_s=3.0)
        print(f"  ((Var({idx}) nil) QD): {format_response(resp)} [{elapsed:.2f}s]")
    except Exception as e:
        print(f"  ((Var({idx}) nil) QD): ERROR: {e}")
    time.sleep(0.3)


print("\n" + "="*70)
print("ANALYSIS COMPLETE")
print("="*70)
