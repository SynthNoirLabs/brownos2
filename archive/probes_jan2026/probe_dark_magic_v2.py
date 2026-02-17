import socket
import struct
import sys
import time
from dataclasses import dataclass

# --- CONFIGURATION ---
HOST = 'wc3.wechall.net'
PORT = 61221

# --- AST & UTILS ---

@dataclass(frozen=True)
class Var:
    i: int
    def __repr__(self): return f"V{self.i}"

@dataclass(frozen=True)
class Lam:
    body: object
    def __repr__(self): return f"λ.{self.body}"

@dataclass(frozen=True)
class App:
    f: object
    x: object
    def __repr__(self): return f"({self.f} {self.x})"

def serialize(term):
    if isinstance(term, Var):
        return bytes([term.i])
    elif isinstance(term, Lam):
        return serialize(term.body) + b'\xFE'
    elif isinstance(term, App):
        return serialize(term.f) + serialize(term.x) + b'\xFD'
    raise ValueError(f"Unknown term type: {term}")

def shift(term, amount, cutoff=0):
    if isinstance(term, Var):
        if term.i >= cutoff:
            return Var(term.i + amount)
        return term
    elif isinstance(term, Lam):
        return Lam(shift(term.body, amount, cutoff + 1))
    elif isinstance(term, App):
        return App(shift(term.f, amount, cutoff), shift(term.x, amount, cutoff))
    return term

def parse_term(data: bytes):
    stack = []
    i = 0
    while i < len(data):
        b = data[i]
        if b == 0xFF: break # End marker
        
        if b == 0xFD:
            if len(stack) < 2: raise ValueError("Stack underflow at App")
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == 0xFE:
            if len(stack) < 1: raise ValueError("Stack underflow at Lam")
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
        i += 1
    return stack[0] if stack else None

# --- CONSTANTS ---

QD_BYTES = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
QD = parse_term(QD_BYTES) # Parse it into AST so we can shift it!

NIL = Lam(Lam(Var(0))) # \x.\y.y
SYS_BACKDOOR = Var(201)
SYS_ECHO = Var(14)
SYS_TARGET = Var(8)

# --- LOGIC BUILDERS ---

def with_a_b(body_using_a_b, custom_cont=None):
    """
    Wraps 'body_using_a_b' logic to run with A and B available.
    """
    shifted_body = shift(body_using_a_b, 2, cutoff=2)
    inner = Lam(Lam(shifted_body))
    
    # Use custom_cont if provided, else QD
    final_cont = custom_cont if custom_cont else QD
    
    # Pair handler: \pair. pair inner
    pair_handler = Lam(App(Var(0), shift(inner, 1, 0))) 
    
    # Either handler: \res. res pair_handler FINAL_CONT
    success = shift(pair_handler, 1, 0)
    failure = shift(final_cont, 1, 0)
    
    either_handler = Lam(App(App(Var(0), success), failure))
    
    # Call: ((201 nil) either_handler)
    term = App(App(SYS_BACKDOOR, NIL), either_handler)
    
    return term

def with_a_b_and_key_safe(body_using_key):
    """
    Safe version that passes 251 from top level.
    """
    shifted_body = shift(body_using_key, 1, cutoff=3)
    key_handler = Lam(shifted_body)
    
    real_body = shift(body_using_key, 1, 1)
    
    key_handler = Lam(real_body)
    
    qd_shifted = shift(QD, 5, 0)
    
    echo_cont = Lam(App(App(Var(0), key_handler), qd_shifted))
    
    sys_echo = shift(SYS_ECHO, 4, 0)
    p251 = Var(3)
    
    call_echo = App(App(sys_echo, p251), echo_cont)
    
    inner_ab = Lam(Lam(call_echo))
    
    pair_handler = Lam(App(Var(0), inner_ab))
    
    sys_bd = shift(SYS_BACKDOOR, 1, 0)
    nil_shifted = shift(NIL, 1, 0)
    qd_bd = shift(QD, 1, 0)
    
    cont_bd = Lam(App(App(Var(0), shift(pair_handler, 1, 0)), shift(qd_bd, 1, 0)))
    
    term_inside = App(App(sys_bd, nil_shifted), cont_bd)
    
    final_lam = Lam(term_inside)
    
    final_term = App(final_lam, Var(251))
    
    return final_term

# --- EXPERIMENTS ---

def exp_key_a_b():
    # Bomb = Key A B
    # A=V2, B=V1, Key=V0
    A = Var(2)
    B = Var(1)
    Key = Var(0)
    
    # (Key A) B
    bomb = App(App(Key, A), B)
    call8 = App(App(Var(8), bomb), QD)
    return with_a_b_and_key_safe(call8)

def exp_key_b_a():
    # Bomb = Key B A
    A = Var(2)
    B = Var(1)
    Key = Var(0)
    
    bomb = App(App(Key, B), A)
    call8 = App(App(Var(8), bomb), QD)
    return with_a_b_and_key_safe(call8)

def exp_key_key_key():
    # Bomb = Key Key Key
    Key = Var(0)
    bomb = App(App(Key, Key), Key)
    call8 = App(App(Var(8), bomb), QD)
    return with_a_b_and_key_safe(call8)

# --- NETWORK ---

def send_and_report(name, term):
    print(f"--- {name} ---")
    data = serialize(term) + b'\xFF'
    
    if len(data) > 1800:
        print("WARN: Payload size", len(data))
        
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        start = time.time()
        s.connect((HOST, PORT))
        s.sendall(data)
        s.shutdown(socket.SHUT_WR)
        
        resp = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk: break
                resp += chunk
            except socket.timeout:
                break
        elapsed = time.time() - start
        
        print(f"Time: {elapsed:.2f}s")
        if len(resp) == 0:
            print("Result: EMPTY response")
        else:
            print(f"Result: {resp}")
            try:
                parsed = parse_term(resp)
                print(f"Parsed: {parsed}")
            except:
                pass
                
    except Exception as e:
        print(f"Error: {e}")
    finally:
        s.close()
    print()

if __name__ == '__main__':
    print("Running AST-based probes (Key Combos)...")
    
    send_and_report("Key A B", exp_key_a_b())
    send_and_report("Key B A", exp_key_b_a())
    send_and_report("Key Key Key", exp_key_key_key())

# --- NEW EXPERIMENTS based on our analysis ---

def exp_just_number():
    """Pass just a number (not a function) to syscall 8"""
    # This should give "Permission denied" (Right 6)
    num = Var(42)
    call8 = App(App(Var(8), num), QD)
    return with_a_b(call8)

def exp_a_a():
    """Pass A A (simple self-application) to syscall 8"""
    # A=V1, B=V0
    A = Var(1)
    bomb = App(A, A)  # A A
    call8 = App(App(Var(8), bomb), QD)
    return with_a_b(call8)

def exp_b_a():
    """Pass B A to syscall 8"""
    A = Var(1)
    B = Var(0)
    bomb = App(B, A)  # B A
    call8 = App(App(Var(8), bomb), QD)
    return with_a_b(call8)

def exp_a_b():
    """Pass A B to syscall 8"""
    A = Var(1)
    B = Var(0)
    bomb = App(A, B)  # A B
    call8 = App(App(Var(8), bomb), QD)
    return with_a_b(call8)

def exp_b_a_a():
    """Pass (B A) A - 3 leafs structure"""
    A = Var(1)
    B = Var(0)
    bomb = App(App(B, A), A)  # (B A) A
    call8 = App(App(Var(8), bomb), QD)
    return with_a_b(call8)

def exp_a_b_a():
    """Pass (A B) A - 3 leafs"""
    A = Var(1)
    B = Var(0)
    bomb = App(App(A, B), A)  # (A B) A
    call8 = App(App(Var(8), bomb), QD)
    return with_a_b(call8)

def exp_a_a_b():
    """Pass (A A) B - 3 leafs"""
    A = Var(1)
    B = Var(0)
    bomb = App(App(A, A), B)  # (A A) B
    call8 = App(App(Var(8), bomb), QD)
    return with_a_b(call8)

def exp_b_b_a():
    """Pass (B B) A - 3 leafs"""
    A = Var(1)
    B = Var(0)
    bomb = App(App(B, B), A)  # (B B) A
    call8 = App(App(Var(8), bomb), QD)
    return with_a_b(call8)

def exp_a_b_b():
    """Pass A (B B) - right-associative 3 leafs"""
    A = Var(1)
    B = Var(0)
    bomb = App(A, App(B, B))  # A (B B)
    call8 = App(App(Var(8), bomb), QD)
    return with_a_b(call8)

def exp_b_a_b():
    """Pass B (A B) - right-associative"""
    A = Var(1)
    B = Var(0)
    bomb = App(B, App(A, B))  # B (A B)
    call8 = App(App(Var(8), bomb), QD)
    return with_a_b(call8)

def run_all_new():
    print("=" * 60)
    print("BATCH 1: Simple structures without Key")
    print("=" * 60)
    
    send_and_report("Just V42 (number)", exp_just_number())
    send_and_report("A A", exp_a_a())
    send_and_report("B A", exp_b_a())
    send_and_report("A B", exp_a_b())
    
    print("=" * 60)
    print("BATCH 2: 3-leaf structures (left-associative)")
    print("=" * 60)
    
    send_and_report("(B A) A", exp_b_a_a())
    send_and_report("(A B) A", exp_a_b_a())
    send_and_report("(A A) B", exp_a_a_b())
    send_and_report("(B B) A", exp_b_b_a())
    
    print("=" * 60)
    print("BATCH 3: 3-leaf structures (right-associative)")
    print("=" * 60)
    
    send_and_report("A (B B)", exp_a_b_b())
    send_and_report("B (A B)", exp_b_a_b())

if __name__ == '__main__' and 'all' in sys.argv:
    run_all_new()
