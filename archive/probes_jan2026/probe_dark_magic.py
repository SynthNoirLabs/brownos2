import socket
import struct
import sys
import time

# --- CONFIGURATION ---
HOST = 'wc3.wechall.net'
PORT = 61221

# --- CONSTANTS ---
# Standard byte values
VAR_0 = b'\\x00'
VAR_1 = b'\\x01'
VAR_2 = b'\\x02'
VAR_251 = b'\\xFB' # Pre-key (becomes 253 after echo)
VAR_253 = b'\\xFD' # APP marker (The Key)
VAR_254 = b'\\xFE' # LAMBDA marker
VAR_255 = b'\\xFF' # END marker

APP = b'\\xFD'
LAM = b'\\xFE'
END = b'\\xFF'

# Syscalls
SYS_ECHO = b'\\x0E'
SYS_BACKDOOR = b'\\xC9' # 201
SYS_TARGET = b'\\x08'   # 8

# Helper Terms
NIL = b'\\x00\\xFE\\xFE'  # \\x.\\y.y (Church False / Scott Nil)
# QD prints the result. 
# QD = 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
QD = b'\\x05\\x00\\xFD\\x00\\x05\\x00\\xFD\\x03\\xFD\\xFE\\xFD\\x02\\xFD\\xFE\\xFD\\xFE'

def send_payload(payload_body):
    """Wraps payload in standard CPS call ((payload) QD) and sends it."""
    # Structure: payload QD APP END
    full_payload = payload_body + QD + APP + END
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((HOST, PORT))
        s.sendall(full_payload)
        
        response = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk: break
                response += chunk
            except socket.timeout:
                break
        s.close()
        return response
    except Exception as e:
        return f"Error: {e}".encode()

def make_app(f, x):
    return x + f + APP

def make_lam(body):
    return body + LAM

# --- LOGIC BUILDER ---

# We need to Construct the "Bomb" using A and B from the backdoor.
# But we can't just write "A" or "B" in the raw bytes because they are returned at runtime.
# We have to write a program that:
# 1. Calls Backdoor (201) with nil.
# 2. Receives the result (A, B) pair.
# 3. Uses A and B to construct the bomb.
# 4. Calls Echo to get the Key (Var 253).
# 5. Combines Bomb + Key.
# 6. Calls Syscall 8.

# Backdoor returns: Left(Pair(A, B))
# Left = \l r. l Pair
# Pair = \s. s A B
# So Backdoor(nil) calls our continuation K with: Pair(A, B)
# Wait, Backdoor returns Either. 
# So we need to handle the Either.
# Backdoor(nil) (HandleSuccess) (HandleFailure)

# HandleSuccess receives "Pair".
# Pair receives a selector "s".
# s receives A and B.

# So the flow is:
# ((201 nil) \pair. ((pair \a b. USE_A_B_HERE) QD)) 
# note: we pass QD at the end to print result, or we call 8 inside.

def run_experiment(name, logic_generator):
    print(f"--- Running: {name} ---")
    payload = logic_generator()
    # Check size
    if len(payload) > 1800:
        print("WARNING: Payload too big, might fail.")
    
    start = time.time()
    res = send_payload(payload)
    end = time.time()
    
    elapsed = end - start
    print(f"Time: {elapsed:.2f}s")
    print(f"Raw Response: {res.hex().upper()}")
    
    # Analyze response
    if b"Permission denied" in res or res.hex().endswith("06"): # Right(6)
        print("Result: Permission Denied (Standard Failure)")
    elif b"Invalid term" in res:
        print("Result: Invalid Term (Syntax Error)")
    elif len(res) == 0:
        print("Result: EMPTY RESPONSE (Interesting!)")
    else:
        print(f"Result: UNKNOWN/SUCCESS? -> {res}")
    print("------------------------------------------------")


# --- EXPERIMENT GENERATORS ---

def exp_recursive_bomb_1():
    """
    Hypothesis: Use A and B to create pure recursion (A A).
    Pass (A A) to Syscall 8.
    
    Term:
    ((201 nil) 
      (\\pair. 
        ((pair 
          (\\a \\b. 
            ((8 ((a a) QD)) QD)  <-- Try to run (a a) passed to 8? No, (a a) diverges immediately.
            # We want to pass the FUNCTION (a a) to 8, not the result of evaluating it?
            # But (a a) evaluates immediately.
            # Maybe we pass \\x. (a a)? Thunked recursion.
          )
        ) QD)
      )
    )
    """
    # This is hard to construct manually in bytes.
    # Let's try simpler: Just pass A (the duplicator) to 8.
    # Logic: 201 nil (\p. p (\a \b. 8 a QD))
    
    # 201 nil
    term = NIL + SYS_BACKDOOR + APP
    
    # Continuation for 201: \pair...
    # We need to unwrap the Either first?
    # Usually 201 returns Left(Pair).
    # So: 201 nil (\x. x SuccessHandler FailHandler)
    
    # Let's assume standard handling:
    # 201 nil ( \res. res (\pair. pair (\a \b. 8 a QD)) (\err. QD err) )
    
    # This is getting complex to hand-code. 
    # Let's assume the repo has 'registry_globals.py' or similar that we can reuse?
    # No, let's write raw bytes for the specific "3 leaf" structures we discussed.
    pass

# Let's write a generic wrapper for "With A and B"
# Wraps: Backdoor(nil) (\res. res (\pair. pair (\a \b. BODY)) QD)
def with_a_b(body_using_v1_v0):
    # v1 = a, v0 = b (inside the innermost lambda)
    
    # Inner: \a \b. BODY
    inner = body_using_v1_v0 + LAM + LAM
    
    # Pair handler: \pair. pair INNER
    pair_handler = inner + VAR_0 + APP + LAM
    
    # Result handler (Success): \pair. ...
    success = pair_handler
    
    # Error handler: Just print
    failure = QD
    
    # Either handler: \res. res SUCCESS FAILURE
    either_handler = failure + success + VAR_0 + APP + APP + LAM
    
    # Call 201
    return either_handler + NIL + SYS_BACKDOOR + APP

# EXPERIMENT 1: Pass A to Syscall 8
def exp_pass_A():
    # Body: 8 a QD -> QD a 8 APP APP
    # a is Var(1)
    body = QD + VAR_1 + SYS_TARGET + APP + APP
    return with_a_b(body)

# EXPERIMENT 2: Pass B to Syscall 8
def exp_pass_B():
    # Body: 8 b QD
    body = QD + VAR_0 + SYS_TARGET + APP + APP
    return with_a_b(body)

# EXPERIMENT 3: Pass (B A) to Syscall 8
# (B A) is a function that takes x and applies A to x. 
# effectively \x. A x -> \x. x x. (Self-applicator!)
def exp_pass_BA():
    # Body: 8 (b a) QD
    # (b a) = a b APP
    term_ba = VAR_1 + VAR_0 + APP
    body = QD + term_ba + SYS_TARGET + APP + APP
    return with_a_b(body)

# EXPERIMENT 4: The "Bomb" (B A) A  -> (Recurse!)
# Wait, if we evaluate (B A) A, it reduces to (A A) which loops forever.
# If we pass this to 8, we are passing a diverging term.
# The server might freeze (as hinted).
def exp_bomb_BAA():
    # Body: 8 ((b a) a) QD
    # ((b a) a) = a (a b APP) APP
    term_baa = VAR_1 + (VAR_1 + VAR_0 + APP) + APP
    body = QD + term_baa + SYS_TARGET + APP + APP
    return with_a_b(body)

# EXPERIMENT 5: The "Key" Injection
# We need to get the key using Echo, THEN combine with A/B.
# This is deeper.
# with_a_b wrapper is not enough because we also need echo.
#
# Logic:
# 201 nil (\res. res (\pair. pair (\a \b. 
#    ECHO(251) (\res2. res2 (\key. 
#       8 (key) QD   <-- Simple test
#    ) QD)
# )) QD)

def with_a_b_and_key(body_using_v2_v1_v0):
    # v2=a, v1=b, v0=key
    
    # Innermost: \key. BODY
    inner_key = body_using_v2_v1_v0 + LAM
    
    # Echo handler: \res2. res2 inner_key QD
    echo_handler = QD + inner_key + VAR_0 + APP + APP + LAM
    
    # Call Echo: echo(251) echo_handler
    # 251 is VAR_251
    call_echo = echo_handler + VAR_251 + SYS_ECHO + APP
    
    # This whole thing is the body for with_a_b
    # But wait, with_a_b expects indices 1 and 0.
    # Now we are adding a layer, so a=v1 (will shift to v?)
    # Let's trace indices.
    # Outside: ... \a \b. (CODE)
    # Inside CODE: ... \key. (BODY)
    # In BODY: key=0. b=1 (shifted by 1 lam). a=2 (shifted by 1 lam).
    
    return with_a_b(call_echo)

# Exp 5.1: Just pass Key to 8 (verify what brownos2 did)
def exp_pass_key():
    # 8 key QD
    # key=0
    body = QD + VAR_0 + SYS_TARGET + APP + APP
    return with_a_b_and_key(body)

# Exp 5.2: (A Key) -> Key Key
# Recursive Key execution.
def exp_A_Key():
    # 8 (a key) QD
    # a=2, key=0
    term = VAR_0 + VAR_2 + APP
    body = QD + term + SYS_TARGET + APP + APP
    return with_a_b_and_key(body)

# Exp 5.3: (B Key) -> \x. Key x
# Key as a callback applicator
def exp_B_Key():
    # 8 (b key) QD
    # b=1, key=0
    term = VAR_0 + VAR_1 + APP
    body = QD + term + SYS_TARGET + APP + APP
    return with_a_b_and_key(body)

# --- MAIN EXECUTION ---

if __name__ == "__main__":
    print("Starting Focused Probe Sequence...")
    
    # 1. Baseline: Pass A and B separately
    run_experiment("Pass A (Duplicator)", exp_pass_A)
    run_experiment("Pass B (Applicator)", exp_pass_B)
    
    # 2. Logical Combinations (3 Leafs)
    run_experiment("Pass (B A) -> Self-Applicator", exp_pass_BA)
    run_experiment("Pass ((B A) A) -> DIVERGENCE/FREEZE", exp_bomb_BAA)
    
    # 3. Key Probes (The "Dark Magic" Mix)
    run_experiment("Pass Key (Verify Permission Denied)", exp_pass_key)
    run_experiment("Pass (A Key) -> Recursive Key", exp_A_Key)
    run_experiment("Pass (B Key) -> Key Applicator", exp_B_Key)
    
