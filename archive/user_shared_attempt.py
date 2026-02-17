import socket
import binascii

HOST = "wc3.wechall.net"
PORT = 61221

# --- Encodings (Reconstructed from Learnings) ---

def encode_int(n):
    """
    Encodes an integer using the 9-lambda additive bitset encoding.
    Weights: V1=1, V2=2, ... V8=128. V0=0.
    Structure: \l9 ... \l0. (V_k ... (V_j V0))
    """
    # 1. Decompose n into weights (powers of 2)
    weights = []
    for i in range(7, -1, -1):
        val = 1 << i
        if n >= val:
            weights.append(i + 1) # V(i+1) represents 2^i
            n -= val
    weights.append(0) # Always include base V0
    
    # 2. Construct body: Apply weights from outermost to innermost
    # Body = V_last @ (... @ (V_first @ V0))
    body = bytes([0x00]) # Start with V0
    
    # Iterate reversed to build application layers correctly (V_k(V_prev))
    for w in reversed(weights[:-1]):
        # Postfix Application: Func Arg FD
        body = bytes([w]) + body + b'\xFD'
    
    # 3. Wrap in 9 lambdas (0xFE)
    return body + b'\xFE' * 9

def encode_string(s):
    """
    Encodes a string as a Scott list of byte-terms.
    nil = \c \n. n  ->  00 FE FE
    cons h t = \c \n. c h t  -> 01 h FD t FD FE FE
    """
    term = bytes.fromhex("00 FE FE") # nil
    
    for char in reversed(s):
        val = ord(char)
        h_term = encode_int(val)
        
        # cons h t
        # Body in postfix: 01 h FD t FD
        body = b'\x01' + h_term + b'\xFD' + term + b'\xFD'
        # Wrap in 2 lambdas
        term = body + b'\xFE' * 2
        
    return term

def build_payload(syscall_byte, arg_term):
    """
    Constructs a term in Continuation-Passing Style:
    ((Syscall Arg) QD)
    """
    # QD (Quick Debug) - A known continuation that prints the result
    QD = bytes.fromhex("0500FD000500FD03FDFEFD02FDFEFDFE")
    
    # Postfix: Syscall Arg FD QD FD FF
    return bytes([syscall_byte]) + arg_term + b'\xFD' + QD + b'\xFD' + b'\xFF'

# --- Exploit Execution ---

def solve():
    print(f"[*] Targeting {HOST}:{PORT}")
    password = "ilikephp"
    print(f"[*] Found Credentials: gizmore:{password}")
    
    # 1. Encode the password
    print(f"[*] Encoding payload...")
    pass_term = encode_string(password)
    
    # 2. Build Payload for Syscall 0x08 (Restricted/Login)
    payload = build_payload(0x08, pass_term)
    
    # 3. Send and Receive
    try:
        s = socket.create_connection((HOST, PORT), timeout=5)
        print(f"[*] Sending {len(payload)} bytes...")
        s.sendall(payload)
        
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            response += chunk
        s.close()
        
        print("\n[+] VM RESPONSE:")
        # The response is a serialized term. We expect a success message or flag.
        print(f"Hex: {binascii.hexlify(response).decode()}")
        print(f"Raw: {response}")
        
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()
