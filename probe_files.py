import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

def query(payload: bytes) -> bytes:
    try:
        with socket.create_connection((HOST, PORT), timeout=5) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            out = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                out += chunk
            return out
    except Exception as e:
        return b""

def encode_int(n: int):
    expr = bytes([0])
    for i in range(1, 9):
        if n & (1 << (i-1)):
            expr = bytes([i]) + expr + bytes([FD])
    term = expr
    for _ in range(9):
        term = term + bytes([FE])
    return term

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

def test_id(i):
    # sys7 (readfile) arg i, then QD
    payload = bytes([0x07]) + encode_int(i) + bytes([FD]) + QD + bytes([FD, FF])
    res = query(payload)
    if res and len(res) > 30: # more than just Right(N)
        return res
    return None

print("Checking readfile(0..20)...")
for i in range(21):
    res = test_id(i)
    if res:
        print(f"ID {i}: {res.hex()[:50]}...")
    else:
        # Check what error it gives
        payload = bytes([0x07]) + encode_int(i) + bytes([FD]) + QD + bytes([FD, FF])
        res = query(payload)
        # Decode Right(N) if possible
        # Standard Right(N) is roughly: 00 03 02 00 FD FD ...
        # Error codes: 3: No such file, 5: Not a file (dir)
        if b"\x00\x03\x02\x00" in res:
             pass # probably error
        else:
             print(f"ID {i} anomalous error: {res.hex()}")

print("Checking readfile(8)...")
payload = bytes([0x07]) + encode_int(8) + bytes([FD]) + QD + bytes([FD, FF])
res = query(payload)
print(f"Result for ID 8: {res.hex()}")

print("Checking name(8)...")
payload = bytes([0x06]) + encode_int(8) + bytes([FD]) + QD + bytes([FD, FF])
res = query(payload)
print(f"Result for name(8): {res.hex()}")

print("Checking readdir(8)...")
payload = bytes([0x05]) + encode_int(8) + bytes([FD]) + QD + bytes([FD, FF])
res = query(payload)
print(f"Result for readdir(8): {res.hex()}")
