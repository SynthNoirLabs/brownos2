import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221

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

# 3-leaf candidates
tests = [
    ("((201 nil) 8)", bytes.fromhex("C9 00 FE FE FD 08 FD FF")),
    ("((201 nil) 14)", bytes.fromhex("C9 00 FE FE FD 0E FD FF")),
    ("((8 14) 251)", bytes.fromhex("08 0E FB FD FD FF")),
    ("((8 14) 252)", bytes.fromhex("08 0E FC FD FD FF")),
    ("((14 251) 8)", bytes.fromhex("0E FB FD 08 FD FF")),
    ("((201 nil) 2)", bytes.fromhex("C9 00 FE FE FD 02 FD FF")),
]

for name, payload in tests:
    print(f"Testing {name}...")
    res = query(payload)
    print(f"  Result: {res.hex()}")
    if res:
        try:
            print(f"  Text: {res.decode('utf-8', 'replace')}")
        except:
            pass
