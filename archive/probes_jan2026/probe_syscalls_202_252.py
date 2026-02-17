#!/usr/bin/env python3
"""
Probe syscalls 202-252 - this range was mentioned as unexplored.
We know:
- 201 (0xC9) = backdoor (works!)
- 252-254 return "syscall does not exist"

Let's check the range 202-251 for any hidden functionality.
"""
import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
FD = 0xFD
FE = 0xFE
FF = 0xFF

nil = bytes([0x00, FE, FE])  # λλ.0


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


def query(payload: bytes, timeout_s: float = 3.0) -> bytes:
    delay = 0.2
    for attempt in range(3):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_all(sock, timeout_s=timeout_s)
        except Exception as e:
            if attempt == 2:
                raise
            time.sleep(delay)
            delay *= 2
    return b""


def decode_response(data: bytes) -> str:
    """Try to decode a response as string via the standard wrapper."""
    if not data:
        return "<EMPTY>"
    if data.startswith(b"Invalid term!"):
        return "Invalid term!"
    if data.startswith(b"Encoding failed!"):
        return "Encoding failed!"
    
    # Try to parse as lambda term and extract string
    try:
        from solve_brownos import parse_term, unwrap_outer, decode_scott_list, strip_lams, eval_bitset_expr
        root = parse_term(data)
        list_term = unwrap_outer(root)
        items = decode_scott_list(list_term)
        chars = []
        for item in items:
            body = strip_lams(item, 9)
            chars.append(chr(eval_bitset_expr(body)))
        return "".join(chars)
    except Exception as e:
        return f"<RAW {len(data)} bytes: {data[:50].hex()}...>"


def test_syscall_with_nil(syscall_id: int) -> str:
    """Test a syscall with nil argument and QD continuation."""
    # Pattern: ((syscall nil) QD)
    payload = bytes([syscall_id]) + nil + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    return decode_response(resp)


def main():
    print("=" * 60)
    print("Scanning syscalls 202-252 (unexplored range)")
    print("=" * 60)
    
    results = {}
    
    for syscall_id in range(202, 253):
        result = test_syscall_with_nil(syscall_id)
        results[syscall_id] = result
        
        # Only print interesting results (not "does not exist")
        if "does not exist" not in result.lower() and "Syscall does not exist" not in result:
            print(f"INTERESTING! syscall {syscall_id} (0x{syscall_id:02X}): {result}")
        else:
            print(f"syscall {syscall_id} (0x{syscall_id:02X}): {result[:60]}")
        
        time.sleep(0.15)  # Be nice to the server
    
    print("\n" + "=" * 60)
    print("Summary of non-standard responses:")
    print("=" * 60)
    
    for syscall_id, result in results.items():
        if "does not exist" not in result.lower() and "Syscall does not exist" not in result:
            print(f"  {syscall_id} (0x{syscall_id:02X}): {result}")


if __name__ == "__main__":
    main()
