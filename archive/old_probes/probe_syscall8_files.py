#!/usr/bin/env python3
"""
Test syscall 8 with file/directory IDs using the backdoor pair bypass.

The continuation prompt claims:
- backdoor(nil) returns Left(pair) where pair = λs. s A B
- Using selector = λA.λB. ((syscall8 <int>) B) bypasses permission denied
- Directory IDs return Left (directory listing)
- File IDs return Right(4) = "Not a directory"

Let's verify this and see if syscall 8 can read FILES we couldn't read before.
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
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


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported: {type(term)}")


def encode_int_proper(n: int) -> object:
    """Encode integer using additive encoding (works for n >= 256)."""
    expr: object = Var(0)
    remaining = n
    weights = [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]
    for idx, weight in weights:
        while remaining >= weight:
            expr = App(Var(idx), expr)
            remaining -= weight
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def query(payload: bytes, timeout_s: float = 5.0) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        sock.settimeout(timeout_s)
        out = b""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                out += chunk
                if FF in chunk:
                    break
            except socket.timeout:
                break
        return out


def parse_response(resp: bytes) -> str:
    if not resp:
        return "(empty)"
    if b"Encoding failed" in resp:
        return "Encoding failed!"
    if b"Invalid term" in resp:
        return "Invalid term!"
    if b"Term too big" in resp:
        return "Term too big!"
    
    if FF not in resp:
        return f"No FF: {resp[:40].hex()}"
    
    # Quick pattern matching
    hex_resp = resp.hex()
    if "000600" in hex_resp:
        return "Right(6) = PermDenied"
    if "000400" in hex_resp:
        return "Right(4) = NotADir"
    if "000500" in hex_resp:
        return "Right(5) = NotAFile"  
    if "000300" in hex_resp:
        return "Right(3) = UnknownId"
    if "000200" in hex_resp:
        return "Right(2) = InvalidArg"
    if "000100" in hex_resp:
        return "Right(1) = NoSyscall"
    if "000000" in hex_resp:
        return "Right(0) = Exception"
    if hex_resp.startswith("01"):
        return f"Left(...) len={len(resp)}"
    
    return f"Unknown: {hex_resp[:60]}"


def test(desc: str, payload: bytes) -> str:
    try:
        resp = query(payload)
        result = parse_response(resp)
        print(f"{desc:60} -> {result}")
        return result
    except Exception as e:
        print(f"{desc:60} -> ERROR: {e}")
        return f"ERROR: {e}"


def main():
    print("=" * 70)
    print("SYSCALL 8 WITH BACKDOOR BYPASS - FILE/DIRECTORY TESTS")
    print("=" * 70)
    
    nil = Lam(Lam(Var(0)))
    syscall8 = Var(8)
    
    # Known file/directory IDs from the filesystem:
    # Directories: 0(/), 1(bin), 2(etc), 3(brownos), 4(var), 5(log), 6(brownos log), 
    #              9(sbin), 22(home), 25(spool), 39(gizmore), 43(mail), 50(dloser)
    # Files: 11(passwd), 14(sh), 15(sudo), 16(false), 46(access.log), 65(.history), 88(dloser mail)
    # Hidden: 256(wtf)
    
    dir_ids = [0, 1, 2, 3, 4, 5, 6, 9, 22, 25, 39, 43, 50]
    file_ids = [11, 14, 15, 16, 46, 65, 88, 256]
    
    print("\n=== Test 1: Normal syscall 8 (should be PermDenied) ===\n")
    
    payload = bytes([0x08]) + encode_term(nil) + bytes([FD]) + QD + bytes([FD, FF])
    test("syscall8(nil) direct", payload)
    
    payload = bytes([0x08]) + encode_term(encode_int_proper(0)) + bytes([FD]) + QD + bytes([FD, FF])
    test("syscall8(int 0) direct", payload)
    
    print("\n=== Test 2: Backdoor pair bypass with directory IDs ===\n")
    print("Pattern: backdoor(nil) >>= λpair. pair (λA.λB. (syscall8 N) B) nil\n")
    
    for n in dir_ids[:5]:  # Test first 5 directories
        int_term = encode_int_proper(n)
        # Selector: λA.λB. ((syscall8 int) B)
        selector = Lam(Lam(App(App(syscall8, int_term), Var(0))))
        # Continuation: λpair. pair selector nil
        cont = Lam(App(App(Var(0), selector), nil))
        
        payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(cont) + bytes([FD]) + QD + bytes([FD, FF])
        test(f"backdoor bypass syscall8({n}) [dir]", payload)
        time.sleep(0.2)
    
    print("\n=== Test 3: Backdoor pair bypass with file IDs ===\n")
    
    for n in file_ids:
        int_term = encode_int_proper(n)
        selector = Lam(Lam(App(App(syscall8, int_term), Var(0))))
        cont = Lam(App(App(Var(0), selector), nil))
        
        payload = bytes([0xC9]) + encode_term(nil) + bytes([FD]) + encode_term(cont) + bytes([FD]) + QD + bytes([FD, FF])
        result = test(f"backdoor bypass syscall8({n}) [file]", payload)
        time.sleep(0.2)
        
        # If we get Left (success), try to decode it!
        if result.startswith("Left"):
            print(f"  ^^^ SUCCESS! Trying to decode...")
    
    print("\n=== Test 4: Compare with regular readdir (syscall 5) ===\n")
    
    payload = bytes([0x05]) + encode_term(encode_int_proper(0)) + bytes([FD]) + QD + bytes([FD, FF])
    test("readdir(0) via syscall 5", payload)
    
    print("\n=== Test 5: Compare with regular readfile (syscall 7) ===\n")
    
    payload = bytes([0x07]) + encode_term(encode_int_proper(11)) + bytes([FD]) + QD + bytes([FD, FF])
    test("readfile(11) via syscall 7 [passwd]", payload)
    
    # Test file 14 which is 0 bytes - maybe syscall8 shows content?
    payload = bytes([0x07]) + encode_term(encode_int_proper(14)) + bytes([FD]) + QD + bytes([FD, FF])
    test("readfile(14) via syscall 7 [/bin/sh]", payload)


if __name__ == "__main__":
    main()
