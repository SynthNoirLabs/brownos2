#!/usr/bin/env python3
"""
What if byte 1 is meant to be used as a syscall selector?

Syscall 1 = error string
If we feed byte 1 to it, what do we get?

Or: use the extracted Church1 as the syscall number somehow.
"""

import socket
import time
from dataclasses import dataclass

HOST = "82.165.133.222"
PORT = 61221

FD, FE, FF = 0xFD, 0xFE, 0xFF
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


def encode_term(term) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unknown term type: {type(term)}")


def query(payload: bytes, timeout_s: float = 5.0) -> bytes:
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except:
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
                except socket.timeout:
                    break
            return out
    except Exception as e:
        return f"ERROR: {e}".encode()


nil = Lam(Lam(Var(0)))
identity = Lam(Var(0))


def make_church(n):
    expr = Var(0)
    for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_string(s: str):
    def encode_byte(n):
        expr = Var(0)
        for idx, weight in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
            if n & weight:
                expr = App(Var(idx), expr)
        term = expr
        for _ in range(9):
            term = Lam(term)
        return term
    def cons(h, t):
        return Lam(Lam(App(App(Var(1), h), t)))
    cur = nil
    for b in reversed(s.encode()):
        cur = cons(encode_byte(b), cur)
    return cur


def parse_term(data: bytes):
    stack = []
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
    return stack[0] if stack else None


def decode_either(term):
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        return None, None
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var):
        if body.f.i == 1:
            return "Left", body.x
        elif body.f.i == 0:
            return "Right", body.x
    return None, None


def decode_bytes_list(term):
    def strip_lams(t, n):
        for _ in range(n):
            if not isinstance(t, Lam):
                return None
            t = t.body
        return t
    
    WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}
    
    def eval_bitset(e):
        if isinstance(e, Var):
            return WEIGHTS.get(e.i, 0)
        if isinstance(e, App) and isinstance(e.f, Var):
            return WEIGHTS.get(e.f.i, 0) + eval_bitset(e.x)
        return 0
    
    def uncons(t):
        if not isinstance(t, Lam) or not isinstance(t.body, Lam):
            return None
        b = t.body.body
        if isinstance(b, Var) and b.i == 0:
            return None
        if isinstance(b, App) and isinstance(b.f, App):
            if isinstance(b.f.f, Var) and b.f.f.i == 1:
                return b.f.x, b.x
        return None
    
    out = []
    cur = term
    for _ in range(10000):
        res = uncons(cur)
        if res is None:
            return bytes(out)
        head, cur = res
        body = strip_lams(head, 9)
        if body is None:
            break
        out.append(eval_bitset(body))
    return bytes(out)


def test_error_string_1():
    """Test what error string syscall returns for code 1."""
    print("\n=== Error string for code 1 ===")
    
    # syscall 0x01 with argument Church1
    payload = bytes([0x01]) + encode_term(make_church(1)) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    
    term = parse_term(resp)
    if term:
        tag, payload_term = decode_either(term)
        if tag == "Left":
            s = decode_bytes_list(payload_term)
            print(f"  Error 1 = '{s.decode() if s else 'empty'}'")
    else:
        print(f"  Raw: {resp}")


def test_dynamic_syscall():
    """
    Try to dynamically call a syscall using the extracted Church numeral.
    
    Idea: Extract byte from key, use that byte value to index into syscalls.
    """
    print("\n=== Dynamic syscall using extracted byte ===")
    
    # Get key, extract byte, then use it... but how?
    # The byte is a Church numeral, not a raw value
    # We'd need to somehow convert Church -> Var index
    
    # Alternative: The "1" might mean "first entry" in some list
    # Or it might be a file descriptor
    
    print("  (Complex to implement dynamically)")
    print("  Instead, let's see what special meaning '1' might have")


def test_read_fd_1():
    """
    What if byte 1 = fd 1 (stdout)?
    Or file id 1 which is /bin directory.
    """
    print("\n=== File/directory id 1 ===")
    
    # name(1)
    payload1 = bytes([0x06]) + encode_term(make_church(1)) + bytes([FD]) + QD + bytes([FD, FF])
    resp1 = query(payload1)
    term1 = parse_term(resp1)
    if term1:
        tag, payload_term = decode_either(term1)
        if tag == "Left":
            s = decode_bytes_list(payload_term)
            print(f"  name(1) = '{s.decode() if s else 'empty'}'")
    
    # readdir(1) - should work since 1 is /bin
    payload2 = bytes([0x05]) + encode_term(make_church(1)) + bytes([FD]) + QD + bytes([FD, FF])
    resp2 = query(payload2)
    print(f"  readdir(1) response length: {len(resp2)} bytes")


def test_use_key_as_continuation_for_read():
    """
    What if we use the key as a continuation for reading?
    """
    print("\n=== Key as continuation for readfile ===")
    
    # echo(251) -> key
    # Then: readfile(some_id, key) where key is the continuation
    
    test_term = Lam(
        App(
            App(Var(0),
                Lam(  # key at Var(0)
                    # readfile(11, key) - 11 is /etc/passwd
                    App(
                        App(Var(9), make_church(11)),  # readfile(11)
                        Var(0)  # key as continuation
                    )
                )
            ),
            Lam(App(App(Var(4), encode_string("ER")), nil))
        )
    )
    
    payload = bytes([0x0E, 251, FD]) + encode_term(test_term) + bytes([FD, FF])
    resp = query(payload, timeout_s=2)
    print(f"  readfile(11, key): {resp[:50] if resp else 'empty'}")


def test_what_is_special_about_1():
    """
    Enumerate what '1' could mean in this system.
    """
    print("\n=== Special meanings of '1' ===")
    
    meanings = {
        "Error code 1": "Not implemented",
        "File id 1": "/bin directory",
        "User id 1": "Not in passwd (root is 0)",
        "Syscall 1": "Error string",
        "fd 1": "stdout (but BrownOS may not use Unix fds)",
        "Boolean": "True in some encodings",
        "Index": "Second item (0-indexed) or first (1-indexed)",
        "Church 1": "λfx.fx (apply f once)",
    }
    
    for meaning, desc in meanings.items():
        print(f"  {meaning:15s}: {desc}")


def main():
    print("=" * 70)
    print("BYTE 1 INTERPRETATION TESTS")
    print("=" * 70)
    
    test_error_string_1()
    time.sleep(0.2)
    
    test_read_fd_1()
    time.sleep(0.2)
    
    test_use_key_as_continuation_for_read()
    time.sleep(0.2)
    
    test_what_is_special_about_1()


if __name__ == "__main__":
    main()
