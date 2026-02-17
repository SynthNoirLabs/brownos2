#!/usr/bin/env python3
"""
Search for the flag by:
1. Scanning ALL file IDs with regular readfile
2. Scanning file names for 'flag', 'answer', 'secret'
3. Reading the empty /bin files which might have hidden content
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
WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


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


def query(payload: bytes, timeout_s: float = 4.0) -> bytes:
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
        raise ValueError(f"Invalid parse: stack size {len(stack)}")
    return stack[0]


def strip_lams(term: object, n: int) -> object:
    cur = term
    for _ in range(n):
        if not isinstance(cur, Lam):
            raise ValueError("Not enough lambdas")
        cur = cur.body
    return cur


def eval_bitset_expr(expr: object) -> int:
    if isinstance(expr, Var):
        return WEIGHTS.get(expr.i, 0)
    if isinstance(expr, App):
        if isinstance(expr.f, Var):
            return WEIGHTS.get(expr.f.i, 0) + eval_bitset_expr(expr.x)
    raise ValueError(f"Unexpected expr")


def decode_byte_term(term: object) -> int:
    body = strip_lams(term, 9)
    return eval_bitset_expr(body)


def decode_either(term: object) -> tuple[str, object]:
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not Either")
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var):
        return ("Left", body.x) if body.f.i == 1 else ("Right", body.x)
    raise ValueError("Not Either")


def uncons_scott_list(term: object) -> tuple[object, object] | None:
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not list")
    body = term.body.body
    if isinstance(body, Var) and body.i == 0:
        return None
    if isinstance(body, App) and isinstance(body.f, App):
        if isinstance(body.f.f, Var) and body.f.f.i == 1:
            return body.f.x, body.x
    raise ValueError("Not list")


def decode_bytes_list(term: object) -> bytes:
    out = []
    cur = term
    for _ in range(100000):
        res = uncons_scott_list(cur)
        if res is None:
            return bytes(out)
        head, cur = res
        out.append(decode_byte_term(head))
    raise RuntimeError("List too long")


def get_name(n: int) -> str | None:
    payload = bytes([0x06]) + encode_term(encode_int_proper(n)) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    try:
        term = parse_term(resp)
        tag, p = decode_either(term)
        if tag == "Left":
            return decode_bytes_list(p).decode('utf-8', 'replace')
    except:
        pass
    return None


def read_file(n: int) -> bytes | None:
    payload = bytes([0x07]) + encode_term(encode_int_proper(n)) + bytes([FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    try:
        term = parse_term(resp)
        tag, p = decode_either(term)
        if tag == "Left":
            return decode_bytes_list(p)
    except:
        pass
    return None


def main():
    print("=" * 70)
    print("FLAG SEARCH")
    print("=" * 70)
    
    print("\n=== Reading known files ===\n")
    
    known_files = {
        11: "/etc/passwd",
        14: "/bin/sh",
        15: "/bin/sudo", 
        16: "/bin/false",
        46: "/var/log/brownos/access.log",
        65: "/home/gizmore/.history",
        88: "/var/spool/mail/dloser",
        256: "wtf"
    }
    
    for fid, path in known_files.items():
        content = read_file(fid)
        if content:
            print(f"File {fid} ({path}): {len(content)} bytes")
            if len(content) < 200:
                print(f"  Content: {content.decode('utf-8', 'replace')!r}")
            else:
                print(f"  First 100: {content[:100].decode('utf-8', 'replace')!r}")
        else:
            print(f"File {fid} ({path}): EMPTY or ERROR")
        time.sleep(0.15)
    
    print("\n=== Scan IDs 0-300 for file names ===\n")
    
    found_names = {}
    for n in range(301):
        name = get_name(n)
        if name:
            found_names[n] = name
        time.sleep(0.05)
    
    print(f"Found {len(found_names)} named entries:")
    for n, name in sorted(found_names.items()):
        keywords = ['flag', 'answer', 'secret', 'key', 'pass', 'solution', 'admin', 'root']
        highlight = any(k in name.lower() for k in keywords)
        mark = " <<<" if highlight else ""
        print(f"  {n}: {name}{mark}")
    
    print("\n=== Reading /bin files (should be 0 bytes normally) ===\n")
    
    for fid in [14, 15, 16]:
        content = read_file(fid)
        name = get_name(fid)
        if content and len(content) > 0:
            print(f"File {fid} ({name}): {content!r}")
        else:
            print(f"File {fid} ({name}): empty")
        time.sleep(0.15)
    
    print("\n=== Check if 'ilikephp' appears anywhere special ===\n")
    
    for fid in [11, 65, 88]:
        content = read_file(fid)
        if content and b"ilikephp" in content:
            print(f"Found 'ilikephp' in file {fid}")
        time.sleep(0.1)


if __name__ == "__main__":
    main()
