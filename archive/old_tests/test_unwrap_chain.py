#!/usr/bin/env python3
"""
Test: Chain echo → unwrap Left → syscall 8

The key is to unwrap the Left(x) returned by echo before passing to syscall 8.

Left x = λl.λr. l x

To extract x from Left(x):
  (Left x) (λa.a) anything = (λa.a) x = x

In de Bruijn terms:
  Left(x) = λ.λ.(1 x')  where x' is x shifted by +2
  identity = λ.0
  
  ((Left x) identity) dummy = identity x = x

So the unwrap operation is: ((echo_result) identity) dummy

But we also need to be careful about the final continuation for syscall 8!
"""
from __future__ import annotations

import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")


def recv_raw(sock: socket.socket, timeout_s: float = 8.0) -> bytes:
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


def query(payload: bytes, timeout_s: float = 8.0) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return recv_raw(sock, timeout_s=timeout_s)


def main():
    print("=" * 60)
    print("Test unwrap chain")
    print("=" * 60)
    
    shifted_qd = bytes([b + 1 if b < FD else b for b in QD])
    identity = bytes([0x00, FE])
    dummy = bytes([0x00, FE, FE])
    
    print("\n[1] Test basic echo then direct application")
    
    print("\n[2] Build: echo(V251) → unwrap → syscall8 → QD")
    
    # V251 = 0xFB
    # After echo wrapping in Left: V253 (0xFD - forbidden!)
    # Let's see what happens
    
    # Chain structure:
    # ((0x0E V251) (λer. ((0x08 ((er id) dummy)) shifted_QD)))
    #
    # Under λer:
    # - er = V0
    # - 0x08 becomes 0x09
    # - id = λ.0 = 00 FE
    # - dummy = nil = 00 FE FE
    # - shifted_QD has indices shifted by +1
    #
    # unwrap = ((er id) dummy) = ((V0 (00 FE)) (00 FE FE))
    
    unwrap = bytes([
        0x00,           # er (V0)
        0x00, FE,       # identity (λ.0)
        FD,             # App(V0, identity)
        0x00, FE, FE,   # dummy (nil)
        FD,             # App(App(V0, identity), dummy)
    ])
    
    inner_call = bytes([0x09]) + unwrap + bytes([FD]) + shifted_qd + bytes([FD])
    cont = inner_call + bytes([FE])
    
    program = bytes([0x0E, 0xFB, FD]) + cont + bytes([FD, FF])
    print(f"  Payload: {program.hex()}")
    out = query(program)
    print(f"  Output: {out!r}")
    
    print("\n[3] Same but with V252")
    
    program = bytes([0x0E, 0xFC, FD]) + cont + bytes([FD, FF])
    print(f"  Payload: {program.hex()}")
    out = query(program)
    print(f"  Output: {out!r}")
    
    print("\n[4] Same but with V250 (would become V252 after echo - valid)")
    
    program = bytes([0x0E, 0xFA, FD]) + cont + bytes([FD, FF])
    print(f"  Payload: {program.hex()}")
    out = query(program)
    print(f"  Output: {out!r}")
    
    print("\n[5] Double echo → unwrap → syscall8")
    
    shifted_qd2 = bytes([b + 2 if b < FD else b for b in QD])
    
    unwrap2 = bytes([
        0x00,           # er2 (V0)
        0x00, FE,       # identity
        FD,             # App
        0x00, FE, FE,   # dummy
        FD,             # App
    ])
    
    inner2 = bytes([0x0A]) + unwrap2 + bytes([FD]) + shifted_qd2 + bytes([FD])
    
    unwrap1 = bytes([
        0x00,           # er1 (V0)
        0x00, FE,       # identity
        FD,
        0x00, FE, FE,   # dummy
        FD,
    ])
    
    outer_inner = bytes([0x0F]) + unwrap1 + bytes([FD]) + inner2 + bytes([FE, FD])
    outer_cont = outer_inner + bytes([FE])
    
    program = bytes([0x0E, 0xF9, FD]) + outer_cont + bytes([FD, FF])
    print(f"  Payload: {program.hex()}")
    out = query(program)
    print(f"  Output: {out!r}")
    
    print("\n[6] Try the 3-leaf terms with unwrap")
    
    three_leafs = [
        ("(V249 V250) V251", bytes([0xF9, 0xFA, FD, 0xFB, FD])),
        ("V249 (V250 V251)", bytes([0xF9, 0xFA, 0xFB, FD, FD])),
    ]
    
    for name, term in three_leafs:
        program = bytes([0x0E]) + term + bytes([FD]) + cont + bytes([FD, FF])
        print(f"  echo({name}) → unwrap → syscall8: ", end="")
        out = query(program)
        print(f"{out!r}")
    
    print("\n[7] What if we DON'T unwrap but pass Left directly?")
    
    direct_cont = bytes([0x09, 0x00, FD]) + shifted_qd + bytes([FD, FE])
    
    program = bytes([0x0E, 0xFB, FD]) + direct_cont + bytes([FD, FF])
    print(f"  echo(V251) → direct to syscall8 (no unwrap): {program.hex()}")
    out = query(program)
    print(f"  Output: {out!r}")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
