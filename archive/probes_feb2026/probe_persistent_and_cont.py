#!/usr/bin/env python3
"""
Probe script testing THREE key hypotheses:
1. Persistent socket: Can we send multiple FF-terminated programs on one connection?
   Does the VM maintain state between them?
2. Continuation sensitivity: Does sys8 behave differently with different continuations?
3. Raw sys8 without any continuation

Based on Oracle analysis and the observation that space's forum script
uses a persistent socket (while True loop on same connection).
"""

from __future__ import annotations

import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD
FE = 0xFE
FF = 0xFF

# QD continuation: write(quote(result))
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

# nil = λc.λn.n = 00 FE FE
NIL = bytes([0x00, FE, FE])


def recv_all(sock: socket.socket, timeout_s: float = 8.0) -> bytes:
    """Receive all available data until timeout or connection close."""
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


def recv_timed(sock: socket.socket, timeout_s: float = 5.0) -> bytes:
    """Receive data with a shorter timeout, for interactive probing."""
    sock.settimeout(timeout_s)
    out = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
            if b"\xff" in chunk:
                break
    except socket.timeout:
        pass
    return out


def classify(out: bytes) -> str:
    if not out:
        return "EMPTY"
    if out.startswith(b"Invalid term!"):
        return "INVALID"
    if out.startswith(b"Encoding failed!"):
        return "ENCFAIL"
    if out.startswith(b"Term too big!"):
        return "TOOBIG"
    # Try to identify Either Left/Right
    # Left = FE FE (01 ...) FD FE  pattern at start after lambdas
    # Right = FE FE (00 ...) FD FE
    try:
        text = out.decode("ascii", errors="replace")
        if text.isprintable() and len(text) < 200:
            return f"TEXT:{text}"
    except Exception:
        pass
    return f"RAW:{out[:30].hex()}{'...' if len(out) > 30 else ''} len={len(out)}"


# ============================================================
# PHASE 1: Multi-FF Persistent Socket Test
# ============================================================


def test_persistent_socket():
    """Test if we can send multiple programs on one connection."""
    print("=" * 60)
    print("PHASE 1: PERSISTENT SOCKET (Multi-FF) TESTS")
    print("=" * 60)

    # Test 1a: Send QD(nil), wait for response, then send another QD(nil) on same socket
    print("\n[1a] Two sequential QD(nil) programs on same socket")
    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        # First program: quote(nil) via QD — should return 00 FE FE FF
        prog1 = bytes([0x04, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])
        sock.sendall(prog1)
        resp1 = recv_timed(sock, timeout_s=5.0)
        print(
            f"  Program 1 (quote nil): {classify(resp1)}  raw={resp1.hex() if resp1 else 'empty'}"
        )

        # Second program on SAME socket
        prog2 = (
            bytes([0x04, 0x01, FE, FE, FE, FE, FE, FE, FE, FE, FE, FD])
            + QD
            + bytes([FD, FF])
        )
        sock.sendall(prog2)
        resp2 = recv_timed(sock, timeout_s=5.0)
        print(
            f"  Program 2 (quote int0): {classify(resp2)}  raw={resp2.hex() if resp2 else 'empty'}"
        )
        sock.close()
    except Exception as e:
        print(f"  ERROR: {e}")

    time.sleep(0.3)

    # Test 1b: Send both programs concatenated in one sendall
    print("\n[1b] Two programs concatenated in single sendall")
    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        prog1 = bytes([0x04, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])
        prog2 = (
            bytes([0x04, 0x01, FE, FE, FE, FE, FE, FE, FE, FE, FE, FD])
            + QD
            + bytes([FD, FF])
        )
        sock.sendall(prog1 + prog2)
        resp = recv_all(sock, timeout_s=8.0)
        print(
            f"  Combined response: {classify(resp)}  raw={resp.hex() if resp else 'empty'}"
        )
        # Check for multiple FF markers
        ff_count = resp.count(bytes([FF]))
        print(f"  FF markers in response: {ff_count}")
        sock.close()
    except Exception as e:
        print(f"  ERROR: {e}")

    time.sleep(0.3)

    # Test 1c: Send backdoor first, then sys8 on same socket
    print("\n[1c] Backdoor(nil) first, then sys8(nil) on same socket")
    try:
        sock = socket.create_connection((HOST, PORT), timeout=15)
        # Program 1: backdoor(nil) with QD
        prog1 = bytes([0xC9]) + NIL + bytes([FD]) + QD + bytes([FD, FF])
        sock.sendall(prog1)
        resp1 = recv_timed(sock, timeout_s=5.0)
        print(
            f"  Backdoor result: {classify(resp1)}  raw={resp1[:40].hex() if resp1 else 'empty'}"
        )

        time.sleep(0.1)

        # Program 2: sys8(nil) with QD
        prog2 = bytes([0x08]) + NIL + bytes([FD]) + QD + bytes([FD, FF])
        sock.sendall(prog2)
        resp2 = recv_timed(sock, timeout_s=5.0)
        print(
            f"  sys8(nil) after backdoor: {classify(resp2)}  raw={resp2.hex() if resp2 else 'empty'}"
        )
        sock.close()
    except Exception as e:
        print(f"  ERROR: {e}")

    time.sleep(0.3)

    # Test 1d: Send backdoor + sys8 concatenated
    print("\n[1d] Backdoor+sys8 concatenated in single sendall")
    try:
        sock = socket.create_connection((HOST, PORT), timeout=15)
        prog1 = bytes([0xC9]) + NIL + bytes([FD]) + QD + bytes([FD, FF])
        prog2 = bytes([0x08]) + NIL + bytes([FD]) + QD + bytes([FD, FF])
        sock.sendall(prog1 + prog2)
        resp = recv_all(sock, timeout_s=10.0)
        print(
            f"  Combined response: {classify(resp)}  raw={resp[:60].hex() if resp else 'empty'}"
        )
        ff_count = resp.count(bytes([FF]))
        print(f"  FF markers: {ff_count}")
        sock.close()
    except Exception as e:
        print(f"  ERROR: {e}")

    time.sleep(0.3)

    # Test 1e: sys8 with NO shutdown — keep socket open for writing
    print("\n[1e] sys8(nil) + QD without socket shutdown (keep write open)")
    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        prog = bytes([0x08]) + NIL + bytes([FD]) + QD + bytes([FD, FF])
        sock.sendall(prog)
        # Do NOT shutdown write side
        resp = recv_timed(sock, timeout_s=6.0)
        print(
            f"  Response (no shutdown): {classify(resp)}  raw={resp.hex() if resp else 'empty'}"
        )
        sock.close()
    except Exception as e:
        print(f"  ERROR: {e}")


# ============================================================
# PHASE 2: Continuation Sensitivity Tests
# ============================================================


def test_continuation_sensitivity():
    """Test if sys8 behaves differently with different continuations."""
    print("\n" + "=" * 60)
    print("PHASE 2: CONTINUATION SENSITIVITY TESTS")
    print("=" * 60)

    def query_raw(payload: bytes, timeout_s: float = 8.0) -> bytes:
        delay = 0.15
        for _ in range(3):
            try:
                sock = socket.create_connection((HOST, PORT), timeout=timeout_s)
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                result = recv_all(sock, timeout_s=timeout_s)
                sock.close()
                return result
            except Exception:
                time.sleep(delay)
                delay *= 2
        return b""

    # Test 2a: sys8(nil) with QD (baseline)
    print("\n[2a] sys8(nil) + QD (baseline)")
    prog = bytes([0x08]) + NIL + bytes([FD]) + QD + bytes([FD, FF])
    resp = query_raw(prog)
    print(f"  Result: {classify(resp)}  raw={resp.hex() if resp else 'empty'}")
    time.sleep(0.15)

    # Test 2b: sys8(nil) with identity continuation (λx.x)
    print("\n[2b] sys8(nil) + identity (λx.x = 00 FE)")
    identity = bytes([0x00, FE])
    prog = bytes([0x08]) + NIL + bytes([FD]) + identity + bytes([FD, FF])
    resp = query_raw(prog)
    print(f"  Result: {classify(resp)}  raw={resp.hex() if resp else 'empty'}")
    time.sleep(0.15)

    # Test 2c: sys8(nil) with nil continuation
    print("\n[2c] sys8(nil) + nil continuation")
    prog = bytes([0x08]) + NIL + bytes([FD]) + NIL + bytes([FD, FF])
    resp = query_raw(prog)
    print(f"  Result: {classify(resp)}  raw={resp.hex() if resp else 'empty'}")
    time.sleep(0.15)

    # Test 2d: sys8(nil) with K = λa.λb.a (drop result, return something)
    print("\n[2d] sys8(nil) + K (λa.λb.a = 01 FE FE)")
    K = bytes([0x01, FE, FE])
    prog = bytes([0x08]) + NIL + bytes([FD]) + K + bytes([FD, FF])
    resp = query_raw(prog)
    print(f"  Result: {classify(resp)}  raw={resp.hex() if resp else 'empty'}")
    time.sleep(0.15)

    # Test 2e: sys8(nil) with write continuation that writes raw result
    # λres. (write (quote res))  — similar to QD but hand-built
    # Actually let's try: λres. (write res) — assume result is already a byte list
    print("\n[2e] sys8(nil) + write-direct (λres. ((write res) nil))")
    # λres. ((02 res) (00 FE FE)) = body: 03 01 FD 00 FE FE FD FE
    # Under the lambda, write=global 2 becomes Var(3), res=Var(0), nil needs shift
    # Actually: in named form: lam("res", apps(g(2), v("res"), nil))
    # In db: Lam(App(App(Var(3), Var(0)), Lam(Lam(Var(0)))))
    # Encoding: 03 00 FD 00 FE FE FD FE
    write_direct = bytes([0x03, 0x00, FD, 0x00, FE, FE, FD, FE])
    prog = bytes([0x08]) + NIL + bytes([FD]) + write_direct + bytes([FD, FF])
    resp = query_raw(prog)
    print(f"  Result: {classify(resp)}  raw={resp.hex() if resp else 'empty'}")
    time.sleep(0.15)

    # Test 2f: sys8(nil) + continuation that does ANOTHER syscall
    # λres. ((echo res) QD)  — echo the result then print via QD
    print("\n[2f] sys8(nil) + (λres. ((echo res) QD))")
    # In DB: Lam(App(App(Var(0x0F), Var(0)), QD_shifted))
    # echo at top level = Var(0x0E), under 1 lambda = Var(0x0F)
    # QD shifted up by 1... this gets complex. Let me build it properly.
    # Actually: the continuation receives the result of sys8.
    # We want: lam("res", apps(g(14), v("res"), QD_term))
    # g(14) under 1 lam = Var(15), v("res") = Var(0)
    # QD as a raw term is already a closed term (no free vars above the lambdas)
    # So we can embed QD directly.
    # Encoding: 0F 00 FD [QD bytes shifted by 1] FD FE
    # But QD contains globals 5,3,2 which become 6,4,3 under 1 extra lambda
    # QD parsed: Lam(App(App(Var(5), Var(0)), App(App(Var(5), Var(0)), App(App(Var(3), Var(0)), Lam(App(Var(2), Lam(Lam(Var(0)))))))))
    # Hmm, QD has free variables (globals). Under 1 extra lambda they shift by 1.
    # Rather than hand-compute, let me try a different approach.

    # Simpler: write a fixed marker "OK" as continuation (always writes "OK")
    # λres. ((write [0x4f, 0x4b]) nil)
    # write = g(2) = Var(3) under 1 lambda
    # [0x4f, 0x4b] = cons(0x4f, cons(0x4b, nil))
    # This is way too big. Let me just try the simplest possible things.

    # Test 2f-simple: sys8(nil) with no continuation at all — just sys8 applied to nil
    # (sys8 nil) = ((Var(8) nil)) — two elements, not CPS
    print("\n[2f] sys8(nil) ALONE — no continuation, no FD wrapper")
    prog = bytes([0x08, 0x00, FE, FE, FD, FF])
    resp = query_raw(prog)
    print(f"  Result: {classify(resp)}  raw={resp.hex() if resp else 'empty'}")
    time.sleep(0.15)

    # Test 2g: Just sys8 by itself (bare Var(8) + FF)
    print("\n[2g] Bare Var(8) — just 08 FF")
    prog = bytes([0x08, FF])
    resp = query_raw(prog)
    print(f"  Result: {classify(resp)}  raw={resp.hex() if resp else 'empty'}")
    time.sleep(0.15)

    # Test 2h: sys8(nil) applied to nil — ((sys8 nil) nil)
    print("\n[2h] ((sys8 nil) nil) = 08 00FEFE FD 00FEFE FD FF")
    prog = bytes([0x08, 0x00, FE, FE, FD, 0x00, FE, FE, FD, FF])
    resp = query_raw(prog)
    print(f"  Result: {classify(resp)}  raw={resp.hex() if resp else 'empty'}")
    time.sleep(0.15)

    # Test 2i: ((sys8 nil) write) — use write as continuation
    print("\n[2i] ((sys8 nil) Var(2)) — write as continuation")
    prog = bytes([0x08, 0x00, FE, FE, FD, 0x02, FD, FF])
    resp = query_raw(prog)
    print(f"  Result: {classify(resp)}  raw={resp.hex() if resp else 'empty'}")
    time.sleep(0.15)

    # Test 2j: ((sys8 nil) echo) — use echo(14) as continuation
    print("\n[2j] ((sys8 nil) Var(14)) — echo as continuation")
    prog = bytes([0x08, 0x00, FE, FE, FD, 0x0E, FD, FF])
    resp = query_raw(prog)
    print(f"  Result: {classify(resp)}  raw={resp.hex() if resp else 'empty'}")
    time.sleep(0.15)

    # Test 2k: ((sys8 nil) quote) — use quote(4) as continuation
    print("\n[2k] ((sys8 nil) Var(4)) — quote as continuation")
    prog = bytes([0x08, 0x00, FE, FE, FD, 0x04, FD, FF])
    resp = query_raw(prog)
    print(f"  Result: {classify(resp)}  raw={resp.hex() if resp else 'empty'}")
    time.sleep(0.15)


# ============================================================
# PHASE 3: Cheatsheet Second Example Deep Exploration
# ============================================================


def test_cheatsheet_second_example():
    """
    The cheatsheet says: ?? ?? FD QD FD
    dloser says this "is also useful in figuring out some crucial properties of the codes"
    and "the different outputs betray some core structures"

    Let's systematically test ALL syscalls in this pattern and carefully analyze
    what "structures" the outputs reveal.
    """
    print("\n" + "=" * 60)
    print("PHASE 3: CHEATSHEET 2ND EXAMPLE — ?? ?? FD QD FD")
    print("=" * 60)

    def query_raw(payload: bytes, timeout_s: float = 8.0) -> bytes:
        delay = 0.15
        for _ in range(3):
            try:
                sock = socket.create_connection((HOST, PORT), timeout=timeout_s)
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                result = recv_all(sock, timeout_s=timeout_s)
                sock.close()
                return result
            except Exception:
                time.sleep(delay)
                delay *= 2
        return b""

    # For each known syscall, test: syscall(Var(N)) via QD for a range of N
    # Focus on what "structures" emerge
    known_syscalls = [
        (0x01, "error_string"),
        (0x02, "write"),
        (0x04, "quote"),
        (0x05, "readdir"),
        (0x06, "name"),
        (0x07, "readfile"),
        (0x08, "sys8"),
        (0x0E, "echo"),
        (0x2A, "towel"),
        (0xC9, "backdoor"),
    ]

    # But also test syscalls with EACH OTHER as arguments
    # e.g., echo(write), echo(quote), quote(write), etc.
    print("\n[3a] Syscall with OTHER syscalls as arguments:")
    # These should reveal how the VM treats globals as first-class values
    tests = [
        ("echo(write)", bytes([0x0E, 0x02, FD]) + QD + bytes([FD, FF])),
        ("echo(quote)", bytes([0x0E, 0x04, FD]) + QD + bytes([FD, FF])),
        ("echo(sys8)", bytes([0x0E, 0x08, FD]) + QD + bytes([FD, FF])),
        ("echo(echo)", bytes([0x0E, 0x0E, FD]) + QD + bytes([FD, FF])),
        ("echo(backdoor)", bytes([0x0E, 0xC9, FD]) + QD + bytes([FD, FF])),
        ("quote(write)", bytes([0x04, 0x02, FD]) + QD + bytes([FD, FF])),
        ("quote(sys8)", bytes([0x04, 0x08, FD]) + QD + bytes([FD, FF])),
        ("quote(echo)", bytes([0x04, 0x0E, FD]) + QD + bytes([FD, FF])),
    ]
    for name, prog in tests:
        resp = query_raw(prog)
        print(
            f"  {name:25s} -> {classify(resp):12s} raw={resp.hex() if resp else 'empty'}"
        )
        time.sleep(0.1)

    # Test what echo returns when given various syscall globals
    # The KEY insight: echo(x) returns Left(x), and then QD serializes x
    # So echo(write) + QD should give us the serialized form of the write syscall
    # This tells us: ARE SYSCALLS LAMBDA TERMS? Or are they special/opaque?
    print("\n[3b] What does quote(Var(N)) return for each global?")
    # quote(Var(N)) serializes the raw Var(N) — should just give us the byte N
    # But what about after evaluation? If Var(N) at top level IS a global,
    # does quote get the Var or the evaluated global?
    # Actually in CPS: ((quote arg) k) = (k (Left serialized_arg))
    # The arg is NOT evaluated before quote sees it — it's captured as-is.
    # But echo DOES evaluate... or does it? Let's check.

    print("\n[3c] CRITICAL: Does the second ?? get EVALUATED before the syscall?")
    print("  Testing: echo(((λx.x) Var(42))) — does echo see the redex or Var(42)?")
    # ((λx.x) Var(42)) should reduce to Var(42) if evaluated
    # echo(redex) via QD: 0E [redex] FD QD FD FF
    # redex = (λx.x)(42) = 00 FE 2A FD
    prog = bytes([0x0E, 0x00, FE, 0x2A, FD, FD]) + QD + bytes([FD, FF])
    resp = query_raw(prog)
    print(f"  echo(id(42)): {classify(resp)}  raw={resp.hex() if resp else 'empty'}")
    time.sleep(0.1)

    # Compare with echo(Var(42)) directly
    prog = bytes([0x0E, 0x2A, FD]) + QD + bytes([FD, FF])
    resp = query_raw(prog)
    print(f"  echo(42):     {classify(resp)}  raw={resp.hex() if resp else 'empty'}")
    time.sleep(0.1)


# ============================================================
# PHASE 4: Test sys8 in a CPS chain within ONE program
# ============================================================


def test_sys8_cps_chain():
    """
    Test sys8 when called as part of a CPS chain within a single program.
    E.g.: backdoor(nil, λpair. sys8(pair, QD))
    """
    print("\n" + "=" * 60)
    print("PHASE 4: SYS8 IN CPS CHAINS (single program)")
    print("=" * 60)

    def query_raw(payload: bytes, timeout_s: float = 10.0) -> bytes:
        delay = 0.15
        for _ in range(3):
            try:
                sock = socket.create_connection((HOST, PORT), timeout=timeout_s)
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                result = recv_all(sock, timeout_s=timeout_s)
                sock.close()
                return result
            except Exception:
                time.sleep(delay)
                delay *= 2
        return b""

    # 4a: backdoor(nil, λresult. sys8(result, QD))
    # CPS: ((backdoor nil) (λresult. ((sys8 result) QD)))
    # Encoding:
    # backdoor = 0xC9 (at top level)
    # nil = 00 FE FE
    # under 1 lambda: sys8 = Var(9), QD globals shift by 1
    # cont = λ. ((09 00 FD) QD_shifted FD) = body FE
    # QD at depth 1: all globals +1
    # QD = lam(app(app(g5,v0), app(app(g5,v0), app(app(g3, v0), lam(app(g2, lam(lam(v0))))))))
    # At depth 0: 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
    # At depth 1 (inside 1 extra lambda): all top-level globals shift +1
    # g5->6, g3->4, g2->3
    # QD_d1 = 06 00 FD 00 06 00 FD 04 FD FE FD 03 FD FE FD FE
    QD_d1 = bytes(
        [0x06, 0x00, FD, 0x00, 0x06, 0x00, FD, 0x04, FD, FE, FD, 0x03, FD, FE, FD, FE]
    )

    # cont = λ. ((Var(9) Var(0)) QD_d1) = 09 00 FD QD_d1 FD FE
    cont = bytes([0x09, 0x00, FD]) + QD_d1 + bytes([FD, FE])

    # Full program: ((0xC9 nil) cont) FF
    prog = bytes([0xC9]) + NIL + bytes([FD]) + cont + bytes([FD, FF])
    print(f"\n[4a] backdoor(nil) -> sys8(result) -> QD")
    print(f"  Payload ({len(prog)} bytes): {prog.hex()}")
    resp = query_raw(prog)
    print(f"  Result: {classify(resp)}  raw={resp[:60].hex() if resp else 'empty'}")
    time.sleep(0.2)

    # 4b: Same but with echo instead of sys8 (to verify the CPS chain works)
    # echo = 0x0E at top, under 1 lambda = 0x0F
    cont_echo = bytes([0x0F, 0x00, FD]) + QD_d1 + bytes([FD, FE])
    prog_echo = bytes([0xC9]) + NIL + bytes([FD]) + cont_echo + bytes([FD, FF])
    print(f"\n[4b] backdoor(nil) -> echo(result) -> QD (control)")
    resp = query_raw(prog_echo)
    print(f"  Result: {classify(resp)}  raw={resp[:60].hex() if resp else 'empty'}")
    time.sleep(0.2)

    # 4c: echo(nil) -> sys8(result) -> QD
    # echo is at top level = 0x0E
    # cont: λ. ((Var(9) Var(0)) QD_d1)
    cont_sys8 = bytes([0x09, 0x00, FD]) + QD_d1 + bytes([FD, FE])
    prog = bytes([0x0E]) + NIL + bytes([FD]) + cont_sys8 + bytes([FD, FF])
    print(f"\n[4c] echo(nil) -> sys8(result) -> QD")
    resp = query_raw(prog)
    print(f"  Result: {classify(resp)}  raw={resp[:60].hex() if resp else 'empty'}")
    time.sleep(0.2)

    # 4d: sys8(nil, λresult. echo(result, QD))
    # Does sys8 even CALL its continuation? If it always returns Right(6),
    # the continuation should receive Right(6) which is a term...
    # cont: λ. ((Var(0x0F) Var(0)) QD_d1)
    cont_echo2 = bytes([0x0F, 0x00, FD]) + QD_d1 + bytes([FD, FE])
    prog = bytes([0x08]) + NIL + bytes([FD]) + cont_echo2 + bytes([FD, FF])
    print(f"\n[4d] sys8(nil) -> echo(result) -> QD (does sys8 call continuation?)")
    resp = query_raw(prog)
    print(f"  Result: {classify(resp)}  raw={resp[:60].hex() if resp else 'empty'}")
    time.sleep(0.2)

    # 4e: sys8(nil, λresult. write(quote(result)))
    # This is essentially QD but manually constructed as continuation
    # Just use QD directly to confirm
    print(f"\n[4e] Baseline: sys8(nil) with standard QD")
    prog = bytes([0x08]) + NIL + bytes([FD]) + QD + bytes([FD, FF])
    resp = query_raw(prog)
    print(f"  Result: {classify(resp)}  raw={resp.hex() if resp else 'empty'}")


# ============================================================
# PHASE 5: Non-shutdown persistent exploration
# ============================================================


def test_no_shutdown_interaction():
    """
    space's script does NOT shutdown the write side.
    It sends data, reads response, sends more data.
    Test this pattern.
    """
    print("\n" + "=" * 60)
    print("PHASE 5: NO-SHUTDOWN INTERACTIVE PATTERN")
    print("=" * 60)

    # Replicate space's exact pattern: open socket, send hex, recv, loop
    print("\n[5a] Send QD only (no FF) — see if server waits for more input")
    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        # Send just QD without FF — server should wait
        sock.sendall(QD)
        resp = recv_timed(sock, timeout_s=3.0)
        print(f"  After QD (no FF): {classify(resp)}")

        # Now send FF
        sock.sendall(bytes([FF]))
        resp = recv_timed(sock, timeout_s=5.0)
        print(f"  After FF: {classify(resp)}  raw={resp.hex() if resp else 'empty'}")
        sock.close()
    except Exception as e:
        print(f"  ERROR: {e}")

    time.sleep(0.3)

    print("\n[5b] Send 'QD ?? FD' split: first QD, then '?? FD FF'")
    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
        # Send QD first
        sock.sendall(QD)
        time.sleep(0.1)
        # Then send argument + FD + FF
        # QD Var(42) FD FF — should print the serialized Var(42)
        sock.sendall(bytes([0x2A, FD, FF]))
        resp = recv_timed(sock, timeout_s=5.0)
        print(f"  QD Var(42): {classify(resp)}  raw={resp.hex() if resp else 'empty'}")
        sock.close()
    except Exception as e:
        print(f"  ERROR: {e}")

    time.sleep(0.3)

    print("\n[5c] Interactive: towel first, then sys8, on one socket (no shutdown)")
    try:
        sock = socket.create_connection((HOST, PORT), timeout=15)
        # Program 1: towel syscall
        prog1 = bytes([0x2A, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])
        sock.sendall(prog1)
        resp1 = recv_timed(sock, timeout_s=5.0)
        print(f"  Towel result: {classify(resp1)}")

        # Program 2: sys8 on same socket
        prog2 = bytes([0x08, 0x00, FE, FE, FD]) + QD + bytes([FD, FF])
        sock.sendall(prog2)
        resp2 = recv_timed(sock, timeout_s=5.0)
        print(
            f"  sys8 after towel: {classify(resp2)}  raw={resp2.hex() if resp2 else 'empty'}"
        )
        sock.close()
    except Exception as e:
        print(f"  ERROR: {e}")


def main():
    print("=" * 60)
    print("BrownOS PERSISTENT SOCKET + CONTINUATION SENSITIVITY PROBE")
    print("=" * 60)

    test_persistent_socket()
    test_continuation_sensitivity()
    test_cheatsheet_second_example()
    test_sys8_cps_chain()
    test_no_shutdown_interaction()

    print("\n" + "=" * 60)
    print("ALL TESTS COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
