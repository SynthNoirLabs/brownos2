#!/usr/bin/env python3
"""
HYPOTHESIS: Syscall 8 might check its continuation and return different results.

When we use QD as continuation → Right(6) "Permission denied"
When we use A/B/identity as continuation → EMPTY (but no output)

What if syscall 8:
- Returns Left(answer) when continuation is "trusted"
- Returns Right(6) when continuation looks like QD

We need a continuation that:
1. ISN'T QD
2. But still writes output
3. To see what syscall 8 actually returns
"""

import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
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
    raise TypeError(f"Unknown: {type(term)}")


def query(payload: bytes, timeout_s: float = 8.0) -> bytes:
    try:
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(timeout_s)
            out = b""
            start = time.time()
            while time.time() - start < timeout_s:
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


def encode_byte_term(n: int):
    expr = Var(0)
    for idx, weight in [
        (8, 128),
        (7, 64),
        (6, 32),
        (5, 16),
        (4, 8),
        (3, 4),
        (2, 2),
        (1, 1),
    ]:
        if n & weight:
            expr = App(Var(idx), expr)
    term = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_string(s: str):
    def cons(h, t):
        return Lam(Lam(App(App(Var(1), h), t)))

    cur = nil
    for b in reversed(s.encode()):
        cur = cons(encode_byte_term(b), cur)
    return cur


def test_custom_continuations():
    """
    Test syscall 8 with various custom continuations that still write output.
    """
    print("=" * 70)
    print("HYPOTHESIS: Syscall 8 checks continuation type")
    print("=" * 70)

    # Continuation 1: Simple write-based handler
    # λresult. ((write "X") nil)
    # This ignores the result but writes "X" to confirm continuation was called
    write_x = Lam(
        App(App(Var(3), encode_string("X")), nil)
    )  # write = Var(2), shifted by 1

    print("\n[1] ((syscall8 nil) λr.write('X'))")
    payload = (
        bytes([0x08])
        + encode_term(nil)
        + bytes([FD])
        + encode_term(write_x)
        + bytes([FD, FF])
    )
    resp = query(payload)
    print(f"    Response: {resp!r}")
    time.sleep(0.3)

    # Continuation 2: Write "L" if Left, "R" if Right
    # λresult. ((result λx.write("L") λx.write("R")))
    left_handler = Lam(App(App(Var(4), encode_string("L")), nil))  # write shifted
    right_handler = Lam(App(App(Var(4), encode_string("R")), nil))
    either_handler = Lam(App(App(Var(0), left_handler), right_handler))

    print("\n[2] ((syscall8 nil) λr.(r (λ.write'L') (λ.write'R')))")
    payload = (
        bytes([0x08])
        + encode_term(nil)
        + bytes([FD])
        + encode_term(either_handler)
        + bytes([FD, FF])
    )
    resp = query(payload)
    print(f"    Response: {resp!r}")
    time.sleep(0.3)

    # Continuation 3: Try to extract Left payload and write it
    # λresult. (result (λpayload. ((write ((quote payload) nil)) nil)) (λerr. write("E")))
    # This is complex - let's try a simpler version first

    # Continuation 4: Use error syscall to convert error code to string
    # λresult. (result (λx.write"L") (λerrcode. ((error errcode) (λstr. (write str nil)))))

    # Let's try: write the result of (error 6) to see if we can trigger that path
    print("\n[3] Direct: ((error 6) (λstr.((write str) nil)))")
    error_cont = Lam(App(App(Var(3), Var(0)), nil))  # λstr. ((write str) nil)
    payload = (
        bytes([0x01])
        + encode_term(encode_byte_term(6))
        + bytes([FD])
        + encode_term(error_cont)
        + bytes([FD, FF])
    )
    resp = query(payload)
    print(f"    Response: {resp!r} (should be 'Permission denied')")
    time.sleep(0.3)

    # Now the real test: syscall8 with Either handler that uses error syscall for Right
    print("\n[4] ((syscall8 nil) EitherHandler) where Right → error → write")
    # This is getting complex. Let me simplify.

    # What if we just write a marker BEFORE calling syscall 8?
    print("\n[5] Write 'A' then syscall8 then write 'B'")
    # ((write "A") λ_. ((syscall8 nil) λ_. ((write "B") nil)))
    inner = Lam(App(App(Var(3), encode_string("B")), nil))  # λ_. write "B"
    syscall_part = App(App(Var(8), nil), inner)  # ((syscall8 nil) inner)
    outer = Lam(syscall_part)  # λ_. syscall_part
    full = App(App(Var(2), encode_string("A")), outer)  # ((write "A") outer)

    payload = encode_term(full) + bytes([FF])
    resp = query(payload)
    print(f"    Response: {resp!r}")
    time.sleep(0.3)


def test_backdoor_as_continuation():
    """
    What if we use the backdoor RESULT as syscall8's continuation?
    """
    print("\n" + "=" * 70)
    print("TEST: Backdoor result as syscall8 continuation")
    print("=" * 70)

    # backdoor(nil) → Left(pair)
    # We want: syscall8(nil) with pair as continuation
    # pair = λs. s A B

    # Chain: backdoor(nil) → extract pair → ((syscall8 arg) pair)
    # But pair expects a selector, so (pair result) = (result A B)
    # If result is Right(6), then (Right(6) A B) = (B 6) = (λab.ab) 6 = λb.6b
    # If result is Left(x), then (Left(x) A B) = (A x) = (λab.bb) x = λb.bb

    # Hmm, let me think... using pair as continuation means:
    # ((syscall8 nil) pair) → (pair result) → (result A B)

    # Let's trace:
    # If result = Right(y) = λl.λr. r y
    # Then (result A B) = ((λl.λr. r y) A B) = (B y) = (λa.λb. a b) y = λb. y b
    # This is a lambda, no output.

    # If result = Left(x) = λl.λr. l x
    # Then (result A B) = ((λl.λr. l x) A B) = (A x) = (λa.λb. b b) x = λb. b b
    # This is also a lambda (little omega pattern), no output.

    # So that explains the empty responses! The pair as continuation produces lambdas.

    print("  Analysis: Using pair as continuation produces lambdas (no output)")
    print("  (Right(y) A B) → λb.(y b)")
    print("  (Left(x) A B) → λb.(b b) = omega pattern")


def test_minimal_3_leaf_with_write():
    """
    What if the "3 leafs" solution involves writing directly?
    """
    print("\n" + "=" * 70)
    print("TEST: Minimal 3-leaf patterns with direct write")
    print("=" * 70)

    # 3 leaves: V(a), V(b), V(c)
    # Patterns: ((Va Vb) Vc), (Va (Vb Vc))

    # What if the solution is just: ((write something) nil) with 3 leaves?
    # write = V2, so: ((V2 X) nil) where X has 1 leaf

    # Actually, what if the answer is hidden in a global we haven't explored?
    # Let's try quoting some unexplored globals

    print("\n  Testing: quote(Var(i)) for various i")
    for i in [0, 8, 9, 10, 11, 12, 13, 14, 15, 200, 201, 202]:
        payload = bytes([0x04, i, FD]) + QD + bytes([FD, FF])
        resp = query(payload, timeout_s=3)
        if resp and resp != b"\xff" and b"Right" not in resp:
            print(f"    quote(V{i}): {resp.hex()[:40]}...")
        time.sleep(0.1)


def test_echo_chain_to_syscall8():
    """
    The author said "why would an OS need echo?" - maybe echo is the key.

    echo(251) → Left(Var(253))  [253 = 0xFD = App marker]

    What if we need to USE Var(253) in a specific way with syscall8?
    """
    print("\n" + "=" * 70)
    print("TEST: Echo chain patterns")
    print("=" * 70)

    # Pattern 1: echo(251) → extract Var(253) → use as syscall8 ARGUMENT
    # We've tried this, got Right(6)

    # Pattern 2: echo(251) → extract Var(253) → APPLY to syscall8
    # (Var(253) syscall8) - treating Var(253) as a function

    # Pattern 3: Build a term with Var(253) that when evaluated does something special

    # Let's try: echo(Var(8)) - echo the syscall8 reference itself!
    print("\n  [1] echo(Var(8)) - echo the syscall8 reference")
    # This should return Left(Var(10)) due to +2 shift
    payload = bytes([0x0E, 0x08, FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    print(f"      Response: {resp.hex() if resp else 'empty'}")
    time.sleep(0.3)

    # Pattern 4: What about echo(Var(201))? That's the backdoor syscall!
    print("\n  [2] echo(Var(201)) - echo the backdoor reference")
    payload = bytes([0x0E, 201, FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    print(f"      Response: {resp.hex() if resp else 'empty'}")
    time.sleep(0.3)

    # Pattern 5: Chain echo twice to get bigger shifts
    # echo(echo(249)) → echo(Left(Var(251))) → ???
    print("\n  [3] Double echo: echo(249) then echo result")
    # First: echo(249) → Left(Var(251))
    # Then: echo(that Left) → Left(Left(Var(253)))? Or error?

    # Build: echo(249) → λresult. ((result (λv.echo(v)) err))
    # Actually this is complex. Let me try raw.

    # echo(Var(252)) → Left(Var(254)) [254 = 0xFE = Lambda marker]
    print("\n  [4] echo(252) - get Var(254) = Lambda marker")
    payload = bytes([0x0E, 252, FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    print(f"      Response: {resp!r}")
    time.sleep(0.3)


def test_omega_computation():
    """
    Since (A B) = ω = λx.xx, what can we compute with omega?
    """
    print("\n" + "=" * 70)
    print("TEST: Omega combinator computations")
    print("=" * 70)

    # ω = λx.xx
    omega = Lam(App(Var(0), Var(0)))

    # Ω = ω ω = infinite loop (will timeout)
    # Don't test this - it diverges

    # But (ω f) where f is some function might be interesting
    # (ω f) = (λx.xx) f = f f

    # What if f = syscall8? Then (ω syscall8) = (syscall8 syscall8)
    # That would call syscall8 with itself as argument!

    print("\n  [1] (ω syscall8) = (syscall8 syscall8)")
    payload = encode_term(App(omega, Var(8))) + bytes([FF])
    resp = query(payload, timeout_s=5)
    print(f"      Response: {resp!r}")
    time.sleep(0.3)

    # What about ((ω syscall8) QD)?
    print("\n  [2] ((ω syscall8) QD) = ((syscall8 syscall8) QD)")
    payload = encode_term(App(App(omega, Var(8)), Var(8))) + bytes([FF])
    # Wait, that's wrong. Let me redo.
    # (ω Var(8)) = (Var(8) Var(8))
    # Then apply QD: ((Var(8) Var(8)) QD)
    term = App(App(App(omega, Var(8)), Var(8)), Lam(Var(0)))  # wrong
    # Actually: ((ω g) k) where g=syscall8, k=QD
    # = (((λx.xx) g) k) = ((g g) k)

    # Let me just send: ((8 8) QD)
    term = App(App(Var(8), Var(8)), Var(0))  # syscall8(syscall8) with identity cont
    # Hmm no that's not right either

    # Simpler: just send 08 08 FD + QD + FD FF
    print("\n  [3] Raw: ((Var(8) Var(8)) QD) - syscall8 with itself as arg")
    payload = bytes([0x08, 0x08, FD]) + QD + bytes([FD, FF])
    resp = query(payload)
    print(f"      Response: {resp.hex() if resp else 'empty'}")
    time.sleep(0.3)


def test_direct_answer_extraction():
    """
    Maybe the answer is hidden in a file or syscall we haven't fully explored.
    """
    print("\n" + "=" * 70)
    print("TEST: Direct answer extraction attempts")
    print("=" * 70)

    # Read file 256 ("wtf") content again
    print("\n  [1] Read file 256 content")
    payload = (
        bytes([0x07])
        + encode_term(encode_byte_term(256))
        + bytes([FD])
        + QD
        + bytes([FD, FF])
    )
    resp = query(payload)
    print(f"      Response length: {len(resp)} bytes")
    # Can't easily decode here, but we know it's "Uhm... yeah... no..."
    time.sleep(0.3)

    # Try name(257), name(258), etc. - maybe more hidden entries?
    print("\n  [2] Looking for hidden entries beyond 256")
    for fid in [257, 258, 259, 260, 300, 400, 500, 512, 1000]:
        payload = (
            bytes([0x06])
            + encode_term(encode_byte_term(fid))
            + bytes([FD])
            + QD
            + bytes([FD, FF])
        )
        resp = query(payload, timeout_s=2)
        if resp and len(resp) > 5:  # More than just Right(3)
            print(f"      name({fid}): {len(resp)} bytes - INTERESTING!")
        time.sleep(0.1)

    # What about negative or special IDs?
    print("\n  [3] Special ID patterns")
    for fid in [255, 254, 253]:  # These are special bytes
        # Encode as Church numeral
        payload = (
            bytes([0x06])
            + encode_term(encode_byte_term(fid))
            + bytes([FD])
            + QD
            + bytes([FD, FF])
        )
        resp = query(payload, timeout_s=2)
        print(f"      name({fid}): {resp.hex()[:30] if resp else 'empty'}...")
        time.sleep(0.1)


def main():
    print("=" * 70)
    print("PROBING SYSCALL 8 - CONTINUATION HYPOTHESIS")
    print("=" * 70)
    print()

    test_custom_continuations()
    time.sleep(0.5)

    test_backdoor_as_continuation()
    time.sleep(0.5)

    test_minimal_3_leaf_with_write()
    time.sleep(0.5)

    test_echo_chain_to_syscall8()
    time.sleep(0.5)

    test_omega_computation()
    time.sleep(0.5)

    test_direct_answer_extraction()

    print("\n" + "=" * 70)
    print("PROBING COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
