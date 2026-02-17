#!/usr/bin/env python3
"""
probe_high_index_syscall.py — Probe high-index global variables (253+)

The wire format only allows Var(0)..Var(252) as direct bytes. But using
lambda wrapping + free variable shifting, we can reach ANY global index
via beta-reduction.

MECHANISM:
Inside k lambdas, a free Var(N+k) refers to global Var(N).
After beta-reduction (eliminating k lambdas), it shifts back down.

To CALL global Var(TARGET) as a syscall:
  ((λ^k . (Var(TARGET+k) arg)) dummy^k)
  where TARGET+k <= 252 (max encodable byte).

For TARGET=253: k lambdas, need Var(253+k) <= 252... impossible!

ALTERNATIVE: Use FREE variables that are ALREADY shifted.
Inside k lambdas, free Var(m) (where m >= k) refers to global Var(m-k).
If we can place a large Var(m) inside k lambdas, it refers to global Var(m-k).

But we're CONSTRUCTING the program at the top level, then wrapping in lambdas.
Inside the lambda body, we write Var(N) where N is the byte value.
If N >= k (number of wrapping lambdas), it's free and refers to global Var(N-k).
Max N = 252 (0xFC). With k wrapping lambdas, the highest reachable global
is Var(252-k). For k=1: max global = Var(251). This is LOWER than 252!

Wait — that's the OPPOSITE of what we want. More lambdas = LOWER max global.

Hmm. Let me reconsider.

At the TOP LEVEL (k=0 lambdas):
  Var(252) = byte 0xFC = global Var(252). This is the max.

Inside 1 lambda (k=1):
  Var(252) = byte 0xFC = free variable referring to global Var(251).
  (Because Var(0) is the lambda param, everything else shifts.)

So wrapping in MORE lambdas makes high bytes refer to LOWER globals.
We can never reach globals ABOVE 252 this way.

The ONLY way to reach global Var(253+) through the wire format would be
if the VM performs some operation that creates high-index references
internally during evaluation. For example:
- If echo (sys14) returns a term containing high-index Vars
- If backdoor (sys201) returns something useful
- If there's a "shift" or "lift" operation

But echo returns its argument unchanged, and backdoor returns the fixed pair.

ACTUALLY — let me reconsider. What about using the RESULT of a computation?

Approach: Use CPS to chain: get a result from one syscall, then use that
result AS a function (i.e., apply it as if it were a syscall).

For example:
  ((echo Var(252)) (λ result. ((result arg) QD)))

Echo returns Left(Var(252)). But Left is λl.λr.(l Var(252+2)) — the payload
is shifted by 2 inside the Either wrapper. When we unwrap it, we get the
original Var(252) back. Not helpful.

What about the BACKDOOR? It returns a pair. What if we apply the pair
components in unexpected ways?

Or: what if there are globals at indices 253-255 that are NOT syscalls but
rather special VALUES that serve as "keys" or "capabilities"?

Since we can't directly reference them, maybe they're only accessible
INDIRECTLY — through some syscall that returns a reference to them?

PLAN:
1. Use lambda wrapping to sweep globals 0..252 with QD (sanity check)
2. Try using CPS chains where the RESULT of one syscall is applied as a function
3. Test if any syscall result, when applied to sys8's number, grants access
4. Test very high globals via deeply nested lambda chains (reaching 253+)

Wait — I just realized there IS a way to reach Var(253+).

The trick: use NEGATIVE shifting. After beta-reduction, free variables
shift DOWN. So if we have MORE wrapping lambdas than expected...

Actually, let me think about this from the byte-level perspective.

To get global Var(253) into a term via beta-reduction:
  Start with App(Lam(body), arg) at top level.
  After beta: body[0 := arg] then shift down by 1.

  If body = Var(1), this shifts to Var(0) = global Var(0). Boring.
  If body = Var(252), this shifts to Var(251). Still under 253.

  But what if we have NESTED beta-reductions?
  Each lambda elimination shifts everything down by 1.
  But the maximum starting value is 252.
  So max reachable after eliminating k lambdas = 252 - k. LOWER.

OK so through beta-reduction alone, we can only reach globals 0..252.
This is because:
1. Wire format caps variable indices at 252
2. Beta-reduction can only DECREASE free variable indices (shift down)
3. There's no mechanism to INCREASE a variable index through evaluation

UNLESS: the VM has some other mechanism. What if:
- Application of a non-lambda to an argument produces something special?
- The VM has built-in reduction rules for certain "global" applications?

In a standard lambda calculus VM, Var(N) applied to arguments is either:
1. A built-in syscall (if N is a known syscall number)
2. Just a stuck application (if N is unknown)

The VM might reduce ((Var(253) arg) cont) in a special way even though
we can't construct such a term through the wire format. But since we
CAN'T construct it, this is moot.

ALTERNATIVE THEORY: The answer is NOT obtained through sys8 succeeding.
Maybe we need to think about what we CAN do differently.

Let me instead focus on exhaustive testing of:
1. All syscalls with COMPLEX arguments (pairs, nested structures)
2. Using the backdoor pair result as a syscall-like function
3. Using any globals (0-252) that we haven't tested as functions
4. The "3 leafs" hint (if it's real)

Also: there's one more thing we can try with high indices:
if we build a term where a SUBSTITUTION produces a variable index
that then gets applied as a syscall during continued evaluation.

Example: Create a term where beta-reduction produces (Var(253) arg cont)
by having the substituted value contribute to the index.

Hmm, that's not how lambda calculus works. Variables are atomic.

OK, let me focus on what's ACTUALLY doable.
"""

from __future__ import annotations

import socket
import time

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FD,
    FE,
    FF,
    QD,
    decode_byte_term,
    decode_bytes_list,
    decode_either,
    encode_byte_term,
    encode_bytes_list,
    encode_term,
    parse_term,
)


HOST = "wc3.wechall.net"
PORT = 61221

CONNECT_TIMEOUT = 15.0
READ_TIMEOUT = 5.0
MAX_READ = 10 * 1024

NIL = Lam(Lam(Var(0)))


def recv_smart(sock, timeout_s=READ_TIMEOUT):
    sock.settimeout(timeout_s)
    out = b""
    while len(out) < MAX_READ:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        out += chunk
        if FF in chunk:
            break
    return out


def query_raw(payload, retries=3):
    delay = 0.2
    for attempt in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=CONNECT_TIMEOUT) as s:
                s.sendall(payload)
                try:
                    s.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_smart(s)
        except Exception as e:
            if attempt == retries - 1:
                return f"ERR:{e}".encode()
            time.sleep(delay)
            delay *= 2
    return b""


def interpret(data):
    if not data:
        return "EMPTY"
    if data.startswith(b"ERR:"):
        return data.decode("utf-8", "replace")
    for prefix in [b"Invalid term!", b"Term too big!", b"Encoding failed!"]:
        if data.startswith(prefix):
            return prefix.decode()
    if FF not in data:
        text = data.decode("utf-8", "replace")
        return f"Raw(no FF): {text!r}"
    try:
        term = parse_term(data[: data.index(FF) + 1])
    except Exception:
        return f"ParseErr: {data[:50].hex()}"
    try:
        tag, payload = decode_either(term)
        if tag == "Right":
            try:
                return f"R({decode_byte_term(payload)})"
            except Exception:
                return "R(<complex>)"
        try:
            bs = decode_bytes_list(payload)
            preview = bs[:80].decode("utf-8", "replace")
            return f"L(len={len(bs)}, {preview!r})"
        except Exception:
            return f"L(<non-bytes>)"
    except Exception:
        return f"Term(non-Either)"


def test(label, payload):
    """Run test and print result."""
    result = query_raw(payload)
    interp = interpret(result)
    print(f"  {label}: {interp}")
    return interp


def make_syscall_qd(syscall_var_index, arg):
    """Build ((Var(N) arg) QD) FF payload."""
    # If N <= 252, we can encode directly
    if syscall_var_index <= 252:
        return (
            bytes([syscall_var_index])
            + encode_term(arg)
            + bytes([FD])
            + QD
            + bytes([FD, FF])
        )
    else:
        # Need lambda wrapping: use k lambdas where k = N - 252
        # Inside k lambdas, Var(252) = byte 0xFC refers to global Var(252-k)
        # We want global Var(N), so we need Var(N+k) inside k lambdas
        # But N+k > 252... hmm.
        #
        # ACTUALLY: inside k lambdas, free Var(252) refers to global Var(252-k).
        # To refer to global Var(N), we need Var(N+k) inside k lambdas.
        # N+k must be <= 252, so k <= 252-N. Since N >= 253, k <= -1. Impossible!
        #
        # So we truly cannot reach globals > 252. See the analysis above.
        # But let's try anyway with a workaround:
        # Use the SHIFTED free variable approach where we place Var(252)
        # inside (252-N) lambdas... but 252-N < 0 when N > 252.
        #
        # Final answer: we CANNOT reach globals > 252 through the wire format.
        raise ValueError(f"Cannot encode syscall at global index {syscall_var_index}")


def make_bypass_syscall_qd(target_global, arg, num_wrapping_lambdas=1):
    """
    Call global Var(target_global) using lambda wrapping to avoid literal byte.
    Inside `num_wrapping_lambdas` lambdas, we use Var(target_global + num_wrapping_lambdas)
    as a free variable. After beta-reduction (eliminating the lambdas), it shifts
    down to global Var(target_global).

    The byte value is target_global + num_wrapping_lambdas, which must be <= 252.
    """
    shifted_index = target_global + num_wrapping_lambdas
    if shifted_index > 252:
        raise ValueError(
            f"Cannot bypass: target {target_global} + {num_wrapping_lambdas} lambdas "
            f"= {shifted_index} > 252"
        )

    # Build: ((λ^k . (Var(shifted) arg)) dummy^k) with QD outside
    # Body: App(Var(shifted_index), arg) under k lambdas
    body = App(Var(shifted_index), arg)
    for _ in range(num_wrapping_lambdas):
        body = Lam(body)

    # Apply to k dummies
    term = body
    for _ in range(num_wrapping_lambdas):
        term = App(term, NIL)

    # Add QD continuation
    return encode_term(term) + QD + bytes([FD, FF])


# =============================================================================
# PHASE 1: Verify the sweep of known syscalls via bypass method
# =============================================================================
def phase_1_verify_known():
    print("=" * 70)
    print("PHASE 1: Verify known syscalls via bypass (sanity check)")
    print("=" * 70)

    known = {
        1: "error_string",
        4: "quote",
        5: "readdir",
        6: "name",
        7: "readfile",
        8: "sys8",
        14: "echo",
        42: "towel",
        201: "backdoor",
    }

    for idx, name in sorted(known.items()):
        payload = make_bypass_syscall_qd(idx, NIL, num_wrapping_lambdas=1)
        test(f"bypass Var({idx})={name}, nil arg", payload)
        time.sleep(0.15)


# =============================================================================
# PHASE 2: Sweep UNCHARTED territory — globals near 253 using bypass
# =============================================================================
def phase_2_near_253():
    """
    We swept 0-252 directly. But we ALSO need to sweep them with bypass
    to check if the bypass mechanism itself triggers different behavior.

    Focus on indices 240-252 (near the boundary) and check if any behave
    differently when called via bypass vs direct.
    """
    print("\n" + "=" * 70)
    print("PHASE 2: Sweep globals 240-252 via bypass (near boundary)")
    print("=" * 70)

    for idx in range(240, 253):
        # Direct call
        direct_payload = (
            bytes([idx]) + encode_term(NIL) + bytes([FD]) + QD + bytes([FD, FF])
        )
        direct_result = test(f"DIRECT Var({idx}), nil arg", direct_payload)
        time.sleep(0.1)

        # Bypass call (skip if shifted index > 252)
        shifted = idx + 1
        if shifted <= 252:
            bypass_payload = make_bypass_syscall_qd(idx, NIL, num_wrapping_lambdas=1)
            bypass_result = test(f"BYPASS Var({idx}), nil arg", bypass_payload)
            time.sleep(0.1)

            if direct_result != bypass_result:
                print(
                    f"  *** MISMATCH at Var({idx}): direct={direct_result}, bypass={bypass_result}"
                )
        else:
            print(f"  BYPASS Var({idx}): skipped (shifted {shifted} > 252)")


# =============================================================================
# PHASE 3: Use backdoor pair components AS syscall functions
# =============================================================================
def phase_3_pair_as_syscall():
    """
    The backdoor returns pair = λf.f A B where:
    A = λab.(bb), B = λab.(ab)

    What if we're supposed to USE one of these as a function that
    somehow interacts with sys8 or acts as an authenticator?

    Test: ((A something) QD) and ((B something) QD)
    Also: (((pair True) arg) QD) — extracting A, applying to arg
    """
    print("\n" + "=" * 70)
    print("PHASE 3: Use backdoor pair components as functions")
    print("=" * 70)

    # First get the backdoor pair
    bd_payload = bytes([0xC9]) + encode_term(NIL) + bytes([FD]) + QD + bytes([FD, FF])
    bd_raw = query_raw(bd_payload)
    if FF not in bd_raw:
        print("  Failed to get backdoor response")
        return

    bd_term = parse_term(bd_raw[: bd_raw.index(FF) + 1])
    tag, pair_term = decode_either(bd_term)
    if tag != "Left":
        print(f"  Backdoor returned {tag}, expected Left")
        return
    print(f"  Got backdoor pair: OK")

    # pair_term is λf. f A B
    # To extract A: apply pair to True (λab.a = Lam(Lam(Var(1))))
    # To extract B: apply pair to False (λab.b = Lam(Lam(Var(0))))
    TRUE = Lam(Lam(Var(1)))
    FALSE = Lam(Lam(Var(0)))

    A_term = App(pair_term, TRUE)  # pair True = A
    B_term = App(pair_term, FALSE)  # pair False = B

    # Test A applied to various things
    for name, arg in [
        ("nil", NIL),
        ("int0", encode_byte_term(0)),
        ("int8", encode_byte_term(8)),
    ]:
        payload = encode_term(App(A_term, arg)) + QD + bytes([FD, FF])
        test(f"(A {name}) + QD", payload)
        time.sleep(0.15)

    # Test B applied to various things
    for name, arg in [
        ("nil", NIL),
        ("int0", encode_byte_term(0)),
        ("int8", encode_byte_term(8)),
    ]:
        payload = encode_term(App(B_term, arg)) + QD + bytes([FD, FF])
        test(f"(B {name}) + QD", payload)
        time.sleep(0.15)

    # Test A applied to B, and B applied to A
    payload_ab = encode_term(App(A_term, B_term)) + QD + bytes([FD, FF])
    test("(A B) + QD = omega?", payload_ab)
    time.sleep(0.15)

    payload_ba = encode_term(App(B_term, A_term)) + QD + bytes([FD, FF])
    test("(B A) + QD", payload_ba)
    time.sleep(0.15)

    # CPS: ((backdoor nil) (λ pair. ((pair (λa.λb. ((a sys8_bypass) QD))) dummy)))
    # Inside depth 1: pair = Var(0), sys8 = Var(9)
    # pair True = A = λab.bb
    # pair (λa.λb. ((a Var(9) nil) QD_shifted)) — use A's structure to access sys8?
    # A = λab.bb. If we pass sys8 as first arg to A: A sys8 = λb.bb = just applies b to b
    # That's not useful.

    # What if pair itself is a capability token? Apply pair to sys8 directly?
    # ((pair Var(8)) QD) — pair applied to sys8
    # pair = λf.f A B, so pair(sys8) = sys8 A B = ((sys8 A) B)
    # This would be sys8 applied to A with continuation B.
    # B = λab.ab, so B(result) = λb.(result b) — it applies result to its arg.
    #
    # This is actually interesting! ((sys8 A) B) could mean:
    # sys8(A) returns result, then B(result) = λb.(result b)
    # If sys8(A) succeeds, result is Left(answer), and B applies it further.
    # But sys8 always returns Right(6)...
    # UNLESS the pair acts as credentials!

    # Let's try: pair applied to sys8 (pair is the "authenticator"?)
    # We need this without literal 0x08, so use bypass.
    # Inside 1 lambda: pair=Var(0), sys8=Var(9)
    # ((Var(0) Var(9)) QD↑1)

    def shift_term(term, d, c=0):
        if isinstance(term, Var):
            return Var(term.i + d) if term.i >= c else term
        if isinstance(term, Lam):
            return Lam(shift_term(term.body, d, c + 1))
        if isinstance(term, App):
            return App(shift_term(term.f, d, c), shift_term(term.x, d, c))
        raise TypeError(f"Unknown: {type(term)}")

    qd_term = parse_term(QD + bytes([FF]))
    qd_s1 = shift_term(qd_term, 1)

    # CPS: ((backdoor nil) (λ pair. ((pair sys8_ref) QD↑1)))
    # pair(sys8_ref) = sys8_ref A B = ((sys8 A) B)
    cont_pair_sys8 = Lam(App(App(Var(0), Var(9)), qd_s1))
    full_pair_sys8 = App(App(Var(201), NIL), cont_pair_sys8)
    payload_pair_sys8 = encode_term(full_pair_sys8) + bytes([FF])
    test(
        "((backdoor nil) (λ pair. ((pair sys8) QD↑1))) — pair dispatches sys8",
        payload_pair_sys8,
    )
    time.sleep(0.15)

    # Also: give pair to sys8 AS the argument, with QD
    # ((sys8 pair) QD) — but via bypass
    cont_sys8_pair = Lam(App(App(Var(9), Var(0)), qd_s1))
    full_sys8_pair = App(App(Var(201), NIL), cont_sys8_pair)
    payload_sys8_pair = encode_term(full_sys8_pair) + bytes([FF])
    test(
        "((backdoor nil) (λ pair. ((sys8 pair) QD↑1))) — sys8(pair)", payload_sys8_pair
    )


# =============================================================================
# PHASE 4: CPS chain — use result of one syscall to INVOKE another
# =============================================================================
def phase_4_cps_invoke():
    """
    What if sys8 only succeeds when called from WITHIN the continuation
    of another specific syscall? I.e., the "kernel" grants permission
    based on the calling context, not just the term structure.

    We tested CPS chains in Phase 5/6/7 of the bypass probe, but let's
    be more systematic: try ALL implemented syscalls as the "setup" call,
    then sys8 in the continuation.
    """
    print("\n" + "=" * 70)
    print("PHASE 4: CPS chains — syscall X → sys8 in continuation")
    print("=" * 70)

    def shift_term(term, d, c=0):
        if isinstance(term, Var):
            return Var(term.i + d) if term.i >= c else term
        if isinstance(term, Lam):
            return Lam(shift_term(term.body, d, c + 1))
        if isinstance(term, App):
            return App(shift_term(term.f, d, c), shift_term(term.x, d, c))
        raise TypeError(f"Unknown: {type(term)}")

    qd_term = parse_term(QD + bytes([FF]))

    # Pattern: ((syscall_X arg_X) (λ result_X. ((sys8 arg_8) QD↑1)))
    # Inside continuation: sys8 = Var(9), result_X = Var(0)
    qd_s1 = shift_term(qd_term, 1)

    # Continuation that calls sys8(nil) with QD
    cont_sys8_nil = Lam(App(App(Var(9), NIL), qd_s1))

    # Continuation that calls sys8(result_of_X) with QD
    cont_sys8_result = Lam(App(App(Var(9), Var(0)), qd_s1))

    setup_calls = [
        # (syscall_index, arg, name)
        (1, encode_byte_term(6), "error_string(6)"),  # "Permission denied" string
        (4, NIL, "quote(nil)"),  # serialized nil
        (5, encode_byte_term(0), "readdir(root)"),  # root directory listing
        (6, encode_byte_term(14), "name(14=sh)"),  # file name
        (7, encode_byte_term(88), "readfile(88=mail)"),  # mail content
        (14, NIL, "echo(nil)"),  # echo
        (14, encode_byte_term(8), "echo(int8)"),  # echo of sys8 number
        (42, NIL, "towel(nil)"),  # towel
        (201, NIL, "backdoor(nil)"),  # backdoor pair
    ]

    for sc_idx, sc_arg, sc_name in setup_calls:
        # Test 1: setup → sys8(nil)
        full = App(App(Var(sc_idx), sc_arg), cont_sys8_nil)
        payload = encode_term(full) + bytes([FF])
        test(f"{sc_name} → sys8(nil)", payload)
        time.sleep(0.1)

        # Test 2: setup → sys8(result_of_setup)
        full2 = App(App(Var(sc_idx), sc_arg), cont_sys8_result)
        payload2 = encode_term(full2) + bytes([FF])
        test(f"{sc_name} → sys8(result)", payload2)
        time.sleep(0.1)


# =============================================================================
# PHASE 5: The "3 leafs" minimal program
# =============================================================================
def phase_5_three_leafs():
    """
    If the author tip is real: "My record is 3 leafs IIRC"
    A "leaf" in a lambda calculus term is a Var node.
    A term with exactly 3 Var nodes (3 leaves):

    Minimal shapes with 3 leaves:
    - App(App(Var(a), Var(b)), Var(c)) = ((a b) c) — 2 apps, 3 vars
    - App(Var(a), App(Var(b), Var(c))) = (a (b c)) — 2 apps, 3 vars
    - Lam(App(App(Var(a), Var(b)), Var(c))) — 1 lam, 2 apps, 3 vars
    - etc.

    The CPS syscall pattern is: ((syscall arg) continuation)
    That's App(App(Var(syscall), arg), continuation)
    With arg = Var(X) and continuation = Var(Y), we get 3 leaves total.

    So a "3 leaf" successful program might be:
    ((Var(8) Var(X)) Var(Y)) FF

    We need to find the right X and Y.

    Or without the CPS convention:
    (Var(a) (Var(b) Var(c))) FF

    Let's exhaustively try all 3-leaf programs of the form ((a b) c) FF
    where a, b, c ∈ {0..20} + {interesting values}.

    Also try (a (b c)) FF.
    """
    print("\n" + "=" * 70)
    print("PHASE 5: Three-leaf programs — exhaustive small search")
    print("=" * 70)

    # For ((Var(8) Var(X)) Var(Y)) FF:
    # This is sys8(Var(X)) with Var(Y) as continuation.
    # Var(Y) must be a continuation that "works" — meaning it can print output.
    # The only globals that print are write(2) and the QD macro.
    # But QD is not a single Var — it's a complex term.
    #
    # Actually, with just 3 leaves, the continuation is a bare Var(Y).
    # The result of sys8 would be applied to Var(Y):
    # ((sys8 Var(X)) Var(Y)) → Var(Y) result
    # = (Y result) if Y is a function.
    #
    # If Y = write (2): (write result) → writes result to socket.
    # But result is an Either, not a bytes list...
    # Unless sys8 returns raw bytes (not wrapped in Either) for the answer?

    # Let's try it. For sys8, we need bypass (no literal 0x08).
    # ((λ.(Var(9) Var(X+1))) dummy Var(Y)) FF — but that's more than 3 leaves.

    # Direct 3-leaf test (includes 0x08 byte):
    interesting = list(range(0, 16)) + [42, 201, 252]

    print("  Testing ((8 X) Y) FF for various X, Y...")
    hits = []
    count = 0
    for x in interesting:
        for y in interesting:
            payload = bytes([0x08, x, FD, y, FD, FF])
            result = query_raw(payload)
            interp = interpret(result)
            count += 1
            if interp not in ("EMPTY", "R(6)", "R(1)"):
                print(f"    *** HIT: ((8 {x}) {y}): {interp}")
                hits.append((x, y, interp))
            if count % 50 == 0:
                print(f"    ...tested {count} combinations...")
            time.sleep(0.05)

    if not hits:
        print(f"  No hits in {count} combinations of ((8 X) Y)")
    else:
        print(f"  {len(hits)} HITS found!")
        for x, y, interp in hits:
            print(f"    ((8 {x}) {y}): {interp}")

    # Also try (8 (X Y)) FF pattern
    print("\n  Testing (8 (X Y)) FF for various X, Y...")
    hits2 = []
    count2 = 0
    for x in interesting:
        for y in interesting:
            payload = bytes([0x08, x, y, FD, FD, FF])
            result = query_raw(payload)
            interp = interpret(result)
            count2 += 1
            if interp not in ("EMPTY", "R(6)", "R(1)"):
                print(f"    *** HIT: (8 ({x} {y})): {interp}")
                hits2.append((x, y, interp))
            if count2 % 50 == 0:
                print(f"    ...tested {count2} combinations...")
            time.sleep(0.05)

    if not hits2:
        print(f"  No hits in {count2} combinations of (8 (X Y))")


# =============================================================================
# PHASE 6: Minimal programs — just a few bytes before FF
# =============================================================================
def phase_6_minimal_programs():
    """
    Try VERY short programs (1-4 bytes + FF) to see if any produce
    unexpected results. The challenge might have a simpler solution
    than we think.
    """
    print("\n" + "=" * 70)
    print("PHASE 6: Ultra-minimal programs (1-4 bytes + FF)")
    print("=" * 70)

    # 1-byte programs: just a Var
    print("  1-byte: Var(N) FF")
    for n in list(range(0, 16)) + [42, 201, 252]:
        payload = bytes([n, FF])
        result = query_raw(payload)
        interp = interpret(result)
        if interp != "EMPTY":
            print(f"    Var({n}): {interp}")
        time.sleep(0.05)

    # 2-byte programs: (Var(a) Var(b)) FD FF or Lam(Var(n)) FE FF
    print("\n  2-byte: App and Lam patterns")
    # Lambda patterns
    for n in list(range(0, 16)) + [42, 201, 252]:
        payload = bytes([n, FE, FF])  # λ.Var(n)
        result = query_raw(payload)
        interp = interpret(result)
        if interp != "EMPTY":
            print(f"    Lam(Var({n})): {interp}")
        time.sleep(0.05)

    # App patterns: (a b) FF
    for a in [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
        for b in [0, 1, 2, 4, 5, 6, 7, 8, 14, 42, 201]:
            payload = bytes([a, b, FD, FF])  # (Var(a) Var(b)) FF
            result = query_raw(payload)
            interp = interpret(result)
            if interp != "EMPTY":
                print(f"    ({a} {b}): {interp}")
            time.sleep(0.03)


def main():
    print("=" * 70)
    print("probe_high_index_syscall.py — High-index and alternative approach probe")
    print(f"target: {HOST}:{PORT}")
    print("=" * 70)

    phase_1_verify_known()
    time.sleep(0.3)

    phase_2_near_253()
    time.sleep(0.3)

    phase_3_pair_as_syscall()
    time.sleep(0.3)

    phase_4_cps_invoke()
    time.sleep(0.3)

    phase_5_three_leafs()
    time.sleep(0.3)

    phase_6_minimal_programs()

    print("\n" + "=" * 70)
    print("ALL PHASES COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
