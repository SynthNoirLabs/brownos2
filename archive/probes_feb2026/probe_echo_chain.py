#!/usr/bin/env python3
"""
Probe: Echo chaining to reach Var(253), Var(254), Var(255)

Key insight:
- echo(Var(N)) returns Left(Var(N+2))
- echo(Var(251)) → Left(Var(253))  [253 = 0xFD = App marker]
- echo(Var(252)) → Left(Var(254))  [254 = 0xFE = Lambda marker]
- echo(Var(253)) → Left(Var(255))  [255 = 0xFF = End marker] - but can't write Var(253) directly!

To reach Var(255), we need to chain:
1. echo(Var(251)) → Left(Var(253))
2. Unwrap Left, feed to echo again → Left(Var(255))

This probe tests:
1. Basic echo to confirm Var(253/254) manufacturing
2. Chained echo to reach Var(255)
3. Syscall 8 with all three special values
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
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


def query_raw(payload: bytes, timeout_s: float = 5.0) -> bytes:
    """Query and return raw response (may not have FF terminator)"""
    delay = 0.2
    for attempt in range(3):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                sock.shutdown(socket.SHUT_WR)
                sock.settimeout(timeout_s)
                out = b""
                while True:
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
        except Exception as e:
            print(f"  [Attempt {attempt + 1} failed: {e}]")
            time.sleep(delay)
            delay *= 2
    return b""


def parse_term(data: bytes) -> object | None:
    """Parse bytecode to term, return None on failure"""
    if not data:
        return None
    stack: list[object] = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            if len(stack) < 2:
                return None
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            if len(stack) < 1:
                return None
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    return stack[0] if len(stack) == 1 else None


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        if term.i >= 0xFD:
            raise ValueError(f"Cannot encode Var({term.i}) - reserved byte!")
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unknown term: {type(term)}")


def term_to_str(term: object, depth: int = 0) -> str:
    """Pretty print a term"""
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"λ.{term_to_str(term.body, depth + 1)}"
    if isinstance(term, App):
        return f"({term_to_str(term.f, depth)} {term_to_str(term.x, depth)})"
    return str(term)


def decode_either(term: object) -> tuple[str, object] | None:
    """Decode Scott Either: Left x = λl.λr.(l x), Right y = λl.λr.(r y)"""
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        return None
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var):
        if body.f.i == 1:
            return ("Left", body.x)
        elif body.f.i == 0:
            return ("Right", body.x)
    return None


def find_var_indices(term: object) -> list[int]:
    """Find all Var indices in a term"""
    if isinstance(term, Var):
        return [term.i]
    if isinstance(term, Lam):
        return find_var_indices(term.body)
    if isinstance(term, App):
        return find_var_indices(term.f) + find_var_indices(term.x)
    return []


# === Test Functions ===


def test_basic_echo():
    """Test basic echo to confirm +2 shift"""
    print("\n=== TEST 1: Basic Echo ===")

    for input_var in [0, 1, 250, 251, 252]:
        # ((echo Var(N)) QD)
        payload = bytes([0x0E, input_var, FD]) + QD + bytes([FD, FF])
        resp = query_raw(payload)

        term = parse_term(resp)
        if term:
            either = decode_either(term)
            if either:
                tag, payload_term = either
                indices = find_var_indices(payload_term)
                print(f"echo(Var({input_var})) → {tag}(Var indices: {indices})")
                print(f"  Full payload: {term_to_str(payload_term)}")
            else:
                print(f"echo(Var({input_var})) → Not Either: {term_to_str(term)}")
        else:
            print(f"echo(Var({input_var})) → Raw: {resp.hex() if resp else 'EMPTY'}")


def test_syscall8_with_echoed_vars():
    """
    Chain: echo(Var(N)) → Left(Var(N+2)), then unwrap and pass to syscall8

    Structure:
    ((echo Var(251)) λleft. ((left (λx. ((syscall8 x) QD))) nil))

    Where:
    - left = Left(Var(253)) = λl.λr.(l Var(253))
    - (left (λx...)) = apply to the unwrapper, ignoring second arg
    - Result: ((syscall8 Var(253)) QD)
    """
    print("\n=== TEST 2: Syscall 8 with Echo-Manufactured Vars ===")

    for input_var, expected_result in [(251, 253), (252, 254)]:
        print(
            f"\nTrying: echo(Var({input_var})) → unwrap → syscall8(Var({expected_result}))"
        )

        # Build the continuation that:
        # 1. Receives Left(Var(N+2))
        # 2. Unwraps it by applying to (λx. ((syscall8 x) QD))
        # 3. Applies result to nil (second arg of Left, ignored)

        # Inner: λx. ((syscall8 x) QD)
        # In de Bruijn: λ. ((8 0) QD_shifted)
        # But QD needs to reference global syscalls 2,4,5 which are at different indices under lambdas

        # Actually, let's try a different approach:
        # Use the Either directly as continuation to syscall8

        # Simpler: ((echo Var(N)) (λeither. ((either (λx. ((8 x) QD))) dummy)))
        # But this is getting complex. Let me try raw bytecode construction.

        # Actually simplest approach:
        # The continuation that unwraps Left and calls syscall8:
        # λleft. (left (λpayload. ((8 payload) QD)) nil)
        # = λ. (0 (λ. ((8 0) QD)) nil)

        # nil = λλ.0 = 00 FE FE
        nil = bytes([0x00, FE, FE])

        # QD needs adjustment for being under lambdas... this is tricky.
        # Let's try a more direct approach: build the whole thing manually

        # ((echo Var(N)) cont) where cont unwraps Left and applies syscall8
        #
        # cont = λleft. ((left handler) dummy)
        # handler = λpayload. ((syscall8 payload) finalCont)
        #
        # Under 1 lambda (left), we need:
        #   ((0 handler) dummy) where 0=left
        # handler under 1 more lambda = λ. ((8 0) QD_under_2_lambdas)

        # Let's try: just chain the syscalls directly using CPS
        # ((echo Var(N)) λresult. ((result onLeft) onRight))
        # where onLeft = λpayload. ((syscall8 payload) QD)

        # Since Left = λl.λr.(l x), applying it:
        # ((Left onLeft) onRight) = (onLeft x) = ((syscall8 x) QD)

        # So the continuation is:
        # λresult. ((result (λpayload. ((syscall8 payload) QD))) anything)

        # In bytecode (de Bruijn):
        # λ. ((0 (λ. ((syscall8_ref 0) QD_ref))) dummy)

        # Under 1 lambda:
        #   syscall8 is global 8, but we're under 1 lambda, so it's Var(9)
        #   QD references globals 2,4,5 → need to shift by +2 total (our lambda + inner lambda)

        # This is getting complicated. Let me try a simpler raw approach:

        # Raw payload approach - build CPS chain manually:
        # We want: echo(Var(251)) then feed result.payload to syscall8

        # Method: use a continuation that extracts Left and calls syscall8
        # cont = λleft. (left handler dummy)  where handler = λx. syscall8_call(x)

        # Let me try building this step by step with explicit bytecode:

        # Step 1: The innermost handler λpayload. ((8 payload) QD)
        # Under this lambda + the outer lambda, globals shift by +2
        # So syscall8 (normally 8) becomes 10, and QD's references need adjustment

        # Actually, QD is a closed term - it doesn't have free variables except
        # the globals it references (2=write, 4=quote, 5=readdir? no wait...)
        # QD = λ.λ.((5 0) ((5 0) ((3) ...) ))
        # It references vars 2,3,5 at certain depths

        # This is too complex. Let me just try sending raw syscall8 with QD
        # after echoing, to see what error we get.

        # First, verify echo works:
        payload1 = bytes([0x0E, input_var, FD]) + QD + bytes([FD, FF])
        resp1 = query_raw(payload1)
        print(f"  echo(Var({input_var})): {resp1.hex() if resp1 else 'EMPTY'}")

        # Now try a complex chain...
        # Let's build: ((echo input) λe.((e (λx.((8 x) QD_shifted))) nil))
        #
        # Bytecode breakdown:
        # echo = 0E
        # input = input_var (e.g. FB for 251)
        # FD = apply echo to input
        # Then apply to continuation
        #
        # continuation = λe.((e handler) nil)
        # e is Var(0) under 1 lambda
        # handler = λx.((8 x) QD)  -- but 8 needs shift, QD needs shift
        # Under our outer λ, globals shift +1
        # Under handler's λ, another +1, so +2 total
        # syscall8 global is at index 8, so under 2 lambdas it's 10
        # nil = 00 FE FE

        # handler = λ.((10 0) QD_shifted_by_2)
        # handler bytecode: (10 0 FD) QD_shifted FD FE
        # but 10 = 0x0A

        # For QD_shifted: QD references 02, 03, 05 at various depths
        # QD = 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
        # These are Var(5), Var(0), Var(5), Var(0), Var(3), Var(2)
        # Under 2 extra lambdas, globals need +2: 5→7, 3→5, 2→4
        # But 0s inside lambdas don't shift (they're bound)

        # Let me parse QD to understand its structure:
        # 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
        # 05 = Var(5)
        # 00 = Var(0)
        # FD = App(Var(5), Var(0))
        # 00 = Var(0)
        # 05 = Var(5)
        # 00 = Var(0)
        # FD = App(Var(5), Var(0))
        # 03 = Var(3)
        # FD = App(App, Var(3)) -- wait, this doesn't make sense sequentially

        # Let me trace through the stack:
        # 05: push Var(5)  → [V5]
        # 00: push Var(0)  → [V5, V0]
        # FD: app          → [App(V5,V0)]
        # 00: push Var(0)  → [App(V5,V0), V0]
        # 05: push Var(5)  → [App(V5,V0), V0, V5]
        # 00: push Var(0)  → [App(V5,V0), V0, V5, V0]
        # FD: app          → [App(V5,V0), V0, App(V5,V0)]
        # 03: push Var(3)  → [App(V5,V0), V0, App(V5,V0), V3]
        # FD: app          → [App(V5,V0), V0, App(App(V5,V0),V3)]
        # FE: lam          → [App(V5,V0), V0, Lam(App(App(V5,V0),V3))]
        # FD: app          → [App(V5,V0), App(V0, Lam(...))]
        # 02: push Var(2)  → [App(V5,V0), App(V0, Lam(...)), V2]
        # FD: app          → [App(V5,V0), App(App(V0,Lam(...)),V2)]
        # FE: lam          → [App(V5,V0), Lam(App(App(V0,Lam(...)),V2))]
        # FD: app          → [App(App(V5,V0), Lam(...))]
        # FE: lam          → [Lam(App(App(V5,V0), Lam(...)))]

        # So QD = λ.(App(App(V5,V0), λ.(App(App(V0,λ.(App(App(V5,V0),V3))),V2))))
        # The free variables in QD are V5, V2 at top level, and V3 inside one lambda
        # Under 2 more lambdas: V5→V7, V2→V4, V3→V5

        # This is getting complex. Let me just try direct raw experiments.


def test_chained_echo_to_255():
    """
    Try to reach Var(255) by chaining echoes:
    1. echo(251) → Left(253)
    2. unwrap, echo again → Left(255)
    """
    print("\n=== TEST 3: Chained Echo to Reach Var(255) ===")

    # Approach: Build a continuation that unwraps Left and echos again
    #
    # ((echo 251) λleft. ((left (λx. ((echo x) QD))) nil))
    #
    # Structure:
    # - echo 251: 0E FB FD
    # - continuation: λ. ((0 handler) nil)
    # - handler: λ. ((0E+2 0) QD+2)  -- echo is at global 14 (0x0E), +2 = 16 (0x10)

    # Actually wait, under lambdas, the GLOBAL index doesn't change,
    # but our de Bruijn reference to it does.
    # If echo is global #14, then:
    # - At top level: Var(14) = 0x0E
    # - Under 1 lambda: Var(15) = 0x0F
    # - Under 2 lambdas: Var(16) = 0x10

    # handler under 2 lambdas: λ. ((16 0) QD_shifted)
    # But 16 = 0x10

    # Let me try building this:
    # handler = λ. ((Var(16) Var(0)) QD_under_3_lambdas)
    # handler bytecode: 10 00 FD [QD_shifted_3] FD FE

    # For QD_shifted by 3 (we're under outer cont λ, inner handler λ, and handler's λ):
    # Original QD refs at top: V5, V2 → V8, V5
    # Inside one lambda of QD: V3 → V6
    # Wait, I need to be more careful about which refs are free

    # Actually the simplest test: just try to call syscall8 directly
    # with Var(253) by chaining

    # Let me try a different approach: just test what happens when
    # we send a term that, when evaluated, produces Var(253) as argument to syscall8

    # Method: ((echo 251) k) where k extracts and feeds to syscall8
    # k = λleft. left (λx. syscall8_call(x)) dummy

    # Actually, let's first just confirm we can USE the Left result
    # by applying it to projections:

    print("\nTest 3a: Verify Left unwrapping works")

    # ((echo 251) λleft. ((left (λx. x)) nil) )
    # This should give us just Var(253)... but we can't print Var(253) with QD!

    # Let's try: ((echo 251) λleft. ((left (λx. ((quote x) write_cont))) nil))
    # Oh wait, quote would fail on Var(253) too ("Encoding failed!")

    # Hmm. We need syscall8 to USE the value, not print it.

    # ((echo 251) λleft. ((left (λx. ((syscall8 x) final))) nil))
    #
    # Let me build this bytecode manually:

    # outer structure: ((echo 251) cont)
    # = 0E FB FD [cont] FD FF
    #
    # cont = λleft. ((left handler) nil)
    # Under this lambda, globals shift +1
    # left = Var(0)
    # handler = λx. ((syscall8 x) QD_under_2)
    # nil = λλ.Var(0) = 00 FE FE
    #
    # handler under 2 lambdas total (cont's + handler's):
    # syscall8 is global 8, so Var(8+2) = Var(10) = 0x0A
    # handler = λ. ((0A 00) QD_shifted_2)

    # QD shifted by 2: need to add 2 to all free variable references
    # QD bytecode: 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
    # Free vars: V5 at positions 0,4 → V7 (0x07)
    #           V3 inside one λ stays V3 (bound inside QD's structure)
    #           V2 inside two λs stays V2 (bound)
    # Wait no, let me retrace QD structure...

    # Actually I realize the issue: QD already has its own lambdas.
    # The free variables in QD (the ones that point to syscalls) need to be shifted.
    #
    # QD structure (from my earlier trace):
    # QD = λ.(App(App(V5,V0), λ.(App(App(V0,λ.(App(App(V5,V0),V3))),V2))))
    #
    # The FREE variables (not bound by QD's lambdas) are:
    # - V5 at outermost lambda body → this is free, references global 5
    # - V3 inside second lambda → relative to that lambda, V3 is free (ref global 3)
    # - V2 inside second lambda → relative to that lambda, V2 is free (ref global 2)
    # - The V5 and V0 inside third lambda... V5 is bound by... wait

    # Let me count more carefully. QD has structure:
    # λ.(body) where body uses V5 (free), V0 (bound to arg)
    # Inside body there's λ.(body2) which uses V0 (bound to new arg), V2, V3 (free)
    # Inside body2 there's λ.(body3) which uses V0 (bound), V3, V5 (free)

    # Free vars in QD that point to globals:
    # From top λ's perspective: V5 = global 5 (readdir? or something)
    # From second λ's perspective: V2 = global 2 (write), V3 = global 3
    # From third λ's perspective: V3 = ?, V5 = ?

    # I need to understand what globals 2,3,4,5 are:
    # 0x02 = write
    # 0x03 = ??? (not implemented per docs)
    # 0x04 = quote
    # 0x05 = readdir

    # QD description says: print(term) = write(quote(term))
    # So it should use write (2) and quote (4)
    # But the bytecode has 05, 03, 02...
    # Maybe 05 here isn't syscall 5 but just part of the encoding?

    # Hmm, I think I'm overcomplicating this. Let me just try building
    # a simple chain and see what happens.

    # Simplified approach: just try raw bytecodes

    # Test: Can we even apply the Left result?
    # ((echo 251) (λleft. ((left id) nil)))
    # where id = λx.x = 00 FE
    # nil = λλ.0 = 00 FE FE

    # Under 1 lambda:
    # left = V0 = 00
    # id = λ.V0 = 00 FE (no shift needed, it's closed)
    # nil = 00 FE FE (closed)

    # cont = λ.((V0 id) nil) = λ.((00 00FE) 00FEFE)
    # = λ.( ((00 (00FE)) FD (00FEFE)) FD )
    # bytecode for cont: 00 00 FE FD 00 FE FE FD FE

    # Full payload: 0E FB FD [00 00 FE FD 00 FE FE FD FE] FD FF
    # = 0E FB FD 00 00 FE FD 00 FE FE FD FE FD FF

    payload = bytes([0x0E, 0xFB, FD, 0x00, 0x00, FE, FD, 0x00, FE, FE, FD, FE, FD, FF])
    print(f"  Payload: {payload.hex()}")
    resp = query_raw(payload, timeout_s=8)
    print(f"  Response: {resp.hex() if resp else 'EMPTY'} ({len(resp)} bytes)")

    # If this works, resp should contain Var(253) somehow
    # But the client may choke on it since 0xFD in output = application marker

    if resp:
        # Try to see if there's any pattern
        print(f"  Raw bytes: {list(resp)}")
        if b"Encoding failed" in resp:
            print("  Got 'Encoding failed' - Var(253) can't be serialized!")
        elif b"Invalid" in resp:
            print(f"  Error: {resp.decode('latin-1', errors='replace')}")


def test_syscall8_chained():
    """
    Build a chain that feeds echo-manufactured Var(253) to syscall8
    """
    print("\n=== TEST 4: Syscall 8 with Chained Echo Result ===")

    # We want: echo(251) → Left(253) → unwrap → syscall8(253) → result
    #
    # ((echo 251) λleft. ((left (λx. ((syscall8 x) QD))) nil))
    #
    # Building blocks:
    # - Under cont's λ: syscall8 = Var(9), echo = Var(15)
    # - Under handler's λ (inside cont): syscall8 = Var(10), x = Var(0)
    # - QD needs shifting: all its free refs +2

    # Let's try constructing handler first:
    # handler = λx. ((syscall8 x) QD_shifted_2)
    # = λ. ((Var(10) Var(0)) QD_shifted_2)
    # syscall8 = 0x08, +2 = 0x0A
    # bytecode start: 0A 00 FD [QD_shifted] FD FE

    # QD_shifted_2: shift all free variable refs in QD by +2
    # Original: 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
    #
    # I need to identify which bytes are free var refs:
    # Parsing QD:
    # Position 0: 05 = Var(5) - FREE (top level)
    # Position 1: 00 = Var(0) - will be bound by first λ
    # Position 2: FD = App
    # Position 3: 00 = Var(0) - bound
    # Position 4: 05 = Var(5) - but we're still at top before any FE
    # ...
    #
    # Actually, the structure after parsing is a TERM, and we need to
    # shift free vars in that term. Let me trace the final structure:
    #
    # QD (parsed) = Lam(App(App(Var(5),Var(0)), Lam(App(App(Var(0),Lam(App(App(Var(5),Var(0)),Var(3)))),Var(2)))))
    #
    # Free in QD (not bound by any of QD's lambdas):
    # - Var(5) at depth 1 (inside 1 lambda) → refers to global 5 → shift to 7
    # - Var(5) at depth 3 (inside 3 lambdas) → refers to global 5+2 = 7 → shift to 9
    # - Var(3) at depth 3 → refers to global 3+2 = 5 → shift to 7
    # - Var(2) at depth 2 → refers to global 2+1 = 3 → shift to 5
    #
    # Wait this is confusing. Let me think about it differently.
    #
    # When we put QD under 2 additional lambdas, every FREE variable
    # reference in QD needs +2 because there are 2 more binders above it.
    #
    # Free vars in QD: those Var(n) where n > (number of enclosing λs in QD at that point)
    #
    # QD = Lam(body1)
    #   body1 = App(App(Var(5),Var(0)), Lam(body2))
    #   - Var(5) at depth 1: 5 > 1 so FREE, refers to index 5-1=4 in global env? No...
    #
    # De Bruijn: Var(n) refers to the n-th enclosing binder (0-indexed).
    # If n >= number of enclosing binders, it's a free variable.
    #
    # In QD at depth 1 (inside the first λ):
    #   Var(0) → bound to that λ's argument
    #   Var(5) → 5 >= 1, so free, refers to global index 5-1 = 4? Or just global 5?
    #
    # Actually in de Bruijn, Var(n) at depth d where n >= d refers to global (n-d).
    # No wait, the convention varies. Let me assume Var(n) at any depth:
    #   n < d → bound to the (n)-th enclosing lambda (0=innermost)
    #   n >= d → free, referring to global at index (n - d)
    #
    # In QD at depth 1: Var(5) → 5 >= 1 → free, global index 5-1=4 → syscall 4 (quote)
    # In QD at depth 2: Var(2) → 2 >= 2 → free, global 2-2=0 → syscall 0? Hmm
    # At depth 3: Var(3) → 3 >= 3 → free, global 0
    #             Var(5) → 5 >= 3 → free, global 2
    #
    # This is getting confusing. Let me just TRY the experiment with QD as-is first,
    # and see what errors we get.

    # Attempt 1: Just use QD without shifting, see what happens
    print("\nTest 4a: Naive chain (QD unshifted)")

    # handler_naive = λ. ((Var(10) Var(0)) QD)
    # 0A 00 FD QD FD FE
    handler_naive = bytes([0x0A, 0x00, FD]) + QD + bytes([FD, FE])

    # cont = λ. ((Var(0) handler) nil)
    # nil = 00 FE FE
    nil = bytes([0x00, FE, FE])
    # 00 [handler] FD [nil] FD FE
    cont_naive = bytes([0x00]) + handler_naive + bytes([FD]) + nil + bytes([FD, FE])

    # full = ((echo 251) cont)
    # 0E FB FD [cont] FD FF
    payload_naive = bytes([0x0E, 0xFB, FD]) + cont_naive + bytes([FD, FF])

    print(f"  Payload: {payload_naive.hex()}")
    resp = query_raw(payload_naive, timeout_s=10)
    print(f"  Response: {resp.hex() if resp else 'EMPTY'} ({len(resp)} bytes)")
    if resp:
        print(f"  As text: {resp.decode('latin-1', errors='replace')}")
        term = parse_term(resp)
        if term:
            print(f"  Parsed: {term_to_str(term)}")
            either = decode_either(term)
            if either:
                print(f"  Either: {either[0]}({term_to_str(either[1])})")


def test_syscall8_with_special_continuation():
    """
    What if we use Var(253) as the CONTINUATION to syscall8, not the argument?
    """
    print("\n=== TEST 5: Syscall 8 with Special Continuation ===")

    # Instead of ((syscall8 arg) QD), try ((syscall8 nil) special_cont)
    # where special_cont is manufactured by echo

    # Chain: ((echo 251) λleft. ((syscall8 nil) (left_payload)))
    # But extracting left_payload to use as continuation...

    # Or simpler: what if syscall8's argument IS a continuation-like thing?
    # ((syscall8 (λk. ...)) QD)

    # Let's try: ((syscall8 identity) QD) where identity = λx.x
    print("\nTest 5a: syscall8 with identity")
    identity = bytes([0x00, FE])
    payload = bytes([0x08]) + identity + bytes([FD]) + QD + bytes([FD, FF])
    resp = query_raw(payload)
    print(f"  Response: {resp.hex() if resp else 'EMPTY'}")
    if resp:
        term = parse_term(resp)
        if term:
            either = decode_either(term)
            if either:
                print(f"  Result: {either[0]}")


def test_direct_special_bytes():
    """
    Test what happens with various special byte combinations
    """
    print("\n=== TEST 6: Direct Special Byte Experiments ===")

    # What if we send malformed bytecode that might confuse the parser?

    # Test: Send just syscall8 reference with echo-chain
    # Chain: echo(251) → extract 253 → use as syscall number?

    # Hmm, syscall numbers are global variable indices, not runtime values.
    # But what if there's a way to invoke a syscall dynamically?

    # Another angle: The "3 leafs" hint
    # A term with exactly 3 Var nodes
    # Simplest: App(App(Var(a), Var(b)), Var(c))
    # Bytecode: a b FD c FD FF

    print("\nTest 6a: 3-leaf terms with syscall8 and special values")

    # Try: ((syscall8 Var(251)) Var(252))
    # But this is using 251, 252 directly (which are valid bytecodes)
    # 3 leaves: syscall8 (Var(8)), Var(251), Var(252)
    payload = bytes([0x08, 0xFB, FD, 0xFC, FD, FF])
    print(f"  ((8 251) 252): {payload.hex()}")
    resp = query_raw(payload, timeout_s=5)
    print(f"  Response: {resp.hex() if resp else 'EMPTY'} ({len(resp)} bytes)")

    # Try: ((Var(251) Var(252)) syscall8)
    payload2 = bytes([0xFB, 0xFC, FD, 0x08, FD, FF])
    print(f"  ((251 252) 8): {payload2.hex()}")
    resp2 = query_raw(payload2, timeout_s=5)
    print(f"  Response: {resp2.hex() if resp2 else 'EMPTY'} ({len(resp2)} bytes)")


def main():
    print("=" * 60)
    print("PROBE: Echo Chaining and Special Variable Investigation")
    print("=" * 60)

    test_basic_echo()
    test_chained_echo_to_255()
    test_syscall8_chained()
    test_syscall8_with_special_continuation()
    test_direct_special_bytes()

    print("\n" + "=" * 60)
    print("PROBE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
