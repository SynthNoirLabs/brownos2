#!/usr/bin/env python3
"""
KEY INSIGHT: Use echo's +2 shift to ACCESS PRIVILEGED SYSCALLS.

Previous attempts passed echo-shifted terms AS ARGUMENTS to syscall 8.
This probe tries to USE echo-shifted terms AS THE SYSCALL ITSELF.

If there's a privileged syscall at index 253+ that we can't encode directly
(because 0xFD/FE/FF are reserved), maybe echo can create a reference to it.

Strategy:
1. echo(Var(251)) under 2 lambdas = Var(253) - which is 0xFD, unserializable
2. BUT if we CALL that result (instead of serializing it), we might access hidden syscalls
3. Use the Either unwrap (Left payload) to get the shifted term, then call it

Author hint: "combining special bytes" + "why would an OS need echo?"
-> Echo's PURPOSE is to create references to hidden globals that can't be wire-encoded!
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    decode_byte_term,
    decode_bytes_list,
    decode_either,
    encode_term,
    parse_term,
)
from solve_brownos_answer import QD as QD_BYTES

FF = 0xFF
FE = 0xFE
FD = 0xFD

NIL_TERM: object = Lam(Lam(Var(0)))
QD_TERM: object = parse_term(QD_BYTES)
I_TERM: object = Lam(Var(0))  # Identity


def term_to_string(term: object) -> str:
    """Human-readable term representation."""
    if isinstance(term, Var):
        return f"V{term.i}"
    if isinstance(term, Lam):
        return f"(λ.{term_to_string(term.body)})"
    if isinstance(term, App):
        return f"({term_to_string(term.f)} {term_to_string(term.x)})"
    return str(term)


def shift(term: object, delta: int, cutoff: int = 0) -> object:
    """De Bruijn shift (increase free vars >= cutoff by delta)."""
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    raise TypeError(f"Unsupported term node: {type(term)}")


def recv_all(sock: socket.socket, timeout_s: float) -> bytes:
    sock.settimeout(timeout_s)
    out = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass
    return out


def query_raw(payload: bytes, timeout_s: float = 4.0) -> bytes:
    """Query and return raw response."""
    with socket.create_connection(("wc3.wechall.net", 61221), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        return recv_all(sock, timeout_s)


def classify_response(resp: bytes) -> str:
    """Classify response for quick display."""
    if not resp:
        return "<silent>"
    if resp.startswith(b"Invalid term!"):
        return "Invalid term!"
    if resp.startswith(b"Encoding failed!"):
        return "Encoding failed!"
    if resp.startswith(b"Term too big!"):
        return "Term too big!"
    if FF not in resp:
        return f"<no FF: {resp[:50].hex()}>"
    
    try:
        term = parse_term(resp)
        tag, payload = decode_either(term)
        if tag == "Right":
            code = decode_byte_term(payload)
            return f"Right({code})"
        else:
            try:
                bs = decode_bytes_list(payload)
                return f"Left('{bs.decode()[:50]}')"
            except:
                return f"Left(<non-bytes>)"
    except Exception as e:
        return f"<parse error: {e}>"


def test_echo_as_syscall_generator() -> None:
    """
    CORE IDEA: Echo returns Left(payload) where payload is the input.
    The payload lives under 2 lambdas (Either structure).
    
    If we echo Var(251), the result's Left payload is... still Var(251)?
    No wait - the SHIFT happens when we INSPECT via QD/quote.
    
    The actual term inside is unchanged, but when serialized, indices shift.
    
    So the trick must be: use echo's result IN EVALUATION, not serialization.
    
    Let's try: echo(Var(k)), then unwrap the Either and CALL the result as a syscall.
    """
    print("=" * 60)
    print("ECHO AS SYSCALL GENERATOR")
    print("=" * 60)
    
    print("\nIdea: echo(Var(k)) → unwrap Left → use result as syscall")
    print("If k+shift reaches a hidden syscall, we might access it.\n")
    
    # Build: ((0x0E Var(k)) (λe. unwrap e and call it))
    # unwrap Either: e is λl.λr. l payload  (Left)
    #                or λl.λr. r errcode   (Right)
    # To extract: (e (λx.x) (λx.x)) applies the Either to identity functions
    # For Left(x): (λl.λr. l x) I I = I x = x
    # For Right(y): (λl.λr. r y) I I = I y = y
    
    # BUT we want to USE the extracted value as a syscall, not just get it.
    # So: ((e I I) arg) cont  - use extracted value as syscall
    
    for base_k in [251, 250, 249, 248, 247, 246, 245, 244, 243, 242]:
        # Build: ((0x0E Var(k)) (λe. (((e I I) nil) QD)))
        # Inside the continuation λe:
        #   e is at Var(0)
        #   Globals shift by +1, so 0x0E becomes 0x0F, etc.
        #   QD needs to be shifted by +1
        
        # Actually let's be more careful with de Bruijn indices:
        # Top level: ((0x0E Var(k)) cont)
        # cont = λe. body
        #   In body: e=Var(0), globals are at Var(g+1)
        
        # We want body = (((e I I) nil) QD_shifted)
        e = Var(0)
        unwrapped = App(App(e, I_TERM), I_TERM)  # e I I
        call_with_nil = App(unwrapped, NIL_TERM)  # (e I I) nil
        qd_shifted = shift(QD_TERM, 1)  # QD with indices shifted by +1
        body = App(call_with_nil, qd_shifted)
        
        cont = Lam(body)
        
        # Full program: ((0x0E Var(k)) cont)
        program = App(App(Var(0x0E), Var(base_k)), cont)
        
        payload = encode_term(program) + bytes([FF])
        resp = query_raw(payload)
        result = classify_response(resp)
        
        effective_index = base_k  # The Var we're echoing
        print(f"echo(Var({base_k})) → unwrap → call as syscall: {result}")
        
        time.sleep(0.2)


def test_nested_echo() -> None:
    """
    "My record is 3 leafs" - maybe 3 echo applications?
    
    echo(echo(echo(x))) applies +2 shift three times when OBSERVED via quote.
    But in evaluation, the term is unchanged...
    
    OR: The echo creates a CLOSURE that captures the shifted environment.
    When that closure is later evaluated, it references shifted indices.
    """
    print("\n" + "=" * 60)
    print("NESTED ECHO (Triple Echo)")
    print("=" * 60)
    
    print("\nIdea: Chain echoes, then use result")
    
    # Let's try a simpler approach: chain echo calls and see what happens
    # ((0x0E ((0x0E ((0x0E Var(k)) cont1)) cont2)) cont3)
    
    # Actually, let's think about this differently.
    # Each echo returns Left(input). If we chain them and unwrap:
    # echo(echo(echo(Var(k)))) = Left(Left(Left(Var(k))))
    # 
    # The "+2" shift only appears when serializing.
    # But maybe there's something special about EVALUATING terms with high indices?
    
    # Let's try building Var(253) directly inside a term (without serializing it)
    # and then using it.
    
    # Problem: We can't encode Var(253) because 0xFD is reserved.
    # BUT: We can build it programmatically inside the VM using computation!
    
    # Idea: Use successor/predecessor on indices somehow?
    # Or: Use the backdoor combinators to construct the term?
    
    print("\nBuilding high-index Vars via echo layering:")
    
    for num_echoes in [1, 2, 3]:
        # Build nested echo: echo(echo(...echo(Var(k))...))
        # Then unwrap all the Lefts and try to use the result
        
        base_k = 251
        
        # Start with innermost
        inner = Var(base_k)
        
        # Wrap in echoes - this is getting complex with de Bruijn
        # Let's try a different approach: build the whole nested structure
        
        # For 1 echo: ((0x0E Var(k)) (λe. unwrap and use))
        # For 2 echoes: ((0x0E Var(k)) (λe1. ((0x0E (e1 I I)) (λe2. unwrap and use))))
        # etc.
        
        def build_echo_chain(n: int, base: int) -> object:
            """Build n nested echoes of Var(base), then unwrap and call as syscall."""
            if n == 0:
                # Base case: just call base as syscall
                # ((Var(base+depth) nil) QD_shifted)
                # But this doesn't work because we can't reference globals directly
                raise ValueError("n must be >= 1")
            
            # The continuation unwraps the Either and either chains another echo
            # or uses the result as syscall
            
            # This is getting complicated. Let me try a simpler direct approach.
            pass
        
        # Simpler: Just send raw bytes that would create Var(253) if allowed
        # Obviously this won't parse, but let's see the error
        if num_echoes == 1:
            # Try sending bytes that include 0xFD as a Var (it should fail)
            # But wait - we can use echo to OBSERVE what happens when we try
            pass
        
        print(f"  {num_echoes} echoes: <implementation complex, see below>")
    
    # NEW IDEA: What if echo's PURPOSE is to let us build terms that
    # CONTAIN high-index Vars, and then those terms get EVALUATED in a
    # context where those indices have meaning?
    
    print("\n\nNEW APPROACH: Echo creates environment references")
    print("-" * 50)
    
    # When we echo a term T, we get Left(T).
    # If T contains free variables, they now live under 2 lambdas (Either).
    # When we APPLY that Either to extractors, the free vars get shifted.
    
    # So: echo(Var(k)) = Left(Var(k)) = λl.λr. l Var(k)
    # When we extract with (Left I I), we're applying lambdas...
    
    # Actually, Left(x) = λl.λr. l x
    # (Left I I) = ((λl.λr. l x) I) I = (λr. I x) I = I x = x
    # So extraction just gives back the original!
    
    # BUT: Inside the Either, Var(k) is under 2 lambdas.
    # If we DON'T extract, but instead APPLY the Either directly to
    # handlers that USE the payload at that depth...
    
    # Var(k) under 2 lambdas, when accessed as Var(k), actually refers to
    # the environment at index k from inside those lambdas.
    
    # This is getting circular. Let me try concrete experiments.


def test_echo_preserves_high_indices() -> None:
    """
    Let's verify what echo actually does to high-index variables.
    
    If we echo Var(251) and DON'T unwrap, but instead apply the Either
    to a handler that will USE that Var(251) in its body...
    """
    print("\n" + "=" * 60)
    print("ECHO HANDLER EXPERIMENT")
    print("=" * 60)
    
    # echo(Var(k)) = Left(Var(k)) = λl.λr. l Var(k)
    # 
    # If we apply this Either to a "left handler" that does something with payload:
    # (Left (λpayload. use payload) anything)
    # = ((λl.λr. l Var(k)) (λpayload. use payload)) anything
    # = (λr. (λpayload. use payload) Var(k)) anything
    # = (λpayload. use payload) Var(k)
    # = use Var(k)
    #
    # The Var(k) here is evaluated in the context where it was created!
    # Inside the Either (2 lambdas), Var(k) with k < 2 is a bound var.
    # With k >= 2, it's a free var pointing k-2 into the environment.
    
    # So Var(251) inside the Either refers to environment index 251-2=249
    # when we created it at top level.
    
    # BUT: If we CREATE Var(251) at top level, it refers to global 251.
    # After echo wraps it in Either (2 lambdas), it's still Var(251),
    # but now under 2 binders, so it refers to global 251-2=249?
    
    # No wait, de Bruijn doesn't work that way. The indices DON'T change
    # when you wrap in lambdas. A Var(k) always means "k binders up".
    
    # So Var(251) at top level = global 251.
    # Var(251) inside λ.λ.body = global 249 (because 2 binders to skip).
    
    # Hmm, but the term structure doesn't change. If we build Var(251)
    # and then it gets wrapped in lambdas, it's still Var(251)...
    
    # WAIT. I think I've been confusing myself.
    
    # Let's be precise:
    # - We build a term T = Var(251) at "design time"
    # - We encode T as bytes: just [251] = 0xFB
    # - We send this to the server
    # - Server parses: Var(251)
    # - Server evaluates in empty env: Var(251) looks up index 251 in globals
    
    # If we build T = echo(Var(251)):
    # - Encoded as: syscall_0x0E applied to Var(251) applied to some cont
    # - Server evaluates: calls syscall 0x0E with Var(251), gets Left(Var(251))
    # - The Left is λl.λr. l Var(251)
    # - Inside those lambdas, Var(251) STILL means "251 binders up"
    # - From inside the 2 lambdas, that's 249 in the outer env (globals)
    
    # So echo(Var(251)) doesn't give us Var(253) - it gives us something
    # that ACTS like Var(249) when evaluated from inside!
    
    # To reach Var(253), we need Var(255) inside the Either.
    # But 255 = 0xFF = end marker, can't encode.
    
    # UNLESS... the echo syscall does something special.
    # What if echo SHIFTS the indices when creating the Either?
    
    print("Hypothesis: echo shifts indices to compensate for Either wrapper")
    print("Test: echo(Var(k)), then use result, compare behavior to global k vs k+2")
    
    # Test: echo Var(6) (syscall 'name'), then apply to int, compare to direct name call
    for k in [6, 7, 8]:  # name, readfile, mystery syscall
        print(f"\n--- Testing k={k} ---")
        
        # Direct call: ((Var(k) arg) QD)
        from solve_brownos_answer import encode_byte_term
        arg = encode_byte_term(0)  # file/dir id 0
        direct = App(App(Var(k), arg), QD_TERM)
        direct_payload = encode_term(direct) + bytes([FF])
        
        # Echo then unwrap and call: 
        # ((0x0E Var(k)) (λe. (((e I I) arg) QD_shifted)))
        e = Var(0)
        unwrapped = App(App(e, I_TERM), I_TERM)
        call_with_arg = App(unwrapped, arg)
        qd_shifted = shift(QD_TERM, 1)
        body = App(call_with_arg, qd_shifted)
        cont = Lam(body)
        echo_call = App(App(Var(0x0E), Var(k)), cont)
        echo_payload = encode_term(echo_call) + bytes([FF])
        
        direct_resp = query_raw(direct_payload)
        time.sleep(0.15)
        echo_resp = query_raw(echo_payload)
        
        print(f"  Direct Var({k}): {classify_response(direct_resp)}")
        print(f"  Echo Var({k}):   {classify_response(echo_resp)}")
        
        time.sleep(0.2)


def test_using_backdoor_to_build_terms() -> None:
    """
    The backdoor returns A = λab.bb and B = λab.ab.
    These are combinators. Can they be used to BUILD new terms?
    
    A x y = y y  (applies second arg to itself)
    B x y = x y  (applies first arg to second)
    
    These look like they could implement successor on Church numerals or
    build recursive structures.
    """
    print("\n" + "=" * 60)
    print("BACKDOOR COMBINATORS AS TERM BUILDERS")
    print("=" * 60)
    
    # Get A and B
    from probe_backdoor_analysis import extract_pair_components
    
    backdoor_payload = bytes([0xC9]) + encode_term(NIL_TERM) + bytes([FD]) + QD_BYTES + bytes([FD, FF])
    resp = query_raw(backdoor_payload)
    term = parse_term(resp)
    _, pair_term = decode_either(term)
    
    # Extract A and B
    cur = pair_term
    while isinstance(cur, Lam):
        cur = cur.body
    a_term = cur.f.x
    b_term = cur.x
    
    print(f"A = {term_to_string(a_term)}  (λab.bb)")
    print(f"B = {term_to_string(b_term)}  (λab.ab)")
    
    # A x y = y y
    # B x y = x y
    
    # What if we apply these to syscall numbers?
    # B 8 nil = 8 nil = syscall 8 with nil? But 8 isn't a term here.
    
    # What about: B (Var(8)) nil = Var(8) nil = syscall 8 applied to nil
    # Then we need to apply that to a continuation.
    
    # ((B Var(8)) nil) = (Var(8) nil)
    # (((B Var(8)) nil) QD) = ((Var(8) nil) QD)
    
    print("\nTesting: ((B Var(8)) nil) with QD continuation")
    
    b_applied_8 = App(b_term, Var(8))  # B Var(8)
    b8_nil = App(b_applied_8, NIL_TERM)  # (B Var(8)) nil
    call = App(b8_nil, QD_TERM)  # ((B Var(8)) nil) QD
    
    payload = encode_term(call) + bytes([FF])
    resp = query_raw(payload)
    print(f"  Result: {classify_response(resp)}")
    
    # What about using A for self-application?
    # A Var(8) Var(8) = Var(8) Var(8) = syscall 8 applied to itself?
    
    print("\nTesting: ((A Var(8)) Var(8))")
    a8 = App(a_term, Var(8))
    a88 = App(a8, Var(8))
    call2 = App(a88, QD_TERM)
    
    payload2 = encode_term(call2) + bytes([FF])
    resp2 = query_raw(payload2)
    print(f"  Result: {classify_response(resp2)}")
    
    time.sleep(0.2)
    
    # What if we use A and B to build something that evaluates to a high index?
    # This is tricky because A and B work on their arguments, not on indices.
    
    # BUT: What if the "3 leafs" means using A, B, and something else?
    # Like: (A (B x)) or similar minimal construction?
    
    print("\nMinimal combinator constructions:")
    
    # Try various 3-node constructions with A and B
    test_cases = [
        ("(A B) nil", App(App(a_term, b_term), NIL_TERM)),
        ("(B A) nil", App(App(b_term, a_term), NIL_TERM)),
        ("A (B nil)", App(a_term, App(b_term, NIL_TERM))),
        ("B (A nil)", App(b_term, App(a_term, NIL_TERM))),
        ("((A B) A)", App(App(a_term, b_term), a_term)),
        ("((B A) B)", App(App(b_term, a_term), b_term)),
        ("((A A) B)", App(App(a_term, a_term), b_term)),
        ("((B B) A)", App(App(b_term, b_term), a_term)),
    ]
    
    for name, expr in test_cases:
        call = App(App(Var(8), expr), QD_TERM)  # Use as arg to syscall 8
        payload = encode_term(call) + bytes([FF])
        resp = query_raw(payload)
        print(f"  syscall8({name}): {classify_response(resp)}")
        time.sleep(0.15)


def main() -> None:
    test_echo_as_syscall_generator()
    test_nested_echo()
    test_echo_preserves_high_indices()
    test_using_backdoor_to_build_terms()


if __name__ == "__main__":
    main()
