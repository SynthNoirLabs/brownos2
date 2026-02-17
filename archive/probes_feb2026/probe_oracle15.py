#!/usr/bin/env python3
"""
probe_oracle15.py — Oracle #15 recommended probes.

4 targeted experiments:
1. Strictness test: does ((λy.λk. k nil) Ω QD) print nil or hang?
2. Wide integers: does name(256) work with 10-lambda encoding?
3. File ID 56154 (the sha1 iteration count): name + readfile
4. Syscall 8 inside backdoor's continuation with shifted QD
"""

from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from solve_brownos_answer import (
    App,
    Lam,
    Var,
    FF,
    FD,
    FE,
    QD,
    encode_term,
    encode_byte_term,
    parse_term,
    decode_either,
    decode_bytes_list,
    decode_byte_term,
)

HOST = "wc3.wechall.net"
PORT = 61221


def recv_all(sock, timeout_s=5.0):
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


def query_raw(payload, timeout_s=5.0):
    try:
        start = time.monotonic()
        with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            result = recv_all(sock, timeout_s=timeout_s)
        elapsed = time.monotonic() - start
        return result, elapsed
    except Exception as e:
        return b"", 0.0


def classify(raw, elapsed):
    if not raw:
        if elapsed >= 4.5:
            return "TIMEOUT"
        return f"EMPTY({elapsed:.1f}s)"
    text = raw.decode("latin-1", errors="replace")
    if text.startswith("Encoding failed"):
        return "ENC_FAIL"
    if text.startswith("Invalid term"):
        return "INVALID_TERM"
    if text.startswith("Term too big"):
        return "TOO_BIG"
    if FF in raw:
        return f"QD_RESP"
    return f"DATA:{text[:80]!r}"


# ── Helpers ────────────────────────────────────────────────────────────


def encode_int_wide(n, num_lambdas=None):
    """Encode integer n using additive bitset with configurable lambda count.

    Standard is 9 lambdas (weights 0,1,2,4,8,16,32,64,128).
    For wider integers, use more lambdas (each new lambda adds a higher power of 2).
    """
    if num_lambdas is None:
        # Auto-detect: use enough lambdas to cover all bits
        if n == 0:
            num_lambdas = 9
        else:
            num_lambdas = max(9, n.bit_length() + 1)  # +1 for the base (Var 0)

    # Weights: index 0 = 0, index k = 2^(k-1) for k >= 1
    expr: object = Var(0)  # base weight 0
    for bit_pos in range(num_lambdas - 1):  # bit_pos 0..num_lambdas-2
        weight = 1 << bit_pos  # 2^bit_pos
        var_idx = bit_pos + 1
        if n & weight:
            expr = App(Var(var_idx), expr)

    term: object = expr
    for _ in range(num_lambdas):
        term = Lam(term)
    return term


def make_shifted_qd(shift_n):
    """Create a QD continuation shifted by +n for use under n lambdas.

    QD at top level uses globals g(2), g(4), g(5), g(0), g(3).
    Under n lambdas, these become g(2+n), g(4+n), etc.

    QD structure: λresult. g(4)(result, λeither. either(λbytes. g(2)(bytes, g(0)), g(0)))

    In de Bruijn under 0 extra lambdas:
    QD = λ. ((g(5) 0) FD ((g(0) ((g(5) 0) FD g(3)) FD) FE) FD g(2)) FD) FE FD) FE

    Actually let's rebuild from the known QD bytes and shift them.
    QD bytes: 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE

    Parse QD → term → shift free vars by +n → re-encode.
    """
    qd_term = parse_term(QD + bytes([FF]))
    shifted = shift_free_vars(qd_term, shift_n, 0)
    return shifted


def shift_free_vars(term, delta, cutoff):
    """Shift free variables (those with index >= cutoff) by delta."""
    if isinstance(term, Var):
        if term.i >= cutoff:
            return Var(term.i + delta)
        return term
    if isinstance(term, Lam):
        return Lam(shift_free_vars(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(
            shift_free_vars(term.f, delta, cutoff),
            shift_free_vars(term.x, delta, cutoff),
        )
    return term


# ── Probe 1: Strictness test ──────────────────────────────────────────


def probe_1_strictness():
    print("=" * 72)
    print("PROBE 1: Strictness test")
    print("  ((λy.λk. k nil) Ω) QD — does the VM evaluate Ω eagerly?")
    print("  If strict: TIMEOUT (Ω diverges before k is reached)")
    print("  If lazy/non-strict: prints nil term")
    print("=" * 72)

    # Ω = (λx. x x)(λx. x x)
    omega_half = Lam(App(Var(0), Var(0)))  # λx. x x
    omega = App(omega_half, omega_half)  # Ω = (λx.xx)(λx.xx)

    # nil = λc.λn. n = 00 FE FE (under 0 extra lambdas)
    nil_term = Lam(Lam(Var(0)))

    # f = λy.λk. k nil
    # In de Bruijn: λ.λ. (0 nil)  — but nil needs shifting!
    # Under 2 lambdas, nil's free vars would shift. nil has no free vars, so it's fine.
    # f = Lam(Lam(App(Var(0), nil_term)))
    f = Lam(Lam(App(Var(0), nil_term)))

    # QD term
    qd_term = parse_term(QD + bytes([FF]))

    # Full: ((f Ω) QD)
    full = App(App(f, omega), qd_term)

    payload = encode_term(full) + bytes([FF])
    print(f"  Payload size: {len(payload)} bytes")
    print(f"  Payload hex: {payload.hex()}")

    out, elapsed = query_raw(payload, timeout_s=8.0)
    result = classify(out, elapsed)
    print(f"  Result: {result} (elapsed: {elapsed:.1f}s)")

    if out and FF in out:
        try:
            parsed = parse_term(out)
            print(f"  Parsed term: {parsed}")
            # Check if it's nil
            if isinstance(parsed, Lam) and isinstance(parsed.body, Lam):
                body = parsed.body.body
                if isinstance(body, Var) and body.i == 0:
                    print("  >>> VM is NON-STRICT (lazy): Ω was NOT evaluated!")
                else:
                    print(f"  >>> Got a 2-lambda term but body is {body}")
            else:
                print(f"  >>> Unexpected shape: {parsed}")
        except Exception as e:
            print(f"  Parse error: {e}")
        print(f"  Hex: {out.hex()}")
    elif "TIMEOUT" in result:
        print("  >>> VM is STRICT (eager): Ω caused divergence!")
    elif "EMPTY" in result:
        print(
            "  >>> EMPTY — possible non-strict with g(0) swallowing, or strict timeout"
        )

    time.sleep(0.5)


# ── Probe 2: Wide integers ───────────────────────────────────────────


def probe_2_wide_integers():
    print("\n" + "=" * 72)
    print("PROBE 2: Wide integers — does the VM accept >9-lambda int encoding?")
    print("=" * 72)

    qd_term = parse_term(QD + bytes([FF]))

    # 2a: name(256) using STANDARD 9-lambda encoding (known to work: returns "wtf")
    print("\n  --- 2a: name(256) with standard 9-lambda (baseline) ---")
    int256_std = encode_byte_term(256)  # Uses V8 twice: (V8 (V8 V0))
    payload_std = (
        bytes([0x06]) + encode_term(int256_std) + bytes([FD]) + QD + bytes([FD, FF])
    )
    out, elapsed = query_raw(payload_std, timeout_s=6.0)
    result = classify(out, elapsed)
    print(f"  name(256) [9-lam]: {result}")
    if out and FF in out:
        try:
            parsed = parse_term(out)
            tag, payload_data = decode_either(parsed)
            if tag == "Left":
                text = decode_bytes_list(payload_data).decode(
                    "latin-1", errors="replace"
                )
                print(f"    → {tag}: {text!r}")
            else:
                err = decode_byte_term(payload_data)
                print(f"    → {tag}({err})")
        except Exception as e:
            print(f"    parse error: {e}")
    time.sleep(0.3)

    # 2b: name(256) using 10-lambda encoding (single bit: V9)
    print("\n  --- 2b: name(256) with 10-lambda (wide int test) ---")
    int256_wide = encode_int_wide(256, num_lambdas=10)
    payload_wide = (
        bytes([0x06]) + encode_term(int256_wide) + bytes([FD]) + QD + bytes([FD, FF])
    )
    out, elapsed = query_raw(payload_wide, timeout_s=6.0)
    result = classify(out, elapsed)
    print(f"  name(256) [10-lam]: {result}")
    if out and FF in out:
        try:
            parsed = parse_term(out)
            tag, payload_data = decode_either(parsed)
            if tag == "Left":
                text = decode_bytes_list(payload_data).decode(
                    "latin-1", errors="replace"
                )
                print(f"    → {tag}: {text!r}")
            else:
                err = decode_byte_term(payload_data)
                print(f"    → {tag}({err})")
        except Exception as e:
            print(f"    parse error: {e}")
    time.sleep(0.3)

    # 2c: name(1) with 10-lambda encoding — does it still return "bin"?
    print("\n  --- 2c: name(1) with 10-lambda (should still return 'bin') ---")
    int1_wide = encode_int_wide(1, num_lambdas=10)
    payload_1w = (
        bytes([0x06]) + encode_term(int1_wide) + bytes([FD]) + QD + bytes([FD, FF])
    )
    out, elapsed = query_raw(payload_1w, timeout_s=6.0)
    result = classify(out, elapsed)
    print(f"  name(1) [10-lam]: {result}")
    if out and FF in out:
        try:
            parsed = parse_term(out)
            tag, payload_data = decode_either(parsed)
            if tag == "Left":
                text = decode_bytes_list(payload_data).decode(
                    "latin-1", errors="replace"
                )
                print(f"    → {tag}: {text!r}")
            else:
                err = decode_byte_term(payload_data)
                print(f"    → {tag}({err})")
        except Exception as e:
            print(f"    parse error: {e}")
    time.sleep(0.3)

    # 2d: name(0) with 10-lambda — should return "/" (root dir name)
    print("\n  --- 2d: name(0) with 10-lambda (should return root or '/') ---")
    int0_wide = encode_int_wide(0, num_lambdas=10)
    payload_0w = (
        bytes([0x06]) + encode_term(int0_wide) + bytes([FD]) + QD + bytes([FD, FF])
    )
    out, elapsed = query_raw(payload_0w, timeout_s=6.0)
    result = classify(out, elapsed)
    print(f"  name(0) [10-lam]: {result}")
    if out and FF in out:
        try:
            parsed = parse_term(out)
            tag, payload_data = decode_either(parsed)
            if tag == "Left":
                text = decode_bytes_list(payload_data).decode(
                    "latin-1", errors="replace"
                )
                print(f"    → {tag}: {text!r}")
            else:
                err = decode_byte_term(payload_data)
                print(f"    → {tag}({err})")
        except Exception as e:
            print(f"    parse error: {e}")
    time.sleep(0.3)


# ── Probe 3: File ID 56154 ───────────────────────────────────────────


def probe_3_file_56154():
    print("\n" + "=" * 72)
    print("PROBE 3: File ID 56154 (sha1 iteration count)")
    print("  If wide integers work, this could be a hidden file.")
    print("=" * 72)

    qd_term = parse_term(QD + bytes([FF]))

    # 56154 in binary: 1101101101011010 (16 bits)
    # Need at least 17 lambdas
    int_56154 = encode_int_wide(56154)
    payload_size = len(encode_term(int_56154))
    print(f"  int(56154) encoded size: {payload_size} bytes")

    # 3a: name(56154)
    print("\n  --- 3a: name(56154) ---")
    payload = (
        bytes([0x06]) + encode_term(int_56154) + bytes([FD]) + QD + bytes([FD, FF])
    )
    print(f"  Total payload: {len(payload)} bytes")
    out, elapsed = query_raw(payload, timeout_s=6.0)
    result = classify(out, elapsed)
    print(f"  name(56154): {result}")
    if out and FF in out:
        try:
            parsed = parse_term(out)
            tag, payload_data = decode_either(parsed)
            if tag == "Left":
                text = decode_bytes_list(payload_data).decode(
                    "latin-1", errors="replace"
                )
                print(f"    → {tag}: {text!r}")
            else:
                err = decode_byte_term(payload_data)
                print(f"    → {tag}({err})")
        except Exception as e:
            print(f"    parse error: {e}")
    time.sleep(0.3)

    # 3b: readfile(56154)
    print("\n  --- 3b: readfile(56154) ---")
    payload = (
        bytes([0x07]) + encode_term(int_56154) + bytes([FD]) + QD + bytes([FD, FF])
    )
    out, elapsed = query_raw(payload, timeout_s=6.0)
    result = classify(out, elapsed)
    print(f"  readfile(56154): {result}")
    if out and FF in out:
        try:
            parsed = parse_term(out)
            tag, payload_data = decode_either(parsed)
            if tag == "Left":
                text = decode_bytes_list(payload_data).decode(
                    "latin-1", errors="replace"
                )
                print(f"    → {tag}: {text!r}")
            else:
                err = decode_byte_term(payload_data)
                print(f"    → {tag}({err})")
        except Exception as e:
            print(f"    parse error: {e}")
    time.sleep(0.3)

    # 3c: readdir(56154)
    print("\n  --- 3c: readdir(56154) ---")
    payload = (
        bytes([0x05]) + encode_term(int_56154) + bytes([FD]) + QD + bytes([FD, FF])
    )
    out, elapsed = query_raw(payload, timeout_s=6.0)
    result = classify(out, elapsed)
    print(f"  readdir(56154): {result}")
    if out and FF in out:
        try:
            parsed = parse_term(out)
            tag, payload_data = decode_either(parsed)
            if tag == "Left":
                print(f"    → {tag}: (directory listing)")
            else:
                err = decode_byte_term(payload_data)
                print(f"    → {tag}({err})")
        except Exception as e:
            print(f"    parse error: {e}")
    time.sleep(0.3)

    # 3d: Also try some other "interesting" IDs
    interesting_ids = [
        (42, "42 (towel/answer to everything)"),
        (201, "201 (backdoor syscall num)"),
        (1337, "1337 (leet)"),
        (9252, "9252 (first 4 digits of target hash)"),
        (31337, "31337 (eleet)"),
        (65535, "65535 (max uint16)"),
    ]

    print("\n  --- 3d: Other interesting file IDs ---")
    for fid, desc in interesting_ids:
        # Skip ones we already know about
        int_fid = encode_int_wide(fid)
        payload = (
            bytes([0x06]) + encode_term(int_fid) + bytes([FD]) + QD + bytes([FD, FF])
        )
        if len(payload) > 2000:
            print(f"  name({fid}) [{desc}]: SKIPPED (payload too big: {len(payload)}B)")
            continue
        out, elapsed = query_raw(payload, timeout_s=6.0)
        if out and FF in out:
            try:
                parsed = parse_term(out)
                tag, payload_data = decode_either(parsed)
                if tag == "Left":
                    text = decode_bytes_list(payload_data).decode(
                        "latin-1", errors="replace"
                    )
                    print(f"  name({fid}) [{desc}]: {tag} → {text!r}")
                else:
                    err = decode_byte_term(payload_data)
                    if err != 3:  # Only print if NOT "No such file"
                        print(f"  name({fid}) [{desc}]: {tag}({err})")
                    # else: silently skip "no such file"
            except Exception as e:
                print(f"  name({fid}) [{desc}]: parse error: {e}")
        else:
            result = classify(out, elapsed)
            if "EMPTY" not in result:
                print(f"  name({fid}) [{desc}]: {result}")
        time.sleep(0.25)


# ── Probe 4: Syscall 8 inside backdoor continuation ─────────────────


def probe_4_sys8_in_backdoor():
    print("\n" + "=" * 72)
    print("PROBE 4: Syscall 8 inside backdoor's continuation")
    print("  backdoor(nil, λpair. sys8(pair, shifted_QD))")
    print("  Tests if sys8 permission depends on call context/state.")
    print("=" * 72)

    # shifted QD: under 1 lambda (the backdoor continuation), free vars shift +1
    shifted_qd = make_shifted_qd(1)

    # nil
    nil_term = Lam(Lam(Var(0)))

    # backdoor(nil, λresult. sys8(result, shifted_QD))
    # g(201) = Var(201) at top level
    # Under the continuation lambda:
    #   result = Var(0) (bound by the cont lambda)
    #   g(8) = Var(8 + 1) = Var(9) (shifted by 1 under the cont lambda)
    #   g(201) = Var(201) at top level

    # Actually, in the CPS convention:
    # ((g(201) nil) (λresult. ((g(8) result) shifted_QD)))
    # = g(201) applied to nil, with continuation that calls g(8) on the result

    # Build: Var(201) nil FD (Var(9) 0 FD shifted_QD FD FE) FD FF
    # Wait, need to be careful with de Bruijn:
    # At top level: g(201) = Var(201), g(8) = Var(8)
    # Under 1 lambda (the cont): g(201) = Var(202), g(8) = Var(9), result = Var(0)

    # The continuation: λresult. ((g(8) result) shifted_QD)
    # = Lam(App(App(Var(9), Var(0)), shifted_QD))
    cont = Lam(App(App(Var(9), Var(0)), shifted_qd))

    # Full term: ((Var(201) nil) cont)
    full = App(App(Var(201), nil_term), cont)

    payload = encode_term(full) + bytes([FF])
    print(f"  Payload size: {len(payload)} bytes")

    out, elapsed = query_raw(payload, timeout_s=8.0)
    result = classify(out, elapsed)
    print(f"  sys8(backdoor_result) in backdoor cont: {result}")
    if out:
        if FF in out:
            try:
                parsed = parse_term(out)
                tag, payload_data = decode_either(parsed)
                if tag == "Left":
                    text = decode_bytes_list(payload_data).decode(
                        "latin-1", errors="replace"
                    )
                    print(f"    → {tag}: {text!r}")
                else:
                    err = decode_byte_term(payload_data)
                    print(f"    → {tag}({err})")
                    if err == 6:
                        print("    >>> Still PermDenied — context doesn't matter")
                    elif err == 2:
                        print("    >>> InvalidArg! Right type, wrong value!")
                    else:
                        print(f"    >>> NEW ERROR CODE! Investigate!")
            except Exception as e:
                print(f"    parse error: {e}")
                print(f"    hex: {out.hex()}")
        else:
            print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.5)

    # 4b: sys8 with the UNWRAPPED backdoor pair (not the Either, the actual pair)
    print("\n  --- 4b: Unwrap backdoor Left → pair, then sys8(pair) ---")

    # ((g(201) nil) (λeither. either(λpair. ((g(8) pair) shifted_QD_2), λerr. write("ERR"))))
    # Under 1 lambda (either handler): g(8)=Var(9), g(2)=Var(3), g(201)=Var(202)
    # Under 2 lambdas (Left handler): g(8)=Var(10), pair=Var(0)
    shifted_qd_2 = make_shifted_qd(2)

    # Left handler: λpair. ((g(8) pair) shifted_QD_2)
    left_handler = Lam(App(App(Var(10), Var(0)), shifted_qd_2))

    # Right handler: λerr. write("ERR")  — shouldn't happen since backdoor(nil) = Left
    # Under 2 lambdas: g(2)=Var(4)
    # Just use a marker
    err_marker_bytes = encode_term(Lam(Lam(Var(0))))  # nil as dummy
    right_handler = Lam(Var(0))  # identity — just return the error

    # either(left_handler, right_handler) = result(left_handler)(right_handler)
    # Under 1 lambda: result = Var(0)
    either_cont = Lam(App(App(Var(0), left_handler), right_handler))

    full = App(App(Var(201), Lam(Lam(Var(0)))), either_cont)
    payload = encode_term(full) + bytes([FF])
    print(f"  Payload size: {len(payload)} bytes")

    out, elapsed = query_raw(payload, timeout_s=8.0)
    result = classify(out, elapsed)
    print(f"  sys8(unwrapped_pair) in backdoor cont: {result}")
    if out:
        if FF in out:
            try:
                parsed = parse_term(out)
                tag, payload_data = decode_either(parsed)
                if tag == "Left":
                    text = decode_bytes_list(payload_data).decode(
                        "latin-1", errors="replace"
                    )
                    print(f"    → {tag}: {text!r}")
                else:
                    err = decode_byte_term(payload_data)
                    print(f"    → {tag}({err})")
            except Exception as e:
                print(f"    parse error: {e}")
                print(f"    hex: {out.hex()}")
        else:
            print(f"    text: {out.decode('latin-1', errors='replace')[:80]!r}")
    time.sleep(0.5)

    # 4c: sys8 with A component of backdoor (λa.λb. bb)
    print("\n  --- 4c: sys8(A) where A=λa.λb.bb ---")
    A = Lam(Lam(App(Var(0), Var(0))))  # λa.λb. b b
    shifted_qd_0 = parse_term(QD + bytes([FF]))  # no shift needed at top level
    full = App(App(Var(8), A), shifted_qd_0)
    payload = encode_term(full) + bytes([FF])
    out, elapsed = query_raw(payload, timeout_s=6.0)
    result = classify(out, elapsed)
    print(f"  sys8(A=λab.bb): {result}")
    if out and FF in out:
        try:
            parsed = parse_term(out)
            tag, payload_data = decode_either(parsed)
            err = decode_byte_term(payload_data) if tag == "Right" else None
            print(f"    → {tag}({err if err is not None else '...'})")
        except Exception as e:
            print(f"    parse error: {e}")
    time.sleep(0.3)

    # 4d: sys8(B) where B=λa.λb. ab
    print("\n  --- 4d: sys8(B) where B=λa.λb.ab ---")
    B = Lam(Lam(App(Var(1), Var(0))))  # λa.λb. a b
    full = App(App(Var(8), B), shifted_qd_0)
    payload = encode_term(full) + bytes([FF])
    out, elapsed = query_raw(payload, timeout_s=6.0)
    result = classify(out, elapsed)
    print(f"  sys8(B=λab.ab): {result}")
    if out and FF in out:
        try:
            parsed = parse_term(out)
            tag, payload_data = decode_either(parsed)
            err = decode_byte_term(payload_data) if tag == "Right" else None
            print(f"    → {tag}({err if err is not None else '...'})")
        except Exception as e:
            print(f"    parse error: {e}")
    time.sleep(0.3)

    # 4e: sys8(ω) where ω=λx.xx
    print("\n  --- 4e: sys8(ω) where ω=λx.xx ---")
    omega_half = Lam(App(Var(0), Var(0)))
    full = App(App(Var(8), omega_half), shifted_qd_0)
    payload = encode_term(full) + bytes([FF])
    out, elapsed = query_raw(payload, timeout_s=6.0)
    result = classify(out, elapsed)
    print(f"  sys8(ω=λx.xx): {result}")
    if out and FF in out:
        try:
            parsed = parse_term(out)
            tag, payload_data = decode_either(parsed)
            err = decode_byte_term(payload_data) if tag == "Right" else None
            print(f"    → {tag}({err if err is not None else '...'})")
        except Exception as e:
            print(f"    parse error: {e}")
    time.sleep(0.3)

    # 4f: sys8 with gizmore's password as byte string
    print("\n  --- 4f: sys8('ilikephp' as byte string) ---")
    from solve_brownos_answer import encode_bytes_list

    pwd_str = encode_bytes_list(b"ilikephp")
    full = App(App(Var(8), pwd_str), shifted_qd_0)
    payload = encode_term(full) + bytes([FF])
    print(f"  Payload size: {len(payload)} bytes")
    if len(payload) > 2000:
        print("  SKIPPED: payload too big")
    else:
        out, elapsed = query_raw(payload, timeout_s=6.0)
        result = classify(out, elapsed)
        print(f"  sys8('ilikephp'): {result}")
        if out and FF in out:
            try:
                parsed = parse_term(out)
                tag, payload_data = decode_either(parsed)
                if tag == "Left":
                    text = decode_bytes_list(payload_data).decode(
                        "latin-1", errors="replace"
                    )
                    print(f"    → {tag}: {text!r}")
                else:
                    err = decode_byte_term(payload_data)
                    print(f"    → {tag}({err})")
            except Exception as e:
                print(f"    parse error: {e}")
    time.sleep(0.3)


# ── Probe 5: Omega applied to each global ────────────────────────────


def probe_5_omega_globals():
    print("\n" + "=" * 72)
    print("PROBE 5: ω(g(n)) = g(n)(g(n)) for each known syscall")
    print("  This is self-application: what happens when a syscall takes itself?")
    print("=" * 72)

    qd_term = parse_term(QD + bytes([FF]))

    # ω(g(n)) = (λx.xx)(g(n)) β→ g(n)(g(n))
    # In CPS: ((g(n) g(n)) QD) — syscall n with g(n) as argument
    # This is slightly different from ω(g(n)) which would be:
    # (ω g(n)) = ((λx.xx) g(n)) = g(n)(g(n))
    # Then we need to observe the result. But g(n)(g(n)) is a partial application
    # (syscall takes arg then cont). So g(n)(g(n))(QD) = full CPS call.

    known = [1, 2, 4, 5, 6, 7, 8, 14, 42, 201]

    for n in known:
        # ((g(n) g(n)) QD) = CPS call: syscall n with g(n) as argument
        full = App(App(Var(n), Var(n)), qd_term)
        payload = encode_term(full) + bytes([FF])
        out, elapsed = query_raw(payload, timeout_s=6.0)
        result = classify(out, elapsed)

        detail = ""
        if out and FF in out:
            try:
                parsed = parse_term(out)
                tag, payload_data = decode_either(parsed)
                if tag == "Left":
                    try:
                        text = decode_bytes_list(payload_data).decode(
                            "latin-1", errors="replace"
                        )
                        detail = f" → {tag}: {text[:40]!r}"
                    except:
                        detail = f" → {tag}({payload_data})"
                else:
                    try:
                        err = decode_byte_term(payload_data)
                        detail = f" → {tag}({err})"
                    except:
                        detail = f" → {tag}({payload_data})"
            except:
                detail = f" hex={out[:20].hex()}"

        print(f"  g({n:3d})(g({n:3d})) via QD: {result}{detail}")
        time.sleep(0.25)


# ── Main ─────────────────────────────────────────────────────────────


def main():
    print("=" * 72)
    print("probe_oracle15.py — Oracle #15 recommended probes")
    print(f"  Target: {HOST}:{PORT}")
    print("=" * 72)
    print()

    probe_1_strictness()
    probe_2_wide_integers()
    probe_3_file_56154()
    probe_4_sys8_in_backdoor()
    probe_5_omega_globals()

    print("\n" + "=" * 72)
    print("All probes complete.")
    print("=" * 72)


if __name__ == "__main__":
    main()
