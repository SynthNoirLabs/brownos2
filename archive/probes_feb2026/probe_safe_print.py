#!/usr/bin/env python3
"""
Safe, no-quote probing helper for BrownOS.

Why this exists:
- QD uses quote(), which can trigger "Encoding failed!" (no 0xFF) and hang naive clients.
- We instead print by calling syscall 0x01 (error string) + syscall 0x02 (write).
"""

from __future__ import annotations

import socket
import time

from solve_brownos_answer import App, Lam, Var, encode_byte_term, encode_bytes_list, encode_term

HOST = "82.165.133.222"  # IPv4 avoids DNS/IPv6 delays
PORT = 61221

FD = 0xFD
FF = 0xFF


def query_all(payload: bytes, timeout_s: float = 6.0) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
        sock.sendall(payload)
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
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


I: object = Lam(Var(0))
NIL: object = Lam(Lam(Var(0)))


def cps(syscall_num: int, arg: object, cont: object) -> object:
    return App(App(Var(syscall_num), arg), cont)


def build_cont_print() -> object:
    """
    Continuation that prints syscall results without quote().

    On result = Left(bytes_list): write(bytes_list)
    On result = Right(code):      write(errorString(code))
    """
    write = 2
    error_string = 1

    # Left handler: λpayload. ((write payload) I)
    left_handler = Lam(App(App(Var(write + 2), Var(0)), I))

    # errorString(code) continuation: λe2. e2 (λbs. (write bs) I) (λ_. I)
    left2 = Lam(App(App(Var(write + 4), Var(0)), I))
    right2 = Lam(I)
    cont_err = Lam(App(App(Var(0), left2), right2))

    # Right handler: λcode. ((errorString code) cont_err)
    right_handler = Lam(App(App(Var(error_string + 2), Var(0)), cont_err))

    # Whole: λres. res left_handler right_handler
    return Lam(App(App(Var(0), left_handler), right_handler))


CONT_PRINT = build_cont_print()


def shift(term: object, delta: int, cutoff: int = 0) -> object:
    if isinstance(term, Var):
        return Var(term.i + delta) if term.i >= cutoff else term
    if isinstance(term, Lam):
        return Lam(shift(term.body, delta, cutoff + 1))
    if isinstance(term, App):
        return App(shift(term.f, delta, cutoff), shift(term.x, delta, cutoff))
    raise TypeError(f"Unsupported term node: {type(term)}")


def run_case(name: str, term: object) -> None:
    payload = encode_term(term) + bytes([FF])
    out = query_all(payload)
    try:
        shown = out.decode("utf-8", "replace")
    except Exception:
        shown = repr(out)
    print(f"{name}: {shown!r} ({len(out)} bytes)")
    time.sleep(0.25)


def main() -> None:
    print("=== Baselines ===")
    run_case("8(nil) -> print", cps(0x08, NIL, CONT_PRINT))

    print("\n=== 3-leaf style chaining (syscalls as continuations) ===")
    # (((201 nil) 8) CONT_PRINT)
    term_bd_to_8 = App(cps(0xC9, NIL, Var(0x08)), CONT_PRINT)
    run_case("((201 nil) 8) -> then print", term_bd_to_8)

    # (((echo 251) 8) CONT_PRINT)  where echo=0x0E, 251=0xFB
    term_echo251_to_8 = App(cps(0x0E, Var(0xFB), Var(0x08)), CONT_PRINT)
    run_case("((echo 251) 8) -> then print", term_echo251_to_8)

    term_echo252_to_8 = App(cps(0x0E, Var(0xFC), Var(0x08)), CONT_PRINT)
    run_case("((echo 252) 8) -> then print", term_echo252_to_8)

    print("\n=== Pass RAW echo result as argument to syscall 8 (no unwrap) ===")
    # echo(251) >>= \\e. 8(e) -> print
    cont_8_raw = Lam(App(App(Var(0x08 + 1), Var(0)), shift(CONT_PRINT, 1)))
    run_case("echo(251) -> 8(echo_result) -> print", cps(0x0E, Var(0xFB), cont_8_raw))
    run_case("echo(252) -> 8(echo_result) -> print", cps(0x0E, Var(0xFC), cont_8_raw))

    print("\n=== Partial-unwrapping tricks (keep +1 shift) ===")
    # echo(252) >>= \\e. 8(e I) -> print
    # Here (e I) is an Either partially applied to its Left-branch handler.
    # For Left(payload), this produces a lambda whose body contains payload shifted by +1.
    cont_8_eI = Lam(App(App(Var(0x08 + 1), App(Var(0), I)), shift(CONT_PRINT, 1)))
    run_case("echo(252) -> 8(e I) -> print", cps(0x0E, Var(0xFC), cont_8_eI))

    # echo(252) >>= \\e. 8(e 8) -> print
    cont_8_e8 = Lam(App(App(Var(0x08 + 1), App(Var(0), Var(0x08 + 1))), shift(CONT_PRINT, 1)))
    run_case("echo(252) -> 8(e 8) -> print", cps(0x0E, Var(0xFC), cont_8_e8))

    print("\n=== Pipe syscall outputs into syscall 8 (in-process) ===")
    # readfile(access.log id=46) >>= \\bs. syscall8(bs) -> print
    access_log_id = encode_byte_term(46)
    rfail = encode_bytes_list(b"readfile failed\n")
    left_bs_to_8 = Lam(App(App(Var(0x08 + 2), Var(0)), shift(CONT_PRINT, 2)))
    right_fail = Lam(App(App(Var(0x02 + 2), rfail), I))
    cont_readfile_then_8 = Lam(App(App(Var(0), left_bs_to_8), right_fail))
    run_case(
        "readfile(access.log) -> 8(bytes) -> print",
        cps(0x07, access_log_id, cont_readfile_then_8),
    )

    print("\n=== Write plain strings (sanity) ===")
    hello = encode_bytes_list(b"hello\n")
    run_case("write('hello')", cps(0x02, hello, I))


if __name__ == "__main__":
    main()
