#!/usr/bin/env python3
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
DRAIN_TIMEOUT = 0.35
MAX_READ = 10 * 1024
STEP_DELAY = 0.3

NIL = Lam(Lam(Var(0)))
IDENTITY = Lam(Var(0))


def syscall_qd_payload(syscall_num: int, argument: object) -> bytes:
    return (
        bytes([syscall_num])
        + encode_term(argument)
        + bytes([FD])
        + QD
        + bytes([FD, FF])
    )


def syscall_cont_payload(
    syscall_num: int, argument: object, continuation: object
) -> bytes:
    return encode_term(App(App(Var(syscall_num), argument), continuation)) + bytes([FF])


def syscall_partial_payload(syscall_num: int, argument: object) -> bytes:
    return encode_term(App(Var(syscall_num), argument)) + bytes([FF])


def build_dbg_continuation() -> object:
    left_marker = encode_bytes_list(b"LEFT:")
    right_marker = encode_bytes_list(b"RIGHT:")
    errstr_fail = encode_bytes_list(b"ERRSTR_FAIL")

    left_handler = Lam(App(App(Var(4), left_marker), NIL))

    err_left_handler = Lam(App(App(Var(7), Var(0)), NIL))
    err_right_handler = Lam(App(App(Var(7), errstr_fail), NIL))
    err_string_handler = Lam(App(App(Var(0), err_left_handler), err_right_handler))

    after_right_marker = Lam(App(App(Var(4), Var(1)), err_string_handler))
    right_handler = Lam(App(App(Var(4), right_marker), after_right_marker))

    return Lam(App(App(Var(0), left_handler), right_handler))


def build_write_quote_continuation() -> object:
    # lambda res. ((write (quote res)) nil)
    # Under one lambda depth: write=Var(3), quote=Var(5), res=Var(0)
    return Lam(App(App(Var(3), App(Var(5), Var(0))), NIL))


def recv_observation(sock: socket.socket, stop_on_ff: bool) -> tuple[bytes, float]:
    start = time.monotonic()
    out = b""
    sock.settimeout(READ_TIMEOUT)
    switched_to_drain = False

    while len(out) < MAX_READ:
        try:
            chunk = sock.recv(min(4096, MAX_READ - len(out)))
        except socket.timeout:
            break
        if not chunk:
            break

        out += chunk

        if stop_on_ff and FF in chunk:
            break

        if not switched_to_drain:
            sock.settimeout(DRAIN_TIMEOUT)
            switched_to_drain = True

    return out, time.monotonic() - start


def parse_first_term(data: bytes) -> object | None:
    if not data or FF not in data:
        return None
    try:
        return parse_term(data[: data.index(FF) + 1])
    except Exception:
        return None


def extract_left_payload_term(data: bytes) -> object | None:
    term = parse_first_term(data)
    if term is None:
        return None
    try:
        tag, payload = decode_either(term)
    except Exception:
        return None
    if tag != "Left":
        return None
    return payload


def extract_left_bytes(data: bytes) -> bytes | None:
    payload = extract_left_payload_term(data)
    if payload is None:
        return None
    try:
        return decode_bytes_list(payload)
    except Exception:
        return None


def interpret_response(data: bytes) -> str:
    if not data:
        return "EMPTY"
    if data.startswith(b"ERR:"):
        return data.decode("utf-8", "replace")
    if data.startswith(b"Invalid term!"):
        return "Invalid term!"
    if data.startswith(b"Term too big!"):
        return "Term too big!"
    if data.startswith(b"Encoding failed!"):
        return "Encoding failed!"

    term = parse_first_term(data)
    if term is not None:
        try:
            tag, payload = decode_either(term)
            if tag == "Right":
                try:
                    return f"Either Right({decode_byte_term(payload)})"
                except Exception:
                    return "Either Right(<non-byte payload>)"

            payload_bytes = decode_bytes_list(payload)
            preview = payload_bytes[:80].decode("utf-8", "replace")
            more = "..." if len(payload_bytes) > 80 else ""
            return (
                f"Either Left(bytes,len={len(payload_bytes)},preview={preview!r}{more})"
            )
        except Exception:
            return "Term output (non-Either or undecodable)"

    text = data.decode("utf-8", "replace")
    return f"Raw bytes/text: {text!r}"


def send_and_observe(
    sock: socket.socket,
    label: str,
    payload: bytes,
    *,
    stop_on_ff: bool,
) -> bytes:
    send_elapsed = 0.0
    recv_elapsed = 0.0
    recv_data = b""
    send_error = ""
    recv_error = ""

    send_start = time.monotonic()
    try:
        sock.sendall(payload)
        send_elapsed = time.monotonic() - send_start
    except Exception as exc:
        send_elapsed = time.monotonic() - send_start
        send_error = str(exc)
        recv_data = f"ERR:send:{exc}".encode("utf-8", "replace")

    if not send_error:
        try:
            recv_data, recv_elapsed = recv_observation(sock, stop_on_ff=stop_on_ff)
        except Exception as exc:
            recv_error = str(exc)
            recv_data = f"ERR:recv:{exc}".encode("utf-8", "replace")

    print(f"  - {label}")
    print(f"    sent[{len(payload)}]: {payload.hex()}")
    print(f"    send_time_s: {send_elapsed:.3f}")
    if send_error:
        print(f"    send_error: {send_error}")
    print(f"    recv[{len(recv_data)}]: {recv_data.hex()}")
    print(f"    recv_time_s: {recv_elapsed:.3f}")
    if recv_error:
        print(f"    recv_error: {recv_error}")
    print(f"    interp: {interpret_response(recv_data)}")

    return recv_data


def run_single(
    label: str,
    payload: bytes,
    *,
    stop_on_ff: bool,
    shutdown_wr: bool,
) -> bytes:
    print(f"\n[{label}]")
    try:
        with socket.create_connection((HOST, PORT), timeout=CONNECT_TIMEOUT) as sock:
            out = send_and_observe(sock, "single", payload, stop_on_ff=stop_on_ff)
            if shutdown_wr:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        return out
    except Exception as exc:
        err = f"ERR:connect:{exc}".encode("utf-8", "replace")
        print(f"  connect_error: {exc}")
        print(f"  interp: {interpret_response(err)}")
        return err


def run_persistent_sequence(
    name: str, steps: list[tuple[str, bytes, bool]]
) -> list[bytes]:
    print(f"\n[{name}]")
    print("  mode: one socket, no shutdown between sends")
    out_list: list[bytes] = []
    try:
        with socket.create_connection((HOST, PORT), timeout=CONNECT_TIMEOUT) as sock:
            for idx, (label, payload, stop_on_ff) in enumerate(steps, start=1):
                out = send_and_observe(
                    sock, f"step {idx}: {label}", payload, stop_on_ff=stop_on_ff
                )
                out_list.append(out)
                if out.startswith(b"ERR:"):
                    print("    sequence aborted after socket error")
                    break
                if idx != len(steps):
                    time.sleep(STEP_DELAY)
    except Exception as exc:
        err = f"ERR:connect:{exc}".encode("utf-8", "replace")
        out_list.append(err)
        print(f"  connect_error: {exc}")
    return out_list


def phase_1_true_persistent_session() -> None:
    print("\n=== PHASE 1: True Persistent Session ===")

    p_towel_qd = syscall_qd_payload(0x2A, NIL)
    p_backdoor_qd = syscall_qd_payload(0xC9, NIL)
    p_sys8_qd = syscall_qd_payload(0x08, NIL)
    p_echo_nil_qd = syscall_qd_payload(0x0E, NIL)
    p_echo_251_qd = syscall_qd_payload(0x0E, Var(251))

    cases = [
        (
            "P1.1 towel(nil)+QD -> towel(nil)+QD",
            [
                ("towel(nil)+QD", p_towel_qd, True),
                ("towel(nil)+QD", p_towel_qd, True),
            ],
        ),
        (
            "P1.2 backdoor(nil)+QD -> sys8(nil)+QD",
            [
                ("backdoor(nil)+QD", p_backdoor_qd, True),
                ("sys8(nil)+QD", p_sys8_qd, True),
            ],
        ),
        (
            "P1.3 echo(nil)+QD -> sys8(nil)+QD",
            [
                ("echo(nil)+QD", p_echo_nil_qd, True),
                ("sys8(nil)+QD", p_sys8_qd, True),
            ],
        ),
        (
            "P1.4 backdoor(nil)+QD -> echo(nil)+QD -> sys8(nil)+QD",
            [
                ("backdoor(nil)+QD", p_backdoor_qd, True),
                ("echo(nil)+QD", p_echo_nil_qd, True),
                ("sys8(nil)+QD", p_sys8_qd, True),
            ],
        ),
        (
            "P1.5 echo(Var251)+QD -> sys8(nil)+QD",
            [
                ("echo(Var251)+QD", p_echo_251_qd, True),
                ("sys8(nil)+QD", p_sys8_qd, True),
            ],
        ),
    ]

    for name, steps in cases:
        _ = run_persistent_sequence(name, steps)


def phase_2_dbg_continuation(dbg: object) -> object | None:
    print("\n=== PHASE 2: Write-Based Debug Continuation (No Quote in DBG) ===")

    _ = run_single(
        "P2.1 ((sys8 nil) DBG)",
        syscall_cont_payload(0x08, NIL, dbg),
        stop_on_ff=False,
        shutdown_wr=True,
    )

    backdoor_resp = run_single(
        "P2.2a backdoor(nil)+QD (extract pair)",
        syscall_qd_payload(0xC9, NIL),
        stop_on_ff=True,
        shutdown_wr=True,
    )
    pair_term = extract_left_payload_term(backdoor_resp)
    if pair_term is None:
        print(
            "  pair extraction failed: could not decode Left payload from backdoor(nil)"
        )
        return None

    print("  extracted backdoor pair: OK")
    _ = run_single(
        "P2.2b ((sys8 backdoor_pair) DBG)",
        syscall_cont_payload(0x08, pair_term, dbg),
        stop_on_ff=False,
        shutdown_wr=True,
    )
    return pair_term


def phase_3_persistent_plus_dbg(dbg: object) -> None:
    print("\n=== PHASE 3: Persistent Session + DBG ===")

    p_backdoor_qd = syscall_qd_payload(0xC9, NIL)
    p_echo_nil_qd = syscall_qd_payload(0x0E, NIL)
    p_echo_251_qd = syscall_qd_payload(0x0E, Var(251))
    p_echo_252_qd = syscall_qd_payload(0x0E, Var(252))
    p_sys8_dbg = syscall_cont_payload(0x08, NIL, dbg)

    out1 = run_persistent_sequence(
        "P3.1 backdoor(nil)+QD -> ((sys8 nil) DBG)",
        [
            ("backdoor(nil)+QD", p_backdoor_qd, True),
            ("((sys8 nil) DBG)", p_sys8_dbg, False),
        ],
    )
    if out1:
        pair = extract_left_payload_term(out1[0])
        print(
            f"  P3.1 pair extracted from step1: {'yes' if pair is not None else 'no'}"
        )

    _ = run_persistent_sequence(
        "P3.2 echo(nil)+QD -> ((sys8 nil) DBG)",
        [
            ("echo(nil)+QD", p_echo_nil_qd, True),
            ("((sys8 nil) DBG)", p_sys8_dbg, False),
        ],
    )

    _ = run_persistent_sequence(
        "P3.3 three echos before sys8",
        [
            ("echo(nil)+QD", p_echo_nil_qd, True),
            ("echo(Var251)+QD", p_echo_251_qd, True),
            ("echo(Var252)+QD", p_echo_252_qd, True),
            ("((sys8 nil) DBG)", p_sys8_dbg, False),
        ],
    )


def phase_4_sys8_continuation_variants() -> None:
    print("\n=== PHASE 4: sys8 With Different Continuations ===")

    _ = run_single(
        "P4.1 ((sys8 nil) (lambda x.x))",
        syscall_cont_payload(0x08, NIL, IDENTITY),
        stop_on_ff=False,
        shutdown_wr=True,
    )

    _ = run_single(
        "P4.2 ((sys8 nil) (lambda res. ((write (quote res)) nil)))",
        syscall_cont_payload(0x08, NIL, build_write_quote_continuation()),
        stop_on_ff=True,
        shutdown_wr=True,
    )

    _ = run_single(
        "P4.3 (sys8 nil) FF (partial application only)",
        syscall_partial_payload(0x08, NIL),
        stop_on_ff=False,
        shutdown_wr=True,
    )


def phase_5_session_canary() -> None:
    print("\n=== PHASE 5: Session Canary (access.log) ===")

    read_access_qd = syscall_qd_payload(0x07, encode_byte_term(46))

    regular = run_single(
        "P5.1 regular connection: ((readfile 46) QD) FF",
        read_access_qd,
        stop_on_ff=True,
        shutdown_wr=True,
    )
    regular_bytes = extract_left_bytes(regular)
    if regular_bytes is None:
        print("  regular decode: failed to decode Left(bytes)")
    else:
        print(f"  regular decode: {len(regular_bytes)} bytes")

    persistent_reads = run_persistent_sequence(
        "P5.2 persistent connection double read of access.log",
        [
            ("((readfile 46) QD) FF #1", read_access_qd, True),
            ("((readfile 46) QD) FF #2", read_access_qd, True),
        ],
    )
    if len(persistent_reads) != 2:
        print("  persistent decode: missing responses")
        return

    p1_bytes = extract_left_bytes(persistent_reads[0])
    p2_bytes = extract_left_bytes(persistent_reads[1])

    print(
        f"  raw_equal(persistent_read1, persistent_read2): {persistent_reads[0] == persistent_reads[1]}"
    )
    if p1_bytes is not None and p2_bytes is not None:
        print(f"  decoded_equal(access.log #1, #2): {p1_bytes == p2_bytes}")
        print(f"  decoded_len(#1)={len(p1_bytes)} decoded_len(#2)={len(p2_bytes)}")
    else:
        print("  decoded compare: could not decode one or both reads")


def phase_6_delayed_input_streaming() -> None:
    print("\n=== PHASE 6: Delayed Input / Streaming Parser Test ===")

    part1 = bytes([0x08, 0x00, FE, FE, FD])
    part2 = QD + bytes([FD, FF])

    print("  sending split program in two writes on one socket")
    try:
        with socket.create_connection((HOST, PORT), timeout=CONNECT_TIMEOUT) as sock:
            send_start = time.monotonic()
            sock.sendall(part1)
            send1_elapsed = time.monotonic() - send_start
            print(f"  - split part1 sent[{len(part1)}]: {part1.hex()}")
            print(f"    send_time_s: {send1_elapsed:.3f}")

            time.sleep(1.0)

            send_start = time.monotonic()
            sock.sendall(part2)
            send2_elapsed = time.monotonic() - send_start
            print(f"  - split part2 sent[{len(part2)}]: {part2.hex()}")
            print(f"    send_time_s: {send2_elapsed:.3f}")

            recv_data, recv_elapsed = recv_observation(sock, stop_on_ff=True)
            print(f"  - split recv[{len(recv_data)}]: {recv_data.hex()}")
            print(f"    recv_time_s: {recv_elapsed:.3f}")
            print(f"    interp: {interpret_response(recv_data)}")
    except Exception as exc:
        err = f"ERR:phase6:{exc}".encode("utf-8", "replace")
        print(f"  error: {exc}")
        print(f"  interp: {interpret_response(err)}")


def main() -> None:
    print("=" * 90)
    print("probe_oracle_v6.py - persistent session + write-observation probes")
    print(f"target: {HOST}:{PORT}")
    print("=" * 90)

    dbg = build_dbg_continuation()

    phase_1_true_persistent_session()
    _ = phase_2_dbg_continuation(dbg)
    phase_3_persistent_plus_dbg(dbg)
    phase_4_sys8_continuation_variants()
    phase_5_session_canary()
    phase_6_delayed_input_streaming()

    print("\nAll phases complete.")


if __name__ == "__main__":
    main()
