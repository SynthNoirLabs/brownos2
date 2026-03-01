#!/usr/bin/env python3
"""Raw byte-level probes: naked 3-leaf, parser edge cases, single bytes."""

import socket, time

HOST = "wc3.wechall.net"
PORT = 61221
FF = 0xFF


def query_raw(payload, timeout_s=8.0):
    try:
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
                    if not chunk:
                        break
                    out += chunk
                    if FF in chunk:
                        break
                except socket.timeout:
                    break
            return out
    except Exception as e:
        return b"ERR:" + str(e).encode()


def test(name, payload):
    time.sleep(0.4)
    r = query_raw(payload)
    if len(r) == 0:
        print(f"  {name}: EMPTY [{len(payload) - 1}b sent]")
    elif r.startswith(b"ERR:"):
        print(f"  {name}: {r.decode()}")
    else:
        h = r.hex()
        try:
            text = r.decode("ascii")
            print(f"  {name}: TEXT={text!r} [{len(payload) - 1}b sent]")
            return
        except:
            pass
        if "00030200fdfd" in h:
            print(f"  {name}: RIGHT(6) [{len(payload) - 1}b sent]")
        else:
            print(f"  {name}: HEX={h[:60]} [{len(r)}b resp, {len(payload) - 1}b sent]")
            try:
                print(f"    raw: {r[:40]!r}")
            except:
                pass


def main():
    print("=" * 70)
    print("SECTION 1: Naked 3-leaf terms (NO continuation)")
    print("  If dloser is right: empty = success when no write continuation")
    print("=" * 70)

    # sys8(nil) — no continuation at all. Just App(Var(8), nil).
    # Postfix: 08 00 FE FE FD FF
    test("sys8(nil) [no cont]", bytes([0x08, 0x00, 0xFE, 0xFE, 0xFD, 0xFF]))

    # sys8(g201(nil)) — sys8 applied to backdoor call. No cont.
    # Postfix: 08 C9 00 FE FE FD FD FF
    test(
        "sys8(backdoor(nil)) [no cont]",
        bytes([0x08, 0xC9, 0x00, 0xFE, 0xFE, 0xFD, 0xFD, 0xFF]),
    )

    # sys201(nil)(sys8) — backdoor with sys8 as continuation
    # Postfix: C9 00 FE FE FD 08 FD FF
    test(
        "backdoor(nil)(sys8) [sys8 as cont]",
        bytes([0xC9, 0x00, 0xFE, 0xFE, 0xFD, 0x08, 0xFD, 0xFF]),
    )

    # Just sys8 alone: 08 FF
    test("sys8 alone [Var(8)]", bytes([0x08, 0xFF]))

    # sys8(sys8): 08 08 FD FF
    test("sys8(sys8)", bytes([0x08, 0x08, 0xFD, 0xFF]))

    # echo(sys8): 0E 08 FD FF
    test("echo(sys8)", bytes([0x0E, 0x08, 0xFD, 0xFF]))

    # The LLM's exact payloads
    test(
        "LLM: sys8(sys201(nil)) 3-leaf",
        bytes([0x08, 0xC9, 0x00, 0xFE, 0xFE, 0xFD, 0xFD, 0xFF]),
    )
    test(
        "LLM: sys201(nil)(sys8) 3-leaf",
        bytes([0xC9, 0x00, 0xFE, 0xFE, 0xFD, 0x08, 0xFD, 0xFF]),
    )

    print()
    print("=" * 70)
    print("SECTION 2: Parser edge cases / stack underflow")
    print("=" * 70)

    test("FD FF [App with empty stack]", bytes([0xFD, 0xFF]))
    test("00 FD FF [App with 1 item]", bytes([0x00, 0xFD, 0xFF]))
    test("FE FF [Lam with empty stack]", bytes([0xFE, 0xFF]))
    test("FD 00 00 FF [underflow then push 2]", bytes([0xFD, 0x00, 0x00, 0xFF]))
    test("FD FE FF", bytes([0xFD, 0xFE, 0xFF]))
    test("FE FD FF", bytes([0xFE, 0xFD, 0xFF]))
    test("FE FE FF [double lam empty]", bytes([0xFE, 0xFE, 0xFF]))
    test("just FF", bytes([0xFF]))
    test("empty (no bytes)", bytes([]))

    # Multi-item stack at end
    test("00 01 FF [2 items on stack]", bytes([0x00, 0x01, 0xFF]))
    test("00 01 02 FF [3 items on stack]", bytes([0x00, 0x01, 0x02, 0xFF]))

    print()
    print("=" * 70)
    print("SECTION 3: Cheat sheet ?? ?? FD QD FD with specific values")
    print("=" * 70)

    QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

    # echo(echo)(QD): 0E 0E FD QD FD FF
    test("echo(echo)(QD)", bytes([0x0E, 0x0E, 0xFD]) + QD + bytes([0xFD, 0xFF]))

    # echo(Var(251))(QD): 0E FB FD QD FD FF
    test("echo(V251)(QD)", bytes([0x0E, 0xFB, 0xFD]) + QD + bytes([0xFD, 0xFF]))

    # sys8(sys8)(QD): 08 08 FD QD FD FF
    test("sys8(sys8)(QD)", bytes([0x08, 0x08, 0xFD]) + QD + bytes([0xFD, 0xFF]))

    # backdoor(nil)(QD): C9 00 FE FE FD QD FD FF — control
    test(
        "backdoor(nil)(QD) [control]",
        bytes([0xC9, 0x00, 0xFE, 0xFE, 0xFD]) + QD + bytes([0xFD, 0xFF]),
    )

    # echo(sys8)(QD): 0E 08 FD QD FD FF
    test("echo(sys8)(QD)", bytes([0x0E, 0x08, 0xFD]) + QD + bytes([0xFD, 0xFF]))

    print()
    print("=" * 70)
    print("SECTION 4: Single-byte opcode scan (0x00-0x10, 0xFA-0xFC)")
    print("  Looking for hidden opcodes or unusual behavior")
    print("=" * 70)

    for b in list(range(0, 17)) + list(range(0xFA, 0xFD)):
        test(f"byte 0x{b:02X} alone", bytes([b, 0xFF]))

    print()
    print("Done.")


if __name__ == "__main__":
    main()
