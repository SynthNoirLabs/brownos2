#!/usr/bin/env python3
import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221
FF = 0xFF


def query_raw(payload, timeout_s=5.0):
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
    print(f"--- Running Probe: {name} ---")
    print(f"Sending ({len(payload)} bytes): {payload.hex()}")

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
        print(f"  {name}: HEX={h[:80]} [{len(r)}b resp, {len(payload) - 1}b sent]")
        if "00030200fdfd" in h:
            print(f"    -> Contains Right(6) pattern")


def main():
    print("=" * 70)
    print("TESTING LLM v12 PROPOSALS: 3-LEAF PURE MATH PARADOXES")
    print("=" * 70)

    # 1. Payload 1: The Echoed Backdoor Inversion
    # sys14 sys201 sys8
    payload_inversion = bytes([0x0E, 0xC9, 0xFD, 0x08, 0xFD, 0xFF])
    test("dark_magic_inversion", payload_inversion)

    # 2. Payload 2: The Target Ouroboros
    # sys8 sys8 sys8
    payload_ouroboros_8 = bytes([0x08, 0x08, 0xFD, 0x08, 0xFD, 0xFF])
    test("dark_magic_ouroboros_8", payload_ouroboros_8)

    # 3. Payload 3: The Backdoor Singularity
    # sys201 sys201 sys201
    payload_singularity = bytes([0xC9, 0xC9, 0xFD, 0xC9, 0xFD, 0xFF])
    test("dark_magic_singularity", payload_singularity)


if __name__ == "__main__":
    main()
