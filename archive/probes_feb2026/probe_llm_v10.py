#!/usr/bin/env python3
import socket, time

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
    print("TESTING LLM v10 PROPOSALS: NATIVE MEMORY DUMP & 3-LEAF PIPE")
    print("=" * 70)

    # 1. Sys201 -> Bad QD (Dump 'A' directly)
    # Bad QD: \r. sys2(r) -> 02 00 FD FE
    # Sys201(nil): C9 00 FE FE FD
    # Payload: sys201(nil)(Bad QD)
    # C9 00 FE FE FD 02 00 FD FE FD FF
    test(
        "Sys201_Left_DirectDump (Bad QD)",
        bytes([0xC9, 0x00, 0xFE, 0xFE, 0xFD, 0x02, 0x00, 0xFD, 0xFE, 0xFD, 0xFF]),
    )

    # 2. Extract 'A' and directly dump it using Bad QD
    # Extract A: \pair. pair (\a \b. a)
    # \a \b. a = 01 FE FE
    # pair (\a \b. a) = 00 01 FE FE FD
    # \pair. pair (\a \b. a) = 00 01 FE FE FD FE
    # Sys201(nil): C9 00 FE FE FD
    # Extract_A(Sys201(nil)): C9 00 FE FE FD 00 01 FE FE FD FE FD
    # Extract_A(Sys201(nil))(Bad QD): C9 00 FE FE FD 00 01 FE FE FD FE FD 02 00 FD FE FD FF
    test(
        "Sys201_A_DirectDump (Bad QD)",
        bytes(
            [
                0xC9,
                0x00,
                0xFE,
                0xFE,
                0xFD,
                0x00,
                0x01,
                0xFE,
                0xFE,
                0xFD,
                0xFE,
                0xFD,
                0x02,
                0x00,
                0xFD,
                0xFE,
                0xFD,
                0xFF,
            ]
        ),
    )

    # 3. Extract 'B' and directly dump it using Bad QD
    # Extract B: \pair. pair (\a \b. b)
    # \a \b. b = 00 FE FE
    # Extract_B = 00 00 FE FE FD FE
    # Extract_B(Sys201(nil))(Bad QD)
    test(
        "Sys201_B_DirectDump (Bad QD)",
        bytes(
            [
                0xC9,
                0x00,
                0xFE,
                0xFE,
                0xFD,
                0x00,
                0x00,
                0xFE,
                0xFE,
                0xFD,
                0xFE,
                0xFD,
                0x02,
                0x00,
                0xFD,
                0xFE,
                0xFD,
                0xFF,
            ]
        ),
    )

    # 4. The 3-Leaf Native Pipe proposed by LLM
    # app(app(app(g(201), nil), g(2)), nil)
    # Meaning: sys201(nil) (sys2) (nil)
    # g(201) = C9
    # nil = 00 FE FE
    # sys201(nil) = C9 00 FE FE FD
    # sys201(nil)(sys2) = C9 00 FE FE FD 02 FD
    # sys201(nil)(sys2)(nil) = C9 00 FE FE FD 02 FD 00 FE FE FD FF
    test(
        "3-Leaf_Native_Pipe (no QD)",
        bytes([0xC9, 0x00, 0xFE, 0xFE, 0xFD, 0x02, 0xFD, 0x00, 0xFE, 0xFE, 0xFD, 0xFF]),
    )

    # 5. Same pipe but using QD as final continuation just in case
    # sys201(nil)(sys2)(nil)(QD)
    # C9 00 FE FE FD 02 FD 00 FE FE FD QD FD FF
    QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")
    test(
        "3-Leaf_Native_Pipe (with QD)",
        bytes([0xC9, 0x00, 0xFE, 0xFE, 0xFD, 0x02, 0xFD, 0x00, 0xFE, 0xFE, 0xFD])
        + QD
        + bytes([0xFD, 0xFF]),
    )


if __name__ == "__main__":
    main()
