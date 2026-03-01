#!/usr/bin/env python3
import socket
import time

HOST = "wc3.wechall.net"
PORT = 61221
FF = 0xFF

from registry_globals import Var, Lam, App, encode_term
NIL = Lam(Lam(Var(0)))
def G(n: int) -> object:
    return Var(n)

def string_to_list(s: str) -> object:
    from solve_brownos_answer import encode_bytes_list
    return encode_bytes_list(s.encode('ascii'))

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


def test(name, payload_term):
    print(f"--- Running Probe: {name} ---")
    payload = encode_term(payload_term) + bytes([FF])
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


def shift(term, by, cutoff=0):
    if isinstance(term, Var):
        return Var(term.i + by) if term.i >= cutoff else term
    elif isinstance(term, Lam):
        return Lam(shift(term.body, by, cutoff + 1))
    elif isinstance(term, App):
        return App(shift(term.f, by, cutoff), shift(term.x, by, cutoff))
    return term


def main():
    print("=" * 70)
    print("TESTING LLM v11 PROPOSALS: V253+ MEMORY DUMP & 3-LEAF HIJACK")
    print("=" * 70)

    # 1. Probe 1: Extract and Print env[253]
    # echo(251) (\v. sys2 (\c\n. c v nil) SAFE_OBS) I
    # echo(251) returns Left(V253).
    # Applied to handler and I: Left(V253) handler I -> handler(V253)

    SAFE_OBS = Lam(App(App(G(2), string_to_list("OK")), NIL))

    # list_wrapper = \c\n. c v nil
    # Here v is Var(2), c is Var(1), nil is NIL (closed, no free vars)
    list_wrapper = Lam(Lam(App(App(Var(1), Var(2)), NIL)))

    # handler = \v. sys2 (list_wrapper) SAFE_OBS
    # sys2 is G(2), shifted by 1 -> G(3)
    # SAFE_OBS is shifted by 1
    handler_253 = Lam(App(App(G(3), list_wrapper), shift(SAFE_OBS, 1)))

    # I = \x.x
    I_AST = Lam(Var(0))

    # echo(251) = G(14)(Var(251))
    payload_read_253 = App(App(App(G(14), Var(251)), handler_253), I_AST)
    test("dark_magic_read_env_253", payload_read_253)

    # 2. Probe 2: Extract and Print env[254]
    # echo(252) (\v. sys2 (\c\n. c v nil) SAFE_OBS) I
    payload_read_254 = App(App(App(G(14), Var(252)), handler_253), I_AST)
    test("dark_magic_read_env_254", payload_read_254)

    # 3. Probe 3: Extract and Print env[255]
    # To reach 255, pipe V253 back into echo.
    # echo(251) (\v253. echo(v253) (\v255. sys2 (\c\n. c v255 nil) SAFE_OBS) I) I

    # handler_255 is the same as handler_253, but shifted appropriately?
    # No, handler_255 is \v255. sys2 (list_wrapper) SAFE_OBS
    # It has 1 lambda, so sys2 is G(3), SAFE_OBS is shifted by 1.
    handler_255 = Lam(App(App(G(3), list_wrapper), shift(SAFE_OBS, 1)))

    # handler_253_to_255 = \v253. echo(v253) handler_255 I
    # echo = G(14), shifted by 1 -> G(15)
    # v253 = Var(0)
    # handler_255 must be shifted by 1
    # I_AST shifted by 1 (though it has no free vars, it's safe to just re-create or shift)
    handler_253_to_255 = Lam(
        App(App(App(G(15), Var(0)), shift(handler_255, 1)), shift(I_AST, 1))
    )

    payload_read_255 = App(App(App(G(14), Var(251)), handler_253_to_255), I_AST)
    test("dark_magic_read_env_255", payload_read_255)

    # 4. Probe 4: The 3-Leaf Evaluator Hijack (Y-Combinator)
    # sys201(nil) sys14
    payload_3leaf_hijack = App(App(G(201), NIL), G(14))
    test("3_leaf_wrapper_strip", payload_3leaf_hijack)


if __name__ == "__main__":
    main()
