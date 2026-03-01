import socket
import sys

from registry_globals import (
    Var,
    Lam,
    App,
    encode_term,
    string_to_list,
    G,
    NIL,
    read_response,
)

HOST = "wc3.wechall.net"
PORT = 61221

# Good QD = \r. sys2(sys4(r))
GOOD_QD = Lam(App(G(2), App(G(4), Var(0))))

# "Bad" QD: \r. sys2(r)   (No quote!)
# Tries to leak native pointer straight to TCP writer
BAD_QD_DUMP = Lam(App(G(2), Var(0)))


def run_probe(name: str, payload_term, qd_term=None):
    print(f"--- Running Probe: {name} ---")
    payload = encode_term(payload_term)

    if qd_term:
        qd = encode_term(qd_term)
        final_payload = qd + payload + b"\xff"
    else:
        final_payload = payload + b"\xff"

    print(f"Sending ({len(final_payload)} bytes): {final_payload.hex()}")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect((HOST, PORT))
            s.sendall(final_payload)
            response = read_response(s)
            print(f"Response: {response.hex()}")
            return response
    except Exception as e:
        print(f"Error: {e}")
        return None


def main():
    print("Testing LLM v10 proposals (Native Dump via Bad QD & Direct Pipe)")

    # 1. Sys201 -> Bad QD (Dump 'A' directly)
    # The backdoor returns Left(pair).
    # Normal response triggers Left branch of echo's Either: app(BAD_QD, pair)
    # pair is \f. f A B
    # Let's apply pair to \a \b. a, then dump it.

    # We'll just run sys201(nil) and let it hit BAD_QD
    # This will do: BAD_QD( Left(pair) )
    # Echo unpacks Left: BAD_QD(pair) = sys2(pair)
    run_probe("Sys201_Left_DirectDump", App(G(201), NIL), qd_term=BAD_QD_DUMP)

    # 2. Extract 'A' and directly dump it using Bad QD
    # \pair. pair (\a \b. a)
    EXTRACT_A = Lam(App(Var(0), Lam(Lam(Var(1)))))
    run_probe(
        "Sys201_A_DirectDump", App(EXTRACT_A, App(G(201), NIL)), qd_term=BAD_QD_DUMP
    )

    # 3. Extract 'B' and directly dump it using Bad QD
    # \pair. pair (\a \b. b)
    EXTRACT_B = Lam(App(Var(0), Lam(Lam(Var(0)))))
    run_probe(
        "Sys201_B_DirectDump", App(EXTRACT_B, App(G(201), NIL)), qd_term=BAD_QD_DUMP
    )

    # 4. The 3-Leaf Native Pipe proposed by LLM
    # app(app(app(g(201), nil_AST), g(2)), nil_AST)
    # Meaning: sys201(nil) (sys2) (nil)
    run_probe(
        "3-Leaf_Native_Pipe", App(App(App(G(201), NIL), G(2)), NIL), qd_term=GOOD_QD
    )


if __name__ == "__main__":
    main()
