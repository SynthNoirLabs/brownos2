#!/usr/bin/env python3
"""
probe_access_log_token.py — Test "connection context token" hypothesis.

Hypothesis (LLM v27): sys8's permission gate checks whether the argument
encodes the CURRENT connection's context. The only connection-specific
value the service exposes is access.log (id 46):
    "<unix_timestamp> <client_ip>:<client_port>\n"

Prior sweeps never passed the live access.log content to sys8 IN THE SAME
connection that generated it. This is the only typed input we missed.

Probes:
  P1: readfile(46)→sys8, SAME connection — the critical test
  P2: readfile(46) content from PRIOR connection → sys8 (control negative)
  P3: sys8("<ip>:<port>" bytes) — just the ip:port field, same connection
  P4: sys8(int(local_src_port)) — source port as Scott integer
  P5: sys8("<timestamp>" bytes) — just the timestamp field
  P6: sys8(int(timestamp)) — timestamp as integer
  P7: sys8("") — empty bytes (baseline)
  P8: Right(7) watch — rapid repeat to detect rate-limit change
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


def encode_term(t):
    if isinstance(t, Var):
        return bytes([t.i])
    if isinstance(t, Lam):
        return encode_term(t.body) + bytes([FE])
    if isinstance(t, App):
        return encode_term(t.f) + encode_term(t.x) + bytes([FD])
    raise TypeError(f"bad: {type(t)}")


def parse_term(data):
    stack = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x = stack.pop()
            f = stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            body = stack.pop()
            stack.append(Lam(body))
        else:
            stack.append(Var(b))
    if len(stack) != 1:
        raise ValueError(f"stack={len(stack)}")
    return stack[0]


def recv_ff(sock, timeout_s=6.0):
    sock.settimeout(timeout_s)
    out = b""
    try:
        while True:
            c = sock.recv(4096)
            if not c:
                break
            out += c
            if FF in c:
                break
    except socket.timeout:
        pass
    return out


_last = 0.0


def query(payload, retries=3, timeout_s=6.0, get_local_port=False):
    global _last
    gap = 0.35
    now = time.time()
    if now - _last < gap:
        time.sleep(gap - (now - _last))
    delay = 0.3
    for _ in range(retries):
        try:
            sock = socket.create_connection((HOST, PORT), timeout=timeout_s)
            local_port = sock.getsockname()[1]  # capture before sending
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            result = recv_ff(sock, timeout_s=timeout_s)
            sock.close()
            _last = time.time()
            if get_local_port:
                return result, local_port
            return result
        except Exception as e:
            time.sleep(delay)
            delay *= 2
    if get_local_port:
        return b"", 0
    return b""


def encode_byte_term(n):
    expr = Var(0)
    for idx, w in ((1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)):
        if n & w:
            expr = App(Var(idx), expr)
    t = expr
    for _ in range(9):
        t = Lam(t)
    return t


def big_int(n):
    expr = Var(0)
    r = n
    for idx, w in [(8, 128), (7, 64), (6, 32), (5, 16), (4, 8), (3, 4), (2, 2), (1, 1)]:
        while r >= w:
            expr = App(Var(idx), expr)
            r -= w
    t = expr
    for _ in range(9):
        t = Lam(t)
    return t


def encode_bytes_list(bs):
    nil = Lam(Lam(Var(0)))

    def cons(h, t):
        return Lam(Lam(App(App(Var(1), h), t)))

    cur = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def strip_lams(t, n):
    for _ in range(n):
        if not isinstance(t, Lam):
            raise ValueError
        t = t.body
    return t


def eval_bs(e):
    if isinstance(e, Var):
        return WEIGHTS[e.i]
    if isinstance(e, App):
        return WEIGHTS[e.f.i] + eval_bs(e.x)
    raise ValueError


def decode_byte_term(t):
    return eval_bs(strip_lams(t, 9))


def uncons(t):
    if not isinstance(t, Lam) or not isinstance(t.body, Lam):
        raise ValueError
    b = t.body.body
    if isinstance(b, Var) and b.i == 0:
        return None
    if (
        isinstance(b, App)
        and isinstance(b.f, App)
        and isinstance(b.f.f, Var)
        and b.f.f.i == 1
    ):
        return b.f.x, b.x
    raise ValueError


def decode_bytes_list(t):
    out = []
    cur = t
    for _ in range(1_000_000):
        r = uncons(cur)
        if r is None:
            return bytes(out)
        h, cur = r
        out.append(decode_byte_term(h))
    raise RuntimeError


def decode_either(t):
    if not isinstance(t, Lam) or not isinstance(t.body, Lam):
        raise ValueError
    b = t.body.body
    if isinstance(b, App) and isinstance(b.f, Var) and b.f.i in (0, 1):
        return ("Left" if b.f.i == 1 else "Right", b.x)
    raise ValueError


KSTAR = Lam(Lam(Var(0)))
N0 = encode_byte_term(0)
N46 = encode_byte_term(46)

G_WRITE = 2
G_READFILE = 7
G_SYS8 = 8
G_ERR_STR = 1


def make_PSE(depth: int) -> object:
    """PSE at embedding depth d — correct write/error_string Var shifts."""
    left_h = Lam(App(App(Var(G_WRITE + depth + 2), Var(0)), KSTAR))
    inner_lft = Lam(App(App(Var(G_WRITE + depth + 4), Var(0)), KSTAR))
    inner_unw = Lam(App(App(Var(0), inner_lft), KSTAR))
    right_h = Lam(App(App(Var(G_ERR_STR + depth + 2), Var(0)), inner_unw))
    return Lam(App(App(Var(0), left_h), right_h))


PSE = make_PSE(0)


def classify(raw):
    if not raw:
        return "EMPTY"
    if all(0x20 <= b <= 0x7E or b in (0x0A, 0x0D) for b in raw if b != 0xFF):
        text = raw.replace(bytes([0xFF]), b"").decode("ascii", "replace").strip()
        if text:
            return f"TEXT:{text!r}"
    if 0xFF in raw:
        try:
            t = parse_term(raw)
            tag, pl = decode_either(t)
            if tag == "Left":
                try:
                    return f"Left({decode_bytes_list(pl).decode('utf-8', 'replace')!r})"
                except:
                    return f"Left(non-str:{encode_term(pl).hex()[:40]})"
            else:
                try:
                    return f"Right({decode_byte_term(pl)})"
                except:
                    return f"Right(non-int:{encode_term(pl).hex()[:40]})"
        except:
            return f"TERM:{raw[: raw.index(0xFF)].hex()[:60]}"
    return f"RAW:{raw[:40].hex()}"


def is_novel(r):
    return (
        r not in {"EMPTY", "Right(6)", "Right(1)", "Right(2)"}
        and "PERM" not in r
        and "Invalid" not in r
        and "Term too big" not in r
    )


# ─────────────────────────────────────────────────────────────────────────────
# P1: readfile(46) → sys8, SAME connection
# Program: readfile(N46)(λr. r(λlog. sys8(log)(PSE_d2))(K*))
#
# Depth 1 (λr):    r=V0, sys8=Var(G_SYS8+1)=Var(9)
# Depth 2 (λlog):  log=V0, sys8=Var(G_SYS8+2)=Var(10)
# PSE at depth 2:  make_PSE(2)
# ─────────────────────────────────────────────────────────────────────────────
def build_p1():
    PSE_d2 = make_PSE(2)
    inner = Lam(App(App(Var(G_SYS8 + 2), Var(0)), PSE_d2))  # λlog. sys8(log)(PSE)
    outer = Lam(App(App(Var(0), inner), KSTAR))  # λr. r(inner)(K*)
    prog = App(App(Var(G_READFILE), N46), outer)
    return encode_term(prog) + bytes([FF])


# ─────────────────────────────────────────────────────────────────────────────
# P2: sys8 with encoded bytes_list of a prior connection's access.log
# (negative control: different connection's token)
# ─────────────────────────────────────────────────────────────────────────────
def build_p2(prior_log_bytes: bytes):
    log_term = encode_bytes_list(prior_log_bytes)
    prog = App(App(Var(G_SYS8), log_term), PSE)
    return encode_term(prog) + bytes([FF])


# ─────────────────────────────────────────────────────────────────────────────
# P3: sys8("<ip>:<port>" bytes) — ip:port field only, same connection
# Same-connection version: do readfile(46) → extract ip:port → sys8
# Program: readfile(N46)(λr. r(λlog. ??? extract ip:port ???)(K*))
#
# Extracting a substring at runtime in pure lambda calc is complex.
# Simpler: do 2 round-trips — get log, parse ip:port client-side, re-encode.
# ─────────────────────────────────────────────────────────────────────────────
def build_p3(ipport_bytes: bytes):
    term = encode_bytes_list(ipport_bytes)
    prog = App(App(Var(G_SYS8), term), PSE)
    return encode_term(prog) + bytes([FF])


# ─────────────────────────────────────────────────────────────────────────────
# P4: sys8(int(local_src_port)) — source port as Scott integer
# ─────────────────────────────────────────────────────────────────────────────
def build_p4(port: int):
    prog = App(App(Var(G_SYS8), big_int(port)), PSE)
    return encode_term(prog) + bytes([FF])


# ─────────────────────────────────────────────────────────────────────────────
# P5: sys8("<timestamp>" bytes) — just the timestamp field
# ─────────────────────────────────────────────────────────────────────────────
def build_p5(ts_bytes: bytes):
    term = encode_bytes_list(ts_bytes)
    prog = App(App(Var(G_SYS8), term), PSE)
    return encode_term(prog) + bytes([FF])


# ─────────────────────────────────────────────────────────────────────────────
# P6: sys8(int(timestamp)) — timestamp as Scott integer
# ─────────────────────────────────────────────────────────────────────────────
def build_p6(ts_int: int):
    prog = App(App(Var(G_SYS8), big_int(ts_int)), PSE)
    return encode_term(prog) + bytes([FF])


# ─────────────────────────────────────────────────────────────────────────────
# P7: sys8(full log bytes) via direct encode — same connection, but encoded
#     client-side and sent in a new connection (control for P1 without same-conn)
# ─────────────────────────────────────────────────────────────────────────────
def build_p7_encoded(log_bytes: bytes):
    """Encode log bytes client-side and pass to sys8 (new connection)."""
    term = encode_bytes_list(log_bytes)
    prog = App(App(Var(G_SYS8), term), PSE)
    return encode_term(prog) + bytes([FF])


# ─────────────────────────────────────────────────────────────────────────────
# P1-variant: same program but with QD instead of PSE to see raw result
# ─────────────────────────────────────────────────────────────────────────────
def build_p1_qd():
    """Same as P1 but uses QD to see raw term output instead of PSE."""
    # readfile(46)(λr. r(λlog. ((sys8 log) QD_shifted))(K*))
    # At depth 2: QD term needs to be embedded. But QD is complex.
    # Use write-based observation instead: λlog. sys8(log)(λres. res K* error_str)
    # Actually let's just use PSE_d2 like P1. QD is too complex to embed.
    return build_p1()  # same thing, PSE handles both Left and Right


def main():
    print("=" * 70)
    print("ACCESS LOG TOKEN HYPOTHESIS PROBE")
    print("Key question: does sys8 need the CURRENT connection's access.log?")
    print("=" * 70)

    # ── Step 1: Get a prior connection's access.log for control tests ──────
    print("\n--- Getting prior connection access.log ---")
    prior_raw = query(
        bytes([G_READFILE]) + encode_term(N46) + bytes([FD]) + QD + bytes([FD, FF])
    )
    prior_log = b""
    if prior_raw and 0xFF in prior_raw:
        try:
            t = parse_term(prior_raw)
            tag, pl = decode_either(t)
            if tag == "Left":
                prior_log = decode_bytes_list(pl)
                print(f"  Prior access.log: {prior_log!r}")
        except Exception as e:
            print(f"  Failed to parse prior log: {e}")

    # Parse fields from prior log
    prior_ts_bytes = b""
    prior_ipport_bytes = b""
    prior_ts_int = 0
    prior_port = 0
    if prior_log:
        line = prior_log.decode("ascii", "replace").strip()
        parts = line.split(" ", 1)
        if len(parts) == 2:
            prior_ts_bytes = parts[0].encode("ascii")
            prior_ipport_bytes = parts[1].encode("ascii")
            try:
                prior_ts_int = int(parts[0])
            except:
                pass
            if ":" in parts[1]:
                try:
                    prior_port = int(parts[1].split(":")[-1])
                except:
                    pass
        print(f"  timestamp: {prior_ts_bytes!r}  ip:port: {prior_ipport_bytes!r}")
        print(f"  ts_int={prior_ts_int}  port={prior_port}")

    # ── Step 2: Get current connection's local port for P4 ─────────────────
    # We'll capture it during P1 execution

    print("\n" + "=" * 70)
    print("PROBES")
    print("=" * 70)

    results = {}

    # ── P1: readfile(46) → sys8 IN SAME CONNECTION ─────────────────────────
    print("\n[P1: readfile(46)→sys8, SAME connection] *** CRITICAL ***")
    p1_payload = build_p1()
    print(f"  size: {len(p1_payload)}B  hex: {p1_payload.hex()}")
    raw, local_port = query(p1_payload, get_local_port=True)
    r1 = classify(raw)
    results["P1:same-conn-log→sys8"] = r1
    print(f"  local_port_used={local_port}")
    print(f"  raw: {raw[:80].hex() if raw else 'EMPTY'}")
    print(f"  → {r1}")
    novel = is_novel(r1)
    if novel:
        print(f"  *** NOVEL! ***")

    time.sleep(0.5)

    # ── P2: prior connection's log → sys8 (negative control) ───────────────
    print("\n[P2: PRIOR connection log→sys8 (control)]")
    if prior_log:
        p2_payload = build_p2(prior_log)
        print(f"  size: {len(p2_payload)}B  log: {prior_log!r}")
        raw2 = query(p2_payload)
        r2 = classify(raw2)
        results["P2:prior-conn-log→sys8"] = r2
        print(f"  → {r2}")
        if is_novel(r2):
            print(f"  *** NOVEL! ***")
    else:
        print("  SKIPPED (no prior log)")
        results["P2:prior-conn-log→sys8"] = "SKIPPED"

    time.sleep(0.5)

    # ── P3: ip:port bytes, same-connection log, new connection ──────────────
    # First get the CURRENT connection's ip:port
    print("\n[P3: ip:port bytes from current log, new connection]")
    curr_raw = query(
        bytes([G_READFILE]) + encode_term(N46) + bytes([FD]) + QD + bytes([FD, FF])
    )
    curr_ipport = b""
    curr_log = b""
    if curr_raw and 0xFF in curr_raw:
        try:
            t = parse_term(curr_raw)
            tag, pl = decode_either(t)
            if tag == "Left":
                curr_log = decode_bytes_list(pl)
                line = curr_log.decode("ascii", "replace").strip()
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    curr_ipport = parts[1].encode("ascii")
                    print(f"  ip:port from this conn: {curr_ipport!r}")
        except Exception as e:
            print(f"  Failed: {e}")

    if curr_ipport:
        p3_payload = build_p3(curr_ipport)
        print(f"  size: {len(p3_payload)}B")
        raw3 = query(p3_payload)
        r3 = classify(raw3)
        results["P3:ipport-bytes→sys8"] = r3
        print(f"  → {r3}")
        if is_novel(r3):
            print(f"  *** NOVEL! ***")
    else:
        results["P3:ipport-bytes→sys8"] = "SKIPPED"

    time.sleep(0.5)

    # ── P4: local source port as integer ────────────────────────────────────
    print(f"\n[P4: local src port as int]")
    # Use the port captured in P1
    if local_port:
        p4_payload = build_p4(local_port)
        print(f"  port={local_port}  size={len(p4_payload)}B")
        raw4 = query(p4_payload)
        r4 = classify(raw4)
        results["P4:src-port-int→sys8"] = r4
        print(f"  → {r4}")
        if is_novel(r4):
            print(f"  *** NOVEL! ***")
        # Also try a fresh connection's port
        print(f"  [P4b: fresh connection's own port]")
        p4b_payload = (
            bytes([G_SYS8]) + b"\x00"
        )  # placeholder; we need to build dynamically
        # Actually let's do it properly: capture port on query
        raw4b, fresh_port = query(build_p4(0), get_local_port=True)  # dummy to get port
        print(f"  fresh port would be: {fresh_port}")
        # Now send with the actual fresh port
        p4b_real = build_p4(fresh_port)
        raw4b_real, p4b_port = query(p4b_real, get_local_port=True)
        # Note: p4b_port != fresh_port since we opened another connection
        # The only true test is P1 which reads in-band
        r4b = classify(raw4b_real)
        results["P4b:fresh-port-int→sys8"] = r4b
        print(f"  → {r4b} (port_used={p4b_port}, port_encoded={fresh_port})")
        if is_novel(r4b):
            print(f"  *** NOVEL! ***")
    else:
        results["P4:src-port-int→sys8"] = "SKIPPED"

    time.sleep(0.5)

    # ── P5: timestamp bytes ──────────────────────────────────────────────────
    print("\n[P5: timestamp bytes → sys8]")
    if prior_ts_bytes:
        p5_payload = build_p5(prior_ts_bytes)
        print(f"  ts={prior_ts_bytes!r}  size={len(p5_payload)}B")
        raw5 = query(p5_payload)
        r5 = classify(raw5)
        results["P5:ts-bytes→sys8"] = r5
        print(f"  → {r5}")
        if is_novel(r5):
            print(f"  *** NOVEL! ***")
    else:
        results["P5:ts-bytes→sys8"] = "SKIPPED"

    time.sleep(0.5)

    # ── P6: timestamp as integer ──────────────────────────────────────────────
    print("\n[P6: timestamp as integer → sys8]")
    if prior_ts_int:
        p6_payload = build_p6(prior_ts_int)
        print(f"  ts_int={prior_ts_int}  size={len(p6_payload)}B")
        raw6 = query(p6_payload)
        r6 = classify(raw6)
        results["P6:ts-int→sys8"] = r6
        print(f"  → {r6}")
        if is_novel(r6):
            print(f"  *** NOVEL! ***")
    else:
        results["P6:ts-int→sys8"] = "SKIPPED"

    time.sleep(0.5)

    # ── P7: full log encoded client-side, new connection (vs P1 same-conn) ──
    print("\n[P7: full log encoded client-side → sys8 (different connection)]")
    if curr_log:
        p7_payload = build_p7_encoded(curr_log)
        print(f"  log={curr_log!r}  size={len(p7_payload)}B")
        raw7 = query(p7_payload)
        r7 = classify(raw7)
        results["P7:encoded-log-new-conn→sys8"] = r7
        print(f"  → {r7}")
        if is_novel(r7):
            print(f"  *** NOVEL! ***")
        print()
        print("  Note: if P1=novel and P7=Right(6), proves SAME-CONNECTION matters")
        print("  Note: if P1=P7=novel, proves it's just the log content, not same-conn")
    else:
        results["P7:encoded-log-new-conn→sys8"] = "SKIPPED"

    time.sleep(0.5)

    # ── P8: rapid repeat to detect Right(7) ──────────────────────────────────
    print("\n[P8: rapid sys8(N0) × 5 — watch for Right(7) = rate limit]")
    for i in range(5):
        r_rapid = classify(
            query(
                encode_term(App(App(Var(G_SYS8), N0), PSE)) + bytes([FF]),
                retries=1,
                timeout_s=3.0,
            )
        )
        print(f"  [{i + 1}] → {r_rapid}")
        if "7" in r_rapid:
            print(f"  *** RIGHT(7) DETECTED! Rate limit is real! ***")
        time.sleep(0.1)  # intentionally fast

    # ── P1 repeat × 3 (with fresh connections) ────────────────────────────
    print("\n[P1 × 3 repeats — confirm consistency]")
    for i in range(3):
        raw_r, lp = query(build_p1(), get_local_port=True)
        rr = classify(raw_r)
        print(f"  [{i + 1}] local_port={lp} → {rr}")
        if is_novel(rr):
            print(f"  *** NOVEL on repeat {i + 1}! ***")
        time.sleep(0.4)

    # ── SUMMARY ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY — Access Log Token Hypothesis")
    print("=" * 70)
    for label, result in results.items():
        novel_mark = " *** NOVEL ***" if is_novel(result) else ""
        print(f"  {label}: {result}{novel_mark}")

    p1_r = results.get("P1:same-conn-log→sys8", "")
    p2_r = results.get("P2:prior-conn-log→sys8", "")
    p7_r = results.get("P7:encoded-log-new-conn→sys8", "")

    print("\n--- DECISION ---")
    if is_novel(p1_r):
        if not is_novel(p2_r):
            print("  P1 NOVEL + P2 boring → context token IS same-connection specific!")
            print("  BREAKTHROUGH: sys8 needs current-connection access.log content!")
        elif not is_novel(p7_r):
            print(
                "  P1 NOVEL + P7 boring → same-connection required (not just content)"
            )
        else:
            print("  P1 NOVEL + P7 also NOVEL → it's the log content, not same-conn")
            print("  → sys8 needs the access.log string regardless of connection")
    else:
        print("  P1 boring → connection context token hypothesis weakens.")
        if any(is_novel(v) for v in results.values()):
            print("  But some other probe was novel — check above!")
        else:
            print("  All probes boring → hypothesis retired.")


if __name__ == "__main__":
    main()
