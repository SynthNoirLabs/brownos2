#!/usr/bin/env python3
"""
Probe whether the WeChall answer can be derived from the backdoor pair (A,B)
or from specific sys8 interactions.

Answer hash: sha1^56154(answer) == "9252ed65ffac2aa763adb21ef72c0178f1d83286"
"""

from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import socket
import time
from dataclasses import dataclass

# ── Protocol constants ──────────────────────────────────────────────────────
HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD  # application
FE = 0xFE  # lambda
FF = 0xFF  # end-of-code marker

# Quick Debug continuation
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

# ── AST types ───────────────────────────────────────────────────────────────


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


# ── Network helpers ─────────────────────────────────────────────────────────


def recv_until_ff(sock: socket.socket, timeout_s: float = 3.0) -> bytes:
    sock.settimeout(timeout_s)
    out = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        out += chunk
        if FF in chunk:
            break
    if FF not in out:
        raise RuntimeError(
            "Did not receive FF-terminated output; got truncated response"
        )
    return out[: out.index(FF) + 1]


def query(payload: bytes, retries: int = 5, timeout_s: float = 3.0) -> bytes:
    delay = 0.15
    last_err: Exception | None = None
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return recv_until_ff(sock, timeout_s=timeout_s)
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed to query {HOST}:{PORT}") from last_err


def safe_query(payload: bytes) -> bytes | None:
    """Query with error handling, returns None on failure."""
    try:
        return query(payload, retries=3, timeout_s=5.0)
    except Exception as e:
        print(f"  [ERROR] {e}")
        return None


# ── Term encoding/decoding ──────────────────────────────────────────────────


def parse_term(data: bytes) -> object:
    stack: list[object] = []
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
        raise ValueError(f"Invalid parse: stack size {len(stack)}")
    return stack[0]


def encode_term(term: object) -> bytes:
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])
    raise TypeError(f"Unsupported term node: {type(term)}")


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def strip_lams(term: object, n: int) -> object:
    cur = term
    for _ in range(n):
        if not isinstance(cur, Lam):
            raise ValueError("Not enough leading lambdas")
        cur = cur.body
    return cur


def eval_bitset_expr(expr: object) -> int:
    if isinstance(expr, Var):
        return WEIGHTS[expr.i]
    if isinstance(expr, App):
        if not isinstance(expr.f, Var):
            raise ValueError("Unexpected function position (expected Var)")
        return WEIGHTS[expr.f.i] + eval_bitset_expr(expr.x)
    raise ValueError(f"Unexpected expr node: {type(expr)}")


def encode_byte_term(n: int) -> object:
    expr: object = Var(0)  # base 0
    for idx, weight in (
        (1, 1),
        (2, 2),
        (3, 4),
        (4, 8),
        (5, 16),
        (6, 32),
        (7, 64),
        (8, 128),
    ):
        if n & weight:
            expr = App(Var(idx), expr)
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_bytes_list(bs: bytes) -> object:
    nil: object = Lam(Lam(Var(0)))

    def cons(h: object, t: object) -> object:
        return Lam(Lam(App(App(Var(1), h), t)))

    cur: object = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


def decode_either(term: object) -> tuple[str, object]:
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not an Either")
    body = term.body.body
    if isinstance(body, App) and isinstance(body.f, Var) and body.f.i in (0, 1):
        return ("Left" if body.f.i == 1 else "Right", body.x)
    raise ValueError("Unexpected Either shape")


def decode_byte_term(term: object) -> int:
    body = strip_lams(term, 9)
    return eval_bitset_expr(body)


def uncons_scott_list(term: object) -> tuple[object, object] | None:
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not a Scott list node")
    body = term.body.body
    if isinstance(body, Var) and body.i == 0:
        return None
    if (
        isinstance(body, App)
        and isinstance(body.f, App)
        and isinstance(body.f.f, Var)
        and body.f.f.i == 1
    ):
        return body.f.x, body.x
    raise ValueError("Unexpected Scott list node shape")


def decode_bytes_list(term: object) -> bytes:
    out: list[int] = []
    cur = term
    for _ in range(1_000_000):
        res = uncons_scott_list(cur)
        if res is None:
            return bytes(out)
        head, cur = res
        out.append(decode_byte_term(head))
    raise RuntimeError("List too long (possible loop)")


def call_syscall(syscall_num: int, argument: object) -> object:
    payload = (
        bytes([syscall_num])
        + encode_term(argument)
        + bytes([FD])
        + QD
        + bytes([FD, FF])
    )
    out = query(payload)
    return parse_term(out)


def libc_crypt(password: str, salt: str) -> str:
    libname = ctypes.util.find_library("crypt")
    if not libname:
        raise RuntimeError("Could not find libcrypt")
    lib = ctypes.CDLL(libname)
    crypt_fn = lib.crypt
    crypt_fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    crypt_fn.restype = ctypes.c_char_p
    out = crypt_fn(password.encode(), salt.encode())
    if not out:
        raise RuntimeError("crypt() returned NULL")
    return out.decode()


# ── Hash checking ───────────────────────────────────────────────────────────

TARGET_HASH = "9252ed65ffac2aa763adb21ef72c0178f1d83286"
ITERATIONS = 56154


def sha1_iterated(s: str, n: int) -> str:
    """Compute sha1^n(s)."""
    data = s.encode("utf-8")
    for _ in range(n):
        data = hashlib.sha1(data).hexdigest().encode("ascii")
    return data.decode("ascii")


def check_candidate(candidate: str, label: str = "") -> bool:
    """Check if sha1^56154(candidate) == TARGET_HASH."""
    h = sha1_iterated(candidate, ITERATIONS)
    match = h == TARGET_HASH
    status = "*** BREAKTHROUGH MATCH ***" if match else "no match"
    if match:
        print(f"\n{'=' * 60}")
        print(f"  BREAKTHROUGH! Answer found: {candidate!r}")
        print(f"  Label: {label}")
        print(f"  Hash: {h}")
        print(f"{'=' * 60}\n")
    return match


def check_candidates_batch(candidates: list[str], category: str) -> list[str]:
    """Check a batch of candidates. Returns list of matches."""
    print(f"\n{'─' * 60}")
    print(f"  CATEGORY: {category}")
    print(f"  Testing {len(candidates)} candidates...")
    print(f"{'─' * 60}")
    matches = []
    for c in candidates:
        if check_candidate(c, label=f"{category}: {c!r}"):
            matches.append(c)
    if not matches:
        print(f"  No matches in this category.")
    return matches


# ── Main probe logic ────────────────────────────────────────────────────────


def main() -> None:
    all_matches: list[str] = []

    # ══════════════════════════════════════════════════════════════════════
    # CATEGORY 1: Strings derived from A and B
    # ══════════════════════════════════════════════════════════════════════
    cat1 = [
        # Bytecodes of A and B
        "00 00 FD FE FE",
        "0000fdFEFE",
        "0000fdfefe",
        "01 00 FD FE FE",
        "0100fdfefe",
        "0000fdfefe0100fdfefe",
        # Lambda notation
        "\\a.\\b.b b",
        "\\a.\\b.a b",
        "\u03bba.\u03bbb.b b",
        "\u03bba.\u03bbb.a b",
        "\\x.\\y.y y",
        "\\x.\\y.x y",
        # De Bruijn notation
        "\u03bb.\u03bb.0 0",
        "\u03bb.\u03bb.1 0",
        "\u03bb\u03bb00",
        "\u03bb\u03bb10",
        # Combinator names
        "M",
        "W",
        "SII",
        "omega",
        "Omega",
        "\u03c9",  # ω
        "\u03a9",  # Ω
        "self-application",
        "self application",
        "mockingbird",
        "Mockingbird",
        "MOCKINGBIRD",
        # Pair-related
        "pair",
        "Pair",
        "cons",
        "Cons",
        "(M,I)",
        "(\u03c9,I)",
        "M,I",
        # The pair bytecode (from QD output of backdoor)
        "010000fdfefefd0100fdfefefdfefe",
        # Towel-related
        "Oh, go choke on a towel!",
        "go choke on a towel",
        # Password variants
        "ilikephp",
        "ILIKEPHP",
        "ILikePhp",
        "iLikePhp",
        "I like PHP",
        "i like php",
        # crypt output
        "GZKc.2/VQffio",
        "GZKcilikephp",
        # File-derived
        "access.log",
        "brownos",
        "/bin/solution",
        "solution",
        "Solution",
        "/bin/false",
        "false",
        "False",
        "FALSE",
        "/bin/sh",
        "/bin/sudo",
        "sudo",
        # Numbers as strings
        "6",
        "8",
        "201",
        "0xC9",
        "14",
        "0x0E",
        # Possible meta-answers
        "The answer is 42",
        "42",
        "Don't Panic",
        "dont panic",
        "towel",
        "Towel",
        # Hex strings
        "ff",
        "FF",
        "0xff",
        "0xFF",
        "fefe",
        "FEFE",
        "fdfd",
        "fdfefe",
        # QD-related
        "0500fd000500fd03fdfefd02fdfefdfe",
        "QD",
        "Quick Debug",
        "quick debug",
        # Challenge name
        "The BrownOS",
        "BrownOS",
        "brownos",
        "brown",
        "Brown",
        "BROWN",
        "os",
        "OS",
        # CTF common
        "flag",
        "FLAG",
        "CTF",
        "pwned",
        "hacked",
        "root",
        "admin",
        "password",
        "secret",
        # German words
        "Passwort",
        "Geheimnis",
        "Loesung",
        "Antwort",
        "braun",
        "Braun",
        # Space's email
        "space@wechall.net",
        "space",
        "Space",
        # Service responses
        "Invalid term!",
        "Term too big!",
        "Not so fast!",
        "Unexpected exception",
        "Not implemented",
        "Invalid argument",
        "No such directory or file",
        "Not a directory",
        "Not a file",
        "Permission denied",
        # Single characters
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
        "g",
        "h",
        "i",
        "j",
        "k",
        "l",
        "m",
        "n",
        "o",
        "p",
        "q",
        "r",
        "s",
        "t",
        "u",
        "v",
        "w",
        "x",
        "y",
        "z",
        "A",
        "B",
        "C",
        "D",
        "E",
        "F",
        "G",
        "H",
        "I",
        "J",
        "K",
        "L",
        "M",
        "N",
        "O",
        "P",
        "Q",
        "R",
        "S",
        "T",
        "U",
        "V",
        "W",
        "X",
        "Y",
        "Z",
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
    ]
    all_matches.extend(check_candidates_batch(cat1, "Strings derived from A and B"))

    # ══════════════════════════════════════════════════════════════════════
    # CATEGORY 2: Capture raw backdoor output and hash it
    # ══════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 60}")
    print(f"  CATEGORY: Raw backdoor output")
    print(f"{'─' * 60}")

    nil_term = Lam(Lam(Var(0)))
    bd_payload = (
        bytes([0xC9]) + encode_term(nil_term) + bytes([FD]) + QD + bytes([FD, FF])
    )
    print("  Querying backdoor(nil) with QD...")
    bd_raw = safe_query(bd_payload)
    time.sleep(0.5)

    if bd_raw is not None:
        bd_hex = bd_raw[: bd_raw.index(0xFF)].hex()
        print(f"  Raw backdoor hex: {bd_hex}")

        bd_candidates = [
            bd_hex,
            bd_hex.upper(),
        ]
        # Try raw bytes as UTF-8
        raw_bytes = bd_raw[: bd_raw.index(0xFF)]
        try:
            bd_utf8 = raw_bytes.decode("utf-8")
            bd_candidates.append(bd_utf8)
        except UnicodeDecodeError:
            print("  Raw bytes not valid UTF-8")
        try:
            bd_latin1 = raw_bytes.decode("latin-1")
            bd_candidates.append(bd_latin1)
        except Exception:
            pass

        # Also parse and try to decode the term structure
        try:
            bd_term = parse_term(bd_raw)
            tag, payload = decode_either(bd_term)
            print(f"  Backdoor Either tag: {tag}")
            if tag == "Left":
                # Try to decode inner as pair
                if isinstance(payload, Lam) and isinstance(payload.body, Lam):
                    pair_body = payload.body.body
                    print(f"  Pair body type: {type(pair_body).__name__}")
                    # Encode the pair payload itself
                    pair_enc = encode_term(payload).hex()
                    bd_candidates.append(pair_enc)
                    bd_candidates.append(pair_enc.upper())
                    print(f"  Pair encoded hex: {pair_enc}")

                # Also try the full Left payload encoded
                left_enc = encode_term(payload).hex()
                bd_candidates.append(left_enc)
                bd_candidates.append(left_enc.upper())
        except Exception as e:
            print(f"  [WARN] Could not parse backdoor term: {e}")

        for c in bd_candidates:
            if check_candidate(c, label=f"Backdoor raw: {c!r:.80}"):
                all_matches.append(c)
    else:
        print("  Failed to query backdoor.")

    # ══════════════════════════════════════════════════════════════════════
    # CATEGORY 3: Read ALL file contents and hash them
    # ══════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 60}")
    print(f"  CATEGORY: File contents")
    print(f"{'─' * 60}")

    file_ids = {
        88: "dloser's mail",
        65: ".history",
        46: "access.log",
        11: "passwd",
    }

    for fid, fname in file_ids.items():
        print(f"\n  Reading file {fid} ({fname})...")
        time.sleep(0.5)
        try:
            file_term = call_syscall(0x07, encode_byte_term(fid))
            tag, file_payload = decode_either(file_term)
            if tag != "Left":
                print(f"    File {fid}: returned {tag}, skipping")
                continue
            file_text = decode_bytes_list(file_payload).decode("utf-8", "replace")
            print(f"    Content length: {len(file_text)} chars")
            print(f"    First 100 chars: {file_text[:100]!r}")

            # Test full content
            file_candidates = [file_text]

            # Test stripped
            file_candidates.append(file_text.strip())

            # Test each line
            for line in file_text.splitlines():
                if line.strip():
                    file_candidates.append(line)
                    file_candidates.append(line.strip())

            # Deduplicate
            file_candidates = list(dict.fromkeys(file_candidates))

            for c in file_candidates:
                if check_candidate(c, label=f"File {fid} ({fname}): {c!r:.60}"):
                    all_matches.append(c)

        except Exception as e:
            print(f"    [ERROR] {e}")

    # ══════════════════════════════════════════════════════════════════════
    # CATEGORY 4: Compute crypt("ilikephp", "GZ") and test variants
    # ══════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 60}")
    print(f"  CATEGORY: crypt() variants")
    print(f"{'─' * 60}")

    try:
        crypt_result = libc_crypt("ilikephp", "GZ")
        print(f"  crypt('ilikephp', 'GZ') = {crypt_result!r}")

        crypt_candidates = [
            crypt_result,
            crypt_result[2:]
            if len(crypt_result) > 2
            else crypt_result,  # without salt prefix
        ]
        # Also test just the hash part
        for c in crypt_candidates:
            if check_candidate(c, label=f"crypt variant: {c!r}"):
                all_matches.append(c)
    except Exception as e:
        print(f"  [ERROR] crypt: {e}")

    # ══════════════════════════════════════════════════════════════════════
    # CATEGORY 5: sys8 with backdoor pair as continuation
    # ══════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 60}")
    print(f"  CATEGORY: sys8 with pair continuation")
    print(f"{'─' * 60}")

    A_term = Lam(Lam(App(Var(0), Var(0))))  # λa.λb.b(b)
    B_term = Lam(Lam(App(Var(1), Var(0))))  # λa.λb.a(b)
    pair_term = Lam(Lam(App(App(Var(1), A_term), B_term)))  # λf.λs. f(A)(B)

    # Test 1: sys8(nil)(pair)
    print("  Test 1: sys8(nil)(pair)...")
    time.sleep(0.5)
    payload1 = (
        bytes([0x08])
        + encode_term(nil_term)
        + bytes([FD])
        + encode_term(pair_term)
        + bytes([FD, FF])
    )
    r1 = safe_query(payload1)
    if r1 is not None:
        r1_hex = r1[: r1.index(0xFF)].hex()
        print(f"    Raw hex: {r1_hex}")
        try:
            t1 = parse_term(r1)
            print(f"    Parsed: {t1}")
        except Exception as e:
            print(f"    Parse error: {e}")
        if check_candidate(r1_hex, label="sys8(nil)(pair) hex"):
            all_matches.append(r1_hex)

    # Test 2: sys8(nil) with identity continuation
    print("  Test 2: sys8(nil)(id)...")
    time.sleep(0.5)
    id_term = Lam(Var(0))
    payload2 = (
        bytes([0x08])
        + encode_term(nil_term)
        + bytes([FD])
        + encode_term(id_term)
        + bytes([FD, FF])
    )
    r2 = safe_query(payload2)
    if r2 is not None:
        r2_hex = r2[: r2.index(0xFF)].hex()
        print(f"    Raw hex: {r2_hex}")
        try:
            t2 = parse_term(r2)
            print(f"    Parsed: {t2}")
        except Exception as e:
            print(f"    Parse error: {e}")
        if check_candidate(r2_hex, label="sys8(nil)(id) hex"):
            all_matches.append(r2_hex)

    # Test 3: sys8(pair_term) with QD — pass pair itself as argument to sys8
    print("  Test 3: sys8(pair_term)(QD)...")
    time.sleep(0.5)
    payload3 = (
        bytes([0x08]) + encode_term(pair_term) + bytes([FD]) + QD + bytes([FD, FF])
    )
    r3 = safe_query(payload3)
    if r3 is not None:
        r3_hex = r3[: r3.index(0xFF)].hex()
        print(f"    Raw hex: {r3_hex}")
        try:
            t3 = parse_term(r3)
            tag3, p3 = decode_either(t3)
            print(f"    Either: {tag3}")
            if tag3 == "Right":
                try:
                    err_code = decode_byte_term(p3)
                    print(f"    Error code: {err_code}")
                except Exception:
                    print(f"    Payload: {p3}")
            elif tag3 == "Left":
                try:
                    content = decode_bytes_list(p3).decode("utf-8", "replace")
                    print(f"    LEFT CONTENT: {content!r}")
                    if check_candidate(content, label="sys8(pair) Left content"):
                        all_matches.append(content)
                except Exception:
                    print(f"    Left payload: {p3}")
        except Exception as e:
            print(f"    Parse/decode error: {e}")

    # Test 4: sys8 with A_term as argument
    print("  Test 4: sys8(A_term)(QD)...")
    time.sleep(0.5)
    payload4 = bytes([0x08]) + encode_term(A_term) + bytes([FD]) + QD + bytes([FD, FF])
    r4 = safe_query(payload4)
    if r4 is not None:
        r4_hex = r4[: r4.index(0xFF)].hex()
        print(f"    Raw hex: {r4_hex}")
        try:
            t4 = parse_term(r4)
            tag4, p4 = decode_either(t4)
            print(f"    Either: {tag4}")
            if tag4 == "Right":
                try:
                    print(f"    Error code: {decode_byte_term(p4)}")
                except Exception:
                    print(f"    Payload: {p4}")
            elif tag4 == "Left":
                try:
                    content = decode_bytes_list(p4).decode("utf-8", "replace")
                    print(f"    LEFT CONTENT: {content!r}")
                    if check_candidate(content, label="sys8(A) Left content"):
                        all_matches.append(content)
                except Exception:
                    print(f"    Left payload: {p4}")
        except Exception as e:
            print(f"    Parse/decode error: {e}")

    # Test 5: sys8 with B_term as argument
    print("  Test 5: sys8(B_term)(QD)...")
    time.sleep(0.5)
    payload5 = bytes([0x08]) + encode_term(B_term) + bytes([FD]) + QD + bytes([FD, FF])
    r5 = safe_query(payload5)
    if r5 is not None:
        r5_hex = r5[: r5.index(0xFF)].hex()
        print(f"    Raw hex: {r5_hex}")
        try:
            t5 = parse_term(r5)
            tag5, p5 = decode_either(t5)
            print(f"    Either: {tag5}")
            if tag5 == "Right":
                try:
                    print(f"    Error code: {decode_byte_term(p5)}")
                except Exception:
                    print(f"    Payload: {p5}")
            elif tag5 == "Left":
                try:
                    content = decode_bytes_list(p5).decode("utf-8", "replace")
                    print(f"    LEFT CONTENT: {content!r}")
                    if check_candidate(content, label="sys8(B) Left content"):
                        all_matches.append(content)
                except Exception:
                    print(f"    Left payload: {p5}")
        except Exception as e:
            print(f"    Parse/decode error: {e}")

    # ══════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════════
    print(f"\n{'=' * 60}")
    print(f"  FINAL SUMMARY")
    print(f"{'=' * 60}")
    if all_matches:
        print(f"  *** {len(all_matches)} MATCH(ES) FOUND! ***")
        for m in all_matches:
            print(f"    -> {m!r}")
    else:
        print(f"  No matches found across all categories.")
        print(f"  The answer is NOT among the {len(cat1)} static candidates")
        print(f"  nor the server-derived values tested.")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
