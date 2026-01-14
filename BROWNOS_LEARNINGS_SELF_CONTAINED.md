# BrownOS — reverse‑engineering notes (self-contained, work-in-progress)

These notes capture everything we discovered while reversing the WeChall “The BrownOS” service (`wc3.wechall.net:61221`), **without using third‑party writeups**.

They are **not** the final challenge solution (the WeChall “Answer” is still unknown), but they document the protocol, data encodings, syscalls, filesystem layout, and major gotchas.

This copy is designed to be pasted into another LLM: it removes local file references and includes the relevant client code inline.

---

## 0) Challenge cheat sheet (as shipped)

```text
FF: End Of Code marker

BrownOS[<syscall> <argument> FD <rest> FD] -> BrownOS[<rest> <result> FD]

Quick debug: 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
For example: QD ?? FD  or  ?? ?? FD QD FD
```

Host/port:

- `wc3.wechall.net:61221` (TCP)

---

## 1) Transport / framing

- The service speaks a **raw binary** protocol. Forum hint: “Perhaps you are sending ASCII instead of bytes?”
- Your program must end with **`0xFF`**, the *end-of-code marker*. Forum hint: “don’t forget the 0xFF at the end”.
- The server often closes the connection with **no output**. Forum hint: “If you didn't want it to return anything, yes.”
- If parsing/evaluation fails you may get a literal `Invalid term!` response (common when you violate the bytecode grammar).

---

## 2) Bytecode / VM model

The byte stream (terminated by `0xFF`) encodes a term in a **postfix** lambda calculus using **de Bruijn indices**:

- `0x00..0xFC` — `Var(i)` (variable index)
- `0xFD` — application node (`App(f, x)`)
  - postfix: `f x FD`
- `0xFE` — lambda node (`Lam(body)`)
  - postfix: `body FE`
- `0xFF` — end-of-code marker (not part of the term)

Parsing is a postfix stack machine:

- push `Var(i)` for bytes `< 0xFD`
- on `FD`: pop `x`, pop `f`, push `App(f, x)`
- on `FE`: pop `body`, push `Lam(body)`
- stop at `FF`

**Important:** because this is de Bruijn, *indices shift under lambdas*. A raw byte value you see inside a closure is not necessarily the same “meaning” as that same byte at top-level (see **QD gotcha** below).

---

## 3) Syscall convention (CPS)

Syscalls are invoked exactly as the cheat sheet describes: in **continuation-passing style**.

If you build a term like:

```text
<syscall> <argument> FD <rest> FD
```

…then the VM reduces it like:

```text
(<syscall> <argument> <rest>)  ==>  (<rest> <result>)
```

In practice we structure payloads as:

- `((syscall arg) continuation)` + `0xFF`

So the service “returns” by applying the continuation to the result.

### 3.1 “Quick Debug” (QD)

We treat QD as an opaque, known-good continuation that **prints the encoded result term** to the socket, terminated by `0xFF`.

Constant (hex), from the cheat sheet:

```text
QD = 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
```

Two key confirmations:

- Applying QD to `nil = 00 FE FE` prints `00 FE FE FF`.
- Applying QD to “integer 0 term” (`00 FE` repeated 9 times) prints `00 FE…FE FF`.

**Gotcha:** QD’s raw bytes contain `0x05`/`0x03`/`0x02`, but conceptually it behaves like:

- `print(term) = write(quote(term))`

This mismatch is because QD is itself a lambda term; de Bruijn indices shift inside it.

---

## 4) Data encodings we confirmed

### 4.1 `Either` (Scott encoding)

Many syscalls return a Scott-encoded either:

- `Left x  = λl.λr. l x`  (tagged success in this service)
- `Right y = λl.λr. r y` (tagged failure)

Note: `Right` payloads are typically **error codes**, also encoded as “integers” (see below).

### 4.2 Integer / “byte term” encoding (9-lambda additive bitset)

Numbers are encoded as:

- 9 leading lambdas
- body is a nested application chain that *adds weights*

Weights by variable index in the body:

| Var index | Weight |
|---:|---:|
| `V0` | 0 |
| `V1` | 1 |
| `V2` | 2 |
| `V3` | 4 |
| `V4` | 8 |
| `V5` | 16 |
| `V6` | 32 |
| `V7` | 64 |
| `V8` | 128 |

Example: 3 is:

```text
λ^9. (V2 @(V1 @ V0))   => 2 + 1 + 0 = 3
```

#### Non-byte IDs (>255) are possible

Because the encoding is **additive**, weights can be repeated:

- `256 = 128 + 128`
- encoded body can be `V8 @(V8 @ V0)` (under the 9 lambdas)

This is how we reached the hidden file **id 256** (see below).

### 4.3 Bytes / strings

Strings and file contents are a **Scott list of byte-terms**:

- `nil = λc.λn. n`
- `cons h t = λc.λn. c h t`

Each list element is the 9-lambda “byte term” above.

---

## 5) Directory listing encoding (syscall `0x05`)

`readdir` does **not** return a plain Scott list. It returns a 3-way Scott list that distinguishes file vs directory nodes:

- `nil = λd.λf.λn. n`              (3 lambdas, body `V0`)
- `dir = λd.λf.λn. d <id> <rest>`  (selector `V2`)
- `file = λd.λf.λn. f <id> <rest>` (selector `V1`)

Practical decoding rule after stripping 3 leading lambdas:

- `V0` => end
- `App(App(Var(2), idTerm), restTerm)` => directory entry
- `App(App(Var(1), idTerm), restTerm)` => file entry

The `<id>` is the 9-lambda integer encoding.

---

## 6) Syscalls we identified (and what they do)

All syscall numbers here are the **top-level** byte value used in the program stream.

### `0x01` — error string

- Input: error code (integer term)
- Output: `Either Left(<bytes>)`

Confirmed mapping (by calling `0x01` with 0..7):

| Code | String |
|---:|---|
| 0 | `Unexpected exception` |
| 1 | `Not implemented` |
| 2 | `Invalid argument` |
| 3 | `No such directory or file` |
| 4 | `Not a directory` |
| 5 | `Not a file` |
| 6 | `Permission denied` |
| 7 | `Not so fast!` |

### `0x02` — write bytes to socket

- Input: bytes list (Scott list of byte-terms)
- Side effect: writes the raw bytes to the TCP stream

We verified this by asking it to write `[0x00, 0xFF]` and observing the socket output.

### `0x03` — not implemented

- Returns `Right(1)` for tested inputs.

### `0x04` — quote / serialize term

- Input: any term
- Output: `Either Left(<bytes>)`, where bytes are the *postfix encoding of the term*, plus a trailing `0xFF`.

Example: quoting the “0 integer term” returns:

```text
00 FE FE FE FE FE FE FE FE FE FF
```

### `0x05` — `readdir`

- Input: directory id (integer term)
- Output: `Either Left(<dirlist>)` using the 3-way list encoding above
- Errors:
  - `Right(4)` on non-directories (e.g., file ids)

### `0x06` — `name`

- Input: id (integer term)
- Output: `Either Left(<bytes>)` (basename of entry)
- Errors:
  - `Right(3)` on unknown ids

### `0x07` — `readfile`

- Input: file id (integer term)
- Output: `Either Left(<bytes>)` (file content)
- Errors:
  - `Right(5)` on non-files (directories)

### `0x08` — “new syscall” (always permission denied in our tests)

- Always returned `Right(6)` (“Permission denied”) for all tested args (numbers/strings/terms).
- A forum thread exists about a “new syscall enabled”, but we haven’t found a working use.

### `0x0E` — evaluation-ish syscall

- Returns `Either Left(<term>)` for many simple arguments.
- Some arguments can lead to long runtime / divergence (treat with care).

### `0x2A` — decoy / trolling string

- Returns `Oh, go choke on a towel!`
- This is **not** the WeChall “Answer”.

### `0xC9` (decimal 201) — backdoor

Why `0xC9`? It’s just `201` in hex (`201₁₀ = C9₁₆`).

- Input: must be **exactly** Scott `nil` (`00 FE FE`), else `Right(2)` (“Invalid argument”).
- Output: `Either Left(<pair>)` where `<pair>` has Scott-cons shape:
  - head `A = λa.λb. b b`
  - tail `B = λa.λb. a b`

This is hinted in the mail spool (see filesystem section).

---

## 7) Filesystem we extracted (via `readdir` + `name` + `readfile`)

IDs shown are the numeric ids returned by the service.

```text
/ (id 0)
├── bin (id 1)
│   ├── false (id 16)         [0 bytes]
│   ├── sh (id 14)            [0 bytes]
│   └── sudo (id 15)          [0 bytes]
├── etc (id 2)
│   ├── brownos (id 3)        [empty dir]
│   └── passwd (id 11)        [181 bytes]
├── home (id 22)
│   ├── dloser (id 50)        [empty dir]
│   └── gizmore (id 39)
│       └── .history (id 65)  [49 bytes]
├── sbin (id 9)               [empty dir]
└── var (id 4)
    ├── log (id 5)
    │   └── brownos (id 6)
    │       └── access.log (id 46)     [changes per connection]
    └── spool (id 25)
        └── mail (id 43)
            └── dloser (id 88)         [177 bytes]
```

### 7.1 `/etc/passwd` contents (id 11)

```text
root:x:0:0:root:/:/bin/false
mailer:x:100:100:mailer:/var:/bin/false
gizmore:GZKc.2/VQffio:1000:1000:Gizmore:/home/gizmore:/bin/sh
dloser:x:1002:1002:dloser:/home/dloser:/bin/false
```

Notes:

- `gizmore` has a classic `crypt(3)`-style hash (`GZKc.2/VQffio`).
- `dloser` has `x` in the password field (typical “password is in /etc/shadow” indicator, though `/etc/shadow` is not present here).

### 7.2 The “password” we recovered

We can crack `gizmore`’s `crypt` hash **from the leaked history file**:

- `.history` (id 65) contains a standalone token line `ilikephp`.
- Running `crypt("ilikephp", salt)` matches `GZKc.2/VQffio`.

What we could *not* do with it:

- There is no interactive shell syscall and `/bin/sh` is an empty file in this pseudo-fs, so this password doesn’t lead to “login somewhere” in the service (as far as we could tell).

### 7.3 `/bin/false` meaning

On Unix systems `/bin/false` is used as a login shell to **disable interactive login** for an account (it exits immediately).

In this challenge fs, `/bin/false` is an empty file, but the `/etc/passwd` entry still communicates the same narrative: `dloser` is meant to be “non-login”.

### 7.4 `.history` (id 65)

```text
sodu deluser dloser
ilikephp
sudo deluser dloser
```

Interpretation:

- `sodu …` is a typo.
- `ilikephp` looks like an accidental password leak (typed as a command).
- `sudo deluser dloser` suggests an attempt to remove `dloser`, but `/etc/passwd` still contains the entry in this snapshot.

### 7.5 `access.log` (id 46)

`access.log` is always a single line:

```text
<timestamp> <client_ip>:<client_port>
```

It changes every time you connect.

### 7.6 mail spool (id 88) — backdoor hint

```text
From: mailer@brownos
To: dloser@brownos
Subject: Delivery failure

Failed to deliver following message to boss@evil.com:

Backdoor is ready at syscall 201; start with 00 FE FE.
```

This is the only explicit hint toward syscall `201` / `0xC9`.

---

## 8) Hidden/unlinked entry: id 256 (“non-byte id”)

Because ids are encoded as integers (not literal 1-byte values), we can address values >255.

Using `256 = 128 + 128` in the 9-lambda encoding:

- `name(256)` => `wtf`
- `readfile(256)` => `Uhm... yeah... no...\n`
- `readdir(256)` => `Right(4)` (“Not a directory”)

This entry is **not reachable** from the directory tree (no `readdir` output links to it).

We scanned `257..1024` using `name()` and found **no additional ids** beyond the normal filesystem + `256`.

---

## 9) “Can we execute commands like whoami?”

We did **not** find any syscall that resembles process execution, and:

- `/bin/sh`, `/bin/sudo`, `/bin/false` are all **0-byte** files.
- Syscalls observed are limited to filesystem-ish operations, quoting, output, plus the backdoor.

So as far as our exploration went, BrownOS is more of a tiny functional VM + virtual fs than a real OS shell.

---

## 10) Major gotchas / lessons learned

- **Always send bytes, not ASCII.** Netcat/echo are easy to misuse; prefer a proper socket client.
- **Always terminate input with `0xFF`.** Otherwise you’ll get “Invalid term!” or no response.
- **No output is normal.** It can be success if you didn’t explicitly write to socket (forum hint above).
- **Use QD early.** Without it, you’re blind: most syscalls return data as terms and the service won’t print it for you.
- **De Bruijn shifting will trick you.** The same byte value can reference different global builtins depending on how many lambdas you’re under (QD is the canonical example).
- **Ids are not limited to 0..255.** The “byte term” encoding is additive and supports repeats; that’s how we found id 256.

---

## 11) Open questions (what’s still missing)

- What is the **actual** WeChall accepted “Answer”?
- What is syscall `0x08` meant to do (and how can it be made to succeed)?
- Is the backdoor pair `(λa.λb. b b, λa.λb. a b)` intended to build a specific combinator / evaluator to reach the answer?
- Is there any hidden id beyond our scan window (>1024)?

---

## Appendix A: Python client used for most reversing (inline)

```python
#!/usr/bin/env python3
from __future__ import annotations

import ctypes
import ctypes.util
import socket
import time
from dataclasses import dataclass


HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD  # application
FE = 0xFE  # lambda
FF = 0xFF  # end-of-code marker

# Quick Debug continuation from the challenge cheat sheet.
# It prints (via syscall 2) the bytecode for the syscall result (via syscall 4),
# terminated by FF, so we can parse the result term on the client side.
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
        raise RuntimeError("Did not receive FF-terminated output; got truncated response")
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
    for idx, weight in ((1, 1), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32), (7, 64), (8, 128)):
        if n & weight:
            expr = App(Var(idx), expr)
    term: object = expr
    for _ in range(9):
        term = Lam(term)
    return term


def encode_bytes_list(bs: bytes) -> object:
    # Scott list of byte-terms.
    nil: object = Lam(Lam(Var(0)))

    def cons(h: object, t: object) -> object:
        return Lam(Lam(App(App(Var(1), h), t)))

    cur: object = nil
    for b in reversed(bs):
        cur = cons(encode_byte_term(b), cur)
    return cur


def decode_either(term: object) -> tuple[str, object]:
    # Scott Either:
    # Left x  = λl.λr. l x  -> λ.λ.(1 x)
    # Right y = λl.λr. r y  -> λ.λ.(0 y)
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
    # nil  = λc.λn. n      -> λ.λ.0
    # cons = λc.λn. c h t  -> λ.λ.(1 h t)
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
    payload = bytes([syscall_num]) + encode_term(argument) + bytes([FD]) + QD + bytes([FD, FF])
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


def main() -> None:
    # Read /etc/passwd-like file and find gizmore's crypt hash.
    passwd_term = call_syscall(0x07, encode_byte_term(11))
    tag, passwd_payload = decode_either(passwd_term)
    if tag != "Left":
        raise RuntimeError("Failed to read passwd file")
    passwd_text = decode_bytes_list(passwd_payload).decode("utf-8", "replace")
    giz_hash = None
    for line in passwd_text.splitlines():
        if line.startswith("gizmore:"):
            parts = line.split(":")
            if len(parts) >= 2:
                giz_hash = parts[1]
            break
    if not giz_hash:
        raise RuntimeError("Could not find gizmore hash in passwd file")

    # Read command log that leaked the password in plaintext.
    log_term = call_syscall(0x07, encode_byte_term(65))
    tag, log_payload = decode_either(log_term)
    if tag != "Left":
        raise RuntimeError("Failed to read log file")
    log_text = decode_bytes_list(log_payload).decode("utf-8", "replace")
    # heuristic: the password is a standalone token line in this file
    candidates = [ln.strip() for ln in log_text.splitlines() if ln.strip() and " " not in ln.strip()]
    if not candidates:
        raise RuntimeError("No password candidates found in log file")

    salt = giz_hash[:2]
    for cand in candidates:
        if libc_crypt(cand, salt) == giz_hash:
            print(cand)
            return
    raise RuntimeError("No candidates matched gizmore's hash")


if __name__ == "__main__":
    main()
```

---

## Appendix B: Minimal demo client (syscall `0x2A` string) (inline)

```python
#!/usr/bin/env python3
import socket
import time
from dataclasses import dataclass


HOST = "wc3.wechall.net"
PORT = 61221

# Quick debug (QD) from the challenge cheat sheet.
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

FD = 0xFD  # application
FE = 0xFE  # lambda
FF = 0xFF  # end-of-code marker


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


def recv_all(sock: socket.socket, timeout_s: float) -> bytes:
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


def query(payload: bytes, retries: int = 5, timeout_s: float = 4.0) -> bytes:
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
                return recv_all(sock, timeout_s=timeout_s)
        except Exception as e:
            last_err = e
            time.sleep(delay)
            delay *= 2
    raise RuntimeError(f"Failed to query {HOST}:{PORT}") from last_err


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


def unwrap_outer(root: object) -> object:
    """
    The service returns a 2-arg wrapper that yields the actual list term as its payload.
    Pattern: λ.λ. (1 payload)
    """
    if not isinstance(root, Lam) or not isinstance(root.body, Lam):
        return root
    body = root.body.body
    if isinstance(body, App) and isinstance(body.f, Var) and body.f.i == 1:
        return body.x
    return root


def uncons_scott_list(term: object) -> tuple[object, object] | None:
    # Scott list:
    #   nil  = λc.λn. n      -> λ.λ.0
    #   cons = λc.λn. c h t  -> λ.λ.(1 h t)
    if not isinstance(term, Lam) or not isinstance(term.body, Lam):
        raise ValueError("Not a 2-lambda Scott list node")
    body = term.body.body
    if isinstance(body, Var) and body.i == 0:
        return None
    if (
        isinstance(body, App)
        and isinstance(body.f, App)
        and isinstance(body.f.f, Var)
        and body.f.f.i == 1
    ):
        head = body.f.x
        tail = body.x
        return head, tail
    raise ValueError("Unexpected Scott list node shape")


def decode_scott_list(term: object) -> list[object]:
    items: list[object] = []
    cur = term
    for _ in range(10000):
        res = uncons_scott_list(cur)
        if res is None:
            return items
        head, cur = res
        items.append(head)
    raise RuntimeError("List too long (possible loop)")


def strip_lams(term: object, n: int) -> object:
    cur = term
    for _ in range(n):
        if not isinstance(cur, Lam):
            raise ValueError("Not enough leading lambdas")
        cur = cur.body
    return cur


WEIGHTS = {0: 0, 1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32, 7: 64, 8: 128}


def eval_bitset_expr(expr: object) -> int:
    """
    Character encoding used by the service:
      a 9-arg lambda where each Var index represents a bit weight.
      The body is a nested application chain like:
        V7 @(V4 @(V3 @(V2 @(V1 @ V0))))
      Interpreted as applying 'add(weight)' functions down to a 0 base.
    """
    if isinstance(expr, Var):
        return WEIGHTS[expr.i]
    if isinstance(expr, App):
        if not isinstance(expr.f, Var):
            raise ValueError("Unexpected function position (expected Var)")
        return WEIGHTS[expr.f.i] + eval_bitset_expr(expr.x)
    raise ValueError(f"Unexpected expr node: {type(expr)}")


def solve() -> str:
    # Call syscall 0x2A (42) with dummy argument, and use QD as continuation to print the result term.
    payload = bytes([0x2A, 0x00, FD]) + QD + bytes([FD, FF])
    out = query(payload)
    root = parse_term(out)
    list_term = unwrap_outer(root)
    items = decode_scott_list(list_term)
    chars = []
    for item in items:
        body = strip_lams(item, 9)
        chars.append(chr(eval_bitset_expr(body)))
    return "".join(chars)


if __name__ == "__main__":
    print(solve())
```

