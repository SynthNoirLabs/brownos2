# BrownOS — reverse‑engineering notes (single source of truth)

These notes capture everything discovered while reversing the WeChall "The BrownOS" service (`wc3.wechall.net:61221`), **without using third‑party writeups**.

They are **not** the final challenge solution (the WeChall "Answer" is still unknown), but they document the protocol, data encodings, syscalls, filesystem layout, and major gotchas. The relevant client code is included inline in the appendices.

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

Return value (when used as a CPS syscall):

- `((0x02 <bytes>) <k>)` calls `<k>` with **`λa.λb.a`** (Church `True`) as the result term.

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

Side-effect probe:

- Reading `/var/log/brownos/access.log` (id 46) twice in the *same* program yields the same line.
- Calling `0x08` between those two reads did **not** change the second read.

### `0x0E` — echo syscall (the “new syscall”)

- Input: any term
- Output: `Either Left(<term>)` that, when **properly unwrapped**, is the **original input** (so it’s effectively an *echo*).
- **Gotcha (why it looked like “+2 shifting”):** the `Left` constructor is `λl.λr. l <payload>`, so the payload lives under **2 lambdas**. Any free de‑Bruijn indices inside it appear shifted by **+2** when you *inspect the raw term* (e.g., via QD), but that shift cancels when you apply/unpack the `Either`.
- **“Special bytes” / freeze warning:** if you echo a term whose raw `Left` payload includes a variable index `253..255`, then `QD`’s `quote` syscall cannot serialize it (those byte values are reserved markers `FD/FE/FF`) and the service responds with `Encoding failed!` (no trailing `FF`), which can hang naïve clients.

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
- **There is a hard input size limit (“Term too big!”).** Large/deep terms (lots of nested apps/lambdas, huge numbers via repeated weights, long byte-lists, etc.) will eventually fail at ~2KB payloads.
- **QD can break on “special bytes”.** If you end up with a term that contains a `Var(i)` where `i ∈ {0xFD,0xFE,0xFF}`, then `quote` cannot serialize it and the service responds with `Encoding failed!` **without** a trailing `0xFF` (naive clients may hang). This can happen when inspecting the raw `Left` payload from syscall `0x0E` on inputs near the top of the `0x00..0xFC` Var range.
- **Some globals are not syscalls.** For example, `Var(0)` behaves like an unbound variable: calling `((0 arg) QD)` produces no output and can run until timeout; printing `QD (0 arg)` shows the stuck application.

---

## 11) Open questions (what’s still missing)

- What is the **actual** WeChall accepted “Answer”?
- What is syscall `0x08` meant to do (and how can it be made to succeed)?
- Is the backdoor pair `(λa.λb. b b, λa.λb. a b)` intended to build a specific combinator / evaluator to reach the answer?
- Is there any hidden id beyond our scan window (>1024)?
- Are there any additional syscalls that are not discoverable via the obvious `0x00..0xFC` scan (e.g., gated behind `0x08`)?

### 2026-02-07 follow-up (`probe_ultra3.py`)

- Continuation behavior is confirmed: `sys8(nil)(write_K)` prints `K`, so syscall `0x08` *does* call its continuation in normal CPS style.
- “Continuation-gate” variants still did not unlock `sys8`:
  - `sys8(nil)(A)`, `sys8(nil)(B)`, `sys8(nil)(pair(A,B))`, and `sys8(nil)(g201)` gave no direct success signal.
  - Forcing these results with an external observer produced derived artifacts (e.g., `LEFT` or `Invalid argument`) from **post-sys8 reduction**, not a direct `sys8` success.
- CBN-thunk argument hypothesis was tested directly and failed:
  - `sys8(g201(nil))(OBS)` -> `Permission denied`
  - `sys8(g201(g8))(OBS)` -> `Permission denied`
  - `sys8(g14(g8))(OBS)` -> `Permission denied`
  - `sys8(g14(g201))(OBS)` -> `Permission denied`
  - `sys8(g7(int(11)))(OBS)` -> `Permission denied`
- Runtime-computed argument chains also failed:
  - `quote(g8) -> sys8(quoted_bytes)` -> `Permission denied`
  - backdoor-pair-captured continuation -> `Permission denied`
- Stateful in-process chaining also failed:
  - `sys8(nil) -> sys8(result)` -> `Permission denied`
  - `sys8(nil) -> backdoor(nil) -> sys8(pair)` -> `Permission denied`
  - `sys8(nil) -> backdoor(result)` -> `Invalid argument`
- Wide-integer ambiguity was removed (new additive encoder for `n > 255`):
  - Validation controls: `name(256)` -> `wtf`, `readfile(256)` -> `Uhm... yeah... no...`
  - Direct `sys8` with true wide ints still denied: `256, 257, 511, 512, 1000, 1002, 1024, 4096` -> `Permission denied`
  - Credential-shaped pairs with true wide UIDs still denied:
    - `sys8(pair(uid=1000, "ilikephp"))` -> `Permission denied`
    - `sys8(pair(uid=1002, "ilikephp"))` -> `Permission denied`
    - `sys8(pair(uid=1000, "GZKc.2/VQffio"))` -> `Permission denied`

Net: the newest “fundamentally different” axes (continuation shape, unevaluated thunk arguments, server-computed quote bytes, closure-captured continuation, multi-syscall stateful chaining, and true wide-integer credential/id inputs) are still blocked by `Right(6)` on syscall `0x08`.

### 2026-02-07 follow-up (`probe_sys8_tracks.py` + `probe_sys8_protocol.py`)

**Tracks 2-5** (echo-mediated / combinator algebra / credential strings / quote→sys8):
- Echo-mediated: `echo(X) → Left(echoed) → sys8(echoed)` tested with nil, int(8), g(8), str("ilikephp") → all `Permission denied`
- Backdoor A/B combinator algebra: `A(A)`, `B(B)`, `A(B)`, `B(A)`, `B(A(B))` fed to sys8 → all EMPTY (divergence/timeout at 5s)
- Credential strings: `"gizmore:ilikephp"`, full passwd line, `"sudo"`, `"root"`, `"gizmore"`, `"dloser"` → all `Permission denied`
- Quote→sys8: `quote(g(8/201/14/0))` bytes fed to sys8 → all `Permission denied`

**Track 6** (protocol-level tricks):
- Out-of-band bytes after 0xFF: password/nil/quoted-g8 appended post-EOF → silently ignored, still `Permission denied`
- Multi-term per connection: server processes ONLY first term; no session state accumulation
- Non-singleton parse stacks: `Invalid term!` — parser requires exactly 1 stack item at EOF
- sys8 without continuation (1-arg only): EMPTY — sys8 is strict CPS, needs 2nd arg
- g(0) exception wrapping: `g(0)(sys8(nil)(OBS))` → EMPTY — g(0) catches and swallows the PermDenied error

**Conclusion**: sys8's permission gate is **provenance-independent** and **protocol-independent**. The gate likely checks something orthogonal to argument value — possibly a specific structural property, or the answer may come from a different path than making sys8 succeed.

### What we ruled out with a full syscall sweep

We ran an exhaustive sweep of `g = 0..252` in CPS form `((g arg) QD)` for `arg ∈ {nil, int0, int1}`.

Only these globals produced results other than the default `Right(1)` (“Not implemented”):

- `0x00` (silent / non-syscall behavior)
- `0x01` (error string)
- `0x02` (write bytes)
- `0x04` (quote)
- `0x05` (readdir)
- `0x06` (name)
- `0x07` (readfile)
- `0x08` (permission denied)
- `0x0E` (echo)
- `0x2A` (towel string)
- `0xC9` (backdoor)

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

---

## 2026-02-07 — Final Synthesis: Oracle + Librarian Consultation

### Oracle Analysis (High-Confidence Reasoning)
- **Primary answer candidate**: `ilikephp` (~70% probability)
  - Classic CTF narrative: investigate OS → find /etc/passwd → find .history → crack hash → submit password
  - The reference solver `solve_brownos_answer.py` already outputs this string
- **Secondary candidates**: `GZKc.2/VQffio` (raw hash, ~15%), `Omega` (combinator name from backdoor pair, ~8%)
- **sys8 assessment**: Uniformly gated with Right(6) regardless of input — likely a deliberate rabbit hole or requires a fundamentally different approach we haven't discovered
- **Recommendation**: Submit `ilikephp` first; if rejected, try hash and combinator name

### Librarian Research Findings
- **Solver list** (from `wechall.net/challenge_solvers_for/142/The+BrownOS`): 4 solvers — l3st3r, space, dloser (author), jusb3
- **No public writeups exist** for this challenge anywhere on the internet
- **Critical dloser quote (2016)**: "I haven't heard of anyone figuring out the meaning of the input codes. Figuring out that part is probably the most important thing to do… essential to eventually getting the solution."
  - This was pre-2018 (before echo syscall 0x0E was added), so the solution path may have evolved
- **Forum hint**: "The different outputs betray some core structures" — refers to how syscall outputs reveal Scott-encoded data structures (Either, lists, integers)
- **Forum hint**: "don't be too literal with the ??s" — the `??` in the cheat sheet aren't literal byte values
- **Historical note**: Challenge originally pointed to `hes2013.wechall.net:61221`, now `wc3.wechall.net:61221`

### Tracks 2-6 Exhaustive Results Summary
| Track | Axis | Result | Key Finding |
|-------|------|--------|-------------|
| 2 | Echo-mediated args → sys8 | ALL Right(6) or EMPTY | Echo transformation doesn't change sys8's permission gate |
| 3 | Backdoor A/B combinator algebra | ALL diverge or Right(6) | A(A), B(B), A(B), B(A), B(A(B)) — none produce useful terms |
| 4 | Credential strings → sys8 | ALL Right(6) | "gizmore:ilikephp", "sudo", "root", etc. — no effect |
| 5 | Quote-mediated bytecode → sys8 | ALL Right(6) | quote(g(8)), quote(g(201)), etc. — no effect |
| 6 | Protocol tricks | Various | Post-0xFF ignored, multi-term processes only first, non-singleton → "Invalid term!", no-continuation → EMPTY, g(0) wrapping → EMPTY |

### Overall Conclusion
sys8's permission gate is **provenance-independent and protocol-independent**. No argument value, source transformation, or protocol trick has changed its behavior from Right(6). The most likely path to solving this challenge is submitting `ilikephp` as the WeChall answer (Track 1), which requires user credentials.

### Status: BLOCKED on Track 1 (WeChall submission)
