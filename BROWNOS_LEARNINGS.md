# BrownOS — reverse‑engineering notes (work-in-progress)

These notes capture everything we discovered while reversing the WeChall “The BrownOS” service (`wc3.wechall.net:61221`), **without using third‑party writeups**.

They are **not** the final challenge solution (the WeChall “Answer” is still unknown), but they document the protocol, data encodings, syscalls, filesystem layout, and all major gotchas we ran into.

---

## 0) Challenge cheat sheet (as shipped)

From `challenge.html`:

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

- The service speaks a **raw binary** protocol. Forum hint (local dump): “Perhaps you are sending ASCII instead of bytes?” (`forums/t917_p2.html`).
- Your program must end with **`0xFF`**, the *end-of-code marker*. Forum hint: “don’t forget the 0xFF at the end” (`forums/t917_p1.html`).
- The server often closes the connection with **no output**. Forum hint: “If you didn't want it to return anything, yes.” (`forums/t917_p3.html`).
- If parsing/evaluation fails you may get a literal `Invalid term!` response. (Common when you send garbage or violate the bytecode grammar.)

---

## 2) Bytecode / VM model

The byte stream (terminated by `0xFF`) encodes a term in a **postfix** lambda calculus using **de Bruijn indices**:

- `0x00..0xFC` — `Var(i)` (variable index)
- `0xFD` — application node (`App(f, x)`)
  - postfix: `f x FD`
- `0xFE` — lambda node (`Lam(body)`)
  - postfix: `body FE`
- `0xFF` — end-of-code marker (not part of the term)

Parsing is a classic postfix stack machine:

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

In practice we always structure payloads as:

- `((syscall arg) continuation)` + `0xFF`

So that the service can “return” the result by calling our continuation.

### 3.1 “Quick Debug” (QD)

We treat QD as an opaque, known-good continuation that **prints the encoded result term** to the socket, terminated by `0xFF`.

Constant (hex), from the cheat sheet:

```text
QD = 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
```

Two key confirmations:

- Applying QD to `nil = 00 FE FE` prints `00 FE FE FF`.
- Applying QD to “integer 0 term” (`00 FE` repeated 9 times) prints `00 FE…FE FF`.

**Gotcha:** QD’s raw bytes contain `0x05`/`0x03`/`0x02`, but conceptually it acts like:

- `print(term) = write(quote(term))`

This mismatch is because QD is a lambda term; de Bruijn indices shift inside it.

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
- Forum thread exists about a “new syscall enabled” (`forums/t1352.html`), but we haven’t found a working use.

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

### 7.1 `/etc/passwd` contents

`/etc/passwd` (id 11):

```text
root:x:0:0:root:/:/bin/false
mailer:x:100:100:mailer:/var:/bin/false
gizmore:GZKc.2/VQffio:1000:1000:Gizmore:/home/gizmore:/bin/sh
dloser:x:1002:1002:dloser:/home/dloser:/bin/false
```

Notes:

- `gizmore` has a classic `crypt(3)`-style hash (`GZKc.2/VQffio`).
- `dloser` has `x` in the password field (typical “password is in /etc/shadow” indicator, though `/etc/shadow` is not present here).

### 7.2 The “password” (what it was used for)

We can crack `gizmore`’s `crypt` hash **from the leaked history file**:

- `/home/gizmore/.history` contains a standalone token line `ilikephp`.
- Running `crypt("ilikephp", salt)` matches `GZKc.2/VQffio`.

`solve_brownos_answer.py` automates this and prints:

```text
ilikephp
```

What we could *not* do with it:

- There is no interactive shell syscall and `/bin/sh` is an empty file in this pseudo-fs, so this password doesn’t lead to “login somewhere” in the service as far as we could tell.
- Submitting `ilikephp` as the WeChall answer was rejected.

### 7.3 `/bin/false` meaning

On Unix systems `/bin/false` is used as a login shell to **disable interactive login** for an account (it exits immediately).

In this challenge fs, `/bin/false` is an empty file, but the `/etc/passwd` entry still communicates the same narrative: `dloser` is meant to be “non-login”.

### 7.4 `/home/gizmore/.history`

`/home/gizmore/.history` (id 65):

```text
sodu deluser dloser
ilikephp
sudo deluser dloser
```

Interpretation:

- `sodu …` is a typo.
- `ilikephp` looks like an accidental password leak (typed as a command).
- `sudo deluser dloser` suggests an attempt to remove `dloser`, but `/etc/passwd` still contains the entry in this snapshot.

### 7.5 `/var/log/brownos/access.log`

`/var/log/brownos/access.log` (id 46) is always a single line:

```text
<timestamp> <client_ip>:<client_port>
```

It changes every time you connect.

### 7.6 `/var/spool/mail/dloser` (backdoor hint)

`/var/spool/mail/dloser` (id 88):

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

## 10) WeChall answer checking (optional ops note)

We used WeChall itself as an “answer oracle” (as a guest session) to test candidate answers. This is rate-limited (roughly ~6 submissions per ~10 minutes).

The scripts in this folder don’t hardcode the solution; they only automate talking to the BrownOS service.

---

## 11) Major gotchas / lessons learned

- **Always send bytes, not ASCII.** Netcat/echo are easy to misuse; prefer a proper socket client.
- **Always terminate input with `0xFF`.** Otherwise you’ll get “Invalid term!” or no response.
- **No output is normal.** It can be success if you didn’t explicitly write to socket (forum hint).
- **Use QD early.** Without it, you’re blind: most syscalls return data as terms and the service won’t print it for you.
- **De Bruijn shifting will trick you.** The same byte value can reference different global builtins depending on how many lambdas you’re under (QD is the canonical example).
- **Ids are not limited to 0..255.** The “byte term” encoding is additive and supports repeats; that’s how we found id 256.

---

## 12) Repo artifacts / how to reproduce key results

- `solve_brownos.py` — calls syscall `0x2A` and prints the trolling string.
  - Run: `python3 solve_brownos.py`
- `solve_brownos_answer.py` — cracks `gizmore`’s `crypt` hash by checking `.history`.
  - Run: `python3 solve_brownos_answer.py`

Forum HTML dumps used for hints are in `forums/`.

---

## 13) Open questions (what’s still missing)

- What is the **actual** WeChall accepted “Answer”?
- What is syscall `0x08` meant to do (and how can it be made to succeed)?
- Is the backdoor pair `(λa.λb. b b, λa.λb. a b)` intended to build a specific combinator / evaluator to reach the answer?
- Is there any hidden id beyond our scan window (>1024)?

