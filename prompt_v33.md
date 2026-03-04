# BrownOS v33 — Comprehensive Deep Reanalysis

**Repo**: `https://github.com/SynthNoirLabs/brownos2`  
**Date**: 2026-03-04  
**Previous**: `prompt_v32.md`  
**Status**: UNSOLVED after 16,000+ probes. Paradigm shift needed.

---

## TABLE OF CONTENTS
1. [Challenge Overview](#1-challenge-overview)
2. [The VM in Detail](#2-the-vm-in-detail)
3. [All Known Syscalls](#3-all-known-syscalls)
4. [The Filesystem](#4-the-filesystem)
5. [The Backdoor Pair — Detailed Analysis](#5-the-backdoor-pair)
6. [Forum Hints — Complete Annotated Collection](#6-forum-hints)
7. [The 16,000-Probe Graveyard](#7-the-graveyard)
8. [The Paradigm Shift — Syntactic Inspection Hypothesis](#8-paradigm-shift)
9. [Remaining Live Theories](#9-remaining-theories)
10. [Concrete Next Steps](#10-next-steps)
11. [Reference: Encoding Helpers](#11-encoding-reference)

---

## 1. Challenge Overview

**WeChall Challenge**: "The BrownOS" by dloser  
**URL**: `https://www.wechall.net/challenge/dloser/brownos/index.php`  
**Service**: `wc3.wechall.net:61221` (TCP)  
**Difficulty**: 10.00/10 (all non-author voters gave it 10)  
**Fun**: 10.00/10  
**Solvers**: 4 — `l3st3r`, `space`, `dloser` (author), `jusb3`  
**Active since**: May 24, 2014  
**No public writeups exist anywhere on the internet.**

### The Goal
Find a string "Answer" and submit it on the challenge page. The answer satisfies:
```
sha1^56154(answer) == "9252ed65ffac2aa763adb21ef72c0178f1d83286"
```
(That's SHA-1 iterated 56,154 times.)

### The Challenge Description
> "Reports have come in about a new kind of operating system that Gizmore is developing. Scans have detected an extra open port on wechall.net that might be related to this. Additionally, one of our dumpster divers has found part of what appears to be a cheat sheet for something called 'BrownOS'."
>
> "Please investigate the service at wc3.wechall.net port 61221."

### The Cheat Sheet (as shipped)
```
FF: End Of Code marker

BrownOS[<syscall> <argument> FD <rest> FD] -> BrownOS[<rest> <result> FD]

Quick debug: 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
For example: QD ?? FD  or  ?? ?? FD QD FD
```

---

## 2. The VM in Detail

### 2.1 Bytecode Format
The byte stream (terminated by `0xFF`) encodes a lambda calculus term in **postfix notation** using **de Bruijn indices**:

| Byte Range | Meaning |
|------------|---------|
| `0x00..0xFC` | `Var(i)` — variable / global reference |
| `0xFD` | `App(f, x)` — application. Postfix: `f x FD` |
| `0xFE` | `Lam(body)` — lambda abstraction. Postfix: `body FE` |
| `0xFF` | End-of-code marker (not part of the term) |

### 2.2 Parsing
Stack machine: push `Var(i)` for bytes `< 0xFD`, on `FD` pop x then f and push `App(f,x)`, on `FE` pop body and push `Lam(body)`, stop at `FF`. Parser requires **exactly 1 item** on stack at EOF.

### 2.3 Execution Model
Pure lazy lambda calculus with **CPS syscalls**. The initial environment has 253 global bindings (`Var(0)` through `Var(252)`). Of these, only 11 are active syscalls; the other 242 return `Right(1)` ("Not implemented") for all inputs.

### 2.4 CPS Convention
```
((syscall argument) continuation) → (continuation result)
```
The VM recognizes `App(App(Var(n), arg), k)` where `Var(n)` is a syscall, evaluates the syscall with `arg`, then applies `k` to the result.

### 2.5 De Bruijn Index Shifting
**CRITICAL**: Inside a `Lam`, all free variable indices shift by +1. A `Var(5)` at top level refers to global 5 (`readdir`). But inside `λ.λ.`, a `Var(5)` refers to global 3 (because the 2 lambda binders consume indices 0 and 1, shifting everything).

### 2.6 QD (Quick Debug)
```hex
QD = 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
```
QD is a lambda term. Semantically: `λresult. write(quote(result))` — it serializes any term to bytes and writes them to the socket, terminated by `0xFF`. It's our primary observation tool.

**QD Gotcha**: The raw hex bytes (05, 03, 02) don't correspond to their "semantic" syscall numbers because QD itself is a lambda term and de Bruijn shifting applies inside it.

---

## 3. All Known Syscalls

### Active Syscalls (11 total)
| Byte | Name | Input | Output |
|------|------|-------|--------|
| `0x01` | error_string | error code (int) | `Left(bytes)` — human-readable error message |
| `0x02` | write | bytes list | Writes raw bytes to socket; returns `True` |
| `0x04` | quote | any term | `Left(bytes)` — postfix bytecode of the term + `0xFF` |
| `0x05` | readdir | dir ID (int) | `Left(3-way list)` or `Right(4)` |
| `0x06` | name | entry ID (int) | `Left(bytes)` — basename, or `Right(3)` |
| `0x07` | readfile | file ID (int) | `Left(bytes)` — contents, or `Right(5)` |
| `0x08` | **THE GATE** | ??? | **Always `Right(6)` — "Permission denied"** |
| `0x0E` | echo | any term | `Left(term)` — identity (added 2018) |
| `0x2A` | towel | ignored | `Left("Oh, go choke on a towel!\n")` |
| `0xC9` | backdoor | must be `nil` | `Left(pair(A,B))` or `Right(2)` |

### Error Code Table (from syscall 0x01)
| Code | Message |
|------|---------|
| 0 | Unexpected exception |
| 1 | Not implemented |
| 2 | Invalid argument |
| 3 | No such directory or file |
| 4 | Not a directory |
| 5 | Not a file |
| 6 | Permission denied |
| 7 | Not so fast! |

### Inactive Globals (242 stubs)
All other indices `0x00..0xFC` not listed above return `Right(1)` ("Not implemented") for every tested input. `Var(0)` is special: it behaves like an unbound variable (stuck application, no output).

---

## 4. The Filesystem

### 4.1 Full Tree
```
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
    │       └── access.log (id 46)     [~31 bytes, changes per connection]
    └── spool (id 25)
        └── mail (id 43)
            └── dloser (id 88)         [177 bytes]

Hidden/unlinked: id 256 — name="wtf", content="Uhm... yeah... no...\n"
Scan 257-1024: no additional IDs found.
```

### 4.2 Key File Contents

**`/etc/passwd` (id 11)**:
```
root:x:0:0:root:/:/bin/false
mailer:x:100:100:mailer:/var:/bin/false
gizmore:GZKc.2/VQffio:1000:1000:Gizmore:/home/gizmore:/bin/sh
dloser:x:1002:1002:dloser:/home/dloser:/bin/false
```
- `gizmore` has a classic `crypt(3)` hash: `GZKc.2/VQffio` (salt=`GZ`)
- `dloser` has `x` (shadow password, no `/etc/shadow` exists)

**`/home/gizmore/.history` (id 65)**:
```
sodu deluser dloser
ilikephp
sudo deluser dloser
```
- `ilikephp` is the leaked password — `crypt("ilikephp", "GZ") == "GZKc.2/VQffio"` ✓

**`/var/log/brownos/access.log` (id 46)**:
```
<unix_timestamp> <client_ip>:<client_port>
```
Changes every connection. Per-connection dynamic nonce.

**`/var/spool/mail/dloser` (id 88)**:
```
From: mailer@brownos
To: dloser@brownos
Subject: Delivery failure

Failed to deliver following message to boss@evil.com:

Backdoor is ready at syscall 201; start with 00 FE FE.
```
The only explicit hint toward syscall `0xC9` (201). "Start with 00 FE FE" = pass `nil` as argument.

### 4.3 Data Encodings

**Integers** (9-lambda additive bitset):
```
λ^9. body
```
Body is nested applications of `Var(1..8)` representing bit weights (1,2,4,8,16,32,64,128) applied to a `Var(0)` base. Example: `3 = λ^9.(V2 @ (V1 @ V0))` = 2+1+0. Values >255 possible via weight repetition: `256 = V8 @ (V8 @ V0)`.

**Either** (Scott encoding):
```
Left(x)  = λl.λr. l(x)    — success
Right(y) = λl.λr. r(y)    — failure
```

**Lists** (2-way Scott, for bytes/strings):
```
nil      = λc.λn. n
cons(h,t)= λc.λn. c(h)(t)
```

**Directory listings** (3-way Scott, unique to `readdir`):
```
nil      = λd.λf.λn. n
dir(id,t)= λd.λf.λn. d(id)(t)
file(id,t)=λd.λf.λn. f(id)(t)
```

---

## 5. The Backdoor Pair

### 5.1 What It Returns
`backdoor(nil)` returns `Left(pair)` where `pair = λs. s(A)(B)`:
- **A** = `λa.λb. b(b)` — applies second arg to itself
- **B** = `λa.λb. a(b)` — applies first arg to second arg

### 5.2 Combinator-Theoretic Analysis
- `A` is "apply-self-to-second": `A(x)(y) = y(y)`
- `B` is function application: `B(f)(x) = f(x)`
- `B` is the identity combinator in disguise when partially applied
- `A(B)` = `λb. b(b)` = the self-application combinator `ω`
- `B(A)` = `λb. A(b)` = `λb.λa.λc. c(c)` — ignores b, always self-applies
- `A(A)` = `λb. b(b)` (same as `ω`) — diverges when applied to itself

### 5.3 What We've Tried With the Pair
Every conceivable combination of A, B, pair with sys8 and credentials. All `Right(6)`.

---

## 6. Forum Hints — Complete Annotated Collection

### From dloser (challenge author)

**May 2014** (thread creation):
> "The service has some restrictions on input size, memory and execution time. They should be more than fair for what you need."

**May 2016** (2 years, 0 solvers):
> **Spoiler 1**: "The second example in the cheat sheet [?? ?? FD QD FD], besides providing a way to get some easy outputs, is also useful in figuring out some crucial properties of the codes."
>
> **Spoiler 2**: "The different outputs betray some core structures. This should give you some substructures that might be helpful elsewhere."
>
> **Key statement**: "I haven't heard of anyone figuring out the meaning of the input codes. Figuring out that part is probably the most important thing to do, if only because it is essential to eventually getting the solution."
>
> "don't be too literal with the ??s"

**Interpretation of "don't be too literal"**: The `??` in `?? ?? FD QD FD` are not single bytes — they're multi-byte encoded terms (e.g., a syscall number is a `Var(n)` byte, but the argument can be an arbitrarily complex term).

**Interpretation of "meaning of the input codes"**: This is the single most important unsolved hint. "Input codes" likely means the bytecodes `0x00..0xFC`, `FD`, `FE`, `FF` themselves. Understanding what they MEAN (variable references in a lambda calculus) is "essential to eventually getting the solution."

**Mar 2018** (to macplox who got "Invalid term!"):
> "The example from the cheat sheet should be a good start to not get that message..."

**Sep 2018** (to l3st3r who got EMPTY output):
> "If you didn't want it to return anything, yes."
This confirms EMPTY = success if the program intentionally produces no output.

### From l3st3r (solver, May 2018)
> "I can make it return 'a towel!' and 'O' ' towel!' (two consecutive reads) using the exact same input data. Granted, I had to send a bad QD."
>
> "And yes, it is a binary protocol."

**Interpretation**: A "bad QD" = a continuation that attempts to write the result directly as bytes, skipping the `quote` step. "Two consecutive reads" likely = TCP chunking of a single write, or a continuation that prints head/tail of a list separately.

### From space (solver, Nov 2025)
> "Folks, you should try it again! It's fun! I just found my old stuff on a legacy hard drive. Don't give up."

### Timeline of Solvers
- **Before 2018** (before echo was added): l3st3r and space solved it
- **After 2018**: jusb3 solved it
- dloser is the author

**CRITICAL CONSTRAINT**: The solution must work WITHOUT the echo syscall (`0x0E`), since two solvers managed without it.

---

## 7. The 16,000-Probe Graveyard

### Retired Hypotheses (with probe counts)

| Category | Axis | Probes | Result |
|----------|------|--------|--------|
| **Direct values** | Integers 0–280, special IDs | 700+ | All Right(6) |
| | Lambdas, pairs, combinators | 60+ | All Right(6) |
| | ALL 253 `Var(b)` values | 253 | All Right(6) |
| | Credential strings (passwords, hashes, usernames) | 50+ | All Right(6) |
| | File contents (passwd, history, mail, access.log) | 20+ | All Right(6) |
| | Naked backdoor pair A, B, pair(A,B) | 10+ | All Right(6) |
| | Combinator algebra: A(A), B(A), A(B), B(B), B(A(B)) | 10+ | All diverge or Right(6) |
| **Provenance** | Echo-mediated arguments | 26 | All Right(6) |
| | CPS adapter composition | 26 | All Right(6) |
| | Computed heads (B(sys8), I(sys8), etc.) | 18 | All Right(6) |
| | Raw minted capabilities (sys8 as direct CPS continuation) | 12 | All Right(6) |
| | Forged Either tokens | 40 | All Right(6) |
| **Higher-order** | Arity ladder (λx.Ω, λxy.Ω, λxyz.Ω) | 3 | All instant Right(6) |
| | QD as callback | 5 | All Right(6) |
| | Typed callback dumpers (quote, error, name, readfile) | 4 | All Right(6) |
| **Continuations** | All continuation shapes | 100+ | All Right(6) |
| | 3-leaf continuations (6 forms × globals) | 760 | All Right(6) |
| **Brute force** | 3-leaf programs (all shapes) | 10,000+ | All Right(6)/EMPTY |
| **Stubs** | All 242 stub globals with typed inputs | 2,420 | All Right(1)/EMPTY |
| **VFS** | Hidden file IDs 257–1024 | 768 | No extra IDs |
| **Protocol** | Multi-term per connection | 3 | Only first processed |
| | Post-0xFF bytes | 3 | Silently ignored |
| | Non-singleton parse stack | 1 | "Invalid term!" |
| **Answers** | Direct WeChall submissions | 12 | All REJECTED |

**Key conclusion from higher-order probes**: `sys8` does NOT apply/call its argument. The arity ladder (`sys8(λx. Ω)`) returns instantly rather than diverging, proving that `sys8` never beta-reduces `(argument something)`.

**Key conclusion from provenance probes**: `sys8` does NOT distinguish between forged terms and natively-minted terms. The gate is value-based or structure-based, not provenance-based.

---

## 8. The Paradigm Shift — Syntactic Inspection Hypothesis

### The Core Realization
Our Oracle analysis produced this insight:

> **"The likely wrong assumption is that syscall 8's 'input' is the evaluated value of its argument. sys8 instead inspects the arg's syntax / serialized byte stream (the 'input codes' hint), so all value/provenance brute forcing can be perfectly exhaustive and still never touch the real predicate."**

### Why This Makes Sense

1. **dloser's hint says "input codes"** — literally the bytecodes. Not "input values" or "input data."
2. **"Figuring out the meaning of the input codes is the most important thing"** — if we already know what values mean, this hint is redundant. But if "codes" means the RAW BYTES of the encoding, then there's an entirely unexplored dimension.
3. **sys8 never applies its argument** (proven by arity ladder) — so it must be doing something ELSE. The most natural "something else" in a VM that has a `quote` syscall is: inspect the AST or byte representation.
4. **16,000 probes of different VALUES all fail** — because they all share whatever structural/syntactic property sys8 rejects.
5. **"Don't be too literal with the ??s"** — the `??` in the cheat sheet might literally mean "these bytes ARE the answer" if you understand what they encode at the bytecode level.

### What This Means Practically

Two lambda terms can have the **same semantic value** but **completely different bytecode representations**. For example, `λx.x` and `(λy.λx.x)(anything)` both reduce to the identity, but their wire representations are different.

If sys8 inspects the raw AST (before or instead of evaluation), then:
- Every probe we've run tests a different VALUE but possibly the same SYNTACTIC PATTERN
- The correct answer might be a specific sequence of bytes that forms a particular AST shape
- The answer might even be a non-normalizing term whose bytecode has the right pattern

### Suggested Test: Differential Syntactic Probes

Build a family of terms that:
1. ALL reduce to the same value (e.g., `nil`)
2. Have DIFFERENT bytecode structures (different nesting, different var indices, different lambda depths)

If any of these gets a different response from sys8, we've confirmed the syntactic inspection hypothesis.

For example:
- `sys8(nil)` — the standard `00 FE FE`
- `sys8((λx.x)(nil))` — identity applied to nil, same value, different bytes
- `sys8((λx.λy.y)(anything)(nil))` — K* applied, same value, more bytes
- `sys8(Lam(Lam(Var(0))))` — same as nil but... wait, this IS the same bytes

Better: use `quote` to generate nil-equivalent terms with different shapes, then feed those shapes to sys8.

---

## 9. Remaining Live Theories

### Theory A: Syntactic/AST Inspection (STRONGEST)
sys8 checks the raw bytecode or AST structure of its argument, not its evaluated value. The "input codes" are the raw bytes. We need to find the specific bytecode pattern that sys8 accepts.

**Testable by**: Sending semantically-equivalent terms with different bytecodes.

### Theory B: The Answer Is Computable Without sys8
Maybe sys8 is a red herring or an optional verifier. The answer might be derivable from:
- The backdoor pair combinators A, B
- The filesystem data (password, hash, mail)
- Some mathematical/cryptographic computation on these values
- The iterated SHA-1 hash itself (crack it offline)

**Against this theory**: dloser's hint structure strongly implies sys8 is central. Also, the challenge page asks for a string answer, and 12 direct string guesses were rejected.

### Theory C: Connection Metadata Gate
sys8 might not check its lambda argument at all. It might check connection metadata (source IP, source port, timing, access.log content) that's set by the server itself.

**Against this theory**: The challenge was solvable by multiple people from different IPs. And we tested access.log nonces already.

### Theory D: De Bruijn Index Laundering
Pass arguments containing `Var(251)` or `Var(252)` into evaluation contexts that add lambdas, shifting them into the reserved `253-255` range. This could trigger hidden VM behavior.

**Testable by**: Small probes with high-index vars in nested lambda contexts.

### Theory E: Multi-Step Program Construction
The answer requires a complex multi-syscall program that:
1. Reads filesystem data
2. Uses the backdoor
3. Performs some computation
4. Calls sys8 with the computed result

We've tested simple chains but not complex programs that, e.g., read the passwd file, extract the hash, use it with the backdoor pair to construct a specific term, and pass THAT to sys8.

---

## 10. Concrete Next Steps

### Priority 1: Test Syntactic Inspection Hypothesis
Build terms that have the SAME semantic value but DIFFERENT bytecode, and see if sys8 responds differently.

```
# All reduce to nil, but different bytecodes:
P1: sys8(nil) PSE                     — baseline: 00 FE FE
P2: sys8((λx.x)(nil)) PSE            — (00 FE)(00 FE FE)FD
P3: sys8((λx.λy.y)(z)(nil)) PSE      — longer bytecode, same value
P4: sys8((λf.f(nil))(λx.x)) PSE      — even more structure
```

### Priority 2: Quote sys8's Argument First
Use `quote(arg)` to verify what bytecode sys8 would "see" for each arg. This detects if the VM normalizes terms before sys8 inspects them.

```
# Quote the argument to see its representation:
Q1: quote(nil) → write bytes            — verify nil's bytecode
Q2: quote((λx.x)(nil)) → write bytes    — is it normalized to nil?
Q3: quote(g(8)) → write bytes           — what does sys8 look like as a term?
```

### Priority 3: Brute-Force Small Bytecodes Directly
Instead of building terms semantically, try sending raw byte sequences as sys8's argument. E.g., try every possible 1-3 byte term as the argument to sys8:
```
For n in 0..252:
  sys8(Var(n)) PSE              — single byte arguments
For n in 0..252:
  sys8(Lam(Var(n))) PSE         — λ.Var(n) arguments
For n,m in small range:
  sys8(App(Var(n), Var(m))) PSE — 2-var application arguments
```
This covers the structural space we might have missed.

### Priority 4: Compute Answer Offline
Try cracking the iterated SHA-1 hash. The answer satisfies `sha1^56154(answer) == "9252ed65ffac2aa763adb21ef72c0178f1d83286"`. With a small enough candidate space (e.g., short ASCII strings), this might be tractable with hashcat or a custom brute-forcer.

---

## 11. Encoding Reference

### Python Helpers (from solve_brownos_answer.py)

```python
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

# Encoding
def encode_term(term) -> bytes:
    if isinstance(term, Var): return bytes([term.i])
    if isinstance(term, Lam): return encode_term(term.body) + bytes([0xFE])
    if isinstance(term, App): return encode_term(term.f) + encode_term(term.x) + bytes([0xFD])

def encode_byte_term(n: int) -> object:
    """Encode integer n as 9-lambda bitset term."""
    expr = Var(0)
    for idx, weight in ((1,1),(2,2),(3,4),(4,8),(5,16),(6,32),(7,64),(8,128)):
        if n & weight: expr = App(Var(idx), expr)
    term = expr
    for _ in range(9): term = Lam(term)
    return term

def encode_bytes_list(bs: bytes) -> object:
    """Encode bytes as Scott list of byte-terms."""
    nil = Lam(Lam(Var(0)))
    def cons(h, t): return Lam(Lam(App(App(Var(1), h), t)))
    cur = nil
    for b in reversed(bs): cur = cons(encode_byte_term(b), cur)
    return cur

# Constants  
NIL = Lam(Lam(Var(0)))           # K* = λa.λb.b = nil = False
TRUE = Lam(Lam(Var(1)))          # K  = λa.λb.a = True
PAIR_AB = Lam(App(App(Var(0), A), B))  # λs.s(A)(B)
A = Lam(Lam(App(Var(0), Var(0))))      # λa.λb.b(b)
B = Lam(Lam(App(Var(1), Var(0))))      # λa.λb.a(b)

# QD
QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

# CPS pattern
def call_syscall(num, arg):
    return bytes([num]) + encode_term(arg) + bytes([0xFD]) + QD + bytes([0xFD, 0xFF])
```

### Named-Term DSL (from probe scripts)
```python
# Global reference (shifts automatically under lambdas)
def g(i): return NGlob(i)   # g(8) = sys8, g(201) = backdoor

# Standard observer: prints "LEFT" on success, error string on failure
PSE = lam("r", apps(v("r"),
    lam("_lp", write_str("LEFT\n")),           # Left handler
    lam("ec", apps(g(1), v("ec"),              # Right handler: decode error
        lam("ei", apps(v("ei"),
            lam("es", apps(g(2), v("es"), NIL)),
            lam("_e2", write_str("ERR_DECODE_FAIL\n"))))))))
```

---

## Summary: Where We Stand

After 16,000+ probes across every conceivable value-based, provenance-based, structural, higher-order, and protocol-based axis, syscall 8 has NEVER returned anything other than `Right(6)` ("Permission denied").

The strongest remaining hypothesis is that **sys8 inspects the raw bytecode/AST structure of its argument** rather than its evaluated value. This aligns with the author's most important hint: "figuring out the meaning of the input codes is probably the most important thing to do."

The next breakthrough will come from:
1. Differential testing of semantically-equivalent but bytecode-different terms
2. Using `quote` to inspect what the VM actually "sees" as an argument's structure  
3. Potentially brute-forcing small raw bytecodes directly as sys8 arguments
4. Or cracking the iterated SHA-1 hash offline if the answer space is small enough
