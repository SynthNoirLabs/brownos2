# BrownOS Programming Challenge — Comprehensive State Summary

**Generated**: 2026-02-17
**Challenge**: WeChall "The BrownOS" — Difficulty 10/10
**Solvers**: ~4 in 12+ years (l3st3r, space, dloser/author, jusb3)
**Server**: `wc3.wechall.net:61221` (TCP)
**Status**: **UNSOLVED**

---

## Table of Contents

1. [What Is This Challenge](#1-what-is-this-challenge)
2. [Protocol — Fully Reverse-Engineered](#2-protocol--fully-reverse-engineered)
3. [Syscall Table — Complete](#3-syscall-table--complete)
4. [Data Encodings — Fully Decoded](#4-data-encodings--fully-decoded)
5. [Filesystem — Fully Extracted](#5-filesystem--fully-extracted)
6. [Key Discoveries](#6-key-discoveries)
7. [Repository Structure](#7-repository-structure)
8. [History of All Attempts](#8-history-of-all-attempts)
9. [Rejected WeChall Answers](#9-rejected-wechall-answers)
10. [Author Hints & Forum Intelligence](#10-author-hints--forum-intelligence)
11. [Open Hypotheses & Unexplored Leads](#11-open-hypotheses--unexplored-leads)
12. [Conclusion & Recommended Next Steps](#12-conclusion--recommended-next-steps)

---

## 1. What Is This Challenge

BrownOS is an extreme CTF challenge hosted on WeChall. It exposes a **lambda calculus-based virtual machine** over a raw TCP socket. The VM accepts postfix-encoded lambda terms, evaluates them, and performs "syscalls" that behave like an operating system's kernel interface (read files, list directories, write to socket, etc.).

**The goal**: Make **syscall 8** (the "solution" syscall, analogous to `/bin/solution`) return success. It currently returns `Right(6)` ("Permission denied") for **every input ever tested** — over 500 distinct combinations across 12+ months of probing.

The challenge ships with only this cryptic cheat sheet:

```
FF: End Of Code marker

BrownOS[<syscall> <argument> FD <rest> FD] -> BrownOS[<rest> <result> FD]

Quick debug: 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
For example: QD ?? FD  or  ?? ?? FD QD FD
```

---

## 2. Protocol — Fully Reverse-Engineered

### 2.1 Transport

- Raw binary over TCP. **Not** ASCII, not line-based.
- Every program must be terminated by `0xFF` (End-of-Code marker).
- Responses may be raw bytes (terminated by `0xFF`), literal error strings (`Invalid term!`, `Term too big!`, `Encoding failed!`), or silence.
- Input size limit: ~2KB before "Term too big!" error.

### 2.2 Bytecode Format (Postfix Lambda Calculus with de Bruijn Indices)

| Byte(s) | Meaning |
|----------|---------|
| `0x00–0xFC` | `Var(i)` — variable reference with de Bruijn index `i` |
| `0xFD` | Application — pop `x`, pop `f`, push `App(f, x)` |
| `0xFE` | Lambda — pop `body`, push `Lam(body)` |
| `0xFF` | End-of-code — stop parsing |

Parsing is a postfix stack machine. The result must be exactly 1 term on the stack at `0xFF`.

### 2.3 Syscall Convention (Continuation-Passing Style)

```
((syscall arg) continuation) FF
```

The VM evaluates: `(syscall arg continuation) ⟹ (continuation result)`

### 2.4 Quick Debug (QD)

The cheat sheet provides QD, a known-good continuation that **prints the encoded result** to the socket:

```
QD = 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
```

Semantically: `QD(term) = write(quote(term))` — serializes any term to its bytecode representation and sends it over the socket, terminated by `0xFF`.

---

## 3. Syscall Table — Complete

An exhaustive sweep of globals `0–252` confirmed only 11 produce behavior other than `Right(1)` ("Not implemented"):

| Syscall | Hex | Name | Input | Output | Status |
|---------|-----|------|-------|--------|--------|
| 0 | 0x00 | (not a syscall) | any | Hangs/silent | N/A |
| 1 | 0x01 | error_string | error code (int) | Left(string) | **Working** |
| 2 | 0x02 | write | bytes list | Left(True), writes to socket | **Working** |
| 3 | 0x03 | (not implemented) | any | Right(1) | Placeholder |
| 4 | 0x04 | quote | any term | Left(serialized bytes) | **Working** |
| 5 | 0x05 | readdir | dir ID (int) | Left(3-way list) | **Working** |
| 6 | 0x06 | name | file/dir ID (int) | Left(name bytes) | **Working** |
| 7 | 0x07 | readfile | file ID (int) | Left(content bytes) | **Working** |
| **8** | **0x08** | **solution** | **any** | **Right(6) — "Permission denied"** | **BLOCKED** |
| 14 | 0x0E | echo | any term | Left(term with +2 index shift) | **Working** |
| 42 | 0x2A | decoy/towel | any | Left("Oh, go choke on a towel!") | **Working** |
| 201 | 0xC9 | backdoor | nil only | Left(pair(A, B)) | **Working** |

### Error Code Reference

| Code | Meaning |
|------|---------|
| 0 | Unexpected exception |
| 1 | Not implemented |
| 2 | Invalid argument |
| 3 | No such directory or file |
| 4 | Not a directory |
| 5 | Not a file |
| 6 | Permission denied |
| 7 | Not so fast! (rate limit) |

---

## 4. Data Encodings — Fully Decoded

### 4.1 Either (Scott Encoding)

Most syscalls return Scott-encoded `Either`:

- `Left x  = λl.λr.(l x)`  — success
- `Right y = λl.λr.(r y)` — error (payload is typically an error code integer)

### 4.2 Integers (9-Lambda Additive Bitset)

Numbers use 9 leading lambdas with an additive body. Variable indices represent bit weights:

| Var Index | Weight |
|-----------|--------|
| V0 | 0 |
| V1 | 1 |
| V2 | 2 |
| V3 | 4 |
| V4 | 8 |
| V5 | 16 |
| V6 | 32 |
| V7 | 64 |
| V8 | 128 |

Example: `3 = λ^9.(V2 @ (V1 @ V0))` → 2 + 1 + 0 = 3

IDs **can exceed 255** via repeated weights: `256 = V8 @ (V8 @ V0)` (128 + 128).

### 4.3 Strings / Byte Lists (Scott Lists)

- `nil = λc.λn.n`
- `cons h t = λc.λn.(c h t)`

Each element is a 9-lambda byte term.

### 4.4 Directory Listings (3-Way Scott Lists)

Syscall `0x05` returns a 3-selector list:

- `nil  = λd.λf.λn.n`
- `dir  = λd.λf.λn.(d id rest)`
- `file = λd.λf.λn.(f id rest)`

### 4.5 Common Terms

| Name | Encoding | Bytes |
|------|----------|-------|
| nil / false / Church 0 | λλ.V0 | `00 FE FE` |
| true / K | λλ.V1 | `01 FE FE` |
| identity / I | λ.V0 | `00 FE` |
| omega / ω | λ.(V0 V0) | `00 00 FD FE` |
| Omega / Ω | (ω ω) | `00 00 FD FE 00 00 FD FE FD` |

---

## 5. Filesystem — Fully Extracted

```
/ (id 0)
├── bin (id 1)
│   ├── false (id 16)           [0 bytes]
│   ├── sh (id 14)              [0 bytes]
│   └── sudo (id 15)            [0 bytes]
├── etc (id 2)
│   ├── brownos (id 3)          [empty dir]
│   └── passwd (id 11)          [181 bytes]
├── home (id 22)
│   ├── dloser (id 50)          [empty dir]
│   └── gizmore (id 39)
│       └── .history (id 65)    [49 bytes]
├── sbin (id 9)                 [empty dir]
└── var (id 4)
    ├── log (id 5)
    │   └── brownos (id 6)
    │       └── access.log (id 46)  [dynamic — changes per connection]
    └── spool (id 25)
        └── mail (id 43)
            └── dloser (id 88)      [177 bytes]
```

**Hidden/unlinked entry**: ID 256 → name: `wtf`, content: `Uhm... yeah... no...\n`

### Key File Contents

**`/etc/passwd` (id 11)**:
```
root:x:0:0:root:/:/bin/false
mailer:x:100:100:mailer:/var:/bin/false
gizmore:GZKc.2/VQffio:1000:1000:Gizmore:/home/gizmore:/bin/sh
dloser:x:1002:1002:dloser:/home/dloser:/bin/false
```

**`/home/gizmore/.history` (id 65)**:
```
sodu deluser dloser
ilikephp
sudo deluser dloser
```

**`/var/spool/mail/dloser` (id 88)**:
```
From: mailer@brownos
To: dloser@brownos
Subject: Delivery failure

Failed to deliver following message to boss@evil.com:

Backdoor is ready at syscall 201; start with 00 FE FE.
```

**`access.log` (id 46)**: Single line with timestamp + client IP:port, changes per connection.

### Password Recovery

- `gizmore` has crypt hash `GZKc.2/VQffio` in `/etc/passwd`
- `.history` leaks `ilikephp` (typed as a command)
- Verified: `crypt("ilikephp", "GZ") == "GZKc.2/VQffio"` ✓
- No login mechanism exists in the VM — `/bin/sh` is 0 bytes

---

## 6. Key Discoveries

### 6.1 The Backdoor (Syscall 201 / 0xC9)

Hinted by the mail spool (`/var/spool/mail/dloser`).

- **Input**: Must be exactly `nil` (`00 FE FE`), otherwise returns `Right(2)` ("Invalid argument")
- **Output**: `Left(pair)` where pair is a Scott-encoded pair containing:
  - `A = λa.λb.(b b)` — self-application of second argument
  - `B = λa.λb.(a b)` — applies first to second
- **Significance**: `(A B) = ω` (the omega combinator, `λx.(x x)`)
- Omega applied to itself (`Ω = ω ω`) causes non-termination

### 6.2 The Echo Syscall (0x0E) — Index Shifting

- Echoes its input wrapped in `Left(...)`, which adds 2 lambdas
- The +2 shift means `echo(Var(251))` → `Left(Var(253))` at the raw level
- **Var(253) = 0xFD** (Application marker) — a runtime-only value that cannot be serialized
- Attempting to `quote` any term containing Var(253+) causes `Encoding failed!`

### 6.3 Syscall 0x2A (42) — Decoy

Returns `"Oh, go choke on a towel!"` — a Hitchhiker's Guide reference. Confirmed **not** the answer.

### 6.4 Hidden File ID 256

- Name: `wtf`
- Content: `Uhm... yeah... no...\n`
- Not reachable from directory tree (no parent directory links to it)
- Scanned IDs 257–1024: no additional entries found

### 6.5 Syscall 8 Behavior Confirmed

- **Always** returns `Right(6)` ("Permission denied") regardless of argument
- Does call its continuation in normal CPS style (confirmed: `sys8(nil)(write_K)` prints K)
- No side effects observed (access.log unchanged after calling)
- No timing differences detected (0.5–0.8s for all inputs, network latency only)
- Each TCP connection is independent — no cross-connection state

---

## 7. Repository Structure

```
brownos2/
├── README.md                           # Quick start guide
├── BROWNOS_MASTER.md                   # 970+ line complete technical reference (SSOT)
├── AGENTS.md                           # Repository conventions & guidelines
├── COMPREHENSIVE_STATE_SUMMARY.md      # This file
├── solve_brownos.py                    # Minimal demo (syscall 0x2A)
├── solve_brownos_answer.py             # Reference client (filesystem + password recovery)
├── registry_globals.py                 # Global registry probe utility
├── challenge.html                      # Saved challenge page
├── utils/
│   ├── decode_backdoor.py              # Backdoor term decoder
│   └── parse_qd.py                     # QD cheat sheet parser
├── forums/                             # Offline WeChall forum threads (HTML)
│   ├── t917_p1.html, t917_p2.html, t917_p3.html  # "Some notes" thread
│   ├── t1352.html                      # "New syscall enabled"
│   ├── t1575.html                      # "Disappointment thread"
│   ├── t1300.html                      # "Pm me to collaborate!"
│   └── b321.html                       # Other forum content
└── archive/                            # All historical research
    ├── old_probes/                     # ~150 early probe scripts (2018–2025)
    ├── probes_jan2026/                 # ~100 January 2026 probes
    ├── probes_feb2026/                 # ~200+ February 2026 probes
    ├── old_tests/                      # Test scripts
    ├── scripts/                        # Utility/analysis scripts
    ├── brute_force/                    # Brute force attempts (C, Python, CUDA)
    ├── logs/                           # Probe execution logs
    ├── data/                           # JSON snapshots (env maps, scan results)
    └── docs/                           # Previous documentation versions
        ├── BROWNOS_LEARNINGS.md
        ├── FINAL_ANALYSIS.md
        ├── FORUM_COMMENTS_TAKEAWAYS.md
        ├── SESSION_FINDINGS.md
        ├── SESSION_SUMMARY.md
        ├── ULTRAWORK_ANALYSIS_SUMMARY.md
        └── (others)
```

**Scale**: ~71,680 lines across 500+ files (mostly probe scripts).

---

## 8. History of All Attempts

### Phase 1: Initial Reverse Engineering (2025 and earlier)

- Decoded the postfix lambda calculus bytecode format
- Identified the CPS syscall convention
- Mapped all syscalls via exhaustive global sweep (0–252)
- Extracted entire filesystem via `readdir` + `name` + `readfile`
- Cracked gizmore's password from `.history` leak
- Discovered the mail spool hint and backdoor syscall 201
- Found hidden file ID 256 ("wtf")

### Phase 2: Syscall 8 Frontal Assault (Jan 2026)

**Exhaustive argument testing**:
- All 1-byte arguments (0–252) → all `Right(6)`
- All 2-byte `λ.Var(n)` patterns → all `Right(6)`
- All 3-byte `λλ.Var(n)` patterns → all `Right(6)`
- 343 combinations of `{0, 1, 2, 8, 201, FD, FE}³` → all `Right(6)`
- Church numerals 0–8 → all `Right(6)`
- Backdoor pair, A combinator, B combinator → all `Right(6)`
- Special terms: identity, nil, true, false, omega, QD → all `Right(6)`

**Continuation variations**:
- QD, identity, nil, single-byte continuations 0–252
- Backdoor combinators A/B as continuations → EMPTY (not Permission denied, but no useful output)
- Different continuations don't change the `Right(6)` result

**Timing analysis**: All calls return in ~0.5–0.8s (network latency). No timing side-channels detected.

### Phase 3: Echo-Mediated Attacks (Jan 2026)

**Theory**: Echo's +2 index shift creates "aliased" values that bypass permission checks.

- `echo(Var(251))` → `Left(Var(253))` — manufactures FD-byte index
- `echo(Var(252))` → `Left(Var(254))` — manufactures FE-byte index
- `echo(Var(253))` → `Invalid term!` — 253 parsed as wire FD, not argument
- Fed echo-derived values to syscall 8 → all `Right(6)`
- `quote(Var(253))` → `Encoding failed!` — cannot serialize special indices

### Phase 4: Backdoor Combinator Algebra (Jan–Feb 2026)

**Theory**: The backdoor pair (A, B) must be combined to produce the "key" for syscall 8.

- `A(A)` → diverges (timeout)
- `B(B)` → diverges
- `A(B)` → ω (omega combinator) → `Right(6)` when fed to syscall 8
- `B(A)` → diverges
- `B(A(B))` → diverges
- All non-divergent results fed to syscall 8 → `Right(6)`

### Phase 5: Credential & String Attacks (Feb 2026)

**Theory**: Syscall 8 needs a credential (username, password, or hash).

- `"ilikephp"` → `Right(6)`
- `"gizmore:ilikephp"` → `Right(6)`
- `"gizmore"`, `"dloser"`, `"root"`, `"sudo"` → all `Right(6)`
- Full passwd line → `Right(6)`
- `"GZKc.2/VQffio"` (raw hash) → `Right(6)`
- Credential-shaped pairs `(uid, password)` with UIDs 1000, 1002 → all `Right(6)`

### Phase 6: Quote-Mediated & Computed Arguments (Feb 2026)

**Theory**: Syscall 8 needs a term that was "produced" by another syscall.

- `quote(g(8))` bytecode → fed to syscall 8 → `Right(6)`
- `quote(g(201))` bytecode → fed to syscall 8 → `Right(6)`
- `backdoor(nil)` result → fed to syscall 8 → `Right(6)`
- Closure-captured continuations → `Right(6)`

### Phase 7: Protocol-Level Tricks (Feb 2026)

**Theory**: The wire format itself can be exploited.

- Bytes appended after `0xFF` → silently ignored, still `Right(6)`
- Multi-term per connection → server processes only first term
- Non-singleton parse stacks → `Invalid term!`
- `sys8` without continuation (1-arg only) → EMPTY (needs 2nd arg)
- `g(0)` exception wrapping → EMPTY

### Phase 8: Multi-Syscall State Chains (Feb 2026)

**Theory**: Calling specific syscalls in a certain order changes internal state.

- `backdoor(nil)` → `echo(result)` → `sys8(...)` → `Right(6)`
- `sys8(nil)` → `sys8(result)` → `Right(6)`
- `sys8(nil)` → `backdoor(nil)` → `sys8(pair)` → `Right(6)`
- `quote(g8)` → `sys8(quoted_bytes)` → `Right(6)`

### Phase 9: Wide Integer & Extended ID Attacks (Feb 2026)

**Theory**: Syscall 8 needs a large integer ID (UID, special code, etc.).

- Wide integers: 256, 257, 511, 512, 1000, 1002, 1024, 4096 → all `Right(6)`
- Credential-shaped pairs with wide UIDs → all `Right(6)`

### Phase 10: "3 Leafs" Exhaustive Search (Feb 2026)

**Theory**: Author's "3 leafs" hint means a minimal 3-variable term is the solution.

- All patterns: `λ.(0(0 0))`, `λλ.(1(0 0))`, `((a b) c)` forms → all `Right(6)` or EMPTY
- 3-leaf hash variants → all `Right(6)`
- Focused probes with every structural permutation → no success

### Phase 11: ULTRAWORK — Parallel Agent Deployment (Jan–Feb 2026)

Deployed 15+ specialized AI agents (Metis, Momus, Oracle, Librarian, Explore, etc.) to attack the problem from different angles simultaneously.

**Metis insights**: Echo creates aliasing, `00 FE FE` might mean something beyond nil
**Oracle insights**: Permission might depend on WHERE call comes from, not WHAT is passed
**Librarian findings**: 4 solvers total, no public writeups exist, dloser's 2016 quote: "figuring out the meaning of the input codes is the most important thing"
**Result**: All agents converged on the same conclusion — syscall 8 is uniformly blocked.

### Phase 12: Continuation-Centric Hypothesis (Feb 2026)

**Theory**: Syscall 8 checks the shape/identity of its continuation, not its argument.

- `sys8(nil)(A)` → EMPTY
- `sys8(nil)(B)` → EMPTY
- `sys8(nil)(pair(A,B))` → no success signal
- `sys8(nil)(g201)` → no success signal
- Observer continuations → `Right(6)` (permission denied confirmed)

---

## 9. Rejected WeChall Answers

These have been **submitted to WeChall and confirmed wrong**:

```
ilikephp, gizmore, GZKc.2/VQffio, dloser
Var(253), Var(251), 253, 251, 0xFD, 0xFB
201, 0xC9, backdoor
3leafs, 3 leafs, echo
FD, fd, FDFE
1, \x01, SOH, 0x01, Church1
echo251, Left(Right(1)), Permission denied, 6, 3
42, wtf
```

---

## 10. Author Hints & Forum Intelligence

### The Author's Note (Collected from Forum Threads)

> "A lot of you are focusing on 8 directly, but … the mail points to the way to get access there. My record is 3 leafs IIRC…
> …did anyone play a bit with that new syscall? … I'm getting some interesting results when combining the special bytes…
> …once it froze my whole system! … Besides, why would an OS even need an echo? I can easily write that myself…"

### Interpretation of Each Hint

| Hint | Interpretation | Status |
|------|---------------|--------|
| "mail points to the way" | Backdoor syscall 201 (from mail spool) | **Found & explored** |
| "3 leafs" | Minimal solution uses 3 variable references | **Tested exhaustively — no success** |
| "combining special bytes" | FD/FE/FF manipulation via echo | **Tested — no success** |
| "froze my whole system" | Omega combinator causes non-termination | **Found (A B = ω)** |
| "why need echo?" | Echo has special purpose beyond I/O | **Found (+2 index shift)** |
| "input codes are the most important thing" (2016) | Understanding bytecode is prerequisite | **Fully decoded** |
| "don't be too literal with ??" | `??` in cheat sheet aren't literal bytes | **Understood** |

### Forum Thread Summary

| Thread | Key Content |
|--------|-------------|
| t917 (3 pages) | Binary protocol basics, QD usage, silence = normal behavior |
| t1352 | "New syscall enabled" — echo (0x0E) added post-launch |
| t1575 | "Disappointment thread" — years of no solvers, encouragement |
| t1300 | Collaboration requests |

### Critical dloser Quote (2016)

> "I haven't heard of anyone figuring out the meaning of the input codes. Figuring out that part is probably the most important thing to do… essential to eventually getting the solution."

This was said **before** echo (0x0E) was added in 2018, so the solution path may have evolved.

---

## 11. Open Hypotheses & Unexplored Leads

### High Priority

1. **Structural property of the argument**: Syscall 8 might check for a very specific lambda term shape that we haven't constructed. The "3 leafs" hint suggests it's minimal but we may be misinterpreting "leaf."

2. **Evaluation-order exploit**: The VM might use call-by-name. Passing an unevaluated thunk that *becomes* something valid during syscall 8's internal reduction could bypass the check.

3. **Syscall 8 called from inside another reduction**: Not as a top-level `((g8 arg) cont)`, but with `g8` appearing as part of a larger term where it gets applied during evaluation by the VM.

4. **The answer comes from a different path entirely**: Maybe syscall 8 is a red herring and the WeChall answer is derived from the discoveries themselves (backdoor, omega, password, filesystem), submitted as a text string. But many candidates have been rejected.

### Medium Priority

5. **IDs beyond 1024**: Only scanned to 1024. The additive encoding supports arbitrarily large numbers.

6. **Encoding ambiguity**: The integer encoding is not unique (e.g., `3 = V2 + V1 + V0 = V1 + V2 + V0`). Maybe syscall 8 checks for a specific encoding.

7. **Time-based or session-based state**: Some external condition (time of day, number of connections, server state) might affect syscall 8.

8. **Echo(echo(...)) deep chains**: Deeply nested echo calls might produce terms with special evaluation properties.

### Low Priority

9. **Hidden syscalls in 202–252 range**: Tested but returned "Not implemented." Could be input-dependent.

10. **Wire format parser bugs**: Specific byte sequences that confuse the parser into treating data as code.

11. **Multi-connection coordination**: Two simultaneous connections coordinating to change shared state.

---

## 12. Conclusion & Recommended Next Steps

### What Is Fully Understood

- The entire protocol (bytecode, CPS, QD)
- All data encodings (Either, integers, strings, directory listings)
- All 11 functional syscalls and their behavior
- The complete filesystem and all file contents
- The backdoor mechanism and its combinator output
- The echo syscall's index-shifting property
- The password (`ilikephp`) and its verification

### What Remains Unknown

- **What makes syscall 8 return `Left(...)` instead of `Right(6)`**
- **What the actual WeChall answer string is**
- Whether these are the same question or different paths

### Assessment

Syscall 8's permission gate has proven to be **provenance-independent** (doesn't matter where the argument came from), **value-independent** (same result for all tested values), and **protocol-independent** (no wire-level tricks work). After 500+ tests across 12+ months and 15+ parallel AI agents, the gate has never been breached.

The most likely remaining paths are:

1. **A very specific, minimal term structure** we haven't constructed (aligned with "3 leafs" hint)
2. **A fundamentally different invocation pattern** where syscall 8 is not called directly but emerges from evaluation
3. **The WeChall answer is a thematic string** derived from all discoveries, but not one we've tried yet

### Recommended Next Steps

1. Re-examine the "3 leafs" hint with fresh interpretation — perhaps "leaf" refers to something other than variable nodes (e.g., 3 bytes, 3 lambdas, 3 applications)
2. Try constructing terms where syscall 8 is invoked *implicitly* through beta-reduction rather than as a top-level call
3. Scan IDs beyond 1024 (up to 65535) for additional hidden files
4. Test with the exact backdoor-derived ω combinator as both argument and continuation to syscall 8 in novel configurations
5. Submit untested WeChall answer candidates: `omega`, `ω`, `Ω`, `self-apply`, `pair`, `AB`, `λab.bb`, combinator-theory terms
6. Revisit whether "combining special bytes" means creating a term with literal `0xFD`/`0xFE` bytes as *data* inside a larger structure

---

*This summary consolidates all findings from BROWNOS_MASTER.md, archive/docs/*.md, 500+ probe scripts, 7 forum threads, and 15+ parallel agent analyses conducted between 2025 and February 2026.*
