# BrownOS v22 — Complete State of the Art (Fresh Document)

You are helping solve WeChall "The BrownOS" (difficulty 10/10, 4 solvers in 12 years). You have NO server/repo access. This document is self-contained with all verified data.

---

## 1. CHALLENGE

- **Service**: `wc3.wechall.net:61221` (raw TCP, binary protocol)
- **Goal**: Find a flag string. Verify: `sha1^56154(flag) == "9252ed65ffac2aa763adb21ef72c0178f1d83286"`
- **Created**: May 2014 by "dloser". Solvers: dloser, l3st3r, space, jusb3.
- **Echo syscall (sys14) added Sept 2018** as a hint after 4 years with 0 solvers.

---

## 2. VM SPECIFICATION

### Bytecode (postfix stack machine, de Bruijn indices)
| Byte | Meaning |
|------|---------|
| `0x00..0xFC` | `Var(i)` |
| `0xFD` | `App`: pop x, pop f, push `App(f,x)` |
| `0xFE` | `Lam`: pop body, push `Lam(body)` |
| `0xFF` | EOF (stop parsing) |

### Evaluation
- Call-by-name lambda calculus + C++ primitive syscalls
- Reduces to WHNF
- Syscall dispatch: `App(App(primitive, arg), cont)` → C++ handler runs, calls `cont(result)`
- 253 global bindings (0..252). 11 active syscalls; 242 return `Right(1)` ("Not implemented")

### Data Encodings (Scott)
- `Left(x) = λl.λr.(l x)` — success
- `Right(y) = λl.λr.(r y)` — error
- Integer: 9 lambdas, additive bitset body. `V1=1, V2=2, V3=4, ..., V8=128, V0=base`
- List: `nil = λc.λn.n`, `cons(h,t) = λc.λn.(c h t)`
- Dir3: `nil3 = λd.λf.λn.n`, `dir(id,rest) = λd.λf.λn.(d id rest)`, `file(id,rest) = λd.λf.λn.(f id rest)`

### QD (Quick Debug)
`05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE` — continuation that does `write(quote(result))`.

---

## 3. COMPLETE SYSCALL MATRIX

| ID | Name | Behavior |
|----|------|----------|
| 0x00 | (unbound) | Diverges |
| 0x01 | error_string | `int → Left(string)`. Codes 0-7 mapped. N≥8 → `Left("")` |
| 0x02 | write | `bytes_list → writes to TCP socket`, calls `cont(True)` |
| 0x04 | quote | `term → Left(bytecode)`. Does NOT reduce arg (CBN). Fails on Var(253+) → `"Encoding failed!"` |
| 0x05 | readdir | `int → Left(dir3_list)` or `Right(4)` |
| 0x06 | name | `int → Left(string)` or `Right(3)` |
| 0x07 | readfile | `int → Left(string)` or `Right(5/3)` |
| 0x08 | ??? | **`Right(6)` for ALL inputs ever tested** (700+ probes) |
| 0x0E | echo | `term → Left(term)`. Wraps in Left; +2 index shift artifact |
| 0x2A | towel | Always `Left("Oh, go choke on a towel!")` regardless of arg |
| 0xC9 | backdoor | Only accepts nil → `Left(pair)`. pair = `λs.(s A B)`, A=`λa.λb.(b b)`, B=`λa.λb.(a b)` |

Non-CPS outputs: `"Encoding failed!"`, `"Invalid term!"`, `"Term too big!"` (raw ASCII, no 0xFF).

---

## 4. COMPLETE FILESYSTEM

```
/ (id 0)
├── bin/ (1) → false(16), sh(14), sudo(15) — all empty files
├── etc/ (2) → brownos/(3) [empty dir], passwd(11)
├── home/ (22) → dloser/(50) [empty], gizmore/(39) → .history(65)
├── sbin/ (9) [empty]
└── var/ (4) → log/(5) → brownos/(6) → access.log(46)
              → spool/(25) → mail/(43) → dloser(88)
Hidden: id 256 name "wtf"
```

**File contents (verbatim)**:
- **passwd(11)**: `root:x:0:0:root:/:/bin/false\nmailer:x:100:100:mailer:/var:/bin/false\ngizmore:GZKc.2/VQffio:1000:1000:Gizmore:/home/gizmore:/bin/sh\ndloser:x:1002:1002:dloser:/home/dloser:/bin/false`
- **.history(65)**: `sodu deluser dloser\nilikephp\nsudo deluser dloser`
- **mail/dloser(88)**: `From: mailer@brownos\nTo: dloser@brownos\nSubject: Delivery failure\n\nFailed to deliver following message to boss@evil.com:\n\nBackdoor is ready at syscall 201; start with 00 FE FE.`
- **wtf(256)**: `Uhm... yeah... no...\n`
- **access.log(46)**: `<unix_timestamp> <client_ip>:<port>` (per-connection, dynamic)

Password: gizmore's hash `GZKc.2/VQffio` cracks to `ilikephp`.

**No valid file IDs exist in ranges**: 89-280, 1000, 1002, 2014, 9252. Node 256 is isolated.

---

## 5. VERBATIM FORUM HINTS

1. **"The mail points the way. My record is 3 leafs IIRC."** — Use backdoor (sys201). Solution is ~3 Var nodes.
2. **"Figuring out the meaning of the input codes is probably the most important thing to do."** (May 2016, pre-echo)
3. **"The second example in the cheat sheet is useful in figuring out crucial properties. The different outputs betray some core structures."** — Use `?? ?? FD QD FD` to discover the type system.
4. **"Don't be too literal with the ??s."** — The `??` are arbitrary terms, not fixed bytes.
5. **"IT is always casting its dark magic, it wont even realize we hacked it."** (Jan 2026) — IT = the evaluator. The solution tricks the evaluator naturally.
6. **"Why would an OS need echo? I can easily write that myself."** — Echo has a specific purpose beyond convenience.
7. **l3st3r (solver)**: "Good input gives good stuff back. Now, what is good input?"
8. Echo added Sept 2018 after 4 years, 0 solvers.

---

## 6. WHAT IS PROVEN BY LIVE TESTING

### 6.1 sys8 is an absolute wall
- **700+ test cases** spanning: all integers 0-4096, all globals 0-252, all strings (credentials, paths, names), all combinators, backdoor pair/A/B/compositions, echo-manufactured Left(X), forged Left/Right wrappers, CPS thunks, multi-step chains, β-equivalent computed arguments, 5346 exhaustive 3-leaf combinations.
- **Result**: Right(6) for every single input. No structural class, provenance, or value bypasses it.

### 6.2 Decoders are operational (reduce arguments)
- `name(I(256))` → `wtf` ✅ (I = λx.x, one β-step)
- `name(I(I(256)))` → `wtf` ✅ (two β-steps)
- `readfile(I(256))` → `Uhm... yeah... no...\n` ✅
- **Decoders reduce their arguments before extracting the integer value.**

### 6.3 Decoders are eager, NOT lazy
- `name((K 256)(Ω))` → **EMPTY** (Ω = `(λx.xx)(λx.xx)` — diverges even in discarded position)
- `name((λx.N256)(Ω))` → **EMPTY** (same: Ω diverges even though `x` is unused)
- `name(((λx.λy.N256) I) Ω)` → **EMPTY** (same)
- **The decoder touches ALL subterms. Ω causes divergence in any position.**

### 6.4 Side effects during decode do NOT reach the socket
- `name((K N256) ((name N256) PS))(PSE)` → **one** `wtf` (only outer name's result)
- `name(M256_with_CPS_body)(PSE)` → **one** `wtf` (no inner side effect output)
- `sys8((K N0) ((readfile N256) PS))(PSE)` → `Permission denied` (no inner readfile output)
- `sys8(M0_read_with_CPS_body)(PSE)` → `Permission denied` (no inner readfile output)
- **Terminating CPS chains embedded in arguments do NOT trigger socket writes during decode.**

### 6.5 Ω vs terminating subterms behave differently
- Ω in discarded position → **EMPTY** (diverges)
- Terminating CPS chain in same position → **outer syscall completes normally**
- This means the evaluator DOES process both, but terminating subterms finish silently while Ω loops forever.

### 6.6 quote does NOT reduce
- `quote(pair(K))` = App(pair, K) serialized (19 bytes, not reduced to A's 5 bytes)
- `quote(pair(I)(I))` = App(App(pair, I), I) serialized (not reduced)
- **quote serializes the unevaluated application tree as-is.**

### 6.7 No provenance sensitivity
- Live `sys201→pair→quote` = literal `pair→quote` (identical bytes)
- `sys8(live_A)` = `sys8(literal_A)` = both Right(6)
- **The VM does not track term origin.**

### 6.8 242 non-active globals are true stubs
- All 242 tested with nil, int(0), int(1), "ilikephp", I, QD, g(8), g(201) → **all Right(1)**

### 6.9 Hash candidates exhausted
- **400+** strings/bytes tested against `sha1^56154` target — zero matches
- Includes: all file contents (with/without newlines), individual lines, error strings, combinator names, bytecodes, challenge metadata, filesystem paths, credentials, protocol constants

---

## 7. HYPOTHESES FORMALLY RETIRED (WITH EVIDENCE)

| Hypothesis | Falsified By |
|---|---|
| sys8 argument of any type/value/provenance | 700+ probes, all Right(6) |
| Forged tokens (Left/Right wrappers) | 40-probe sweep, all Right(6) |
| Runtime-vs-wire exploit (non-serializable terms) | Oracle 3-axis falsifiers |
| Provenance-sensitive closures | F2a/F3a identical bytes |
| Partial-unwrap depth-shift gadget | P4 Encoding failed (quote doesn't reduce) |
| Side effects during eager decode | Probes 1-4, only outer syscall output |
| Pair-as-cons duck typing | Structural proof (1 lambda ≠ 2 lambdas) |
| Backdoor A/B as file IDs | All "Invalid argument" (2 lambdas ≠ 9-lambda int) |
| Hidden VFS nodes 89-280, 1000, 1002, 2014, 9252 | All "No such file" |
| C++ memory leak / ROP | Evaluator handles gracefully |
| IP-based authentication | Same IP, still Right(6) |
| Silent success | Architecturally impossible (anonymous TCP) |

---

## 8. WHAT IS GENUINELY UNKNOWN

1. **What does sys8 actually check?** It returns Right(6) for every value type. Does it check something we haven't conceived?
2. **Is sys8 even the goal?** Maybe the flag comes from a different mechanism entirely.
3. **What is "the meaning of the input codes" beyond the type system?** We decoded: Var/App/Lam/EOF, Scott Either/Int/List/Dir3. The author said this is "the most important thing." Is there a second layer?
4. **What does "dark magic / IT doesn't realize" mean concretely?** The evaluator is tricked. But how, if side effects during decode don't reach the socket?
5. **Where is the flag data stored?** It's not in any readable file. It's not in error strings. If sys8 returns it on success, how do we make sys8 succeed?
6. **What's the significance of A(B) = `λb.λc.(b c)` (= B combinator)?** The backdoor pair produces this when composed. Is it a clue or a red herring?

---

## 9. PRECISE CHARACTERIZATION OF THE DECODER

The integer decoder (used by name, readfile, readdir, sys8):
1. **Reduces** its argument (not syntactic-only) — I(N) works
2. **Multi-step** — I(I(N)) works
3. **Eager** — touches ALL subterms, even discarded ones. Ω diverges anywhere.
4. **But side-effect-free** — embedded CPS chains don't produce socket output during reduction
5. **Rejects non-9-lambda terms** — A (2λ), B (2λ), pair (1λ) all "Invalid argument"
6. **No provenance sensitivity** — live backdoor terms = literal terms

This means: the decoder calls the evaluator to reduce arguments, but syscall dispatch during that inner reduction either doesn't happen or its output is captured/suppressed.

---

## 10. YOUR TASK

After 700+ probes, 400+ hash candidates, and systematic falsification of every proposed theory:

### Think about
1. **Why does the author say "A lot of you are focusing on 8 directly"?** What does "NOT directly" look like?
2. **The mail says "the mail points to the way to get access THERE."** Where is "there"? Is it sys8, or something else?
3. **"3 leafs" and "must print"** — what 3-leaf program architecture actually writes to the socket?
4. **"IT doesn't realize"** — the evaluator naturally produces the flag. NOT through a syscall succeeding, but through the evaluation process itself.
5. **"The meaning of the input codes"** — pre-echo (2016), this was "the most important thing." What meaning is left to discover?
6. **Decoders reduce but don't leak side effects** — is this a clue? Maybe the side effect goes somewhere OTHER than the socket?

### Provide
- **A)** What we're still wrong about (max 3 bullets)
- **B)** Top 2 hypotheses (each must explain ALL 8 hints in section 5)
- **C)** 8 exact payloads (AST + step-by-step hex derivation + expected result + what we learn)
- **D)** 5 offline hash candidates not yet in our tested set
- **E)** The single most informative server query remaining

### Constraints
- Do NOT propose sys8 argument variations (700+ tested, wall confirmed)
- Do NOT propose side-effect-during-decode (falsified by 5 probes)
- Do NOT propose runtime-vs-wire / provenance theories (3-axis falsified)
- EVERY payload must have correct de Bruijn indices. Under N lambdas, global G is at `Var(G+N)`.
