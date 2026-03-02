# BrownOS v23 — Latest Evidence + Precise Decoder Model

You have access to the full repo at `https://github.com/SynthNoirLabs/brownos2`. Key files:
- `BROWNOS_MASTER.md` — complete reverse-engineering reference
- `solve_brownos_answer.py` — working Python client with all encoders/decoders
- `prompt_v22_full.md` — previous complete state (219 lines, VM spec, filesystem, all hints, all negative results)
- `archive/probes_feb2026/` — 150+ probe scripts with live results
- `archive/logs/` — raw output logs from probe runs

This prompt covers ONLY what's new since v22. Read `prompt_v22_full.md` for full context.

---

## 1. WHAT WE TESTED SINCE v22

### 1.1 Producer→Consumer Composition ("inner syscall feeds outer decoder")

The hypothesis: an inner syscall's **return value** could feed an outer syscall's argument during evaluation. Proposed unwrap pattern: `U(syscall, arg) = syscall(arg)(I)(I)(K*)`.

**Theoretical trace** of `write(U(error_string(6)))(K*)`:
```
error_string(6)(I)       → I(Left("Permission denied")) = Left("Permission denied")
Left(string)(I)          → λr.(I string)
(λr.(I string))(K*)      → I(string) = string
write(string)(K*)        → should print "Permission denied"
```

**Live results:**

| Payload | Expected | Actual | Hex |
|---|---|---|---|
| `write(U(error_string(6)))(K*)` | "Permission denied" | **EMPTY** | (none) |
| `write(U(name(256)))(K*)` | "wtf" | **EMPTY** | (none) |
| `write(U(readfile(256)))(K*)` | "Uhm..." | **EMPTY** | (none) |
| `write(U(error_string(6)))(PSE)` | — | **"Invalid argument"** | `496e76616c696420617267756d656e74` |
| `write(U(name(256)))(PSE)` | — | **"Invalid argument"** | `496e76616c696420617267756d656e74` |
| `write(U(readfile(256)))(PSE)` | — | **"Invalid argument"** | `496e76616c696420617267756d656e74` |
| `name(U(echo(256)))(PSE)` | "wtf" | **"Invalid argument"** | `496e76616c696420617267756d656e74` |
| `readfile(U(echo(256)))(PSE)` | "Uhm..." | **"Invalid argument"** | `496e76616c696420617267756d656e74` |
| `write(U(quote(U(backdoor(nil)))))(K*)` | pair bytecode | **EMPTY** | (none) |

### 1.2 Root Cause: Structural Composition Bug

The P1-P3 EMPTY results were caused by `K*` as outer continuation suppressing `Right(2)` from write. With PSE, the actual error is **"Invalid argument"** — write rejects what the unwrap chain produces.

**Why write rejects it:** The unwrap chain DOES extract the string from Left. But then the outer `cps_handler = λr. r(left_handler)(right_handler)` receives the raw string and applies it to TWO handlers. Since a Scott string (2-lambda cons) is structurally identical to a Scott Either (also 2-lambda), the handler destructures the string as if it were an Either instead of passing it to write whole.

```
handler(string) = string(λs.write(s)(K*))(K*)
                = cons('P', rest)(λs.write(s)(K*))(K*)
                = (λs.write(s)(K*))('P')(rest)       ← DESTRUCTURES the string!
                = write('P')(K*)(rest)                ← writes ONE BYTE TERM, not a list
                → Right(2) = Invalid argument
```

**This is NOT a server limitation — it's a term-structure confusion.** Scott Either and Scott List are both 2-lambda terms. Without an explicit tag, you cannot distinguish them at the lambda calculus level.

### 1.3 Verified: write DOES accept I-wrapped strings

| Test | Result |
|---|---|
| `write('wtf')(K*)` direct | `wtf` ✅ |
| `write(I('wtf'))(K*)` one wrap | `wtf` ✅ |
| `write(I(I('wtf')))(K*)` two wraps | `wtf` ✅ |

The write decoder reduces its argument. `I(string)` → string works fine. The issue is specifically with the unwrap-from-Either pattern, not with write's decoder.

### 1.4 Standard CPS Chains Still Work Perfectly

| Chain | Result |
|---|---|
| `error_string(6)(λr. r(λs.write(s)(K*))(K*))` | "Permission denied" ✅ |
| `name(256)(λr. r(λs.write(s)(K*))(K*))` | "wtf" ✅ |
| `readfile(256)(λr. r(λs.write(s)(K*))(K*))` | "Uhm... yeah... no...\n" ✅ |

### 1.5 Diagnostic: Inner CPS Chain Doesn't Survive

| Test | Result |
|---|---|
| `error_string(6)(I)(QD)` | EMPTY |
| `error_string(6)(I)(I)(QD)` | EMPTY |
| `error_string(6)(I)(I)(K*)(QD)` | EMPTY |
| `echo(256)(I)(QD)` | EMPTY |
| `echo(256)(I)(I)(QD)` | EMPTY |
| `echo(256)(I)(I)(K*)(QD)` | EMPTY |

After `syscall(arg)(I)` returns Left(x), further applications treat Left(x) as a 2-lambda term and don't reconstitute the original value in a way that's useful for further CPS consumption.

### 1.6 Quote Reveals What Unwrap Chains Produce

| Test | Quoted output |
|---|---|
| `quote(U(echo(256)))(QD)` | Complex application tree (NOT N256) |
| `quote(U(error_string(6)))(QD)` | Complex application tree (NOT the string) |
| `quote(U(name(256)))(QD)` | Complex application tree (NOT "wtf") |

The unwrap chain produces partially-reduced APPLICATION trees, not the clean values we expected. The CBN evaluator stops at WHNF at each step, leaving unevaluated subterms.

### 1.7 Sparse Hidden VFS Nodes

| ID | name() | readfile() |
|---|---|---|
| 56154 (hash iterations) | — | "No such directory or file" |
| 61221 (service port) | — | "No such directory or file" |

Combined with earlier scans: 0-280, 1000, 1002, 2014, 9252 — all "No such file." Only id 256 ("wtf") exists as a hidden node.

### 1.8 Side-Effect During Decode (from prior round)

| Test | Result |
|---|---|
| `name((K N256) ((name N256) PS))(PSE)` | One "wtf" only (no inner side effect) |
| `name(M256_with_CPS_body)(PSE)` | One "wtf" (no in-body side effect) |
| `sys8((K N0) ((readfile N256) PS))(PSE)` | "Permission denied" (no inner readfile) |

Side effects during decode do NOT reach the socket. The decoder reduces arguments enough to extract values, but nested CPS chains' I/O is suppressed.

### 1.9 Hash Candidates — All Miss

Tested since v22: `3 leafs`, `Good input gives good stuff back`, `the meaning of the input codes`, `IT is always casting its dark magic...`, `A(B)=B`, plus 10 exact file-content line variants and 15 prior candidates.

---

## 2. PRECISE DECODER MODEL (UPDATED)

Based on all evidence:

1. **Decoders REDUCE arguments** (I(N) → N works for name/readfile/write)
2. **Multi-step reduction works** (I(I(N)) works)
3. **Decoders are eager** (Ω diverges even in discarded positions)
4. **Side effects during decode are suppressed** (CPS chains don't write to socket)
5. **write accepts I-wrapped strings** (write(I(s)) = write(s))
6. **Standard CPS is the ONLY working composition model** — the U(I)(I)(K*) unwrap pattern fails due to Either/List structural confusion
7. **The `syscall(arg)(I)` trick produces Left(x) but further applications destructure it as a cons cell** — Left and cons are indistinguishable in pure Scott encoding

---

## 3. WHAT IS FORMALLY RETIRED (CUMULATIVE)

| Hypothesis | Evidence |
|---|---|
| sys8 argument of any type/value | 700+ probes |
| Runtime-vs-wire exploit | 3-axis Oracle falsification |
| Provenance-sensitive closures | Live=literal under all syscalls |
| Side effects during decode | 5 probes, only outer syscall output |
| **Producer→consumer via U(I)(I)(K*) unwrap** | **write rejects: Either/List indistinguishable** |
| Sparse VFS nodes 0-280, 1000, 1002, 2014, 9252, 56154, 61221 | All "No such file" |
| 400+ hash candidates | Zero matches |

---

## 4. WHAT IS GENUINELY OPEN

1. **Standard CPS chains work.** We can compose `syscall1 → unwrap → syscall2 → unwrap → write`. We've done this extensively. Is there a SPECIFIC chain we haven't tried?

2. **The decoder reduces.** We can pass computed integers to name/readfile. But we've scanned up to 61221 with no hidden files.

3. **"3 leafs"** — a minimal program. What ARCHITECTURE could a 3-leaf program have that we haven't tested? Not a new sys8 argument, but a fundamentally different program structure.

4. **"Dark magic / IT doesn't realize"** — the evaluator does something natural that produces the flag. WHAT?

5. **"The meaning of the input codes"** — we understand: postfix de Bruijn, Scott encodings, decoders reduce. What layer is STILL missing?

---

## 5. YOUR TASK

### Constraints
- Do NOT propose sys8 argument variations
- Do NOT propose U(I)(I)(K*) unwrap chains (structurally broken)
- Do NOT propose side-effect-during-decode
- Do NOT propose runtime-vs-wire / provenance theories
- Do NOT propose sparse VFS nodes without a STRONG reason for a specific ID
- EVERY payload MUST use standard CPS composition (the only model that works)

### Provide
- **A)** What we're still wrong about (max 3 bullets)
- **B)** Top 2 hypotheses explaining ALL 8 forum hints simultaneously
- **C)** 8 exact payloads using STANDARD CPS (AST + hex + expected + what we learn)
- **D)** 5 offline hash candidates
- **E)** The single most informative server query
