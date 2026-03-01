# BrownOS — Full State Transfer (No Repo Access)

You have no code or repository access, so this prompt includes everything needed.
Do NOT assume hidden implementation details beyond what is documented here.

---

## 0) Mission and Hard Objective

The challenge is WeChall "The BrownOS". The server is a lambda-calculus VM over raw TCP.

- Endpoint: `wc3.wechall.net:61221`
- Input: postfix lambda-bytecode ending with `0xFF`
- Goal: recover a string `answer` such that:
  - `sha1^56154(answer) == 9252ed65ffac2aa763adb21ef72c0178f1d83286`
- Important: this is NOT auto-scored from socket activity.
  - The TCP service is anonymous.
  - No account/session binding exists over the socket.
  - Therefore "silent success" is impossible.
  - The VM must output bytes containing useful data (ideally the flag) to the socket.

---

## 1) Wire Protocol (Complete Minimum)

Bytecode grammar:
- `0x00..0xFC` -> `Var(i)`
- `0xFD` -> `App`
- `0xFE` -> `Lam`
- `0xFF` -> end-of-code marker

Postfix examples:
- `App(f, x)` encodes as `<f><x>FD`
- `Lam(body)` encodes as `<body>FE`

Critical gotchas:
- Must send raw bytes, not ASCII hex.
- Must include exactly one terminating `0xFF`.
- Extra bytes after first `0xFF` are ignored.
- Server evaluates one term per connection.

---

## 2) Data Encodings Used by VM

### Either
- `Left x = \l.\r. l x` (success path)
- `Right y = \l.\r. r y` (error path)

### Integer encoding
- 9-lambda additive bitset encoding (not plain Church numerals)
- This matters for decoding error codes.

### Scott list
- `nil = \c.\n. n`
- `cons h t = \c.\n. c h t`

`sys2` expects Scott list of byte-terms.

---

## 3) Verified Syscalls

Active syscalls:
- `0x01` (1): error_string
- `0x02` (2): write
- `0x04` (4): quote
- `0x05` (5): readdir
- `0x06` (6): name
- `0x07` (7): readfile
- `0x08` (8): target syscall
- `0x0E` (14): echo
- `0x2A` (42): decoy towel message
- `0xC9` (201): backdoor

All other globals 0..252 not listed above -> Right(1) Not implemented (or silent for non-callable shapes).

### Key behavior
- `sys8` always returns `Right(6)` (Permission denied) on all argument classes tested.
- `sys14` echo returns `Left(term)` and can manufacture runtime `Var(253+)` via +2 shift under Either.
- `sys201(nil)` returns `Left(pair)` where:
  - `pair = \s. s A B`
  - `A = \a.\b. b b`
  - `B = \a.\b. a b`

---

## 4) Hard Correction: Right(3) vs Right(6)

A previous long-standing analysis bug misread encoded error payload bits and over-reported Right(3).

Current corrected state:
- Strings often hit `Right(3)` path (No such file)
- Non-string / structured / combinator arguments generally hit `Right(6)` path
- But no tested argument has bypassed permission gate to produce success through `sys8`

The practical result remains unchanged: no direct `sys8` argument strategy has succeeded.

---

## 5) Backdoor + Echo Facts You Must Respect

### Echo special-byte manufacturing
- `echo(Var(251))` can produce runtime `Var(253)`
- `echo(Var(252))` can produce runtime `Var(254)`

But:
- `quote` on terms containing these impossible vars often gives `Encoding failed!`
- Direct attempts to treat those vars as native pointers via `sys2` did not leak memory

### Backdoor combinator behavior
- `A B -> \x. x x` (little omega form)
- Many self-application chains diverge or halt silently
- No tested combinator path yielded printable flag output

---

## 6) What Was Tested Recently (and Failed)

### LLM v10 family (native memory leak / ROP framing)
Executed payload classes:
- `sys201(nil)` + bad continuation to force raw `sys2` write
- direct dump attempts for A/B
- `sys201(nil)(sys2)(nil)` “3-leaf native pipe”

Observed:
- All EMPTY (0 bytes output)
- No native pointer dump
- No crash artifact useful for extraction

### LLM v11 family (V253/V254/V255 extraction through wrappers)
Executed payload classes:
- wrap runtime-forbidden vars into one-element Scott lists
- feed into `sys2`
- nested echo to attempt `V255`
- 3-leaf wrapper-strip test

Observed:
- All EMPTY
- No printed bytes
- No exploitable side-channel

### LLM v12 family (pure 3-leaf paradoxes)
Executed raw payloads:
- `0E C9 FD 08 FD FF` (`sys14 sys201 sys8`)
- `08 08 FD 08 FD FF` (`sys8 sys8 sys8`)
- `C9 C9 FD C9 FD FF` (`sys201 sys201 sys201`)

Observed:
- All EMPTY
- No data printed
- No protocol-visible success signal

Conclusion of v10-v12:
- “Silent success” hypothesis is invalid
- Evaluator can reduce to WHNF and terminate without socket output
- No proof of memory exfiltration via these paths

---

## 7) Author/Forum Clues (High Value)

From challenge author (dloser), historically:
1. "Mail points the way" -> backdoor/mail clue matters
2. "My record is 3 leafs IIRC" -> extremely small AST likely exists
3. "new syscall" and "combining special bytes" -> echo relevance
4. "once it froze my whole system" -> pathological evaluator behavior can occur
5. direct quote: "IT is always casting its dark magic, it wont even realize we hacked it"

Interpretation currently used:
- “IT” refers to evaluator/reducer behavior, not a classic memory corruption exploit
- But any winning path must still produce printable output

---

## 8) Non-Negotiable Constraints For Your Next Proposal

1. Your proposal MUST account for anonymous socket architecture:
   - No "silent award", no hidden account linkage.
2. Your proposal MUST include a print path:
   - `sys2`, `sys4`, or a deterministic error-printing mechanism.
3. If claiming 3-leaf viability:
   - show exact 3-leaf AST,
   - show reduction steps,
   - show why final state calls printing behavior.
4. Do NOT suggest already-failed families:
   - generic V253 pointer dumping,
   - pure paradoxes with no print syscall,
   - `sys8` argument brute-force variants without new mechanism.

---

## 9) What You Need To Deliver Now

Provide exactly:

A) **3 strongest novel hypotheses** (not previously tested families)
- each with one-sentence novelty claim

B) **For each hypothesis, 2 concrete payloads**
- exact AST notation
- exact postfix bytes (hex)
- predicted reduction trace (short but explicit)
- explicit reason it should print bytes

C) **Expected observable outputs**
- what would indicate progress vs failure
- how to distinguish EMPTY vs Right(6) vs Encoding failed vs useful leak

D) **Prioritization order**
- rank 1..6 payloads by expected signal quality

Keep it rigorous. No architecture assumptions beyond what is stated above.
