# BrownOS — Open Questions, Hypotheses & Strategic Synthesis

## Current Status Summary

After extensive reverse engineering (500+ test cases, 200+ probe scripts, brute force attempts), BrownOS syscall 8 remains locked with `Right(6)` "Permission denied" for all tested inputs. We have:

- ✅ Fully documented the wire protocol and VM model
- ✅ Decoded all data encodings (Either, integers, strings, directories)
- ✅ Mapped the complete filesystem and extracted all file contents
- ✅ Identified all 11 active syscalls
- ✅ Cracked gizmore's password (`ilikephp`)
- ✅ Discovered the backdoor (syscall 201) and its combinator pair
- ✅ Understood echo's role in manufacturing Var(253+) values
- ✅ Found hidden file id 256 ("wtf")
- ❌ NOT found the argument or method to make syscall 8 succeed
- ❌ NOT found the WeChall answer

---

## Definitive Findings (High Confidence)

1. **Syscall 8 is CPS-compliant** — it calls its continuation with the result, not a special mechanism
2. **Syscall 8 is argument-independent** (for most argument types) — Right(6) regardless
3. **String arguments trigger Right(3) NoSuchFile** — a distinctly different code path from Right(6)
4. **The backdoor pair triggers Right(3) NoSuchFile** when passed to syscall 8
5. **No hidden syscalls exist** in 0–252
6. **No cross-connection state** — each TCP connection is isolated
7. **No timing-based checks** — responses are uniformly fast
8. **Echo manufactures Var(253+)** — the only way to create these runtime values
9. **Quote cannot serialize Var(253+)** — "Encoding failed!" with no FF terminator

---

## Disproven Hypotheses

| # | Hypothesis | Evidence Against |
|:---:|---|---|
| 1 | Callback — sys8 applies its arg as callback | All projections return identical Right(6) |
| 2 | Echo-manufactured token unlocks sys8 | Var(253/254) as arg → Right(6) |
| 3 | Any 3-leaf term is the key | All enumerated patterns → Right(6) |
| 4 | Backdoor pair unlocks sys8 | A, B, pair → Right(6) or Right(3) |
| 5 | Divergent terms bypass checks | ω, Ω → Right(6) or timeout |
| 6 | Echo-transformed syscall reference | echo(Var(8)) → extract → still Right(6) |
| 7 | Timing/race condition | Uniform response times |
| 8 | Cross-connection state | Each connection independent |
| 9 | Protocol tricks (post-FF, multi-term) | All ignored or error |
| 10 | Password "ilikephp" as syscall arg | Right(3) NoSuchFile |
| 11 | Credential pairs (UID + password) | Right(6) |
| 12 | Combinator algebra (A/B compositions) | Diverge or Right(6) |

---

## Active Hypotheses (Not Yet Disproven)

### HIGH Priority

#### H1: Wire Format Injection via Var(253)
Var(253) = byte 0xFD = the Application marker. If the VM's internal representation doesn't fully separate the term structure from the wire format, then a runtime Var(253) might be misinterpreted as an Application node during some internal operation. This could:
- Cause the parser to re-parse a serialized term differently
- Trigger an internal evaluation path that bypasses permission checks
- Create a "confused deputy" scenario

**Why not yet tested**: We've passed Var(253) as an argument, but haven't explored all the ways it could interact with the VM's internal operations.

#### H2: Syscall Sequence / State Machine
Maybe syscall 8 has an internal pre-condition that's set by calling other syscalls first (within the same term/evaluation, not across connections). For example:
- `backdoor(nil)(λpair. sys8(???)(QD))` — call backdoor, then use the pair in a specific way with sys8
- `echo(251)(λresult. sys8(result)(QD))` — echo to get Var(253), then use it

**Partially tested**: We've tried chaining syscalls, but may have missed the right combination or wrong continuation structure.

#### H3: The "3 Leafs" Solution We Haven't Considered
The author said "3 leafs" but we've only interpreted this as 3 Var nodes. Other interpretations:
- 3 bytes in the raw program (excluding FF)
- 3 top-level syntactic elements
- 3 specific variable indices (e.g., the values 0, 8, 201 or similar)
- A term with exactly 3 leaf nodes that isn't a direct `((a b) c)` pattern
- Maybe the "3 leafs" includes lambda bodies as part of the count

#### H4: Evaluation Context Matters
Syscall 8 might check WHERE/HOW it's called, not just WHAT is passed. Maybe:
- It must be called from within another syscall's continuation
- It must be called with the result of a specific computation as its argument
- The term structure around the syscall call matters (not just the argument)

#### H5: The Right(3) NoSuchFile Path
String arguments and the backdoor pair produce Right(3) "NoSuchFile" instead of Right(6) "PermDenied". This suggests syscall 8 **does** try to interpret certain arguments as file paths/identifiers. Maybe:
- The right path/ID hasn't been found
- A specific file content (read via readfile) is the correct argument
- The path encoding needs a specific format we haven't tried

### MEDIUM Priority

#### H6: Var(253) as Part of a Larger Construction
Instead of passing Var(253) directly, construct a term that uses it in a structural way:
- A lambda that captures Var(253) in its closure
- A pair/list containing Var(253) as an element
- An application where Var(253) appears as the function or argument position

#### H7: Non-Standard Program Structure
Maybe the solution doesn't use the standard `((syscall arg) continuation)` pattern. Other structures:
- A term that reduces to a syscall call through lambda reduction
- Using the VM's evaluation order to construct the syscall dynamically
- A self-modifying or self-referential term

#### H8: IDs Beyond 1024
We only scanned filesystem IDs up to 1024. The additive encoding supports arbitrary large numbers. There might be hidden entries at higher IDs that contain the answer or a key.

#### H9: The Answer Isn't From Syscall 8
Maybe the WeChall answer comes from a different mechanism entirely:
- A string hidden in the backdoor's output
- A specific transformation of filesystem data
- The bytecode of the solution term itself
- Something derived from the combinators A and B

### LOW Priority

#### H10: Server Version / Behavior Change
The challenge has been updated over the years (echo added in 2018). Maybe:
- Current behavior differs from when it was solved
- The solution path changed with the updates
- There's a version-specific exploit

---

## Strategic Recommendations

### Path 1: Focus on the Right(3) Code Path
Since string arguments make syscall 8 return `Right(3)` "NoSuchFile" instead of `Right(6)` "PermDenied", there's clearly a file-lookup mechanism inside syscall 8. Try:
- Encoding filesystem paths as strings: `/bin/solution`, `/etc/passwd`, etc.
- Trying every known filename
- Constructing directory-qualified paths

### Path 2: Syscall Chaining Within Single Term
Build complex terms that call multiple syscalls in sequence within a single evaluation:
```
backdoor(nil)(λpair.
  echo(int251)(λechoed.
    sys8(???)(QD)))
```
The key is figuring out what `???` should be, using values derived from backdoor and echo.

### Path 3: Enumerate More Interpretations of "3 Leafs"
Systematically generate and test ALL possible terms with exactly 3 Var nodes that involve syscall 8, backdoor, and/or echo references.

### Path 4: Try Program Structures Other Than CPS
Instead of `((sys8 arg) QD)`, try:
- `(sys8 arg)` with no continuation (we know this gives empty output)
- `sys8` alone (just the variable reference)
- Terms where sys8 appears in non-function position
- λ-wrapping sys8 to change its evaluation context

### Path 5: Deep Analysis of Backdoor Combinator Properties
A and B are closely related to omega and application. Their deeper combinatorial properties might reveal the answer:
- Church encoding of specific values using A and B
- Y combinator construction attempts
- Fixed-point combinators from A and B

---

## What A Complete Solution Might Look Like

Based on all hints, the solution likely follows this pattern:

1. **Discover the backdoor** via mail spool → syscall 201 with nil
2. **Use echo** to manufacture a special value (Var(253) or similar)
3. **Construct a minimal term** (3 leaves) that combines the backdoor result and/or echo-manufactured value
4. **This term, when evaluated, makes syscall 8 succeed** — either by:
   - Being the correct argument that bypasses the permission check
   - Creating a term that, through reduction, produces the right input
   - Exploiting a VM/parser quirk related to the special bytes

The answer might be:
- A short string returned by a successful syscall 8 call
- A token/password that must be submitted to WeChall
- Something we can derive purely from the filesystem without making syscall 8 succeed

---

## Repository Structure for Further Research

```
brownos2/
├── solve_brownos.py           # Quick test (calls syscall 0x2A)
├── solve_brownos_answer.py    # Full reference client
├── registry_globals.py        # Global scanner
├── BROWNOS_MASTER.md          # Single source of truth (technical docs)
├── llm_context/               # These 10 context files
├── utils/                     # Decode/analysis tools
├── forums/                    # Raw HTML forum dumps
├── archive/
│   ├── probes_feb2026/        # 130 probe scripts (latest)
│   ├── probes_jan2026/        # 55 probe scripts
│   ├── old_probes/            # 100+ early probes
│   ├── brute_force/           # C/CUDA brute force code
│   ├── logs/                  # Probe output logs
│   ├── data/                  # JSON scan results
│   ├── scripts/               # Decode/analyze utilities
│   └── docs/                  # Previous doc versions
└── challenge.html             # Saved challenge page
```
