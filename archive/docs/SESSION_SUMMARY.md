# BrownOS Challenge - Comprehensive Session Summary

**Last Updated**: January 19, 2026 (Evening Session)  
**Challenge**: WeChall "The BrownOS" (10/10 difficulty, ~4 solvers since 2014)  
**Host**: `82.165.133.222:61221` (TCP, IPv4)

---

## Executive Summary

We have successfully reverse-engineered the BrownOS lambda calculus VM, identified all syscalls, mapped the filesystem, and discovered the "key" mechanism via echo(251). However, **syscall 8 remains locked** with "Permission denied" for all tested inputs. The answer to submit to WeChall is still unknown.

---

## Confirmed Discoveries

### 1. Wire Format (Postfix Lambda Calculus)
| Byte | Meaning |
|------|---------|
| 0x00-0xFC | Var(n) - de Bruijn index |
| 0xFD | App - Application marker |
| 0xFE | Lam - Lambda marker |
| 0xFF | End - End of code |

### 2. Syscall Table
| ID | Name | Behavior |
|----|------|----------|
| 0x01 | error | Returns error string for code |
| 0x02 | write | Writes bytes to socket |
| 0x04 | quote | Serializes term to bytes |
| 0x05 | readdir | Lists directory entries |
| 0x06 | name | Returns name for file/dir ID |
| 0x07 | readfile | Reads file content |
| 0x08 | **LOCKED** | Always returns Right(6) "Permission denied" |
| 0x0E | echo | Returns Left(input+2) - shifts de Bruijn indices |
| 0x2A | towel | Returns "Oh, go choke on a towel!" |
| 0xC9 | backdoor | Returns Left(pair) with combinators A, B |

### 3. The Key Mechanism (CRITICAL)
```
echo(251) → Left(Var(253))
```
- **Var(253) = 0xFD** = App marker in wire format (unserializable!)
- The "key" is a runtime-only value that cannot be directly encoded
- `(key nil)` fires the **LEFT** branch when pattern-matched as Either
- Extracting via `((payload identity) handler)` gives **byte 1**

### 4. Backdoor Combinators
```
backdoor(nil) → Left(pair)
pair = λs. s A B
A = λab.bb  (self-application)
B = λab.ab  (normal application)
```

### 5. Filesystem Structure
```
/ (id 0)
├── bin/           (id 1)
├── etc/           (id 2)
│   └── passwd     (id 11) - contains gizmore:GZKc.2/VQffio (cracked: "ilikephp")
├── home/          (id 22)
│   └── gizmore/   (id 39)
│       └── .history (id 65) - contains "ilikephp"
├── var/           (id 4)
│   └── spool/mail/dloser (id 88) - hints at backdoor syscall 201
└── Hidden: id 256 = "wtf" / "Uhm... yeah... no..."
```

---

## What We've Tried (All Failed for Syscall 8)

### Arguments Tested
- nil, identity, Church numerals 0-255
- Var(251), Var(252), Var(253) (via echo)
- Backdoor pair, A combinator, B combinator
- All combinations of A, B with nil/identity
- File IDs, directory IDs
- Password strings ("ilikephp", "gizmore")
- Echo-shifted terms

### Continuations Tested
- QD (standard debug continuation)
- Identity, nil
- Var(253) as continuation (causes empty response)
- All single-byte continuations 0-252
- Backdoor combinators as continuations

### Patterns Tested
- 3-leaf minimal terms (all combinations)
- Double/triple echo chains
- Syscall chaining (backdoor → echo → syscall8)
- Key applied to syscall8 reference
- Syscall8 from within echo continuation

---

## Key Observations

### Empty Responses (Significant!)
These patterns produce **empty** responses (not "Permission denied"):
- `((syscall8 nil) Var(253))` - key as continuation
- `(key syscall8)` - key applied to syscall8 reference
- `((payload identity) nil)` - double application of extracted payload

### Byte 1 Extraction (Consistent)
- `((payload arg) handler)` always extracts byte 1, regardless of `arg`
- This works for: identity, nil, true, false, Church numerals
- The payload behaves like a function that ignores its argument

### Quote Failures
- `quote(key)` → "Encoding failed!" (contains Var(253) = 0xFD)
- `quote((key nil))` → "Encoding failed!"
- Any term containing Var(253+) cannot be serialized

---

## Author Hints (from forums)

1. **"the mail points to the way"** → backdoor syscall 201 ✓
2. **"My record is 3 leafs IIRC"** → minimal 3-Var solution?
3. **"combining special bytes froze my system"** → FD/FE/FF manipulation?
4. **"why would an OS even need an echo?"** → echo manufactures the key! ✓

---

## Remaining Hypotheses

### HIGH Priority
1. **Wire format injection**: Var(253) IS 0xFD (App marker). Could applying it cause parser confusion?
2. **3-leaf literal interpretation**: Maybe "3 leafs" means something very specific we haven't tried
3. **Empty response = success?**: The empty responses might indicate something worked differently

### MEDIUM Priority
4. **Byte 1 IS the answer**: Maybe the answer is literally "1" in some form we haven't tried
5. **State-based check**: Multiple connections or syscall sequence might matter
6. **Different extraction method**: The nested Either might have more levels

### LOW Priority
7. **Hidden syscalls beyond 252**: Though we scanned, maybe encoding tricks exist
8. **Timing-based**: Side-channel or timing attack

---

## Files Structure

### Essential Files
- `solve_brownos.py` - Basic working client
- `solve_brownos_answer.py` - Reference client with helpers
- `BROWNOS_LEARNINGS.md` - Full technical documentation
- `BROWNOS_LEARNINGS_SELF_CONTAINED.md` - Standalone version for LLMs
- `SESSION_SUMMARY.md` - This file

### Active Probes (36 files)
Recent probe scripts testing various hypotheses. Key ones:
- `probe_direct_extraction.py` - Byte extraction patterns
- `probe_var253_runtime.py` - Runtime Var(253) behavior
- `probe_syscall8_with_key.py` - Key + syscall8 combinations

### Archived
- `archive/old_probes/` - 100 older probe files
- `archive/old_tests/` - Old test files
- `archive/*.json` - Scan results

---

## Answers Already Rejected by WeChall
```
1, \x01, SOH, 0x01, Church1
Var(253), Var(251), 253, 251, 0xFD, 0xFB
ilikephp, gizmore, GZKc.2/VQffio, dloser
201, 0xC9, backdoor
3leafs, 3 leafs, echo
FD, fd, FDFE
echo251, Left(Right(1)), Permission denied, 6
```

## New Answer Candidates to Try (Jan 19 Evening)
Based on today's findings, these are untested candidates:
```
A, B, AB, BA                    # Backdoor combinator names
λab.bb, λab.ab                  # Combinator definitions
00FEFE                          # nil encoding
00FEFEFDFE                      # (nil) with lambda
254, 0xFE, Var254               # From echo(252) finding
255, 0xFF, Var255               # End marker as value
empty, EMPTY                    # Empty response significance
selfapply, self-apply           # A combinator meaning
apply                           # B combinator meaning
omega, Ω                        # Self-application result
wtf                             # Hidden file id 256 name
```

---

## Session Update - January 19, 2026 Evening

### Consultations Completed
- **Oracle**: Suggested "3 leafs" might be the minimal 3-term eliminator `λλλ.(V2 V1 V0)`
- **Metis**: Deep analysis of author hints - suggested trying echo(253) for Var(255)=0xFF

### New Tests Run

| Test | Result | Significance |
|------|--------|--------------|
| `echo(253)` | "Invalid term!" | 253 parsed as wire byte, not arg |
| `echo(252)` | "Encoding failed!" | **Var(254) WAS created** but unserializable |
| `((syscall8 nil) A)` | EMPTY | Different from "Permission denied" |
| `((syscall8 nil) B)` | EMPTY | Different from "Permission denied" |
| Minimal 3-leaf terms | EMPTY | No output for raw minimal terms |
| File scan 0-300 | No new files | All known IDs already documented |
| Using Var(253) as syscall | EMPTY | Any operation involving Var(253) returns empty |

### Critical Finding: Empty vs Permission Denied
- Normal syscall8 with QD: Returns `Right(6)` = "Permission denied"
- Syscall8 with A/B as continuation: Returns **EMPTY** (0 bytes)
- Any operation involving runtime Var(253): Returns **EMPTY**

This suggests:
1. Var(253) operations cause VM to fail silently or infinite loop
2. A/B combinators as continuations trigger unusual behavior
3. The "empty" path might be significant

### Remaining Mysteries
1. Why does echo(252) create Var(254) but echo(253) fails?
2. What exactly happens when we use Var(253) in operations?
3. Is there a way to use the empty-response path productively?
4. What is the literal "3 leafs" solution?

## Next Steps

1. **Try different approaches to the "3 leafs" hint**
2. **Investigate the timing of empty responses** - are they hangs or completions?
3. **Try answer variations on WeChall** based on new findings
4. **Consider if the answer involves the backdoor A/B combinators directly**

---

## Session Update - January 19, 2026 (Continued)

### Additional Tests Run

| Test | Result | Significance |
|------|--------|--------------|
| Syscalls 202-252 | All "does not exist" | No hidden syscalls beyond 201 |
| `((backdoor nil) QD)` | 20 bytes (pair) | QD works, returns pair |
| `((backdoor nil) (λx. ...))` | EMPTY for ALL | Index shifting breaks everything |
| 3-leaf wirings as backdoor cont | All EMPTY | Doesn't unlock anything |
| Backdoor arity probes | All EMPTY | Can't detect multiple args |
| `((syscall8 A) B)` patterns | All Permission denied or EMPTY | No unlock |

### Key Insights from Today

1. **Backdoor context suppresses ALL output** - even `write` doesn't work inside the backdoor continuation. This is fundamental to understanding the challenge.

2. **QD works because of de Bruijn indices** - QD uses V2, V3, V5 which reference syscalls in the global VM context. When you wrap QD in lambdas, these indices shift incorrectly.

3. **EMPTY ≠ crash** - The EMPTY responses complete in ~5.5s (same as normal), indicating the VM completes but produces no output.

4. **Syscall 8 is consistently locked** - All tested arguments return Right(6) = Permission denied (19 bytes).

5. **Echo returns encoded numbers** - `echo(251)` returns `Left(253_as_byte_term)`, NOT a raw `Var(253)`.

### Updated Answer Candidates (NOT YET TESTED on WeChall)

```
# From backdoor structure
pair, λs.sAB, sAB
0000fdfefe, 0100fdfefe          # A and B wire encodings

# Literal "3 leafs" interpretations  
3, three, III
((2 1) 0), (2 (1 0))            # 3-leaf wire patterns
020100fdfd, 020100fdfdfefefe    # Encoded 3-leaf terms

# Context/capability concepts
context, capability, permission
unlock, key, token

# Combinator names
selfapply, self-apply, apply
omega, Ω, diverge

# From echo findings
253, 254, 255
Var253, Var254, Var255
```

### Remaining Hypotheses

1. **The answer might be meta** - something about the challenge structure itself
2. **State-based unlock** - specific sequence of syscalls changes permission  
3. **The answer is visible but unrecognized** - in file contents or error messages
4. **Wire format exploit** - parser confusion with FD/FE/FF still unexplored
