# BrownOS Syscall 8 - ULTRAWORK Deep Analysis Summary

**Date**: January 2026  
**Challenge**: WeChall BrownOS (10/10 difficulty, ~4 solvers since 2014)

---

## Executive Summary

We deployed 15+ parallel agents (Metis, Momus, Oracle, Librarian, Explore) and conducted extensive testing to understand syscall 8. Despite exhaustive analysis, syscall 8 consistently returns `Right(6)` ("Permission denied") for all tested inputs.

---

## Confirmed Facts

### Echo Behavior
| Input | Output | Significance |
|-------|--------|--------------|
| `echo(Var(n))` | `Left(Var(n+2))` | Confirmed +2 index shift |
| `echo(Var(251))` | `Left(Var(253))` | Manufactures FD-byte index |
| `echo(Var(252))` | `Left(Var(254))` | Manufactures FE-byte index |
| Quoting Var(253+) | "Encoding failed!" | Cannot serialize special indices |

### Syscall Response Codes
| Code | Meaning | When Observed |
|------|---------|---------------|
| `Right(1)` | Syscall does not exist | Var(252-254) called as syscalls |
| `Right(2)` | Invalid argument | Wrong argument type |
| `Right(6)` | Permission denied | Syscall 8 with ALL inputs |

### Backdoor (Syscall 201)
- Input: Must be nil (`λλ.0` = `00 FE FE`)
- Output: `Left(pair)` where pair = `λs. s A B`
- A = `λab.bb` (self-apply second argument)
- B = `λab.ab` (apply first to second, ≈ identity)
- These combinators can produce ω but NOT Y combinator

---

## Disproven Hypotheses

### 1. Callback Hypothesis ❌
**Theory**: Syscall 8 applies its argument as a callback to hidden capabilities.  
**Test**: Passed identity, projections, K-combinators.  
**Result**: All return identical `Right(6)`. Syscall 8 is NOT callback-based.

### 2. Echo-Manufactured Token ❌
**Theory**: Var(253/254/255) are the "key" to syscall 8.  
**Test**: `syscall8(Var(253))`, `syscall8(Var(254))`, combinations with A/B.  
**Result**: All return `Right(6)`.

### 3. Three-Leaf Minimal Terms ❌
**Theory**: "3 leafs" means a 3-Var term is the key.  
**Test**: All patterns: `λ.(0 (0 0))`, `λλ.(1 (0 0))`, etc.  
**Result**: All return `Right(6)`.

### 4. Backdoor Pair as Token ❌
**Theory**: A, B, or the pair itself unlocks syscall 8.  
**Test**: `syscall8(A)`, `syscall8(B)`, `syscall8(pair)`, `(pair syscall8)`.  
**Result**: All return `Right(6)`.

### 5. Divergent Terms / Timing Attack ❌
**Theory**: "Froze system" means divergent terms bypass checks.  
**Test**: `syscall8(Ω)`, timing comparisons.  
**Result**: No timing difference, still `Right(6)`.

### 6. Echo Transforming Syscall Reference ❌
**Theory**: Echo the syscall 8 reference itself.  
**Test**: `echo(Var(8))` → extract → call.  
**Result**: Still `Right(6)`.

---

## Remaining Unexplored Leads

### High Priority

1. **Syscall sequence/state change**
   - What if calling specific syscalls in order changes internal state?
   - Untested: `backdoor` → `echo` → specific pattern → `syscall8`

2. **Hidden syscalls 202-252**
   - We confirmed 252-254 return "does not exist"
   - Range 202-252 might have hidden functionality

3. **Evaluation context**
   - Syscall 8 might check WHERE/HOW it's called
   - Maybe must be called from within another syscall's continuation

4. **Raw byte manipulation**
   - "Combining special bytes" might mean raw byte injection
   - Parser quirks with FD/FE/FF sequences

### Medium Priority

5. **ID 256 discrepancy**
   - Learnings say `name(256)` = "wtf"
   - Our test shows `name(256)` = "/" (root)
   - Need to verify with exact encoding

6. **Password "ilikephp"**
   - Cracked from history, but no login possible
   - Might enable something else

7. **IDs beyond 1024**
   - Only scanned to 1024
   - Additive encoding supports arbitrary large numbers

---

## Technical Artifacts

### Key Probe Scripts Created
- `probe_callback_hypothesis.py` - Tests callback semantics
- `probe_metis_insights.py` - Tests Metis recommendations
- `probe_var254_investigation.py` - Investigates special indices
- `probe_divergent_terms.py` - Tests infinite loops

### Encoding Reference
```
Wire format (postfix):
- Var(n) = byte n (0x00-0xFC)
- Lambda = 0xFE
- Application = 0xFD
- End = 0xFF

nil = λλ.0 = 00 FE FE
I = λ.0 = 00 FE
ω = λ.(0 0) = 00 00 FD FE
Ω = (ω ω) = 00 00 FD FE 00 00 FD FE FD
```

---

## Agent Insights Worth Revisiting

### From Metis
> "Echo might create ALIASING - the same term exists in two permission contexts"

> "'00 FE FE' might refer to a SEQUENCE of operations, not just nil encoding"

### From Oracle
> "Echo's +2 lift is useful when code runs under EXTRA BINDERS (hidden capabilities)"

> "Permission might depend on WHERE the call comes from, not WHAT is passed"

### From Explore (Learnings)
> "We couldn't use the mail/backdoor hint to make syscall 0x08 succeed"

> "Syscall 0x0E combining special bytes froze the system - not fully explored"

---

## Conclusion

Syscall 8 remains locked. The solution likely involves:
1. A specific COMBINATION we haven't tried
2. An ORDERING of operations that sets up state
3. A CONTEXT from which syscall 8 must be called
4. Something about the WIRE FORMAT we don't understand

The "3 leafs" hint suggests the solution is MINIMAL. We may be overcomplicating it.

---

## Next Steps

1. Scan syscalls 202-252 for hidden functionality
2. Test calling syscall 8 from INSIDE other syscall continuations
3. Try raw byte sequences that aren't valid lambda terms
4. Investigate the exact encoding of "3 leafs" more literally
