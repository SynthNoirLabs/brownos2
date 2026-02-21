# BrownOS — Complete Research Log & Probe Results

## Research Timeline

### Phase 1: Initial Reverse Engineering (Jan 2026)
- Established TCP connection and binary protocol
- Decoded the cheat sheet and QD continuation
- Discovered postfix lambda calculus bytecode format
- Mapped all data encodings (Either, integers, strings, directories)

### Phase 2: Syscall Discovery (Jan 2026)
- Exhaustive sweep of globals 0–252 with args {nil, int0, int1}
- Identified all 11 active syscalls (0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0E, 0x2A, 0xC9)
- Confirmed 242 globals return "Not implemented"

### Phase 3: Filesystem Exploration (Jan 2026)
- Recursive directory traversal using readdir/name/readfile
- Extracted all file contents (passwd, .history, mail, access.log)
- Cracked gizmore's password (`ilikephp`) from hash + history file
- Discovered hidden file id 256 ("wtf")

### Phase 4: Backdoor Investigation (Jan 2026)
- Found mail hint pointing to syscall 201
- Called backdoor with nil, obtained pair (A, B)
- Analyzed A and B as omega-related combinators
- Tested A, B, pair, omega as arguments to syscall 8 — all failed

### Phase 5: Echo Deep Dive (Jan 2026)
- Confirmed echo +2 index shift behavior
- Discovered echo(251) → Var(253) manufacturing
- Tested Var(253) and Var(254) as syscall 8 arguments — failed
- Investigated "Encoding failed!" behavior with special indices

### Phase 6: Exhaustive Syscall 8 Testing (Jan–Feb 2026)
- 500+ unique test cases for syscall 8
- All 1-byte, 2-byte, 3-byte argument patterns
- Combinatorial testing with special values
- Timing analysis, parallel connection tests
- All continuation variations
- All return Right(6) or empty response

### Phase 7: Advanced Strategies (Feb 2026)
- Echo-mediated argument construction
- Combinator algebra (A/B combinations)
- Credential strings as arguments
- Quote-mediated bytecode injection
- Protocol-level tricks (post-FF bytes, multi-term, non-singleton stacks)
- Continuation-shape variations
- CBN-thunk arguments
- Runtime-computed argument chains
- Stateful in-process syscall chaining
- Wide-integer credential pairs

---

## Exhaustive Syscall 8 Test Matrix

### Category 1: Simple Arguments

| Argument | Result |
|---|---|
| nil (λλ.V0) | Right(6) |
| true/K (λλ.V1) | Right(6) |
| identity (λ.V0) | Right(6) |
| Church numerals 0–255 | Right(6) |
| All Var(0)–Var(252) at top level | Right(6) or silent |
| All λ.Var(0)–λ.Var(252) | Right(6) |
| All λλ.Var(0)–λλ.Var(252) | Right(6) |

### Category 2: Filesystem/Credential Arguments

| Argument | Result |
|---|---|
| String "ilikephp" | Right(3) NoSuchFile |
| String "gizmore" | Right(3) NoSuchFile |
| String "gizmore:ilikephp" | Right(3) NoSuchFile |
| String "GZKc.2/VQffio" (hash) | Right(3) NoSuchFile |
| String "root", "sudo", "dloser" | Right(3) NoSuchFile |
| Full passwd line for gizmore | Right(3) NoSuchFile |
| File IDs as integers | Right(6) |
| UID 1000, 1002 | Right(6) |
| pair(uid=1000, "ilikephp") | Right(6) |
| pair(uid=1002, "ilikephp") | Right(6) |

**Notable**: String arguments produce Right(3) "NoSuchFile" instead of Right(6), indicating a different code path.

### Category 3: Backdoor-Derived Arguments

| Argument | Result |
|---|---|
| A = λλ.(V0 V0) | Right(6) |
| B = λλ.(V1 V0) | Right(6) |
| pair(A, B) = λs.(s A B) | Right(3) NoSuchFile |
| ω = λ.(V0 V0) | Right(6) |
| Ω = (ω ω) | Right(6) or timeout |
| A(A), A(B), B(A), B(B) | Diverge or Right(6) |
| B(A(B)) | Diverge or timeout |
| pair applied to true/false | Right(6) |

### Category 4: Echo-Manufactured Arguments

| Argument | Result |
|---|---|
| Var(253) (via echo(251)) | Right(6) |
| Var(254) (via echo(252)) | Right(6) |
| echo(X) → Left(echoed) → sys8(echoed) | Right(6) |
| echo(nil), echo(int8), echo(g8), echo(str) | Right(6) |

### Category 5: Combinatorial / Brute Force

| Pattern | Count Tested | Result |
|---|:---:|---|
| All {0,1,2,8,201,FD,FE}³ combinations | 343 | All Right(6) |
| 3-leaf terms: ((Va Vb) Vc) with various indices | ~1000+ | All Right(6) |
| 3-leaf terms: (Va (Vb Vc)) with various indices | ~1000+ | All Right(6) |
| λλλ.(V2 V1 V0) style eliminators | Dozens | All Right(6) |

### Category 6: Continuation Variations

| Continuation | Result |
|---|---|
| QD (standard) | Right(6) visible |
| Identity (λ.V0) | Empty |
| nil (λλ.V0) | Empty |
| Var(253) | Empty |
| A combinator | Empty |
| B combinator | Empty |
| All Var(0)–Var(252) | Right(6) or empty |
| write-based K observer | Right(6) visible as K |
| pair(A,B) | Empty |

### Category 7: Multi-Step / Stateful

| Pattern | Result |
|---|---|
| sys8(nil) → sys8(result) | Right(6) |
| sys8(nil) → backdoor(nil) → sys8(pair) | Right(6) |
| backdoor(nil) → sys8(pair_component) | Right(6) |
| echo(X) → sys8(echoed) | Right(6) |
| quote(g8) → sys8(quoted_bytes) | Right(6) |
| sys8(g201(nil)) | Right(6) |
| g7(int(11)) → sys8(result) | Right(6) |

### Category 8: Protocol Tricks

| Trick | Result |
|---|---|
| Post-0xFF bytes (password/nil/quoted-g8) | Ignored, still Right(6) |
| Multiple terms per connection | Server processes only first |
| Non-singleton parse stack | "Invalid term!" |
| sys8 without continuation (1-arg only) | Empty (strict CPS) |
| g(0) exception wrapping: g(0)(sys8(nil)(OBS)) | Empty |

### Category 9: Timing / Side-Channel

| Test | Result |
|---|---|
| Response time comparison across args | All ~0.5–0.8s (network latency only) |
| Omega as argument (divergence test) | Returns immediately (no evaluation) |
| Deep nesting (50 lambdas) | Same timing as nil |
| Parallel connections (backdoor + sys8) | No cross-connection effect |
| Timing offsets (0.1–1.0s) | No effect |

---

## Brute Force Attempts

### WeChall Answer Hash Cracking

Target hash: `sha1^56154(answer) == "9252ed65ffac2aa763adb21ef72c0178f1d83286"`

| Search Space | Tool | Result |
|---|---|---|
| Printable ASCII 1–3 chars | Python | No match |
| Printable ASCII 4 chars | C (GPU) | No match |
| Printable ASCII 5 chars | CUDA GPU | No match |
| All 2-byte sequences (65,536) | C multithreaded | Did not complete (~40hr est.) |

Each candidate requires 56,154 SHA1 iterations, making brute force extremely expensive.

---

## Probe Script Inventory

### archive/old_probes/ (~100 files)
Early exploration scripts testing various hypotheses.

### archive/probes_jan2026/ (~55 files)
January 2026 probes including:
- Basic verification, syscall scanning
- Key/backdoor combination tests
- Wire format injection attempts
- Dark magic / radical approaches
- Payload structure investigation

### archive/probes_feb2026/ (~130 files)
February 2026 probes including:
- Oracle-guided hypothesis testing (22+ oracle probes)
- Echo chain variants (v1–v6)
- Backdoor authentication probes
- Hash cracking attempts
- Full 253×253 sweep
- Phase 2 systematic testing (fuzzer, forum mining, echo special)
- Mail/3-leaf template testing
- Final sweep and validation

### archive/old_tests/ (~10 files)
Historical test scripts for specific patterns.

### archive/scripts/ (~10 files)
Analysis and decode utilities for processing probe output.

### archive/brute_force/ (~10 files)
C and CUDA brute force code for hash cracking.

---

## Key Data Files

| File | Contents |
|---|---|
| `archive/data/env_map_0_252.json` | Environment map of all globals 0–252 |
| `archive/globals_registry_*.json` | Systematic global probing results |
| `archive/scan_name_0_255.json` | Filesystem name scan results |
| `archive/scan_name_1025_5000.json` | Extended ID scan results |
| `archive/syscall8_*.json` | Syscall 8 specific test results |
| `archive/sweep_syscalls_nil_fast.json` | Fast syscall sweep results |

---

## Definitive Conclusions from Research

1. **Syscall 8 is not disabled** — it calls its continuation with Right(6) in normal CPS style
2. **No hidden syscalls exist** in the 0–252 range
3. **No cross-connection state** — each connection is independent
4. **No timing-based checks** — all responses have uniform latency
5. **String arguments enter a different code path** (Right(3) vs Right(6))
6. **Empty responses are distinct from errors** — they indicate the continuation ran but produced no output
7. **The solution involves something we haven't discovered yet**
