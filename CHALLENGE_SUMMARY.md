# BrownOS Challenge: Comprehensive Summary

## 1. Overview
"The BrownOS" is a high-difficulty (10/10) challenge on WeChall involving a lambda calculus-based virtual machine accessible via TCP at `wc3.wechall.net:61221`. The system is a custom operating system where "programs" are lambda terms sent as postfix bytecode.

## 2. Technical Architecture
### Virtual Machine
- **Bytecode**:
  - `0x00 - 0xFC`: Variable (De Bruijn index)
  - `0xFD`: Application (App)
  - `0xFE`: Lambda (Lam)
  - `0xFF`: End-of-code marker
- **Execution Model**: System calls use Continuation-Passing Style (CPS). The typical calling convention is `((syscall argument) continuation)`.

### Key System Calls
| ID | Hex | Name | Functionality |
|----|-----|------|---------------|
| 0 | 0x00 | write | Basic output. |
| 2 | 0x02 | debug | Enhanced output (often used with syscall 4). |
| 4 | 0x04 | quote | Returns the bytecode of a given term. |
| 7 | 0x07 | readfile | Accesses the virtual filesystem by file ID. |
| 8 | 0x08 | solution | The primary goal (currently returns Permission Denied). |
| 14 | 0x0E | echo | Shifts variable indices in a term by 2. |
| 42 | 0x2A | towel | Returns "Oh, go choke on a towel!". |
| 201| 0xC9 | backdoor| Returns combinators A and B (pair). |

## 3. Major Findings
### Filesystem Exploration
Using syscall 0x07, the following critical files were identified:
- **File 11 (/etc/passwd)**: Contained the user `gizmore` and a crypt hash.
- **File 65 (.history)**: Leaked command history containing a plaintext password.
- **Credential**: The password for `gizmore` is `ilikephp`.

### The Backdoor and Omega
Syscall 201 returns a Scott-encoded pair of combinators:
- **A**: `λa.λb. b b` (Self-application of the second argument)
- **B**: `λa.λb. a b` (Application)
- **Significance**: Applying A to B (`A B`) results in the **Omega combinator** (`ω = λx.x x`), which causes infinite recursion/loops.

### The Hitchhiker Hint
Syscall 42 returns a reference to *The Hitchhiker's Guide to the Galaxy*, strongly suggesting that the number `42` is a significant thematic answer.

## 4. Attempts to Solve Syscall 8
Syscall 0x08 consistently returns `Right(6)` (Permission Denied). Extensive attempts to bypass this include:
- **Provenance Manipulation**: Using `echo` (14) to wrap arguments or `quote` (4) to pass raw terms.
- **Combinator Attacks**: Passing `A`, `B`, `ω`, or the backdoor pair directly to syscall 8.
- **Credential Injection**: Sending `ilikephp` or "gizmore" in various encodings.
- **Brute Force**: Testing all 1-3 byte sequences and common ASCII strings against the syscall.
- **Protocol Fuzzing**: Testing multi-term payloads and malformed bytecode.
**Status**: All technical attempts to "unlock" syscall 8 have failed.

## 5. Potential Answer Candidates
Based on the "discovery" nature of the challenge, the following are the top candidates for the WeChall submission:
1. `ilikephp` (Recovered user password)
2. `omega` (Thematic result of the backdoor)
3. `42` (Thematic answer from the towel hint)
4. `wtf` (Name of hidden file 256)

## 6. Resources
- `BROWNOS_MASTER.md`: Complete technical documentation.
- `solve_brownos_answer.py`: Reference script for filesystem and password recovery.
- `archive/`: Historical logs and probe scripts.
