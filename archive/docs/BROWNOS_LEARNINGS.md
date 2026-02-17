# BrownOS — Reverse-Engineering Notes (Work-in-Progress)

These notes capture everything discovered while reversing the WeChall "The BrownOS" service (`wc3.wechall.net:61221`), **without using third-party writeups**.

They are **not** the final challenge solution (the WeChall "Answer" is still unknown), but they document the protocol, data encodings, syscalls, filesystem layout, and all major gotchas encountered.

---

## 0) Challenge Cheat Sheet

From `challenge.html`:

```text
FF: End Of Code marker

BrownOS[<syscall> <argument> FD <rest> FD] -> BrownOS[<rest> <result> FD]

Quick debug: 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
For example: QD ?? FD  or  ?? ?? FD QD FD
```

Host/port: `wc3.wechall.net:61221` (TCP)

---

## 1) Author Hints (Collected)

The challenge author allegedly shared this note:

> "A lot of you are focusing on 8 directly, but … the mail points to the way to get access there. My record is 3 leafs IIRC…  
> …did anyone play a bit with that new syscall? … I'm getting some interesting results when combining the special bytes…  
> …once it froze my whole system! … Besides, why would an OS even need an echo? I can easily write that myself…"

**Interpretation:**
- "mail points to the way" → Backdoor syscall 201, triggered by `/var/spool/mail/dloser`
- "3 leafs" → Minimal solution has 3 variable nodes (or 3 bytes?)
- "combining special bytes" → FD/FE/FF manipulation
- "froze my system" → Some input causes unusual behavior (not found)
- "why need echo?" → Echo syscall (0x0E) has special purpose beyond I/O

---

## 2) Wire Format / Bytecode

The byte stream (terminated by `0xFF`) encodes a term in **postfix** lambda calculus using **De Bruijn indices**:

| Byte Range | Meaning |
|------------|---------|
| `0x00-0xFC` | `Var(i)` - variable with De Bruijn index i |
| `0xFD` | Application: pop x, pop f, push App(f, x) |
| `0xFE` | Lambda: pop body, push Lam(body) |
| `0xFF` | End-of-code marker |

**Important:** De Bruijn indices shift under lambdas. A byte value inside a closure has different meaning than at top-level.

---

## 3) Syscall Convention (CPS)

Syscalls use **continuation-passing style**:

```text
((syscall arg) continuation) FF
```

The VM reduces: `(<syscall> <argument> <rest>) ==> (<rest> <result>)`

### Quick Debug (QD)

Standard continuation that prints results to socket:

```text
QD = 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
```

---

## 4) Data Encodings

### Either (Scott encoding)
- `Left x  = λl.λr. l x` (success)
- `Right y = λl.λr. r y` (error)

### Integer/Byte (9-lambda additive)
9 leading lambdas, body adds weights:
- V0=0, V1=1, V2=2, V3=4, V4=8, V5=16, V6=32, V7=64, V8=128

### Common Terms
- `nil = 00 FE FE` = λλV0 (also = false, Church 0)
- `K = 01 FE FE` = λλV1 (also = true)
- `I = 00 FE` = λV0 (identity)

---

## 5) Complete Syscall Table

| Syscall | Name | Input | Output |
|---------|------|-------|--------|
| 0x01 | error_string | error code | Left(string) |
| 0x02 | write | bytes list | Left(K), writes to socket |
| 0x03 | (not implemented) | any | Right(1) |
| 0x04 | quote | term | Left(serialized bytes) |
| 0x05 | readdir | dir ID | Left(3-way list) |
| 0x06 | name | file/dir ID | Left(name bytes) |
| 0x07 | readfile | file ID | Left(content bytes) |
| **0x08** | **???** | **any** | **Right(3) = Permission denied** |
| 0x0E | echo | term | Left(term with +2 index shift) |
| 0x2A (42) | filesystem? | any | Left(545 bytes - full tree?) |
| 0xC9 (201) | backdoor | nil only | Left(pair: λλ((V1 A) B)) |

### Error Codes
| Code | Meaning |
|------|---------|
| 0 | Unexpected exception |
| 1 | Not implemented |
| 2 | Invalid argument |
| 3 | Permission denied |
| 4 | Not a directory |
| 5 | Not a file |
| 6 | (legacy, possibly permission) |
| 7 | Not so fast! |
| 110 | Invalid term (253, 254, 255) |

---

## 6) Filesystem

```text
/ (id 0)
├── bin (id 1)
│   ├── false (id 16) [0 bytes]
│   ├── sh (id 14) [0 bytes]
│   └── sudo (id 15) [0 bytes]
├── etc (id 2)
│   ├── brownos (id 3) [empty dir]
│   └── passwd (id 11) [181 bytes]
├── home (id 22)
│   ├── dloser (id 50) [empty dir]
│   └── gizmore (id 39)
│       └── .history (id 65) [49 bytes]
├── sbin (id 9) [empty dir]
└── var (id 4)
    ├── log (id 5)
    │   └── brownos (id 6)
    │       └── access.log (id 46) [dynamic]
    └── spool (id 25)
        └── mail (id 43)
            └── dloser (id 88) [177 bytes - backdoor hint]
```

**Hidden entry**: ID 256 = "wtf" file with "Uhm... yeah... no..."

### Key Files
- `/etc/passwd`: Contains `gizmore:GZKc.2/VQffio` (crypt hash)
- `/home/gizmore/.history`: Contains `ilikephp` (cracks the hash)
- `/var/spool/mail/dloser`: Hints at backdoor syscall 201

---

## 7) Backdoor Details (Syscall 201)

**Input**: Must be exactly `nil` (00 FE FE), else Right(2)

**Output**: `Left(pair)` where:
- `pair = λλ((V1 A) B)`
- `A = λλ(V0 V0)` = little omega
- `B = λλ(V1 V0)` = K applied style

---

## 8) Echo Syscall Details (0x0E)

Echo shifts De Bruijn indices by +2 (due to Either wrapper):
- `echo(V0)` → `Left(V2)`
- `echo(V251)` → `Left(V253)`

**Critical**: V253 = 0xFD cannot be serialized → "Encoding failed!"

---

## 9) Syscall 8 Investigation

### Status
After 500+ test cases, **always returns Right(3) "Permission denied"**

### Tested Patterns (All Failed)
- All 1-byte arguments (0-252)
- All 2-byte λVn patterns (0-252)
- All 3-byte λλVn patterns (0-252)
- 343 combinations of special bytes {0,1,2,8,201,FD,FE}³
- Church numerals 0-8
- Backdoor pair structure and components A, B
- Applying backdoor pair to true/false
- Nested syscall combinations
- Echo-derived values (V250-V252)
- Omega (infinite loop) as argument
- QD as argument
- V5, V8, V201 patterns
- Malformed/boundary programs
- Programs with multiple FF markers

### Timing Analysis
- All calls return in ~0.5-0.8s (network latency only)
- Omega as argument: no delay (syscall doesn't evaluate deeply)
- Complex nested lambdas: no delay

### Parallel Connection Tests
- Each TCP connection is completely independent
- No shared state between connections
- Backdoor on one connection doesn't affect syscall 8 on another
- Timing offsets have no effect

### Continuation Variations
- Only QD (or similar V5-based structure) produces visible output
- Lambda continuations return EMPTY
- Different continuations don't change Right(3) for syscall 8

---

## 10) Rejected WeChall Answers

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

## 11) Major Gotchas

1. **Send bytes, not ASCII** - Use proper socket client
2. **Always terminate with 0xFF** - Otherwise "Invalid term!" or no response
3. **No output is normal** - Success can produce no output
4. **Use QD for visibility** - Most syscalls return terms, not raw output
5. **De Bruijn shifting** - Same byte means different things under lambdas
6. **IDs can exceed 255** - Additive encoding allows ID 256+
7. **Input size limit** - "Term too big!" at ~2KB
8. **V253-V255 break quote** - "Encoding failed!" with no FF terminator

---

## 12) Remaining Hypotheses

1. **Wire format exploit**: Specific byte sequence exploits parser
2. **Multi-step unlock**: Specific syscall sequence before calling 8
3. **External factor**: Time-based, session-based, or auth required
4. **Different interpretation**: "3 leafs" means something unexpected
5. **Program structure**: Maybe not standard `syscall arg FD cont FD FF`

---

## 13) Files in Repository

- `solve_brownos_answer.py` - Extracts "ilikephp" from filesystem (not the challenge answer)
- `forums/` - HTML dumps of forum discussions with hints

---

*Last updated: January 2026*
*Challenge stats: ~4 solvers in 12 years, difficulty 10/10*
