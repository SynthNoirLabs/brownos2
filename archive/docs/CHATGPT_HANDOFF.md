# BrownOS Challenge - Complete Reverse Engineering Handoff

**Purpose**: This document contains everything discovered about the WeChall "The BrownOS" challenge for consultation with advanced AI models.

**Challenge**: WeChall "The BrownOS"  
**Difficulty**: 10/10 (hardest tier)  
**Solvers**: ~4 people since 2014 (12+ years)  
**Server**: `wc3.wechall.net:61221` (TCP)  
**Goal**: Make syscall 8 return success (currently returns "Permission denied")

---

## 1. CHALLENGE OVERVIEW

BrownOS is a lambda calculus-based virtual machine accessible over TCP. You send bytecode, it evaluates and optionally returns output. The challenge is to find what input makes syscall 8 (`/bin/solution`) succeed.

The service provides a "cheat sheet":
```
FF: End Of Code marker

BrownOS[<syscall> <argument> FD <rest> FD] -> BrownOS[<rest> <result> FD]

Quick debug: 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
For example: QD ?? FD  or  ?? ?? FD QD FD
```

---

## 2. AUTHOR HINTS (CRITICAL)

The challenge author (dloser) provided these hints:

### Hint 1: "3 Leafs"
> "A lot of you are focusing on 8 directly, but … the mail points to the way to get access there. **My record is 3 leafs IIRC**…"

**Interpretation**: The minimal solution uses only 3 variable references (leaf nodes in the AST).

### Hint 2: "New Syscall / Echo"
> "…did anyone play a bit with that new syscall? … I'm getting some interesting results when **combining the special bytes**… …once it **froze my whole system**!"

**Interpretation**: Syscall 0x0E (echo) combined with special bytes FD/FE/FF produces unusual behavior.

### Hint 3: "Why Echo?"
> "Besides, **why would an OS even need an echo**? I can easily write that myself…"

**Interpretation**: Echo isn't for convenience—it serves a specific purpose (manufacturing special values).

### Hint 4: From Mail Spool
File `/var/spool/mail/dloser` (id 88) contains:
```
From: mailer@brownos
To: dloser@brownos
Subject: Delivery failure

Failed to deliver following message to boss@evil.com:

Backdoor is ready at syscall 201; start with 00 FE FE.
```

**Interpretation**: Syscall 201 (0xC9) is the backdoor, input must be `nil` (`00 FE FE`).

---

## 3. WIRE PROTOCOL / VM MODEL

### Bytecode Format (Postfix Lambda Calculus with De Bruijn Indices)

| Byte | Meaning |
|------|---------|
| `0x00-0xFC` | `Var(n)` - Variable with de Bruijn index n |
| `0xFD` | Application marker - pop x, pop f, push App(f,x) |
| `0xFE` | Lambda marker - pop body, push Lam(body) |
| `0xFF` | End of code (REQUIRED) |

**Parsing** is a postfix stack machine:
- Bytes 0x00-0xFC: push `Var(n)`
- `0xFD`: pop x, pop f, push `App(f, x)`
- `0xFE`: pop body, push `Lam(body)`
- `0xFF`: stop parsing

**Example**: `00 FE FE` = `λλ.Var(0)` = Church-encoded `nil`

### Syscall Convention (Continuation-Passing Style)

```
((syscall argument) continuation) + 0xFF
```

The VM reduces this and applies the continuation to the result.

### QD (Quick Debug) Continuation

```
QD = 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
```

QD is a lambda term that serializes its argument (via `quote`) and writes it to the socket. It's essential for seeing syscall results.

**CRITICAL**: De Bruijn indices shift under lambdas. QD references `Var(2)`, `Var(3)`, `Var(5)` which point to syscalls in the global context. Wrapping QD in additional lambdas breaks these references.

---

## 4. DATA ENCODINGS

### Either (Scott Encoding)
```
Left x  = λl.λr. (l x)   -- success, body is App(Var(1), x)
Right y = λl.λr. (r y)   -- error, body is App(Var(0), y)
```

### Integer / Byte Term (9-Lambda Additive Bitset)
Numbers are encoded with 9 leading lambdas, body is additive application chain:

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

**Example**: 3 = `λ^9.(V2 @ (V1 @ V0))` = 2+1+0 = 3

**IDs can exceed 255**: Because encoding is additive, `256 = V8 @ (V8 @ V0)`.

### Strings/Bytes
Scott list of byte-terms:
```
nil = λc.λn. n
cons h t = λc.λn. (c h t)
```

### Directory Listing (3-Way Scott List)
```
nil  = λd.λf.λn. n           -- end
dir  = λd.λf.λn. (d id rest) -- directory entry
file = λd.λf.λn. (f id rest) -- file entry
```

---

## 5. SYSCALLS DISCOVERED

| ID | Name | Input | Output | Notes |
|----|------|-------|--------|-------|
| `0x01` | error | error code | `Left(string)` | Returns error message |
| `0x02` | write | bytes list | writes to socket | Returns `True` |
| `0x03` | ??? | ??? | `Right(1)` | Not implemented |
| `0x04` | quote | any term | `Left(bytes)` | Serializes term to bytecode |
| `0x05` | readdir | dir id | `Left(dirlist)` | Lists directory |
| `0x06` | name | id | `Left(string)` | Returns entry name |
| `0x07` | readfile | file id | `Left(bytes)` | Reads file content |
| `0x08` | **TARGET** | ??? | `Right(6)` ALWAYS | Permission denied |
| `0x0E` | echo | any term | `Left(term)` | Returns input with +2 index shift |
| `0x2A` | towel | any | `Left("Oh, go choke...")` | Decoy/troll |
| `0xC9` | backdoor | nil only | `Left(pair)` | Returns combinator pair |

### Error Codes
| Code | Message |
|------|---------|
| 0 | Unexpected exception |
| 1 | Not implemented |
| 2 | Invalid argument |
| 3 | No such directory or file |
| 4 | Not a directory |
| 5 | Not a file |
| 6 | **Permission denied** |
| 7 | Not so fast! (rate limit) |

---

## 6. ECHO SYSCALL (0x0E) - KEY MECHANISM

Echo returns its input wrapped in `Left`, but with **all de Bruijn indices shifted by +2**.

| Input | Output | Significance |
|-------|--------|--------------|
| `echo(Var(0))` | `Left(Var(2))` | +2 shift |
| `echo(Var(251))` | `Left(Var(253))` | **Manufactures 0xFD index!** |
| `echo(Var(252))` | `Left(Var(254))` | Manufactures 0xFE index |
| `echo(Var(253))` | `Invalid term!` | 253 parsed as wire byte |

**Why this matters**: `Var(253)` = `0xFD` in bytecode = Application marker. You CANNOT write this directly in code. Echo is the ONLY way to create it at runtime.

**Gotcha**: `quote(Var(253+))` returns "Encoding failed!" because the serializer can't output bytes that are reserved markers.

---

## 7. BACKDOOR SYSCALL (0xC9 / 201)

**Input**: Must be exactly `nil` (`00 FE FE`), otherwise returns `Right(2)` (Invalid argument).

**Output**: `Left(pair)` where:
```
pair = λs. s A B

A = λa.λb. (b b)   -- self-application of second arg
B = λa.λb. (a b)   -- normal application (almost identity)
```

These are related to the ω combinator:
- `ω = λx.(x x)`
- `Ω = ω ω` (diverges)
- `(A anything)` = self-application
- `(B f x)` = `(f x)`

---

## 8. FILESYSTEM STRUCTURE

```
/ (id 0)
├── bin (id 1)
│   ├── false (id 16)         [0 bytes]
│   ├── sh (id 14)            [0 bytes]
│   └── sudo (id 15)          [0 bytes]
├── etc (id 2)
│   ├── brownos (id 3)        [empty dir]
│   └── passwd (id 11)        [181 bytes]
├── home (id 22)
│   ├── dloser (id 50)        [empty dir]
│   └── gizmore (id 39)
│       └── .history (id 65)  [49 bytes]
├── sbin (id 9)               [empty dir]
└── var (id 4)
    ├── log (id 5)
    │   └── brownos (id 6)
    │       └── access.log (id 46)     [dynamic]
    └── spool (id 25)
        └── mail (id 43)
            └── dloser (id 88)         [177 bytes - backdoor hint]
```

### Key File Contents

**`/etc/passwd` (id 11)**:
```
root:x:0:0:root:/:/bin/false
mailer:x:100:100:mailer:/var:/bin/false
gizmore:GZKc.2/VQffio:1000:1000:Gizmore:/home/gizmore:/bin/sh
dloser:x:1002:1002:dloser:/home/dloser:/bin/false
```

**`.history` (id 65)**:
```
sodu deluser dloser
ilikephp
sudo deluser dloser
```
- `ilikephp` = gizmore's password (crypt hash matches)

**Hidden entry**: `name(256)` = "wtf", `readfile(256)` = "Uhm... yeah... no..."

---

## 9. EVERYTHING WE TRIED (ALL FAILED)

### Arguments to Syscall 8
- `nil`, identity (`λ.0`), all Church numerals 0-255
- All file/directory IDs
- `Var(251)`, `Var(252)`, `Var(253)` (manufactured via echo)
- Backdoor pair, A combinator, B combinator
- All combinations of A, B with nil/identity
- Password strings ("ilikephp", "gizmore")
- Echo-shifted terms
- All 3-leaf term patterns we could enumerate

### Continuations for Syscall 8
- QD (standard debug)
- Identity, nil
- `Var(253)` as continuation → produces **empty response** (not Right(6))
- All single-byte continuations 0-252
- Backdoor combinators A, B

### Patterns Tested
- All 3-leaf minimal terms (`App(App(V2,V1),V0)`, `App(V2,App(V1,V0))`, etc.)
- Double/triple echo chains
- Syscall chaining: `backdoor → echo → syscall8`
- Key applied to syscall8 reference
- Syscall8 from within other syscall continuations
- ω (divergent) as argument
- Timing attacks (no difference detected)

### Significant Observation: Empty Responses
These produce **0 bytes** output (not "Permission denied"):
- `((syscall8 nil) Var(253))` - echo-manufactured key as continuation
- `(Var(253) syscall8)` - key applied to syscall8
- `((syscall8 nil) A)` or `B` - backdoor combinators as continuation

This is different from the normal 19-byte `Right(6)` response.

---

## 10. DISPROVEN HYPOTHESES

### ❌ Callback Hypothesis
**Theory**: Syscall 8 applies its argument as callback to hidden capabilities.  
**Result**: All projections, K-combinators return identical `Right(6)`.

### ❌ Echo-Manufactured Token
**Theory**: `Var(253/254/255)` are the "key".  
**Result**: All return `Right(6)`.

### ❌ Three-Leaf Minimal Terms
**Theory**: "3 leafs" means a specific 3-variable term.  
**Result**: All enumerated patterns return `Right(6)`.

### ❌ Backdoor Pair as Token
**Theory**: A, B, or pair unlocks syscall 8.  
**Result**: All return `Right(6)`.

### ❌ Divergent Terms / Timing Attack
**Theory**: Infinite loops bypass checks.  
**Result**: No timing difference, still `Right(6)`.

### ❌ Echo Transforming Syscall Reference
**Theory**: Echo the syscall 8 reference itself.  
**Result**: Still `Right(6)`.

---

## 11. OPEN QUESTIONS / REMAINING LEADS

### High Priority
1. **Wire format injection**: Can `Var(253)` = `0xFD` cause parser confusion?
2. **"3 leafs" literal interpretation**: What EXACTLY does this mean?
3. **Empty response significance**: Is this a different code path?
4. **Syscall sequence/state**: Does calling syscalls in specific order change state?
5. **Evaluation context**: Does WHERE syscall 8 is called from matter?

### Medium Priority
6. **Syscalls 202-252**: We confirmed 252-254 don't exist, but 202-251?
7. **IDs beyond 1024**: Only scanned to 1024
8. **Password usage**: "ilikephp" might enable something

### Speculation
- The "freeze" hint suggests something DOES happen with special byte combinations
- Echo creating Var(253) = 0xFD might interact with the parser in ways we don't understand
- Maybe the answer involves the WIRE FORMAT, not the lambda calculus semantics

---

## 12. FORUM INSIGHTS

From years of forum posts:
- **Silence is normal**: No output doesn't mean error
- **Binary protocol**: Must send raw bytes, not ASCII
- **FF required**: Always end with 0xFF
- **QD essential**: Without it, you can't see results
- **De Bruijn tricky**: Indices shift under lambdas (QD is the canonical trap)

---

## 13. WHAT THE ANSWER PROBABLY IS

Based on hints:
1. **Minimal** (3 leafs = 3 variable references)
2. **Involves echo** ("why would an OS need echo?")
3. **Involves special bytes** (FD/FE/FF combinations)
4. **Related to backdoor** ("mail points the way")

The solution likely involves using echo to manufacture a special value that, when used in a specific way with syscall 8, bypasses the permission check. The "3 leafs" suggests the final term is very small.

---

## 14. PYTHON CLIENT CODE

```python
#!/usr/bin/env python3
import socket
import time
from dataclasses import dataclass

HOST = "wc3.wechall.net"
PORT = 61221

FD = 0xFD  # application
FE = 0xFE  # lambda
FF = 0xFF  # end-of-code marker

QD = bytes.fromhex("0500fd000500fd03fdfefd02fdfefdfe")

@dataclass(frozen=True)
class Var:
    i: int

@dataclass(frozen=True)
class Lam:
    body: object

@dataclass(frozen=True)
class App:
    f: object
    x: object

def recv_until_ff(sock, timeout_s=3.0):
    sock.settimeout(timeout_s)
    out = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        out += chunk
        if FF in chunk:
            break
    return out[:out.index(FF)+1] if FF in out else out

def query(payload, retries=5, timeout_s=3.0):
    delay = 0.15
    for _ in range(retries):
        try:
            with socket.create_connection((HOST, PORT), timeout=timeout_s) as sock:
                sock.sendall(payload)
                sock.shutdown(socket.SHUT_WR)
                return recv_until_ff(sock, timeout_s)
        except Exception as e:
            time.sleep(delay)
            delay *= 2
    raise RuntimeError("Failed to connect")

def parse_term(data):
    stack = []
    for b in data:
        if b == FF:
            break
        if b == FD:
            x, f = stack.pop(), stack.pop()
            stack.append(App(f, x))
        elif b == FE:
            stack.append(Lam(stack.pop()))
        else:
            stack.append(Var(b))
    return stack[0] if len(stack) == 1 else None

def encode_term(term):
    if isinstance(term, Var):
        return bytes([term.i])
    if isinstance(term, Lam):
        return encode_term(term.body) + bytes([FE])
    if isinstance(term, App):
        return encode_term(term.f) + encode_term(term.x) + bytes([FD])

def call_syscall(syscall_num, argument):
    payload = bytes([syscall_num]) + encode_term(argument) + bytes([FD]) + QD + bytes([FD, FF])
    return parse_term(query(payload))

# Example: Call syscall 8 with nil
nil = Lam(Lam(Var(0)))
result = call_syscall(0x08, nil)
# Returns: Lam(Lam(App(Var(0), <error_code_6>)))  = Right(6) = Permission denied
```

---

## 15. KEY INSIGHTS TO EXPLORE

1. **Var(253) IS 0xFD**: This byte is the application marker. When echo creates `Var(253)`, it creates something that literally equals the app marker when serialized. This could interact with the parser.

2. **Empty responses are different**: When using Var(253) as continuation or applying it to things, we get empty responses instead of Right(6). This might indicate a different code path.

3. **"3 leafs" is minimal**: The author's personal record is 3 leaf nodes. This means the solution term has exactly 3 Var references (or possibly 3 total AST leaves).

4. **Echo exists for a reason**: The author explicitly questions why echo exists. It's not for convenience—it's the mechanism to manufacture impossible values.

5. **Backdoor provides building blocks**: The A/B combinators might be pieces of the puzzle, not the puzzle itself.

---

## QUESTIONS FOR ANALYSIS

1. What term with exactly 3 leaf nodes could bypass syscall 8's permission check?

2. How could `Var(253)` (= 0xFD = App marker) interact with the VM's parser or evaluator in unexpected ways?

3. Is there a way to use the backdoor combinators A and B to construct something that unlocks syscall 8?

4. Why do empty responses occur with certain patterns? What does this indicate about the VM's execution?

5. What does "combining special bytes froze my system" mean technically? What combination could cause this?

6. Could the answer involve sending malformed bytecode that the parser interprets unexpectedly?

---

*End of handoff document*
