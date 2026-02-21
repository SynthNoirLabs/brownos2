# BrownOS — Complete Syscall Reference

## Syscall Invocation Pattern

All syscalls use continuation-passing style (CPS):

```
((syscall argument) continuation) + 0xFF
```

Postfix bytecode:
```
<syscall_byte> <arg_bytes> FD <continuation_bytes> FD FF
```

The VM evaluates this and applies `continuation` to the `result`.

## Complete Syscall Table

### Active Syscalls

| ID (hex) | ID (dec) | Name | Input | Output | Notes |
|:---:|:---:|---|---|---|---|
| 0x01 | 1 | error_string | error code (int term) | `Left(bytes)` | Returns human-readable error message |
| 0x02 | 2 | write | bytes list (Scott list) | `Left(true)` + side effect | Writes raw bytes to TCP socket |
| 0x04 | 4 | quote | any term | `Left(bytes)` | Serializes term to postfix bytecode |
| 0x05 | 5 | readdir | directory ID (int term) | `Left(3-way list)` | Lists directory contents |
| 0x06 | 6 | name | entry ID (int term) | `Left(bytes)` | Returns filesystem entry name |
| 0x07 | 7 | readfile | file ID (int term) | `Left(bytes)` | Reads file content |
| **0x08** | **8** | **TARGET** | **???** | **Right(6) always** | **Permission denied — THE GOAL** |
| 0x0E | 14 | echo | any term | `Left(term)` | Returns input (see echo section) |
| 0x2A | 42 | towel | any | `Left(string)` | Returns "Oh, go choke on a towel!" |
| 0xC9 | 201 | backdoor | nil only | `Left(pair)` | Returns combinator pair (A, B) |

### Inactive/Not Implemented

| ID Range | Behavior |
|---|---|
| 0x00 | Non-syscall — hangs/diverges if called as syscall |
| 0x03 | Returns Right(1) "Not implemented" |
| 0x09–0x0D | Returns Right(1) "Not implemented" |
| 0x0F–0x29 | Returns Right(1) "Not implemented" |
| 0x2B–0xC8 | Returns Right(1) "Not implemented" |
| 0xCA–0xFC | Returns Right(1) "Not implemented" |

Verified via exhaustive sweep of all globals 0–252 with args {nil, int0, int1}.

---

## Detailed Syscall Descriptions

### 0x01 — error_string

Returns a human-readable error message for a given error code.

**Input**: Integer term (9-lambda encoding)
**Output**: `Left(bytes)` containing the error string

| Error Code | String Returned |
|:---:|---|
| 0 | `Unexpected exception` |
| 1 | `Not implemented` |
| 2 | `Invalid argument` |
| 3 | `No such directory or file` |
| 4 | `Not a directory` |
| 5 | `Not a file` |
| 6 | `Permission denied` |
| 7 | `Not so fast!` |

### 0x02 — write

Writes raw bytes to the TCP socket.

**Input**: Scott list of byte terms
**Output**: `Left(true)` where true = `λa.λb. a`
**Side effect**: The bytes are written to the TCP connection

Example: Writing `[0x48, 0x69]` ("Hi") sends those two bytes to the client.

### 0x04 — quote (serialize)

Serializes any lambda term back into postfix bytecode.

**Input**: Any term
**Output**: `Left(bytes)` where bytes is the postfix encoding of the term, including a trailing `0xFF`

**Critical limitation**: Cannot serialize terms containing `Var(253)`, `Var(254)`, or `Var(255)` because those byte values are reserved markers (FD, FE, FF). Attempting to quote such terms produces `Encoding failed!` with no `0xFF` terminator, which can hang naive clients.

### 0x05 — readdir

Lists the contents of a directory.

**Input**: Directory ID as integer term
**Output**: `Left(3-way_list)` with the directory listing (see Data Encodings for format)
**Errors**:
- `Right(4)` "Not a directory" — if the ID is a file, not a directory
- `Right(3)` "No such directory or file" — if the ID doesn't exist

### 0x06 — name

Returns the filename/dirname of a filesystem entry.

**Input**: Entry ID as integer term
**Output**: `Left(bytes)` containing the basename (e.g., "passwd", "bin")
**Errors**:
- `Right(3)` "No such directory or file" — if the ID doesn't exist

### 0x07 — readfile

Reads the content of a file.

**Input**: File ID as integer term
**Output**: `Left(bytes)` containing the file content
**Errors**:
- `Right(5)` "Not a file" — if the ID is a directory
- `Right(3)` "No such directory or file" — if the ID doesn't exist

### 0x08 — TARGET SYSCALL (Permission Denied)

**This is the syscall we need to make succeed to solve the challenge.**

**Current behavior**: Always returns `Right(6)` ("Permission denied") for every argument tested.

**Tested arguments** (all returned Right(6)):
- nil, identity, all Church numerals 0–255
- All file/directory IDs
- Scott byte lists (strings like "ilikephp", "gizmore", etc.)
- Backdoor pair and its components (A, B, omega)
- Echo-manufactured values (Var(253), Var(254))
- All 3-leaf term patterns enumerated
- Every 1-byte, 2-byte (λVn), and 3-byte (λλVn) argument
- 343 combinations of special bytes {0, 1, 2, 8, 201, FD, FE}³
- Combinators: K, I, S, ω, Ω, etc.

**Tested continuations** (all produced Right(6) or empty response):
- QD (standard), identity, nil
- Var(253) as continuation → empty response
- A, B combinators as continuation → empty response
- All single-byte globals 0–252

**Side-effect test**: Reading access.log before and after syscall 8 shows no state change.

**CPS behavior confirmed**: `sys8(nil)(write_K)` does print K, proving syscall 8 calls its continuation in normal CPS style — it just always passes Permission denied as the result.

### 0x0E — echo (the "new syscall")

Returns its input wrapped in `Left(...)`.

**Input**: Any term
**Output**: `Left(term)` — the original input

**Critical detail**: The `Left` wrapper adds 2 lambdas (`λl.λr. (l <payload>)`), so when you inspect the raw payload (e.g., via QD), free De Bruijn indices appear shifted by +2. This shift **cancels** when you properly unpack the Either by applying it to selectors.

**Why it matters**: Echo can manufacture terms with "impossible" variable indices:
- `echo(Var(251))` → `Left(Var(253))` — creates a runtime Var(253) which equals byte 0xFD (Application marker)
- `echo(Var(252))` → `Left(Var(254))` — creates a runtime Var(254) which equals byte 0xFE (Lambda marker)
- These values **cannot exist in source code** and **cannot be serialized** by quote

**Failure cases**:
- `echo(Var(253))` → `Invalid term!` (253 = 0xFD is parsed as App marker, not a variable)

### 0x2A — towel (decoy)

**Input**: Any argument (ignored)
**Output**: `Left(bytes)` containing `"Oh, go choke on a towel!"`

This is a Hitchhiker's Guide to the Galaxy reference (42 = 0x2A). It is confirmed **NOT** the WeChall answer.

### 0xC9 — backdoor (syscall 201)

**Input**: Must be exactly `nil` (Scott-encoded `λλ.V0` = `00 FE FE`). Any other argument returns `Right(2)` "Invalid argument".

**Output**: `Left(pair)` where pair contains two combinator terms:

```
pair = λs. (s A B)

A = λa.λb. (b b)    bytecode: 00 00 FD FE FE
B = λa.λb. (a b)    bytecode: 01 00 FD FE FE
```

**Combinator analysis**:
- A applied to anything: `A x = λb.(b b)` — self-application of second arg
- B applied to anything: `B f x = (f x)` — normal function application
- `(A B) = λx.(x x) = ω` — the little omega combinator
- `(ω ω) = Ω` — diverges (infinite loop)

**Discovery source**: The mail spool file `/var/spool/mail/dloser` (ID 88) explicitly hints:
```
Backdoor is ready at syscall 201; start with 00 FE FE.
```

---

## Syscall Sweep Results

Exhaustive scan of globals 0–252 using `((g arg) QD)` with arg ∈ {nil, int0, int1}:

| Behavior | Global IDs |
|---|---|
| Left (success) | 2, 4, 14, 42, 201 |
| Right(6) Permission denied | 8 only |
| Right(2) Invalid argument | 1, 5, 6, 7 (with nil) |
| Right(1) Not implemented | All others (242 globals) |
| Silent / non-syscall | 0 |

No hidden syscalls were found in the 0–252 range.
