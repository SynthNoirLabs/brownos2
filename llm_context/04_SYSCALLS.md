# BrownOS — Complete Syscall Reference

## Invocation Pattern (CPS)

```
((syscall argument) continuation) + 0xFF
Postfix: <syscall_byte> <arg_bytes> FD <continuation_bytes> FD FF
```

Result: `(continuation result)` — continuation is called with the syscall's return value.

## Active Syscalls

| ID | Dec | Name | Input | Output |
|:---:|:---:|---|---|---|
| 0x01 | 1 | error_string | error code (int) | `Left(bytes)` |
| 0x02 | 2 | write | bytes list | `Left(true)` + TCP write |
| 0x04 | 4 | quote | any term | `Left(bytes)` |
| 0x05 | 5 | readdir | dir ID (int) | `Left(3-way list)` |
| 0x06 | 6 | name | entry ID (int) | `Left(bytes)` |
| 0x07 | 7 | readfile | file ID (int) | `Left(bytes)` |
| **0x08** | **8** | **TARGET** | **???** | **Right(6) always** |
| 0x0E | 14 | echo | any term | `Left(term)` |
| 0x2A | 42 | towel | any | `Left("Oh, go choke...")` |
| 0xC9 | 201 | backdoor | nil only | `Left(pair(A,B))` |

### Inactive: 0x00 (non-syscall, hangs), 0x03 and all others 0x09–0xFC → Right(1) "Not implemented"

Verified via exhaustive sweep of globals 0–252 with args {nil, int0, int1}.

---

## Detailed Descriptions

### 0x01 — error_string

| Error Code | String |
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

Writes raw bytes to TCP socket. Returns `Left(true)` where true = `λa.λb. a`.

### 0x04 — quote (serialize)

Serializes any term to postfix bytecode. **Cannot serialize Var(253+)** — returns `Encoding failed!` without trailing 0xFF.

### 0x05 — readdir

Returns 3-way Scott list (see Encodings). Errors: Right(4) on non-dirs, Right(3) on unknown IDs.

### 0x06 — name

Returns basename as bytes. Right(3) on unknown IDs.

### 0x07 — readfile

Returns file content as bytes. Right(5) on dirs, Right(3) on unknown IDs.

### 0x08 — TARGET SYSCALL ⚠️

**Always returns Right(6) "Permission denied"** for every argument tested. See file 08_NEGATIVE_RESULTS.md for the complete test matrix.

Key finding: `sys8(nil)(write_K)` prints K, proving syscall 8 **does** call its continuation in normal CPS style — it just always passes Right(6) as the result.

Side-effect test: reading access.log before and after sys8 shows **no state change**.

### 0x0E — echo ("new syscall", added Sept 2018)

Returns input wrapped in `Left(...)`. The `Left` wrapper adds 2 lambdas, so free de Bruijn indices appear +2 shifted when inspecting the raw payload — this shift cancels when properly unpacking the Either.

**Key capability**: Echo can manufacture "impossible" runtime values:
- `echo(Var(251))` → `Left(Var(253))` — runtime Var(253) = byte 0xFD
- `echo(Var(252))` → `Left(Var(254))` — runtime Var(254) = byte 0xFE
- These **cannot exist in source code** and **cannot be serialized** by quote
- `echo(Var(253))` → `Invalid term!` (0xFD parsed as App marker)

### 0x2A — towel (decoy)

Returns `"Oh, go choke on a towel!"`. Hitchhiker's Guide reference. **NOT the answer.**

### 0xC9 — backdoor (syscall 201)

**Input**: Must be exactly nil (`00 FE FE`). Any other arg → Right(2).

**Output**: `Left(pair)` where:
```
pair = λs. (s A B)
A = λa.λb. (b b)    bytecode: 00 00 FD FE FE
B = λa.λb. (a b)    bytecode: 01 00 FD FE FE
```

Combinator properties:
- `A x = λb.(b b)` — self-application of second arg
- `B f x = (f x)` — normal function application
- `(A B) = λx.(x x) = ω` (little omega)
- `(ω ω) = Ω` — diverges

Discovery: mail spool `/var/spool/mail/dloser` says "Backdoor is ready at syscall 201; start with 00 FE FE."
