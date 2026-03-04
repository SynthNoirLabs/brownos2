# BrownOS Syscall Behavior Map

| Syscall (Hex) | Syscall (Dec) | Name | Input | Output (Success) | Output (Failure) | Description |
|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| 0x01 | 1 | errorString | Error Code (Int) | `Either Left(List Byte)` | - | Returns descriptive string for error code. |
| 0x02 | 2 | write | List Byte | `Church True` (λa.λb.a) | - | Writes bytes to the TCP socket. |
| 0x04 | 4 | quote | Any Term | `Either Left(List Byte)` | - | Serializes term to postfix bytecode. |
| 0x05 | 5 | readdir | ID (Int) | `Either Left(3-way List)` | `Right(4)` | Lists directory contents. |
| 0x06 | 6 | name | ID (Int) | `Either Left(List Byte)` | `Right(3)` | Returns basename of entry. |
| 0x07 | 7 | readfile | ID (Int) | `Either Left(List Byte)` | `Right(5)` | Returns file content. |
| 0x08 | 8 | ??? | ??? | ??? | `Right(6)` | Gated syscall. Always returns Permission Denied. |
| 0x0E | 14 | echo | Any Term | `Either Left(Term)` | - | Returns term wrapped in Left. Shifts indices by +2. |
| 0x2A | 42 | decoy | Any | List Byte | - | Returns "Oh, go choke on a towel!". |
| 0xC9 | 201 | backdoor | `nil` | `Either Left(Pair A B)` | `Right(2)` | Returns combinators A (λab.bb) and B (λab.ab). |

## Special Markers
- `0xFD`: Application (App)
- `0xFE`: Lambda (Lam)
- `0xFF`: End-of-code

## Data Encodings
- **Either (Scott)**: `Left x = λl.λr. l x`, `Right y = λl.λr. r y`
- **Integer (9-λ Bitset)**: λ^9. additive weights based on Var index 0-8.
- **List (Scott)**: `nil = λc.λn. n`, `cons h t = λc.λn. c h t`
- **3-way List (readdir)**: `nil = λd.λf.λn. n`, `dir = λd.λf.λn. d id rest`, `file = λd.λf.λn. f id rest`

## Shifting and Hidden Indices
- Syscall 14 (echo) shifts de Bruijn indices by +2 because of the `λl.λr.` wrapper.
- `echo(V0)` -> `λl.λr. l V2`.
- Indices `253, 254, 255` exist in the VM but cannot be quoted by Syscall 4 (used by QD) because they clash with FD, FE, FF markers. Quoting them returns "Encoding failed!".
