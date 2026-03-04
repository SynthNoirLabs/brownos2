# BrownOS — Offline Analysis & Findings

This document summarizes the exhaustive offline research and analysis of the BrownOS challenge, incorporating findings from the forum archive, challenge HTML, and lambda calculus theory.

## 1. The Backdoor Pair (Syscall 201)
Syscall 201, when called with `nil` (`00 FE FE`), returns `Left(pair A B)` where:
- **A = λa.λb. b b** (Constant function returning self-application/omega)
- **B = λa.λb. a b** (Identity function; also Church numeral 1)

These are the "substructures" mentioned by dloser. **B** is a transparent wrapper, while **A** introduces the capability for recursion or divergence (self-application). The mail spool confirms: *"Backdoor is ready at syscall 201; start with 00 FE FE."*

## 2. Capability Bitmask Theory (The "Meaning of Input Codes")
The author hinted that figuring out the meaning of input codes (syscall IDs) is essential.
Mapping known syscalls:
- **1** (0001): Error String (Meta-data)
- **2** (0010): Write (Output)
- **4** (0100): Quote (Serialization)
- **5** (0101): Readdir (Serialization + Meta-data)
- **6** (0110): Name (Serialization + Output)
- **7** (0111): Readfile (Serialization + Output + Meta-data)
- **8** (1000): Sys8 (System/Execution?)
- **14** (1110): Echo (System + Serialization + Output)

**Findings**:
- Syscall numbers are **capability bitmasks**.
- **Bit 0 (1)**: Metadata Access
- **Bit 1 (2)**: Output Stream
- **Bit 2 (4)**: Serialization/Traversal
- **Bit 3 (8)**: Execution/System Privilege

Under this theory, **sys8** (1000) is the raw "System Privilege" or "Kernel" access. Calling it with the right argument unlocks the remaining capability bits for other syscalls.

## 3. The "3 Leafs" and "Visit Things" Paradox
- **Hint**: *"My record is 3 leafs IIRC."* (dloser, Jan 2026)
- **Hint**: *"If you manage to reach the part where you need to visit things..."* (pouniok, Mar 2026)
- **Fact**: A "leaf" is a `Var(i)` node. A 3-leaf program is tiny, e.g., `((8 201) nil)` or `((201 nil) 8)`.
- **Deduction**: The 3-leaf program is the **privilege escalation** exploit. It doesn't print the answer itself; it unlocks the system ("EMPTY = success"). The "visit things" phase refers to using `readdir`/`readfile` on restricted IDs (like `/root` or IDs > 255) *after* the unlock.

## 4. The "Special Bytes" Dark Magic
- **Hint**: *"Combining the special bytes... once it froze my whole system!"*
- **Mechanism**: `echo(Var(251))` returns `Left(Var(253))`. But `253` is `0xFD` (Application marker).
- **Result**: This allows constructing a term that contains a raw `0xFD` *inside* a lambda body. When this term is evaluated or quoted, it can cause the VM to interpret data as code or vice versa, leading to memory corruption, info leaks, or privilege bypasses.

## 5. Forum Clues & Metadata Search
- **Hidden Text**: Light-gray text found in forums:
  - *"Perhaps you are sending ASCII instead of bytes?"*
  - *"If you give it good input, you get good stuff back... Now, what is good input? ;)"*
  - *"EMPTY = success if you didn't want it to return anything."* (Crucial for the unlock phase).
- **Metadata**: No hidden comments or steganography found in meta tags or script contents. Meta generator is standard `GWFv3.04`.
- **Iteration Count**: `56154` is `0xDB5A`. The hash `9252ed65ffac2aa763adb21ef72c0178f1d83286` is unique to this challenge.

## 6. Formatting the Answer
- The answer is **case-insensitive**.
- It is a string found *after* privileging the session.
- Likely candidates include strings found in `/root`, `/etc/shadow` (if it exists), or unlinked file IDs discovered via privilege.

## Summary of the Solution Path
1. **Privilege Escalation**: Use the **backdoor (201)** to get A/B, then use them in a **3-leaf program** with **sys8** (or manufacture special bytes via **echo**) to unlock the system.
2. **Exploration**: Use privileged `readdir`/`readfile` to "visit things" and find the secret string.
3. **Verification**: Verify the string against the iterated SHA1 hash.
