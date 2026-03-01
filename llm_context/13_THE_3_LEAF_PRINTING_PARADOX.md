# BrownOS — The 3-Leaf Printing Paradox

## The Absolute Constraints (Proven through V1-V12 Probes)
1. **The Target is a String**: The WeChall server requires you to submit the hash of a specific string.
2. **The Socket is Anonymous**: The challenge server cannot award points automatically. A "silent success" is mathematically impossible.
3. **The Solution MUST Print**: The VM *must* output bytes over the TCP socket.
4. **The Record is 3 Leafs**: The author's solution AST uses only 3 variable references (`Var(X)`).

## The Logical Deduction
Because the payload MUST print, one of the 3 leaves in the author's record MUST be a printing syscall. 

There are only three syscalls capable of writing to the socket:
1. `sys2` (write): Takes a Scott-encoded list of integers. Crashes on native objects.
2. `sys4` (quote): Serializes ASTs. Crashes with `Encoding failed!` if it hits `0xFD` or `0xFE`.
3. `sys1` (error_string): Takes an integer (e.g., 6) and returns a Scott-encoded error string (e.g., "Permission denied").

## The Echo Enabler ("Dark Magic")
Echo (`sys14` / `0x0E`) was added years later, and it enabled the first solves.
`echo(X)` returns `Left(X)`. Free variables inside `X` are shifted by +2.
`echo(Var(251))` produces a runtime `Var(253)` (which is the byte `0xFD`, the application marker).

Author: *"why would an OS even need an echo? I can easily write that myself... I'm getting some interesting results when combining the special bytes... once it froze my whole system!"*

## The Problem
If we apply `sys2` or `sys4` to a construct containing this forbidden byte, what happens? 
We know `sys4` crashes with `Encoding failed!` (returning text to the socket!). But `Encoding failed!` is not the flag. 

How do we construct a 3-leaf AST that actively prints data by tricking `sys2`, `sys4`, or `sys1` into printing the flag, utilizing `echo` or the Backdoor (`sys201`)?
