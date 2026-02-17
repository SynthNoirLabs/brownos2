# BrownOS Quick Reference - Key Facts Only

## The Challenge
- Lambda calculus VM over TCP (`wc3.wechall.net:61221`)
- Goal: Make syscall 8 succeed (currently returns "Permission denied")
- ~4 solvers in 12 years

## Wire Format
```
0x00-0xFC = Var(n)    # de Bruijn index
0xFD = Application    # postfix: f x FD
0xFE = Lambda         # postfix: body FE  
0xFF = End of code    # REQUIRED
```

## Critical Syscalls
| ID | What | Notes |
|----|------|-------|
| 0x08 | TARGET | Always Right(6) "Permission denied" |
| 0x0E | Echo | Returns Left(input) with +2 index shift |
| 0xC9 | Backdoor | Input=nil, returns Left(pair with A,B combinators) |

## The Key Mechanism (Echo)
```
echo(Var(251)) → Left(Var(253))
```
- Var(253) = 0xFD = Application marker byte
- CANNOT be written directly in code
- Echo is the ONLY way to create it

## Author Hints
1. **"3 leafs"** - Minimal solution has 3 variable references
2. **"combining special bytes froze system"** - FD/FE/FF manipulation
3. **"why would OS need echo?"** - Echo manufactures special values
4. **Mail says** - "Backdoor at syscall 201; start with 00 FE FE"

## Backdoor Output
```
pair = λs. s A B
A = λab.(b b)   # self-apply second arg
B = λab.(a b)   # normal apply
```

## Everything Tried (FAILED)
- All arguments: nil, identity, numerals, file IDs, manufactured Var(253/254)
- All continuations: QD, identity, Var(253), A, B
- All 3-leaf patterns we enumerated
- Echo chains, syscall sequences, divergent terms

## Significant Observation
**Empty responses** (0 bytes, not Right(6)) occur with:
- Var(253) as continuation
- Backdoor combinators as continuation
- Applying Var(253) to things

This is DIFFERENT from normal "Permission denied" response.

## Open Questions
1. What 3-leaf term bypasses permission?
2. How does Var(253)=0xFD interact with parser?
3. Why do empty responses occur?
4. What "combining special bytes" causes freeze?
5. Does syscall order/context matter?

## Encodings
```
nil = 00 FE FE           # λλ.0
identity = 00 FE         # λ.0
Left(x) = λl.λr.(l x)    # body is App(Var(1), x)
Right(y) = λl.λr.(r y)   # body is App(Var(0), y)
```

## QD (Debug Continuation)
```
QD = 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
```
Prints serialized result to socket. References syscalls via Var(2,3,5).

---

**The answer is likely**: A minimal 3-leaf term using echo-manufactured Var(253) in a way that exploits how 0xFD interacts with the VM/parser.
