# BrownOS Challenge — Overview & Background

## Challenge Identity

- **Name**: The BrownOS
- **Platform**: WeChall (wechall.net)
- **Author**: dloser (WeChall user, top-10 ranked player)
- **Created**: May 24, 2014
- **Difficulty**: 10/10 (hardest tier on the site)
- **Solvers**: 4 people in 12+ years (l3st3r, space, dloser [author], jusb3)
- **No public writeups exist** anywhere on the internet

## Challenge Description (from challenge.html)

> Reports have come in about a new kind of operating system that Gizmore is developing. Scans have detected an extra open port on wechall.net that might be related to this. Additionally, one of our dumpster divers has found part of what appears to be a cheat sheet for something called "BrownOS".
>
> Please investigate the service at wc3.wechall.net port 61221.

## The Cheat Sheet (exact text)

```
FF: End Of Code marker

BrownOS[<syscall> <argument> FD <rest> FD] -> BrownOS[<rest> <result> FD]

Quick debug: 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
For example: QD ?? FD  or  ?? ?? FD QD FD
```

## What BrownOS Is

A **lambda calculus-based virtual machine** over TCP. NOT a real OS. Send raw binary bytecode (lambda calculus terms in postfix), it evaluates the term and optionally returns output.

## The Goal

Make **syscall 8** return **success** (`Left(...)`) instead of `Right(6)` "Permission denied". The successful result is presumably the WeChall answer.

## Server

- **Host**: `wc3.wechall.net` (historically also `hes2013.wechall.net`)
- **Port**: 61221
- **Protocol**: Raw binary TCP

## Key Operational Facts

- The server speaks **raw bytes**, not ASCII text
- Every input must end with `0xFF` (End of Code marker)
- No output is normal — doesn't mean error
- Rate-limited (error 7 = "Not so fast!")
- Input size limit ~2KB — "Term too big!" error
- **Each TCP connection is independent — no shared state between connections**
- **Server processes ONLY the first term per connection; no session accumulation**

## WeChall Answer Submission

WeChall hashes answers with `sha1^56154(answer)`. Target hash:
```
9252ed65ffac2aa763adb21ef72c0178f1d83286
```

## ALL Answers Already Rejected by WeChall

**DO NOT re-suggest any of these. They have been submitted and REJECTED:**

```
ilikephp, gizmore, GZKc.2/VQffio, dloser, root, mailer
omega, Ω, ω, A, B, AB, BA, selfapply, self-apply, apply
backdoor, 201, 0xC9
Var(253), Var(251), 253, 251, 0xFD, 0xFB
echo, echo251, FD, fd, FDFE
Permission denied, 6, 3
42, wtf, towel
3leafs, 3 leafs, echo
1, \x01, SOH, 0x01, Church1
Left(Right(1))
0000fdfe (omega bytecode)
0800fd00fdff (3-leaf minimal)
```

The answer is NOT any obvious string from filesystem contents, combinator names, protocol constants, or error strings.

## Historical Timeline

- **May 2014**: Challenge created
- **May 2016**: 0 solvers after 2 years; dloser hints about "input codes"
- **Jun 2016**: Bug fix for "certain unexpected inputs"
- **Sept 2018**: Echo syscall (0x0E) added; new version deployed
- **Late 2018**: l3st3r and space likely solved it
- **2019–2025**: No new solvers; periodic community check-ins
- **Jan–Feb 2026**: This research effort (500+ test cases, 200+ probe scripts, exhaustive sweeps)

## Current Status

**UNSOLVED** by this research effort. Syscall 8 returns Right(6) for every input ever tested. The solution requires either making syscall 8 succeed or discovering something fundamentally new.
