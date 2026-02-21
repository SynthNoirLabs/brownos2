# BrownOS Challenge — Overview & Background

## Challenge Identity

- **Name**: The BrownOS
- **Platform**: WeChall (wechall.net)
- **Author**: dloser (WeChall user, top-10 ranked player)
- **Created**: May 24, 2014
- **Difficulty**: 10/10 (hardest tier on the site)
- **Score**: 9 points
- **Solvers**: 4 people in 12+ years (l3st3r, space, dloser [author], jusb3)
- **No public writeups exist** for this challenge anywhere on the internet
- **Category**: Unknown (not classified as crypto, web, reversing, etc.)
- **Copyright years listed**: 2014–2026 (actively maintained)

## Challenge Description (from challenge.html)

> Reports have come in about a new kind of operating system that Gizmore is developing. Scans have detected an extra open port on wechall.net that might be related to this. Additionally, one of our dumpster divers has found part of what appears to be a cheat sheet for something called "BrownOS".
>
> Please investigate the service at wc3.wechall.net port 61221.

## The Cheat Sheet (exact text from the challenge page)

```
FF: End Of Code marker

BrownOS[<syscall> <argument> FD <rest> FD] -> BrownOS[<rest> <result> FD]

Quick debug: 05 00 FD 00 05 00 FD 03 FD FE FD 02 FD FE FD FE
For example: QD ?? FD  or  ?? ?? FD QD FD
```

## What BrownOS Is

BrownOS is a **lambda calculus-based virtual machine** accessible over TCP. It is NOT a real operating system — it's a tiny functional VM with a virtual filesystem. You send it raw binary bytecode (a lambda calculus term in postfix notation), it evaluates the term, and optionally returns output.

## The Goal

Make **syscall 8** (referred to as `/bin/solution` in some contexts) return **success** instead of "Permission denied" (error code 6). The successful result is presumably the WeChall answer string that you submit on the challenge page.

## Server

- **Host**: `wc3.wechall.net` (historically also `hes2013.wechall.net`)
- **Port**: 61221
- **Protocol**: Raw binary TCP
- **IP**: Changes over time; currently resolves to WeChall infrastructure

## Key Facts

- The server speaks **raw bytes**, not ASCII text
- Every input must end with `0xFF` (End of Code marker)
- No output is normal — it doesn't mean error
- The service is shared and rate-limited (error code 7 = "Not so fast!")
- Input size limit exists (~2KB) — "Term too big!" error
- Each TCP connection is independent — no shared state between connections
- The server processes ONLY the first term per connection; no session accumulation

## WeChall Answer Submission

WeChall hashes answers with `sha1^56154(answer)` before comparing. The target hash is:
```
9252ed65ffac2aa763adb21ef72c0178f1d83286
```

## Current Status

**UNSOLVED** by this research effort. All approaches to make syscall 8 succeed return error 6 (Permission denied). The strongest answer candidate recovered from filesystem exploration is `ilikephp` (gizmore's password), but this has been **rejected by WeChall**.

## Answers Already Rejected by WeChall

```
ilikephp, gizmore, GZKc.2/VQffio, dloser
Var(253), Var(251), 253, 251, 0xFD, 0xFB
201, 0xC9, backdoor
3leafs, 3 leafs, echo
FD, fd, FDFE
1, \x01, SOH, 0x01, Church1
echo251, Left(Right(1)), Permission denied, 6, 3
42, wtf
omega, Ω, towel
A, B, AB, BA
selfapply, self-apply, apply
```

## Historical Timeline

- **May 2014**: Challenge created
- **May 2016**: dloser notes nobody has understood "input codes" yet (2 years, 0 solvers)
- **Jun 2016**: Bug fix for "certain unexpected inputs"
- **Sep 2018**: New syscall (echo, 0x0E) added; new challenge version deployed
- **May 2018**: l3st3r working on it (eventually solved it)
- **Sep 2018**: space posts a Python client example
- **Jan 2021–present**: Disappointment thread; periodic check-ins from community
- **Nov 2025**: space encourages people to try again
- **Jan–Feb 2026**: This research effort (extensive probing, 500+ test cases)
