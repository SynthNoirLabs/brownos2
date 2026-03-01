# BrownOS — Complete Negative Results (CRITICAL — READ THIS FIRST)

## ⚠️ WHY THIS FILE EXISTS

Multiple LLMs have proposed "breakthrough" theories that were already tested and failed. This file documents **everything that has been tried**. If your suggestion appears in this file, it has been tested against the live server and does not work.

## The Definitive Conclusion

> **Syscall 8's permission gate is PROVENANCE-INDEPENDENT and PROTOCOL-INDEPENDENT.**
> No argument value, source transformation, construction method, or protocol trick has changed its behavior from Right(6).
> The gate does not depend on what ran before sys8, what constructed the argument, or how the argument was delivered.

---

## 1. Simple Arguments → sys8

| Argument Type | Examples | Result |
|---|---|---|
| nil (λλ.V0) | `00 FE FE` | Right(6) |
| true/K (λλ.V1) | | Right(6) |
| identity (λ.V0) | | Right(6) |
| Church numerals 0–255 | All tested | Right(6) |
| All Var(0)–Var(252) at top level | 253 values | Right(6) or silent |
| All λ.Var(N) wrappers | 253 variants | Right(6) |
| All λλ.Var(N) wrappers | 253 variants | Right(6) |

## 2. Filesystem/Credential Arguments → sys8

| Argument | Result |
|---|---|
| String "ilikephp" | Right(3) NoSuchFile |
| String "gizmore" | Right(3) NoSuchFile |
| String "gizmore:ilikephp" | Right(3) NoSuchFile |
| String "GZKc.2/VQffio" (hash) | Right(3) NoSuchFile |
| String "root", "sudo", "dloser" | Right(3) NoSuchFile |
| String "/bin/solution" | Right(3) NoSuchFile |
| String "/bin/sh" (VALID existing path, id 14) | Right(3) NoSuchFile |
| String "/home/gizmore" (VALID existing path, id 39) | Right(3) NoSuchFile |
| Full passwd line for gizmore | Right(3) NoSuchFile |
| File IDs as integers (0–256) | Right(6) |
| UID 1000, 1002 | Right(6) |
| pair(uid=1000, "ilikephp") | Right(6) |
| pair(uid=1002, "ilikephp") | Right(6) |

**Notable**: String arguments → Right(3); non-string arguments → Right(6). Different code path.

## 3. Backdoor-Derived Arguments → sys8

| Argument | Result |
|---|---|
| A = λλ.(V0 V0) | Right(6) |
| B = λλ.(V1 V0) | Right(6) |
| pair(A, B) = λs.(s A B) | Right(3) NoSuchFile |
| ω = λ.(V0 V0) | Right(6) |
| Ω = (ω ω) | Timeout/diverge |
| A(A), A(B), B(A), B(B) | Diverge or Right(6) |
| B(A(B)) | Diverge/timeout |
| pair applied to true/false/selectors | Right(6) |

## 4. Echo-Manufactured Arguments → sys8

| Argument | Result |
|---|---|
| Var(253) via echo(251) | Right(6) |
| Var(254) via echo(252) | Right(6) |
| echo(X) → Left(X') → sys8(Left(X')) for various X | Right(6) |
| echo(nil), echo(int8), echo(g8), echo(str) → unwrap → sys8 | Right(6) |

## 5. Continuation Variations for sys8

| Continuation | Result |
|---|---|
| QD (standard) | Right(6) visible |
| Identity (λ.V0) | Empty |
| nil (λλ.V0) | Empty |
| Var(253) | Empty |
| A, B combinators | Empty |
| All single-byte globals 0–252 | Right(6) or empty |
| write-based observer | Right(6) visible |
| pair(A,B) as continuation | Empty |

## 6. Combinatorial / Brute Force — sys8

| Pattern | Count | Result |
|---|:---:|---|
| All {0,1,2,8,201,FD,FE}³ combos | 343 | All Right(6) |
| 3-leaf: ((Va Vb) Vc) all key indices | 361+ | All Right(6)/empty |
| 3-leaf: (Va (Vb Vc)) all key indices | 361+ | All Right(6)/empty |
| 3-leaf exhaustive (probe_3leaf_exhaustive.py) | **5,346** | **All Right(6)/empty** |
| λλλ.(V2 V1 V0) style eliminators | Dozens | All Right(6) |
| Church K, I, S, ω, Ω combinators | All tested | Right(6) |

## 7. Multi-Step / Stateful Chaining

| Pattern | Result |
|---|---|
| `sys8(nil) → sys8(result_of_first)` | Right(6) |
| `sys8(nil) → backdoor(nil) → sys8(pair)` | Right(6) |
| `backdoor(nil) → sys8(pair_component)` | Right(6) |
| `echo(X) → sys8(echo_result)` | Right(6) |
| `quote(g8) → sys8(quoted_bytes)` | Right(6) |
| `backdoor-pair-captured continuation → sys8` | Right(6) |

## 8. CBN-Thunk Arguments (TESTED AND FAILED)

The hypothesis that BrownOS uses lazy eval and sys8 rejects unevaluated thunks was **directly tested**:

| Pattern | Result |
|---|---|
| `sys8(g201(nil))(OBS)` | Right(6) PermDenied |
| `sys8(g201(g8))(OBS)` | Right(6) PermDenied |
| `sys8(g14(g8))(OBS)` | Right(6) PermDenied |
| `sys8(g14(g201))(OBS)` | Right(6) PermDenied |
| `sys8(g7(int(11)))(OBS)` | Right(6) PermDenied |

Whether the argument is an evaluated value or an unevaluated thunk, sys8 returns Right(6).

## 9. CPS Chain: sys8 as Continuation of sys201 (TESTED AND FAILED)

The "pass sys8 as continuation to backdoor" hypothesis was **directly tested**:

| Payload | Result |
|---|---|
| `(((sys201 nil) sys8) QD)` | Right(6) PermDenied |
| `(((echo g251) sys8) QD)` | Right(6) PermDenied |
| `((sys201 nil) (λpair. ((sys8 pair) shifted_QD)))` | Right(6) PermDenied |
| `((sys201 nil) (λpair. ((sys8 pair) manual_observer)))` | Right(6) PermDenied |
| backdoor → λpair. sys8('/bin/solution') with shifted QD | Right(6) PermDenied |

Shifted QD (manually adjusting de Bruijn indices by +1) was also tested — still Right(6).

## 10. Protocol-Level Tricks (TESTED AND FAILED)

| Trick | Result |
|---|---|
| Post-0xFF bytes (password/nil/quoted-g8) | Silently ignored |
| Multiple terms per connection | Server processes only first |
| Non-singleton parse stack | "Invalid term!" |
| sys8 without continuation (1-arg only) | Empty (strict CPS) |
| g(0) exception wrapping | Empty |

## 11. Wide-Integer / Extended Arguments

| Argument | Result |
|---|---|
| 256, 257, 511, 512, 1000, 1002, 1024, 4096 | Right(6) |
| pair(uid=1000, "ilikephp") with true wide UIDs | Right(6) |

## 12. Timing / Side-Channel

| Test | Result |
|---|---|
| Response time comparison across arguments | All ~0.5-0.8s (network only) |
| Omega as argument (divergence test) | Returns immediately |
| Deep nesting (50 lambdas) | Same timing as nil |
| Parallel connections (backdoor + sys8) | No cross-connection effect |

## 15. "Consumer Inversion": pair(sys8) = sys8(A)(B) (TESTED AND FAILED)

The idea of applying the backdoor pair TO sys8 (instead of passing pair as argument) was tested across **10+ probe scripts**:

| Pattern | Probe File(s) | Result |
|---|---|---|
| `pair(sys8)(QD)` — pair dispatches sys8 | probe_pair_sys8.py, probe_double_question.py, probe_pair_bytecode.py | Right(6) or empty |
| `pair(sys8)(nil)` — B as continuation | probe_pair_fix.py, probe_pair_sys8.py Phase 1 | Empty |
| `((backdoor nil) (λp. ((p sys8) QD)))` — live pair | probe_high_index_syscall.py, probe_pair_syscall_destr.py T7 | Right(6) or empty |
| `pair(sys8)(left_handler)(right_handler)` — extraction | probe_decode_quote_k252.py, probe_pair_sys8.py Phases 12-13 | Right(6) |
| `sys8(nil)(pair)` — pair as continuation | probe_echo_nest_and_pair_cont.py, probe_kernel_window.py | Empty |
| `sys8(nil)(A)`, `sys8(nil)(B)` — components as continuation | probe_pivot.py, probe_kernel_window.py Phase 7 | Empty |
| `pair(λa.λb.sys8(a))(nil)` — extract A → sys8 | probe_pair_sys8_fixed.py, probe_hidden_syscall.py | Right(6) |
| `pair(λa.λb.sys8(b))(nil)` — extract B → sys8 | probe_pair_sys8_fixed.py, probe_hidden_syscall.py | Right(6) |
| `pair(λa.λb.sys8(a(b)))(nil)` — sys8(ω) via pair | probe_pair_sys8_fixed.py, probe_oracle_v4.py | Right(6)/timeout |
| `sys8(pair)(pair)` — pair as both arg and cont | probe_pair_sys8_fixed.py Phase 10 | Empty |

The "empty response = success trapped in a lambda" theory was also tested by applying additional arguments to extract results. All extraction attempts returned Right(6) or empty.

## 16. Var(253) in Function Position / OOB Execution (TESTED AND FAILED)

The idea of executing Var(253) as a function (not argument) to trigger out-of-bounds array access was tested:

| Pattern | Probe File | Result |
|---|---|---|
| `V253(sys8)(QD)` — Var(253) as function | probe_var255.py | Empty/error |
| `(Var(253) syscall8)` — 253 as function | probe_continuation_hypothesis.py | Empty/error |
| Call echo's Var(253) as function directly | probe_extended_ids.py | Empty/error |
| Can Var(253) be called as a function? | probe_hidden_globals.py | No evidence of special behavior |
| Apply Var(253) directly | probe_use_unserializable.py | Empty/error |
| echo(251) → unwrap → use V253 as syscall | Multiple probes | Empty/error |

Var(253) in function position does not trigger any observable OOB behavior, special syscall, or different response pattern.

## 17. Valid Filesystem Paths as sys8 String Arguments (TESTED)

The hypothesis that sys8 does POSIX-style path resolution was tested:

| Path String | Exists in FS? | Result |
|---|---|---|
| "/bin/sh" | Yes (id 14) | Right(3) NoSuchFile |
| "/home/gizmore" | Yes (id 39) | Right(3) NoSuchFile |
| "/bin/solution" | **No** | Right(3) NoSuchFile |
| "ilikephp" | No (not a path) | Right(3) NoSuchFile |

**Conclusion**: Even valid existing filesystem paths return Right(3). sys8 does NOT perform path-to-ID resolution. The string code path appears to do direct string comparison, not VFS lookup. All strings (valid or invalid paths, or non-paths) return Right(3) uniformly.
## 13. Previous LLM Suggestions (ALL TESTED, ALL FAILED)

An audit of external LLM suggestions was conducted with results:

| LLM Claim | Tested | Result |
|---|---|---|
| Feed raw echo results to sys8 (no unwrap) | Yes | Right(6) |
| Generate runtime-shifted unquotable terms → sys8 | Yes | Right(6) |
| Use per-connection nonce from access.log | Yes | Right(6) + false positive |
| Backdoor pair/combinator as capability token | Yes | Right(6) |
| Sweep sys8 with globals as argument (200–252) | Yes, 53 tests | All Right(6) |
| Hidden CTF-style file IDs | Yes, 12 tests | All "No such file" |
| "3-leaf" CPS chain: `(((sys201 nil) sys8) QD)` | Yes | Right(6) |
| Shifted-QD rescue | Yes | Right(6) |
| Duck-typed pair as string path | Structurally wrong (pair≠cons) | N/A |
| "Guaranteed" backdoor→sys8 authentication | No authentication state exists | N/A |
| "Consumer Inversion" pair(sys8)=sys8(A)(B) | Yes, 10+ probes | Right(6)/empty |
| Var(253) as function/OOB syscall | Yes, 6+ probes | Right(6)/empty |
| Valid filesystem paths as string args | Yes (/bin/sh, /home/gizmore) | Right(3) still |

## 14. Brute Force Hash Cracking

Target: `sha1^56154(answer) == "9252ed65ffac2aa763adb21ef72c0178f1d83286"`

| Space | Result |
|---|---|
| Printable ASCII 1–3 chars | No match |
| Printable ASCII 4 chars | No match |
| Printable ASCII 5 chars (GPU) | No match |

Each candidate requires 56,154 SHA1 iterations — brute force is extremely expensive.

---

## Summary Statistics

- **500+ unique syscall 8 test cases** across all categories
- **5,346 exhaustive 3-leaf term combinations** tested
- **200+ probe scripts** written
- **10+ probes testing pair(sys8) consumer inversion** — all failed
- **6+ probes testing Var(253) in function position** — all failed
- **Zero positive signals** — every test returned Right(6), Right(3), empty, or timeout
- **All LLM suggestions (2 rounds) tested and failed**

## 7. The "C++ Memory Leak / ROP" Fallacy (LLM v10/v11/v12)
Tested:
- Passing raw Backdoor `A` and `B` directly to `sys2` (Write) expecting a native pointer dump. (e.g., `sys201(nil) (Bad QD)`) -> `EMPTY`
- "3-Leaf Native Pipe" `sys201(nil) (sys2) (nil)` -> `EMPTY`
- "V253 OOB Array Extraction" mapping `echo(Var(251))` into `sys2` -> `EMPTY`
- Pure Math Paradoxes (`sys14 sys201 sys8`, `sys8 sys8 sys8`, `sys201 sys201 sys201`) -> `EMPTY`

**Conclusion**: The C++ evaluator gracefully handles paradoxes by either silently crashing via OOB (caught internally) or evaluating to WHNF and halting. It DOES NOT leak native memory pointers through `sys2` or `sys4`. `sys2` strictly expects a Scott-encoded list, and unbound variables do not automatically dereference to the global array unless explicitly accessed through a syscall that reads globals.

## 8. The "Silent Success" Hallucination
Tested:
- Sending mathematically valid but non-printing payloads (like the Ouroboros `sys8 sys8 sys8`) and checking WeChall score.
**Conclusion**: WeChall uses an anonymous raw TCP socket. There is no authentication or session binding. The server *cannot* know who connected, so "silent success" auto-awarding points is architecturally impossible. The solution MUST force the VM to output the flag string to our socket. If there is no TCP write, we haven't solved it.

## 9. Detailed v12 Reduction Traces (Why "Pure Math Paradoxes" Return EMPTY)

The v12 payloads (`sys14 sys201 sys8`, `sys8 sys8 sys8`, `sys201 sys201 sys201`) all returned EMPTY. Here is **why** each fails:

### Payload 1: `App(App(Var(14), Var(201)), Var(8))` — sys14(sys201)(sys8)

```
Step 1: Evaluator sees App(App(echo, Var(201)), Var(8)).
  - Echo is a C++ primitive. Intercepts App(App(echo, arg), cont).
  - arg = Var(201) — the RAW global variable, NOT the result of calling syscall 201.
  - Echo wraps it: Left(Var(201)) = λl.λr.(l Var(203)) [Var(201) shifts to 203 under 2 lambdas]
  - Calls cont(Left(Var(203))) = Var(8)(Left(Var(203))) = sys8(Left(Var(203)))
Step 2: sys8 is a C++ primitive. Intercepts App(App(sys8, arg), cont).
  - But there IS no second argument (cont). sys8(Left(Var(203))) is a partial application.
  - VM reaches WHNF and stops → EMPTY.
```

**Critical misconception corrected**: `echo(Var(201))` wraps the raw variable reference, NOT the backdoor pair. To get the pair you must CALL `sys201(nil)` = `App(App(Var(201), nil), cont)`.

### Payload 2: `App(App(Var(8), Var(8)), Var(8))` — sys8(sys8)(sys8)

```
Step 1: Evaluator sees App(App(sys8, sys8), sys8).
  - Syscall dispatch fires: sys8(arg=sys8, cont=sys8).
  - sys8 evaluates with arg=sys8 → returns Right(6).
  - Calls cont(Right(6)) = sys8(Right(6)).
Step 2: sys8 has one argument Right(6) but no continuation.
  - Partial application → WHNF → EMPTY.
```

**Key insight**: sys8 is NOT a lambda you can beta-reduce. It's a C++ primitive. The third Var(8) serves as continuation for the first call but becomes an argless call itself.

### Payload 3: `App(App(Var(201), Var(201)), Var(201))` — sys201(sys201)(sys201)

```
Step 1: sys201's C++ hook checks: is arg == nil? 
  - arg = Var(201) which is NOT nil → Right(2) "Invalid argument."
  - Calls cont(Right(2)) = Var(201)(Right(2)).
Step 2: sys201 checks: is Right(2) == nil? No → Right(2) again.
  - But now there's no continuation → partial application → WHNF → EMPTY.
```

### Why ALL print-less payloads return EMPTY

**The 3-Leaf Printing Paradox**: For ANY output to appear on the TCP socket, the program MUST call `sys2` (write) or have QD as its continuation (which internally calls `sys4` then `sys2`). None of the v12 payloads contain a printing syscall or QD. Without a write instruction, the VM evaluates to WHNF and stops. No bytes go to the socket. This is not a subtle math error — there is literally no instruction to write anything.
