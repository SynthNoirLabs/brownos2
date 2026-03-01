# Syscall 8 LLM Suggestion Audit Report

Date: 2026-02-23
Project: BrownOS (WeChall)
Status: UNSOLVED

## Purpose
This report records, with evidence, what external LLMs suggested and what was actually tested in the BrownOS repo and against the live service (`wc3.wechall.net:61221`).

---

## Suggested Items

The audited suggestions were:

1. G1: feed raw echo results to sys8 (`sys8(echo(g251/g252))`) without unwrap.
2. G2: generate runtime-shifted unquotable terms (`Var(253..255)`) and feed sys8.
3. G3: use per-connection nonce from `access.log` in the same program.
4. G4: use backdoor pair/combinator values (A, B, pair, combinations) as capability tokens.
5. G5: sweep sys8 with globals as argument.
6. G6: scan sparse high/CTF-like IDs for hidden files.
7. Gemini-specific claims: call-by-name trap, duck-typed pair path, shifted-QD fix, and guaranteed 3-leaf chain.

---

## What Was Executed

### A) ChatGPT proposal script
- File: `archive/probes_feb2026/probe_sys8_next.py`
- Modes run:
  - `--skip-globals --skip-id-scan`
  - `--skip-id-scan --globals-start 200 --globals-end 252`
  - `--skip-globals`

### B) Direct payload checks for breakthrough claims
- File: `archive/probes_feb2026/probe_llm_payloads.py`
- Included explicit tests of:
  - `(((sys201 nil) sys8) QD)`
  - echo-chain variants
  - shifted-QD variant

### C) Follow-up reruns (2026-02-23)
- `archive/probes_feb2026/probe_phase2_continuation.py`
- `archive/probes_feb2026/probe_phase2_fuzzer.py`
- `archive/probes_feb2026/probe_high_index_syscall.py`

### D) Historical logs cross-checked
- `archive/logs/probe_3leaf_systematic_output.log`
- `archive/logs/probe_nonsyscall_sweep.log`

---

## Evidence Summary

## G1-G6 outcomes
Source: `archive/docs/llm_suggestion_analysis_chatgpt_probe_sys8_next.md`

| Group | Tests | Result |
|---|---:|---|
| G1 | 2 | Permission denied baseline |
| G2 | 6 | Permission denied baseline |
| G3 | 3 | 2 Permission denied, 1 side-effect false positive |
| G4 | 9 | Permission denied baseline |
| G5 | 53 (200..252) | Permission denied baseline |
| G6 | 12 | No such directory/file |

Interpretation: no syscall-8 unlock signal in G1-G6.

## Continuation-space rerun (after detector fix)
Source: live run of `probe_phase2_continuation.py` (2026-02-23)

- Script summary: **No breakthroughs**.
- Requests: 32
- Dominant categories:
  - `EMPTY` (majority)
  - encoded `Right(6)` artifacts (`HEX:000302...`)
  - textual `Permission denied`

Interpretation: previous breakthrough labels were classifier artifacts.

## Phase2 fuzzer rerun
Source: live run of `probe_phase2_fuzzer.py`

- Requests: 37
- sys8-targeting groups remained Permission denied.
- "Flagged" outputs were sys2 class-sensitivity (`Invalid argument` vs text write), not sys8 bypass.

## High-index/boundary rerun
Source: live run of `probe_high_index_syscall.py`

- Boundary globals 240..252 unchanged.
- `backdoor -> sys8(result)` and tested CPS chains remained `R(6)`.
- 3-leaf sweeps:
  - `((8 X) Y)` - 361 combos, no hits
  - `(8 (X Y))` - 361 combos, no hits

## Historical consistency checks

- `archive/logs/probe_3leaf_systematic_output.log`: extensive 3-leaf search with repeated `EMPTY` outcomes.
- `archive/logs/probe_nonsyscall_sweep.log`: `H8-BASE` and `H8-PAIR` both in `RIGHT_6` bucket.

---

## Claim-by-Claim Verdicts

| Claim | Verdict | Evidence |
|---|---|---|
| G1 unwrapped-echo bypass | Rejected | G1 remained Permission denied |
| G2 unquotable runtime bypass | Rejected | G2 remained Permission denied |
| G3 access.log nonce unlock | Rejected | G3A/G3B denied; G3C side-effect only |
| G4 backdoor combinator capability | Rejected | G4 and prior combinator matrices fail |
| G5 global argument trigger | Rejected/already exhausted | sweeps did not unlock |
| G6 hidden-ID CTF numbers | Negative for tested targets | No such directory/file responses |
| "Guaranteed" 3-leaf chain | Rejected | direct payload tests + sweeps no success |
| shifted-QD rescue | Rejected | continuation reruns show no unlock |

---

## Fixes and Corrections Applied

1. **False breakthrough detector fixed**
- File: `archive/probes_feb2026/probe_phase2_continuation.py`
- Change: stricter `is_breakthrough(label, result)` to avoid marking baseline artifacts as breakthroughs.

2. **Master synthesis updated**
- File: `BROWNOS_MASTER.md`
- Added 2026-02-23 follow-up documenting rerun outcomes and artifact correction.

3. **Rejected-answer clarity maintained**
- `BROWNOS_MASTER.md` section 11a and `README.md` status explicitly list known rejected candidate answers.

---

## Final Status

- Syscall 8 remains unsolved.
- No tested LLM-proposed path produced a success signal.
- Apparent anomalies were attributable to continuation/output artifacts and classifier overreach.
- Obvious WeChall candidate submissions are already rejected (see `BROWNOS_MASTER.md` section 11a).

---

## Canonical Evidence Files

- `archive/docs/llm_suggestion_analysis_chatgpt_probe_sys8_next.md`
- `BROWNOS_MASTER.md`
- `archive/probes_feb2026/probe_phase2_continuation.py`
- `archive/probes_feb2026/probe_phase2_fuzzer.py`
- `archive/probes_feb2026/probe_high_index_syscall.py`
- `archive/probes_feb2026/probe_llm_payloads.py`
- `archive/probes_feb2026/probe_sys8_next.py`
- `archive/logs/probe_3leaf_systematic_output.log`
- `archive/logs/probe_nonsyscall_sweep.log`
