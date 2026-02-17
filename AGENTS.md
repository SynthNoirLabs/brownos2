# Repository Guidelines

**Updated:** 2026-02-16

## Overview

WeChall "The BrownOS" reverse-engineering project. Lambda calculus VM over TCP. Goal: make syscall 8 succeed.

## Structure

```
brownos2/
├── solve_brownos.py         # Minimal demo (syscall 0x2A)
├── solve_brownos_answer.py  # Full reference client (filesystem + password)
├── registry_globals.py      # Global registry utilities
├── BROWNOS_MASTER.md        # Complete technical docs — single source of truth
├── challenge.html           # Challenge page snapshot
├── utils/
│   ├── decode_backdoor.py   # Backdoor decoder
│   └── parse_qd.py          # QD cheat sheet parser
├── forums/                  # Offline forum HTML dumps
└── archive/                 # All historical research
    ├── old_probes/          # Early probe scripts
    ├── probes_jan2026/      # January 2026 probes
    ├── probes_feb2026/      # February 2026 probes
    ├── old_tests/           # Historical test scripts
    ├── scripts/             # Decode/analyze/trace utilities
    ├── brute_force/         # Brute-force source code and output logs
    ├── logs/                # Probe output logs
    ├── data/                # JSON data snapshots (env maps, scan results)
    └── docs/                # Previous documentation versions
```

## Where to Look

| Task | Location |
|------|----------|
| Understand protocol | `BROWNOS_MASTER.md` sections 1–3 |
| Syscall reference | `BROWNOS_MASTER.md` section 6 |
| Data encodings | `BROWNOS_MASTER.md` sections 4–5 |
| Filesystem layout | `BROWNOS_MASTER.md` section 7 |
| Gotchas & anti-patterns | `BROWNOS_MASTER.md` section 10 |
| Open questions | `BROWNOS_MASTER.md` section 11 |
| Working client example | `solve_brownos_answer.py` |
| Quick test | `solve_brownos.py` |
| Past probe scripts | `archive/probes_feb2026/`, `archive/probes_jan2026/`, `archive/old_probes/` |
| Past analysis results | `archive/logs/`, `archive/data/`, `archive/docs/` |

## Commands

```bash
python3 solve_brownos.py           # Basic connection test
python3 solve_brownos_answer.py    # Full filesystem exploration
python3 -m compileall .            # Syntax check
```

## Conventions

- Python 3, 4-space indent, PEP 8-ish
- `snake_case` functions/vars, `UPPER_SNAKE_CASE` constants (`FD`, `FE`, `FF`, `QD`)
- `@dataclass(frozen=True)` for terms: `Var`, `Lam`, `App`
- No linter enforced; keep diffs minimal
- Intentionally no package layout — scripts in root

## Anti-Patterns (THIS PROJECT)

### Protocol
- **NEVER** send ASCII — raw bytes only
- **NEVER** forget `0xFF` end-of-code marker
- **NEVER** use `Var(i)` where `i ∈ {0xFD, 0xFE, 0xFF}` in terms passed to `quote`

### Network
- **AVOID** tight loops — service is shared, rate-limits
- **AVOID** payloads >2KB — "Term too big!" error
- Use exponential backoff on retries

### De Bruijn Indices
- **REMEMBER** indices shift under lambdas — raw bytes mislead
- **REMEMBER** echo's `Left` payload is under 2 lambdas (+2 shift)

## Gotchas

| Trap | Reality |
|------|---------|
| No output | Normal if no explicit write — not failure |
| `Var(0)` as syscall | Not a syscall — hangs until timeout |
| IDs only 0–255 | False — encoding is additive, supports >255 |
| QD is optional | Without QD you're blind — use it early |

## Testing

No formal test suite. When changing protocol/decoder:
1. Add reproducible snippet
2. Validate against known response (e.g., `0x04` quote, `0x07` read `/etc/passwd`)

## Commit Guidelines

Imperative messages: "Add dirlist decoder"

PRs must include:
- What changed, why (1–3 bullets)
- Validation commands + output excerpt
- Network impact notes (timeouts, rate-limits)
