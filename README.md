# BrownOS Challenge

WeChall "The BrownOS" — Difficulty 10/10, ~4 solvers in 12 years.

## Challenge Overview

BrownOS is a lambda calculus-based "operating system" accessible via TCP. The goal is to make syscall 8 (`/bin/solution`) return success instead of "Permission denied" (error 6).

**Server**: `wc3.wechall.net:61221`

## Repository Structure

```
brownos2/
├── solve_brownos.py         # Minimal demo client (syscall 0x2A)
├── solve_brownos_answer.py  # Full reference client (filesystem + password recovery)
├── registry_globals.py      # Global registry utilities
├── BROWNOS_MASTER.md        # Complete reverse-engineering documentation
├── challenge.html           # Saved copy of challenge page
├── utils/
│   ├── decode_backdoor.py   # Backdoor decoder utility
│   └── parse_qd.py          # QD cheat sheet parser
├── forums/                  # Offline HTML dumps of WeChall forum threads
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

## Quick Start

```bash
# Basic connection test (syscall 0x2A)
python3 solve_brownos.py

# Full reference client (filesystem exploration + password recovery)
python3 solve_brownos_answer.py
```

## Key Technical Details

- **Protocol**: Lambda calculus terms encoded as postfix bytecode (FD=App, FE=Lam, FF=EOF)
- **Syscalls**: CPS-style — `((syscall arg) continuation)`, use QD as continuation to print results
- **Known syscalls**: 0x01 (error string), 0x02 (write), 0x04 (quote), 0x05 (readdir), 0x06 (name), 0x07 (readfile), 0x08 (solution), 0x0E (echo), 0x2A (decoy), 0xC9 (backdoor)
- **Error codes**: 0=Exception, 1=NotImpl, 2=InvalidArg, 3=NoSuchFile, 4=NotDir, 5=NotFile, 6=PermDenied, 7=RateLimit

## Status

**UNSOLVED** — All approaches return error 6 (Permission denied) on syscall 8. All obvious answer candidates (`ilikephp`, `gizmore`, `GZKc.2/VQffio`, `42`, `towel`, `dloser`, `omega`, `echo`, `253`, `3leafs`, `FD`, `1`) have been submitted to WeChall and **rejected**.

## Documentation

All technical documentation is in [BROWNOS_MASTER.md](BROWNOS_MASTER.md) — protocol, syscalls, filesystem, data encodings, gotchas, and full research log.
