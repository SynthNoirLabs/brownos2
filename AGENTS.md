# Repository Guidelines

## Project Structure & Module Organization

- `solve_brownos_answer.py`: Primary reference client (term parsing/encoding, syscall helper, decoding helpers).
- `solve_brownos.py`: Minimal demo client (calls syscall `0x2A` and decodes the returned string).
- `forums/`: Offline HTML dumps of relevant WeChall forum threads (used as hint references).
- `challenge.html`: Saved copy of the WeChall challenge page (includes the “QD” cheat sheet).
- `BROWNOS_LEARNINGS*.md`: Reverse-engineering notes; `*_SELF_CONTAINED.md` is designed for copy/paste into other tools/LLMs.

This repo is intentionally lightweight (no Python package layout). Keep new helpers as small scripts in the repo root unless there’s a clear need to introduce a package.

## Build, Test, and Development Commands

- `python3 solve_brownos.py`: Connects to `wc3.wechall.net:61221` and prints the syscall `0x2A` output.
- `python3 solve_brownos_answer.py`: Connects to the service and demonstrates filesystem/syscall decoding (prints the recovered `gizmore` password from `/etc/passwd` + `.history`).
- `python3 -m compileall .`: Quick syntax check for all scripts.

Network access is required to run the clients; avoid tight loops (the remote service is shared and may rate-limit).

## Coding Style & Naming Conventions

- Python 3, 4-space indentation, PEP 8-ish formatting.
- Prefer explicit types where helpful; keep data structures as `@dataclass`es (`Var`, `Lam`, `App`).
- Naming: `snake_case` for functions/vars, `UPPER_SNAKE_CASE` for constants (`FD`, `FE`, `FF`, `QD`).

No formatter/linter is enforced in-repo; keep diffs minimal and readable.

## Testing Guidelines

There is no formal test suite. When changing protocol/decoder logic:

- Add a small reproducible snippet (or script) that exercises the behavior.
- Validate against at least one known syscall response (e.g., quoting via `0x04`, reading `/etc/passwd` via `0x07`).

## Commit & Pull Request Guidelines

This repo currently has no Git history. Use clear, imperative messages (e.g., “Add dirlist decoder”).

For PRs, include:

- What changed and why (1–3 bullets).
- How you validated (commands run + short output excerpt).
- Any network/service-impact notes (timeouts, retries, rate-limit considerations).

