# BrownOS v25 — Computed-Head Hypothesis Retired, What's Left?

**Repo**: `https://github.com/SynthNoirLabs/brownos2`  
**Date**: 2026-03-02  
**Previous**: `prompt_v24.md` (CPS adapter algebra confirmed)

---

## What happened since v24

You proposed testing **function-position provenance**: whether sys8's permission gate checks the syntactic head (`Var(8)` in source) vs the runtime value after β-reduction. We ran 18 probes.

### Result: hypothesis DEAD

The B combinator (`λa.λb. a(b)`, from the backdoor pair) successfully delivers any syscall to head position via β-reduction. Normal syscalls dispatch correctly. **sys8 still returns Right(6) through every computed-head path.**

```
Phase 1 — Controls (all pass ✅):
  B(name)(N256)→PS          = "wtf"              (matches direct call)
  B(readfile)(N256)→PS      = "Uhm... yeah..."   (matches direct call)
  B(error_string)(N6)→PS    = "Permission denied" (matches direct call)

Phase 2 — sys8 via computed head (all Right(6) ❌):
  B(sys8)(N0)→PSE           = "Permission denied"
  B(sys8)(N256)→PSE         = "Permission denied"
  B(sys8)(K*)→PSE           = "Permission denied"
  I(sys8)(N0)→PSE           = "Permission denied"
  K(sys8)(junk)(N0)→PSE     = "Permission denied"
  (λx.x)(sys8)(N0)→PSE     = "Permission denied"
  (λf.λx.f(x)(PSE))(sys8)(N0) = "Permission denied"

Phase 3 — Echo producing the head function:
  echo(name)→extract→B→name(N256)   = "wtf"              ✅
  echo(sys8)→extract→B→sys8(N0)     = "Permission denied" ❌

Phase 4 — Backdoor pair as combinator source:
  bdoor→pair→B→name(N256)   = "wtf"              ✅
  bdoor→pair→B→sys8(N0)     = "Permission denied" ❌
```

**Conclusion**: Permission check is **runtime-based**. The evaluator identifies the sys8 primitive after β-reduction, regardless of how it reaches head position.

### Bugs in your proposed payloads (corrected in our probes)

1. **Your probes 3–4**: B as echo's continuation doesn't unwrap Either. `B(Left(name))(K*) = Left(name)(K*) = K*(name) = λb.b`, not `name`. We fixed with explicit Either-unwrapping continuations.
2. **Your probes 5–6**: PS/PSE embedded at depth 2 had wrong write ref (Var(4) at depth 4 = global[0], should be Var(6) = global[2] = write). We built `make_PS(depth)` / `make_PSE(depth)` factories that correctly shift global refs.
3. **Your PSE**: Same Var(4)→Var(6) bug at depth 4 from v23/v24. Inside `λe → λc → λr2 → λstr`, write (global[2]) = Var(2 + 4 lambdas) = Var(6), not Var(4).

---

## Complete axis retirement table (cumulative)

| Axis | Probes | Verdict |
|------|--------|---------|
| sys8 argument value (ints, strings, terms, file contents) | 700+ | Right(6) always |
| sys8 argument structure (lambdas, pairs, ω, combinators) | 50+ | Right(6) always |
| sys8 argument provenance (echo-produced, readfile-produced, backdoor-produced) | 26 | Right(6) always |
| sys8 continuation variants | 100+ | Right(6) always |
| Forged Either tokens | 40 | Right(6) always |
| Runtime-vs-wire exploit | 10 | Retired |
| Provenance sensitivity (live vs literal) | 5 | None |
| Side effects during eager decode | 5 | None reach socket |
| Hidden VFS nodes (0–280, special IDs) | 30+ | Only 256 exists |
| **CPS adapter composition** (echo→sys8, bdoor→sys8, readfile→sys8) | **26** | **Adapters work, sys8 still Right(6)** |
| **Computed head / function-position** (B, I, K, λ-wrappers, echo→B, bdoor→B) | **18** | **Runtime check, not syntactic** |

**Total probes on sys8**: ~1000+. Every structural class, every composition path, every wrapper — all Right(6).

---

## What we now know for certain

1. **CPS adapter algebra works perfectly**: `C_g = λr. r(g)(K*)` routes Left/Right between any syscalls
2. **Echo IS a generic Left producer**: `echo(X)` → `Left(X)`, routable to any consumer
3. **Computed heads work**: B(f)(x) = f(x) dispatches correctly for all normal syscalls
4. **sys8's permission check is runtime-based**: it identifies the sys8 primitive after reduction
5. **Backdoor only accepts nil**: `backdoor(X≠K*)` → `Right(2)` always
6. **backdoor(K*) returns Left(pair)**: pair = `λf.λg. f(A)(B)` where A=ω, B=applicator

## What we've proven we CAN do

- Read any file by ID (`readfile(id)→PS`)
- Get any file's name (`name(id)→PS`)
- List directory contents (`readdir(id)→PS`)
- Convert error codes to strings (`error_string(code)→PS`)
- Quote any term to bytecode (`quote(term)→PS`)
- Echo any term through Left (`echo(term)→adapter→consumer`)
- Route Left/Right values between syscalls (`C_g`, `R_g` adapters)
- Compose multi-step pipelines (4+ step chains work)
- Compute syscall heads via β-reduction (B, I, K wrappers)
- Extract pair components from backdoor (pair(K*)=B, pair(K)=A)

## What we CANNOT do

- Make sys8 return anything other than Right(6)

---

## Remaining live directions (honest assessment)

We've now retired the three most promising axes: argument space, adapter composition, and computed head. What's genuinely left?

### 1. Something about the evaluator we haven't modeled

The hint "IT is always casting its dark magic, it wont even realize we hacked it" implies tricking the evaluator. We've tested:
- ❌ Different arguments
- ❌ Different continuations
- ❌ Different composition paths
- ❌ Different head-arrival mechanisms

What we HAVEN'T tested: **whether there's an evaluator behavior that none of these probe categories reach.** For example:
- Does the evaluator have a special case for terms that DON'T reduce to a syscall call? (e.g., a term that produces the answer as a side effect of reduction, without ever "calling" sys8)
- Is there an eval/apply distinction where some reduction paths go through a different code path?

### 2. The answer might not come from sys8 at all

The challenge says "make syscall 8 succeed." But what if "succeed" means something different than we think? What if sys8 is a decoy and the answer is computed from things we CAN already read?

Known readable data:
- `/etc/passwd`: `gizmore:GZKc.2/VQffio:1000:1000:...`
- Command log (file 65): `ilikephp` (the password)
- File 256: `wtf`
- Root dir name: `/`
- Pair bytecode: `010000fdfefefd0100fdfefefdfefe`

None of these match `sha1^56154(answer) = 9252ed65ffac2aa763adb21ef72c0178f1d83286`.

### 3. Hidden file at an untested ID

We scanned 0–280 and a few special IDs. The additive encoding supports arbitrarily large IDs. There could be a file at some large ID we haven't tried. But without a clue about WHICH ID, this is needle-in-haystack.

### 4. The "3 leafs" hint might be MORE literal than we think

"My record is 3 leafs IIRC." We interpreted this as the size of an adapter. But what if it literally means the smallest PROGRAM that solves the challenge has exactly 3 Var references?

The `probe_3leaf_full_sweep.py` already tested all `((Var(a) Var(b)) Var(c))` patterns (3 leaves, left-associated). But there are other 3-leaf shapes:
- `(Var(a) (Var(b) Var(c)))` — right-associated
- `(Var(a) λ.(Var(b) Var(c)))` — with a lambda
- Other structures involving lambdas between the 3 vars

### 5. Something about the cheat sheet we missed

"The second example in the cheat sheet is useful in figuring out crucial properties. The different outputs betray some core structures."

The second example is `?? ?? FD QD FD`. We've used this to map the syscall table. But "crucial properties" and "core structures" might mean something deeper about the Scott encodings or the CPS mechanism itself.

---

## Your call

We're 1000+ probes deep with zero progress on sys8. The three strongest remaining hypotheses from the hint set are:

1. **Non-standard 3-leaf shapes** (right-associated, lambda-containing)
2. **The answer is derived from readable data, not from sys8 returning Left**
3. **There's an evaluator mechanism we haven't conceptualized yet**

What direction?

**Probe scripts**: `probe_cps_adapters.py`, `probe_computed_head.py` (both in repo)
**Full docs**: `BROWNOS_MASTER.md`, `solve_brownos_answer.py`
