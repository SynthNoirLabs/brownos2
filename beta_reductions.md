# Beta-reduction analysis for syscalls applied to backdoor pair

The backdoor at syscall 201 returns a Scott pair `pair(A,B)` where:
- `A = λa.λb. b b`
- `B = λa.λb. a b`
- `pair(A,B) = λs. s A B`

When `pair` is applied to a syscall `X`, we get:
`pair(X) = (λs. s A B) X = X A B`

In BrownOS, syscalls are invoked as `X arg cont`. Thus, `X A B` means:
- `arg = A = λa.λb. b b`
- `cont = B = λa.λb. a b`

## Syscall 8 (Solution)
`sys8(A)(B)`
- Argument `A` is passed to `sys8`.
- If `sys8` succeeds, it calls `B` with the result: `B result`.
- If `sys8` fails, it returns `Right(error_code)`.
- Our probes show `sys8(A)(B)` returns `Right(6)` (Permission Denied).

## Syscall 14 (Echo)
`echo(A)(B)`
- `echo` returns `Left(A)`.
- The continuation `B` is applied to this result: `B (Left A)`.
- `B = λa.λb. a b`, so `B (Left A) = λb. (Left A) b`.
- If we apply this to some `QD`, we get `(Left A) QD = QD A`.
- Our probes confirm `echo(A)(QD)` returns `Left(A)`.

## Syscall 2 (Write)
`write(A)(B)`
- `write` expects a Scott list of bytes. `A` is not a valid list.
- Probes show `write(A)(QD)` returns `Right(2)` (Invalid argument).

## Syscall 4 (Quote)
`quote(A)(B)`
- `quote` returns the bytecode of `A` as a byte list.
- `quote(A)(QD)` returns `Left(bytes_of_A)`.

## Syscall 5 (Readdir)
`readdir(A)(B)`
- `readdir` expects an integer ID. `A` is not a valid integer.
- Probes show `readdir(A)(QD)` returns `Right(2)` (Invalid argument).

## Summary
The "3-leaf" program `((201 nil) X)` is equivalent to `X A B`. This applies syscall `X` to the combinator `A` with `B` as the continuation. For `X=8`, this results in `Permission Denied`, suggesting that neither `A` nor the combination is the key to unlocking the solution via syscall 8 directly.
