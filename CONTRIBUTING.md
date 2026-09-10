# Contributing

Thanks for wanting to help. The project is small and deliberately narrow; the
fastest way to get a change in is to keep it that way.

## Before you write code

Open an issue first for anything that is not an obvious bug fix. `reap` has
an explicit scope and non-goals list in the
[README](README.md#scope-and-non-goals); a change that fights it will be
declined no matter how well it is built.

## The gates

The gate commands are the same locally and in CI, defined once in the
[`justfile`](justfile):

```sh
just ci        # gofmt no-op, go mod tidy no-op, go vet, the full suite
```

The suite runs serialized (`go test -p 1`): it builds real repositories and
drives real PTYs, and a flaky green hides regressions in a tool that deletes.
There is no hosted CI; the local gate is the gate.

## Sending the change

Keep pull requests small and single-purpose. New behaviour needs a test that
fails without it, and anything that changes the interface (commands, flags,
exit codes, the `scan --json` / `apply --json` schemas) needs a line in
the README.

The `scan --json` and `apply --json` schemas are contracts: fields are
added, never renamed or removed.
