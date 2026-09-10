# reap: one set of commands for local and CI. If it passes here it passes there.
#
# Everyday loop:   just            (runs ci)
# Manual release:  just release v0.2.0
#                  (publish needs `gh` auth)

default: ci

# gates: formatting, module hygiene, vet, tests
ci: fmt-check tidy-check vet test

# gofmt must be a no-op. Checks before/after rather than against HEAD, so it
# works on a tree with unrelated work in progress, locally as in CI. A real
# difference fails, after having written the fixed files: run again, commit.
fmt-check:
	#!/bin/sh
	set -eu
	if command -v sha256sum >/dev/null 2>&1; then HASH="sha256sum"; else HASH="shasum -a 256"; fi
	sum() { find . -name '*.go' -not -path './.git/*' -print0 | sort -z | xargs -0 cat | $HASH | cut -d' ' -f1; }
	before=$(sum)
	gofmt -w .
	if [ "$before" != "$(sum)" ]; then
		echo "gofmt -w . changed files; gofmt -l says:" >&2
		gofmt -l . >&2
		exit 1
	fi

# go mod tidy must be a no-op, same before/after contract as fmt-check.
tidy-check:
	#!/bin/sh
	set -eu
	cp go.mod go.mod.bak
	cp go.sum go.sum.bak
	trap 'rm -f go.mod.bak go.sum.bak' EXIT
	go mod tidy
	if ! cmp -s go.mod go.mod.bak || ! cmp -s go.sum go.sum.bak; then
		echo "go mod tidy changed go.mod/go.sum; run it and commit" >&2
		exit 1
	fi

vet:
	go vet ./...

# Serialized: the fixture suite spans real git/jj repos and PTY-shaped
# choreography; -p 1 keeps package load from stepping on itself and keeps a
# red run honest (a flaky green hides regressions in a tool that deletes).
test:
	go test -p 1 ./... -count=1 -timeout 40m

# cross-compile every release target into dist/, with version info stamped in.
dist TAG:
	#!/bin/sh
	set -eu
	rm -rf dist && mkdir -p dist
	COMMIT="$(git rev-parse --short HEAD)"
	DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	LD="-s -w -X github.com/deblasis/reap/internal/cli.Version={{TAG}} -X github.com/deblasis/reap/internal/cli.Commit=$COMMIT -X github.com/deblasis/reap/internal/cli.Date=$DATE"
	for target in windows/amd64 windows/arm64 darwin/arm64 darwin/amd64 linux/amd64 linux/arm64; do
		os="${target%/*}"; arch="${target#*/}"
		out="dist/reap_${os}_${arch}"
		[ "$os" = "windows" ] && out="${out}.exe"
		echo "building $out"
		CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$LD" -o "$out" ./cmd/reap
	done
	if command -v sha256sum >/dev/null 2>&1; then SUM="sha256sum"; else SUM="shasum -a 256"; fi
	(cd dist && $SUM reap_* > SHA256SUMS && cat SHA256SUMS)

# publish dist/ as the GitHub release for TAG (create or upload --clobber)
publish TAG:
	#!/bin/sh
	set -eu
	notes="$(mktemp)"
	cat > "$notes" <<NOTES
	Cross-compiled binaries for windows/amd64, windows/arm64, darwin/arm64, darwin/amd64, linux/amd64 and linux/arm64, plus SHA256SUMS.

	Install (both scripts verify the SHA-256 before installing):

	    curl -fsSL https://raw.githubusercontent.com/deblasis/reap/main/install.sh | sh

	    irm https://raw.githubusercontent.com/deblasis/reap/main/install.ps1 | iex

	reap deletes directories for a living; read the safety model in the
	README before pointing it at anything you love.
	NOTES
	if gh release view "{{TAG}}" --repo deblasis/reap >/dev/null 2>&1; then
		gh release upload "{{TAG}}" dist/* --repo deblasis/reap --clobber
	else
		gh release create "{{TAG}}" dist/* --repo deblasis/reap --title "reap {{TAG}}" --notes-file "$notes"
	fi
	rm -f "$notes"

# full manual release from this machine: just release v0.2.0
release TAG: (dist TAG) (publish TAG)
