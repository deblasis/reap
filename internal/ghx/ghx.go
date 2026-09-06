// Package ghx answers one question for the whole scan: which (repository,
// branch) heads have open PRs authored by this user?
//
// Two-phase, pinned against gh 2.83 (where `search prs` exposes NO head-ref
// fields at all — the field-name test caught this on its first run):
//
//  1. one `gh search prs --author @me --state open --json repository` call
//     finds the base repos with open authored PRs (usually a handful);
//  2. one `gh pr list -R <base> --author @me --state open --json
//     headRefName,headRepository` per HIT repo only — not per candidate —
//     recovers the head branches.
//
// The head slug: pr list's headRepository.nameWithOwner comes back EMPTY in
// 2.83, but for authored PRs the head fork is the author's own, so the slug
// is <my-login>/<headRepository.name> (or the nameWithOwner when populated).
//
// Failure discipline mirrors gitx/jjx: gh missing, auth-expired, timing out,
// unparseable, or TRUNCATED at the result limit all mean the fact is
// unavailable for every dir — never "no open PRs". A silently narrowed PR set
// is exactly the false-SAFE the invariants forbid.
package ghx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// searchLimit is the --limit for the search call. gh's search caps at 1000;
// 200 is comfortably above any realistic personal open-PR count, and hitting
// it exactly is treated as truncation (unavailable), not a complete answer.
const searchLimit = 200

// maxBases caps the phase-2 fan-out: repos with open authored PRs. Past the
// cap the whole PR set degrades to Unavailable (never silently narrowed).
// 50 covers the realistic personal-fleet ceiling (this account measured 50
// with open PRs) while bounding the phase; the pool keeps it inside budget.
const maxBases = 50

// Client runs gh with a budget.
type Client struct {
	Budget time.Duration
}

// PRHeads is the parsed result: heads maps "owner/repo" -> open head branch set.
type PRHeads struct {
	Unavailable bool
	Truncated   bool
	Why         string
	heads       map[string]map[string]bool
}

type searchRow struct {
	Repository struct {
		Name          string `json:"name"`
		NameWithOwner string `json:"nameWithOwner"`
	} `json:"repository"`
}

type prRow struct {
	HeadRefName string `json:"headRefName"`
	HeadRepo    struct {
		Name          string `json:"name"`
		NameWithOwner string `json:"nameWithOwner"`
	} `json:"headRepository"`
}

// OpenPRHeads performs the search plus the per-hit-repo pr lists.
func (c Client) OpenPRHeads() PRHeads {
	var p PRHeads
	if c.Budget <= 0 {
		p.Unavailable = true
		p.Why = "no gh exec budget configured"
		return p
	}
	out, why := c.run("search", "prs", "--author", "@me", "--state", "open",
		"--json", "repository", "--limit", fmt.Sprint(searchLimit))
	if why != "" {
		p.Unavailable = true
		p.Why = why
		return p
	}
	var rows []searchRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		p.Unavailable = true
		p.Why = fmt.Sprintf("gh search: unparseable output: %v", err)
		return p
	}
	if len(rows) == searchLimit {
		p.Truncated = true
		p.Unavailable = true
		p.Why = fmt.Sprintf("gh search: result limit (%d) reached; the PR set cannot be trusted as complete", searchLimit)
		return p
	}
	bases := map[string]bool{}
	for _, r := range rows {
		// search's repository object populates nameWithOwner (unlike pr
		// list's headRepository, which leaves it empty — pinned by the live
		// parse test).
		if s := SlugFromURL(r.Repository.NameWithOwner); s != "" {
			bases[s] = true
		}
	}

	login := c.login()
	p.heads = map[string]map[string]bool{}

	// Bounded, parallel fan-out. The spec's budget is "gh is one call"; the
	// two-phase shape (forced by gh 2.83's search lacking head fields) makes
	// it 2 + N. Measured on this account, N was 51 and the serial version
	// alone blew 150s — so the per-base calls run under a small pool with a
	// total wall budget and a base cap; exceeding either degrades the whole
	// set to Unavailable (truncated semantics) rather than silently
	// narrowing which PRs are known.
	if len(bases) > maxBases {
		p.Unavailable = true
		p.Why = fmt.Sprintf("gh: %d repos with open PRs exceeds the fan-out cap (%d); PR set cannot be trusted as complete", len(bases), maxBases)
		return p
	}
	type baseResult struct {
		base string
		prs  []prRow
		why  string
	}
	results := make(chan baseResult, len(bases))
	deadline := time.After(c.Budget * 4) // total wall: search + all bases
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for base := range bases {
		wg.Add(1)
		go func(base string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-deadline:
				results <- baseResult{base: base, why: "gh fan-out budget exhausted"}
				return
			}
			defer func() { <-sem }()
			out, why := c.run("pr", "list", "-R", base, "--author", "@me",
				"--state", "open", "--json", "headRefName,headRepository", "--limit", "100")
			if why != "" {
				results <- baseResult{base: base, why: why}
				return
			}
			var prs []prRow
			if err := json.Unmarshal([]byte(out), &prs); err != nil {
				results <- baseResult{base: base, why: fmt.Sprintf("unparseable: %v", err)}
				return
			}
			if len(prs) == 100 {
				// Per-base truncation is the same silent-narrowing class the
				// search limit guards against.
				results <- baseResult{base: base, why: "result limit reached"}
				return
			}
			results <- baseResult{base: base, prs: prs}
		}(base)
	}
	wg.Wait()
	close(results)
	for res := range results {
		if res.why != "" {
			// One unreadable base poisons the whole set's completeness.
			p.Unavailable = true
			p.Why = fmt.Sprintf("gh pr list -R %s: %s", res.base, res.why)
			p.heads = nil
			return p
		}
		for _, pr := range res.prs {
			slug := pr.HeadRepo.NameWithOwner
			if slug == "" && pr.HeadRepo.Name != "" && login != "" {
				slug = login + "/" + pr.HeadRepo.Name
			}
			if slug == "" {
				slug = res.base // same-repo PR with an empty head object
			}
			if p.heads[slug] == nil {
				p.heads[slug] = map[string]bool{}
			}
			p.heads[slug][pr.HeadRefName] = true
		}
	}
	return p
}

// login resolves the authenticated login once (needed to reconstruct fork
// head slugs); empty on any failure, which degrades those heads to the base
// slug — a miss, never a false hold.
func (c Client) login() string {
	out, why := c.run("api", "user", "--jq", ".login")
	if why != "" {
		return ""
	}
	return strings.TrimSpace(out)
}

// NewHeads builds a PRHeads from a precomputed slug -> branch-set map. It is
// the injection point for tests and the fault-injection suite (fake gh
// output), and for callers that cache a previous run's parsed set.
func NewHeads(heads map[string]map[string]bool) PRHeads {
	return PRHeads{heads: heads}
}

// Holds reports whether (repo slug, branch) has an open authored PR. Always
// false when the set is unavailable — callers route that case to MANUAL
// gh-unavailable themselves; Holds is only the positive matcher.
func (p PRHeads) Holds(slug, branch string) bool {
	if p.heads == nil {
		return false
	}
	return p.heads[slug] != nil && p.heads[slug][branch]
}

// AuthStatus checks gh authentication for doctor: found-but-unauthenticated
// is reported distinctly, because it silently collapses the SAFE set to near
// zero and deserves its own line, not a generic "gh missing".
func (c Client) AuthStatus() (installed, authenticated bool) {
	if _, err := exec.LookPath("gh"); err != nil {
		return false, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.Budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gh", "auth", "status")
	return true, cmd.Run() == nil
}

func (c Client) run(args ...string) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), c.Budget)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Sprintf("gh %s: timeout after %s", args[0], c.Budget)
	}
	if err != nil {
		return "", fmt.Sprintf("gh %s: %v: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), ""
}

// SlugFromURL extracts "owner/repo" from the remote URL spellings git hands
// out: git@github.com:owner/repo.git, https://github.com/owner/repo.git,
// ssh://git@github.com/owner/repo, and already-clean "owner/repo".
func SlugFromURL(u string) string {
	u = strings.TrimSpace(u)
	u = strings.TrimSuffix(u, ".git")
	if i := strings.Index(u, "github.com"); i >= 0 {
		u = u[i+len("github.com"):]
		u = strings.TrimPrefix(u, ":")
		u = strings.TrimPrefix(u, "/")
	}
	parts := strings.Split(strings.Trim(u, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

// Available reports whether gh is on PATH.
func Available() bool {
	_, err := exec.LookPath("gh")
	return err == nil
}
