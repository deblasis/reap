package ghx

import (
	"strings"
	"testing"
	"time"
)

func TestSlugFromURL(t *testing.T) {
	cases := map[string]string{
		"git@github.com:deblasis/wintty.git":     "deblasis/wintty",
		"https://github.com/deblasis/wintty.git": "deblasis/wintty",
		"ssh://git@github.com/deblasis/wintty":   "deblasis/wintty",
		"deblasis/wintty":                        "deblasis/wintty",
		"https://gitlab.com/x/y":                 "", // non-github is not this join's business
		"https://github.com/a/b/c":               "",
	}
	for in, want := range cases {
		if got := SlugFromURL(in); got != want {
			t.Errorf("SlugFromURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// The join: a fork checkout with an upstream remote must match the PR whose
// head repository is the fork slug (the head branch always lives on origin,
// fork or not — matching "upstream" only was the round-3 spec bug).
func TestHoldsAnyRemoteSlug(t *testing.T) {
	p := PRHeads{heads: map[string]map[string]bool{
		"deblasis/wintty": {"feat/dormant-surfaces": true},
	}}
	if !p.Holds("deblasis/wintty", "feat/dormant-surfaces") {
		t.Fatal("fork-slug + branch must hold")
	}
	if p.Holds("deblasis/wintty", "main") {
		t.Fatal("branch without an open PR must not hold")
	}
	if p.Holds("ghostty-org/ghostty", "feat/dormant-surfaces") {
		t.Fatal("upstream slug must not absorb fork PRs")
	}
}

// An unavailable set must never positively match: callers route it to MANUAL
// gh-unavailable; Holds staying false is what keeps that honest.
func TestUnavailableNeverHolds(t *testing.T) {
	p := PRHeads{Unavailable: true, Why: "auth expired"}
	if p.Holds("deblasis/wintty", "main") {
		t.Fatal("unavailable set must not match anything")
	}
}

func TestZeroBudgetRefuses(t *testing.T) {
	p := Client{}.OpenPRHeads()
	if !p.Unavailable {
		t.Fatal("zero-budget client must refuse rather than run unbounded")
	}
}

// One live call, when gh is installed and authed: asserts the JSON shape
// against the installed gh version (field names are part of the contract; a
// gh rename would otherwise fail silently into unparseable=unavailable).
func TestLiveSearchParses(t *testing.T) {
	if !Available() {
		t.Skip("gh not on PATH")
	}
	installed, authed := Client{Budget: 15 * time.Second}.AuthStatus()
	if !installed || !authed {
		t.Skip("gh not authenticated; live parse test skipped")
	}
	p := Client{Budget: 15 * time.Second}.OpenPRHeads()
	// This test pins the SEARCH phase (field names against the installed
	// gh). Phase-2 degradation on the real account — the fan-out cap, or one
	// big repo's pr list timing out — is the honest-unavailable contract
	// working, not a parse failure. Only search-phase and unparseable
	// outcomes fail the pin.
	if p.Unavailable {
		if strings.Contains(p.Why, "gh search:") || strings.Contains(p.Why, "unparseable") {
			t.Fatalf("live search failed against an authed gh: %s", p.Why)
		}
		t.Logf("phase-2 degraded honestly on this account: %s", p.Why)
		return
	}
	// Whatever the account's open PRs are, the parse must have produced a
	// usable map (possibly empty) rather than an error.
	if p.heads == nil && !p.Unavailable {
		t.Fatal("parse produced no head map")
	}
}
