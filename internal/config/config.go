// Package config loads and saves reap's config.json, resolves the state
// directory, and owns path discipline: every path reap compares (holds,
// protect globs, overrides, lineage, cache keys) is canonicalized here once,
// because Windows path comparison is case-insensitive, separators and trailing
// slashes vary, and \\?\ long-path prefixes appear in walks. A hold that
// silently fails to match defeats the highest-priority safety rail, and the
// failure mode of a mismatch is a deleted directory, not an error.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Thresholds carries every tunable from the spec's config section. Durations
// are expressed in their natural units; exec budgets as time.Duration.
type Thresholds struct {
	ActiveHours          int     `json:"active-hours"`
	ScratchManualDays    int     `json:"scratch-manual-days"`
	ScratchSafeDays      int     `json:"scratch-safe-days"`
	RemoteStaleHours     int     `json:"remote-stale-hours"`
	QuarantineCapGB      float64 `json:"quarantine-cap-gb"`
	QuarantineRetentionD int     `json:"quarantine-retention-days"`
	QuarantineMargin     float64 `json:"quarantine-margin"`
	MinFreeMB            int     `json:"min-free-mb"`
	GitBudget            string  `json:"git-budget"`
	JJBudget             string  `json:"jj-budget"`
	GHBudget             string  `json:"gh-budget"`
	FetchBudget          string  `json:"fetch-budget"`
}

// Config is the whole config.json shape.
type Config struct {
	Roots      []string   `json:"roots"`
	Protect    []string   `json:"protect"`
	Thresholds Thresholds `json:"thresholds"`
	GH         bool       `json:"gh"`
	JJ         bool       `json:"jj"`
}

// Budgets parses the exec budget strings once; zero values mean the caller
// should refuse to proceed rather than hang forever on a wedged tool.
func (t Thresholds) Budgets() (git, jj, gh, fetch time.Duration, err error) {
	git, err = time.ParseDuration(t.GitBudget)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("git-budget: %w", err)
	}
	jj, err = time.ParseDuration(t.JJBudget)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("jj-budget: %w", err)
	}
	gh, err = time.ParseDuration(t.GHBudget)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("gh-budget: %w", err)
	}
	fetch, err = time.ParseDuration(t.FetchBudget)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("fetch-budget: %w", err)
	}
	return git, jj, gh, fetch, nil
}

// Default returns the shipped configuration. Roots and protect defaults are
// the measured 2026-09-06 layout; %VAR% and ~ expand against the interactive
// user's profile at load time, and doctor prints the expanded list so a
// wrong-context (elevated) run is visible rather than silent.
func Default() Config {
	home, _ := os.UserHomeDir()
	return Config{
		Roots: []string{
			`C:\temp`, `C:\tmp`, `C:\wt`, `C:\zc`, `C:\src`,
			`%TEMP%`,
			filepath.Join(home, "CODE", "OSS"),
			filepath.Join(home, "source"),
		},
		Protect: []string{
			`**/OneDrive/**`,
			`**/AppData/Local/vigz/**`,
			`**/.cache/**`,
			`**/AppData/Local/wsl/**`,
			`**/Virtual Hard Disks/**`,
			`%TEMP%/claude/**`,
			filepath.Join(home, "CODE", "OSS", "wintty"),
			filepath.Join(home, "CODE", "OSS", "wintty-release"),
			filepath.Join(home, "CODE", "OSS", "ghostty"),
			filepath.Join(home, "CODE", "OSS", "ssho*"),
			filepath.Join(home, "CODE", "deblasis.net"),
		},
		Thresholds: Thresholds{
			ActiveHours:          48,
			ScratchManualDays:    7,
			ScratchSafeDays:      21,
			RemoteStaleHours:     72,
			QuarantineCapGB:      2,
			QuarantineRetentionD: 30,
			QuarantineMargin:     2.5,
			MinFreeMB:            256,
			GitBudget:            "30s",
			JJBudget:             "30s",
			GHBudget:             "15s",
			FetchBudget:          "120s",
		},
		GH: true,
		JJ: true,
	}
}

// Load reads dir/config.json, falling back to defaults when absent. A present
// but unreadable or invalid config is an error, never silently defaults: a
// half-loaded protect list is the worst possible failure direction.
func Load(dir string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(ConfigPath(dir))
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	// Strip a leading UTF-8 BOM: PowerShell 5's Set-Content -Encoding UTF8
	// writes one, and json.Unmarshal treats it as garbage (a Windows-first
	// tool WILL meet BOM'd JSON from common Windows tooling).
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Default(), fmt.Errorf("parse %s: %w", ConfigPath(dir), err)
	}
	if len(cfg.Roots) == 0 {
		return Default(), fmt.Errorf("%s: roots must not be empty (refusing to scan nothing)", ConfigPath(dir))
	}
	if err := cfg.Thresholds.validate(); err != nil {
		return Default(), fmt.Errorf("%s: %w", ConfigPath(dir), err)
	}
	return cfg, nil
}

// validate refuses threshold typos that would mint false SAFEs wholesale:
// scratch-safe-days 0 makes every scratch dir SAFE at any age, and an
// inverted manual/safe pair silently swaps the tiers.
func (t Thresholds) validate() error {
	if t.ActiveHours <= 0 {
		return fmt.Errorf("thresholds: active-hours must be > 0, got %d", t.ActiveHours)
	}
	if t.ScratchManualDays <= 0 || t.ScratchSafeDays < t.ScratchManualDays {
		return fmt.Errorf("thresholds: need 0 < scratch-manual-days (%d) <= scratch-safe-days (%d)",
			t.ScratchManualDays, t.ScratchSafeDays)
	}
	if t.RemoteStaleHours <= 0 {
		return fmt.Errorf("thresholds: remote-stale-hours must be > 0, got %d", t.RemoteStaleHours)
	}
	if t.QuarantineCapGB <= 0 || t.QuarantineRetentionD <= 0 || t.QuarantineMargin < 1 {
		return fmt.Errorf("thresholds: quarantine-cap-gb (%v), quarantine-retention-days (%d) and quarantine-margin >= 1 (%v) required",
			t.QuarantineCapGB, t.QuarantineRetentionD, t.QuarantineMargin)
	}
	if t.MinFreeMB <= 0 {
		return fmt.Errorf("thresholds: min-free-mb must be > 0, got %d", t.MinFreeMB)
	}
	for name, s := range map[string]string{
		"git-budget": t.GitBudget, "jj-budget": t.JJBudget, "gh-budget": t.GHBudget, "fetch-budget": t.FetchBudget,
	} {
		if _, err := time.ParseDuration(s); err != nil {
			return fmt.Errorf("thresholds: %s %q: %w", name, s, err)
		}
	}
	return nil
}

// Save writes the config atomically (temp file + rename) so a crash mid-write
// can never leave a truncated config.json, which Load would then treat as a
// hard error.
func Save(dir string, cfg Config) error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return AtomicWrite(ConfigPath(dir), raw, 0o644)
}

// AtomicWrite writes bytes to path via temp-and-rename in the same directory.
// Single-writer discipline is enforced elsewhere (apply.lock); this guards
// against partial files, not concurrent writers.
func AtomicWrite(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".reap-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// ConfigPath is where config.json lives inside the state dir.
func ConfigPath(dir string) string { return filepath.Join(dir, "config.json") }

// StateDir resolves the per-user, machine-local state directory. REAP_DIR
// overrides everything (a machine-level override, same rule as incoda's
// INCODA_DIR: setting it per-project splits state and makes both halves look
// healthy).
func StateDir() (string, error) {
	if d := strings.TrimSpace(os.Getenv("REAP_DIR")); d != "" {
		return filepath.Clean(d), nil
	}
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "reap"), nil
		}
		return "", fmt.Errorf("LOCALAPPDATA is unset; set REAP_DIR to choose a state directory")
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", "reap"), nil
	default:
		if d := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); d != "" {
			return filepath.Join(d, "reap"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".local", "state", "reap"), nil
	}
}

// Canonical normalizes a path for comparison: filepath.Clean, forward slashes
// collapsed to the platform separator, \\?\ and \\?\UNC\ long-path prefixes
// stripped, and case folded on Windows (NTFS is case-insensitive; a hold typed
// as c:\temp\foo must match a scanned C:\temp\Foo or the safety rail silently
// fails). The result uses backslashes on Windows and forward slashes
// elsewhere, with no trailing separator.
func Canonical(p string) string {
	p = strings.TrimSpace(p)
	for _, prefix := range []string{`\\?\UNC\`, `\\?\`} {
		if strings.HasPrefix(p, prefix) {
			p = strings.TrimPrefix(p, prefix)
			if prefix == `\\?\UNC\` {
				p = `\\` + p
			}
			break
		}
	}
	p = filepath.Clean(strings.ReplaceAll(p, `/`, string(os.PathSeparator)))
	if p != string(os.PathSeparator) {
		p = strings.TrimSuffix(p, string(os.PathSeparator))
	}
	if runtime.GOOS == "windows" {
		// 8.3 expansion before folding: Go temp dirs and some tool output
		// carry short forms (ALESSA~1) while git/jj record long ones, and a
		// textual mismatch on either side silently defeats every comparison
		// built on Canonical.
		p = longPath(p)
		p = strings.ToLower(p)
	}
	return p
}

// IsUnder reports whether path is equal to or inside dir, matched on path
// component boundaries. C:\temp\foo must never cover C:\temp\foobar: the
// plain prefix-compare bug class turns a hold into a broader deletion than
// the user asked for.
func IsUnder(path, dir string) bool {
	pc, dc := Canonical(path), Canonical(dir)
	if pc == dc {
		return true
	}
	return strings.HasPrefix(pc, dc+string(os.PathSeparator))
}

// ExpandRoots expands %VAR% and ~ in roots against the current environment
// and home. On Windows the expansion happens for the interactive user's
// profile; doctor prints the result so an elevated context (where %TEMP%
// resolves elsewhere) is visible.
func ExpandRoots(roots []string) []string {
	home, _ := os.UserHomeDir()
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		r = strings.TrimSpace(r)
		if r == "~" || strings.HasPrefix(r, `~\`) || strings.HasPrefix(r, "~/") {
			r = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(r, "~"), `\/`))
		}
		// The spec's spelling is Windows-style %VAR%; expand it directly so it
		// works identically on every platform (os.ExpandEnv would leave the
		// trailing % of %VAR% behind as a literal).
		r = expandPercentVars(r)
		if r != "" {
			out = append(out, r)
		}
	}
	return out
}

func expandPercentVars(s string) string {
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			return s
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			return s
		}
		name := s[i+1 : i+1+j]
		val, ok := os.LookupEnv(name)
		if !ok {
			val = ""
		}
		s = s[:i] + val + s[i+2+j:]
	}
}

// globRegex compiles protect globs. Protect patterns support ** across
// separators and * within a component, matched case-insensitively on Windows
// via Canonical (the pattern and the path are both canonicalized first).
// A trailing separator+** (the shape of every built-in protect default)
// covers the directory itself as well as everything under it: `vigz/**`
// reads as "vigz and its tree", and a candidate that IS vigz must KEEP.
func globRegex(glob string) (*regexp.Regexp, error) {
	c := Canonical(glob)
	sep := regexp.QuoteMeta(string(os.PathSeparator))
	trailingTree := false
	if strings.HasSuffix(c, string(os.PathSeparator)+"**") {
		trailingTree = true
		c = strings.TrimSuffix(c, string(os.PathSeparator)+"**")
	}
	var sb strings.Builder
	sb.WriteString(`^`)
	for i := 0; i < len(c); i++ {
		ch := c[i]
		switch ch {
		case '*':
			if i+1 < len(c) && c[i+1] == '*' {
				// ** matches any number of path components (or none)
				sb.WriteString(`.*`)
				i++
			} else {
				sb.WriteString(`[^` + sep + `]*`)
			}
		default:
			sb.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	if trailingTree {
		sb.WriteString(`(` + sep + `.*)?`)
	}
	sb.WriteString(`$`)
	return regexp.Compile(sb.String())
}

// MatchProtect reports whether path matches any protect glob.
func MatchProtect(path string, globs []string) (bool, error) {
	pc := Canonical(path)
	for _, g := range globs {
		for _, eg := range ExpandRoots([]string{g}) {
			re, err := globRegex(eg)
			if err != nil {
				return false, fmt.Errorf("protect glob %q: %w", g, err)
			}
			if re.MatchString(pc) {
				return true, nil
			}
		}
	}
	return false, nil
}
