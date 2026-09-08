package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The activity command through the dispatch layer: the digest renders the
// dir records (open/closed) with the weak-attribution caveat when
// old-format events are present, and --json emits the machine schema.
func TestWiringActivityCommand(t *testing.T) {
	d := t.TempDir()
	qd := filepath.Join(d, "queues", "build")
	if err := os.MkdirAll(qd, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "2026-09-07 18:03:05 queue=build event=enqueue pid=1 slots=5 cmd=zig build test\n" +
		"2026-09-07 18:08:31 queue=build event=release pid=1 rc=0\n" +
		"2026-09-07 19:05:00 queue=build event=release pid=99 dir=C:\\wt\\thing reason=\"big build\" owner=agent dur=42m30s cmd=pwsh -File x.ps1\n"
	if err := os.WriteFile(filepath.Join(qd, "lane.log"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("INCODA_DIR", d)

	var out bytes.Buffer
	if code := cmdActivity(nil, &out, os.Stderr); code != ExitOK {
		t.Fatalf("activity: %d (%s)", code, out.String())
	}
	if !strings.Contains(out.String(), "C:\\wt\\thing") {
		t.Fatalf("dir record missing:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "weak") {
		t.Fatalf("old-format caveat missing:\n%s", out.String())
	}

	var js bytes.Buffer
	if code := cmdActivity([]string{"--json"}, &js, os.Stderr); code != ExitOK {
		t.Fatalf("activity --json: %d", code)
	}
	if !strings.Contains(js.String(), `"dir": "C:\\\\wt\\\\thing"`) && !strings.Contains(js.String(), "thing") {
		t.Fatalf("json record missing:\n%s", js.String())
	}

	// --since filters: the new-format record is from 'now-ish' 2026-09-07
	// (test clock is 2026-09-08+); a 1h window shows nothing.
	out.Reset()
	if code := cmdActivity([]string{"--since", "1h"}, &out, os.Stderr); code != ExitOK {
		t.Fatalf("activity --since: %d", code)
	}
	if strings.Contains(out.String(), "thing") {
		t.Fatalf("stale record survived --since:\n%s", out.String())
	}
	_ = time.Now
}
