package verdict

import (
	"fmt"
	"sync"
	"testing"

	"github.com/deblasis/reap/internal/gitx"
)

// The deciding path under scan's 4-worker pool (round 14's gate: the
// round-13 package-var implementation raced here - 53 wrong-value KEEP
// rows in 60ms under -race; the parameter-passed fact must be race-free).
func TestDecideConcurrentRailsRaceFree(t *testing.T) {
	mkInput := func(dirty int) Input {
		f := &gitx.Facts{Dirty: dirty}
		return Input{
			Kind: "git-repo", Path: `C:\x`, GitBackend: true,
			Held: true, Git: f,
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				dirty := n % 3 // distinct facts per goroutine
				v := Decide(mkInput(dirty))
				want := ""
				if dirty > 0 {
					want = fmt.Sprintf("%d dirty/untracked files", dirty)
				}
				if v.BlockedClassFact != want {
					t.Errorf("cross-stamped fact under concurrency: got %q want %q", v.BlockedClassFact, want)
					return
				}
				if v.Verdict != Keep || v.Code != "held-by-user" {
					t.Errorf("rail lost under concurrency: %+v", v)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
