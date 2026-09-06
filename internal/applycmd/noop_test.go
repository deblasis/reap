package applycmd

import (
	"bytes"
	"errors"
	"os/exec"
	"time"

	"github.com/deblasis/reap/internal/gitx"
)

// newNoopGitRunner returns a Runner whose execs never run: re-verify tests
// use it for non-git dirs where git facts are not applicable. It refuses
// (zero budget) rather than hitting a real repo.
func newNoopGitRunner() gitx.Runner {
	return gitx.Runner{}
}

var errNoop = errors.New("noop runner")

var _ = exec.Command // keep exec for future shim fixtures
var _ = time.Second
var _ = bytes.MinRead
