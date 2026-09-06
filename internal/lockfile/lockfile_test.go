package lockfile

import (
	"path/filepath"
	"testing"
)

// The probe proves the lock is enforced, not merely non-erroring: a second
// independent handle must be refused while the first holds the lock. A
// filesystem that silently ignores locks would make reap's apply.lock a no-op,
// which is the difference between serialized destructive runs and racing ones.
func TestLockIsEnforcedAcrossHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe.lock")

	a, err := Open(path)
	if err != nil {
		t.Fatalf("open first handle: %v", err)
	}
	defer a.Close()

	ok, err := a.TryLock()
	if err != nil {
		t.Fatalf("trylock first handle: %v", err)
	}
	if !ok {
		t.Fatal("could not take an uncontended lock")
	}

	// Same-process second handle must see the lock held. On Windows the
	// byte-range lock denies even our own second handle; on Unix flock locks
	// attach to the open file description, so a fresh open is a fresh
	// contender.
	free, err := IsFree(path)
	if err != nil {
		t.Fatalf("probe second handle: %v", err)
	}
	if free {
		t.Fatal("second handle locked the file while the first held it; this filesystem does not enforce locks")
	}

	if err := a.Unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	free, err = IsFree(path)
	if err != nil {
		t.Fatalf("re-probe after unlock: %v", err)
	}
	if !free {
		t.Fatal("lock still reported held after Unlock")
	}
}

// Close must release the lock so a crashed-and-restarted process (or a test
// sequence) never sees a stale hold from a closed handle.
func TestCloseReleases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe2.lock")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.TryLock(); err != nil || !a.Held() {
		t.Fatalf("trylock: held=%v err=%v", a.Held(), err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	free, err := IsFree(path)
	if err != nil {
		t.Fatal(err)
	}
	if !free {
		t.Fatal("lock survived Close")
	}
}
