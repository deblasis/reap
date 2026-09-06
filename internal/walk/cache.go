package walk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/deblasis/reap/internal/config"
)

// cacheEntry is sizes-only BY TYPE: bytes and the two cheap invalidation keys
// (direct-child dir mtime and child count). MaxMtime is deliberately absent so
// no future caller can serve a cached lastActivity into a verdict; SAFE facts
// always come from the current walk.
type cacheEntry struct {
	DirMtime   int64 `json:"dirMtime"`   // unix nanos of the dir's own mtime
	ChildCount int   `json:"childCount"` // direct children at walk time
	Bytes      int64 `json:"bytes"`
	WalkTs     int64 `json:"walkTs"` // unix nanos of the walk that produced it
}

// Cache is the sizes-only sizecache.json. Entries are trusted at most TTL and
// are rewalked when the dir's mtime or direct-child count changed (deep writes
// change neither, which is exactly why the TTL exists as the correctness
// bound).
type Cache struct {
	mu      sync.Mutex
	path    string
	entries map[string]cacheEntry
	ttl     time.Duration
}

const defaultTTL = 7 * 24 * time.Hour

// LoadCache reads stateDir/sizecache.json (absent = empty cache).
func LoadCache(stateDir string) (*Cache, error) {
	c := &Cache{
		path:    filepath.Join(stateDir, "sizecache.json"),
		entries: map[string]cacheEntry{},
		ttl:     defaultTTL,
	}
	raw, err := os.ReadFile(c.path)
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &c.entries); err != nil {
		// A corrupt cache is an optimization loss, not state: start empty.
		return c, nil
	}
	return c, nil
}

// Size returns the cached size for path when the entry is fresh (within TTL)
// and the cheap invalidation keys still match. ok=false means rewalk. The
// second return is never an activity value.
func (c *Cache) Size(path string) (bytes int64, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, present := c.entries[config.Canonical(path)]
	if !present {
		return 0, false
	}
	if time.Since(time.Unix(0, e.WalkTs)) > c.ttl {
		return 0, false
	}
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	if fi.ModTime().UnixNano() != e.DirMtime {
		return 0, false
	}
	if n, err := os.ReadDir(path); err != nil || len(n) != e.ChildCount {
		return 0, false
	}
	return e.Bytes, true
}

// Record stores a walked size. Partial walks are not recorded: a lower bound
// must never become the cached truth.
func (c *Cache) Record(path string, info DirInfo, now time.Time) {
	if info.Partial {
		return
	}
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	children, err := os.ReadDir(path)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[config.Canonical(path)] = cacheEntry{
		DirMtime:   fi.ModTime().UnixNano(),
		ChildCount: len(children),
		Bytes:      info.Bytes,
		WalkTs:     now.UnixNano(),
	}
}

// Save persists the cache atomically and prunes entries whose paths no longer
// exist (deleted dirs must not accumulate forever).
func (c *Cache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for p := range c.entries {
		// Keys are canonical; deletion checks must use the same form, and a
		// missing path simply fails Stat.
		if _, err := os.Stat(p); os.IsNotExist(err) {
			delete(c.entries, p)
		}
	}
	raw, err := json.Marshal(c.entries)
	if err != nil {
		return err
	}
	return config.AtomicWrite(c.path, raw, 0o644)
}
