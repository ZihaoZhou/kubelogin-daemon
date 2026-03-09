package workload

import (
	"sync"
	"time"
)

// ResourceTracker manages K8s resources created by the stress test,
// using ReserveSlot/CommitSlot/ReleaseSlot to avoid TOCTOU races.
type ResourceTracker struct {
	mu        sync.Mutex
	resources map[string]*TrackedResource
	reserved  int
	maxCount  int
}

// NewResourceTracker creates a new tracker with the given capacity.
func NewResourceTracker(maxCount int) *ResourceTracker {
	return &ResourceTracker{
		resources: make(map[string]*TrackedResource),
		maxCount:  maxCount,
	}
}

// ReserveSlot atomically claims a slot. Returns false if at capacity.
func (t *ResourceTracker) ReserveSlot() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.resources)+t.reserved >= t.maxCount {
		return false
	}
	t.reserved++
	return true
}

// CommitSlot records a successful create. Must be called after ReserveSlot.
func (t *ResourceTracker) CommitSlot(kind, name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.reserved--
	t.resources[kind+"/"+name] = &TrackedResource{
		Kind: kind, Name: name, CreatedAt: time.Now(),
	}
}

// ReleaseSlot releases a reserved slot when create fails.
func (t *ResourceTracker) ReleaseSlot() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.reserved--
}

// Remove removes a resource from tracking.
func (t *ResourceTracker) Remove(kind, name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.resources, kind+"/"+name)
}

// Count returns the number of tracked resources.
func (t *ResourceTracker) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.resources)
}

// ListOlderThan returns resources older than the given age.
func (t *ResourceTracker) ListOlderThan(maxAge time.Duration) []*TrackedResource {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	var old []*TrackedResource
	for _, r := range t.resources {
		if now.Sub(r.CreatedAt) > maxAge {
			old = append(old, r)
		}
	}
	return old
}

// ListByKind returns tracked resource names of the given kind.
func (t *ResourceTracker) ListByKind(kind string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	var names []string
	for key, r := range t.resources {
		if r.Kind == kind {
			_ = key
			names = append(names, r.Name)
		}
	}
	return names
}

// OrphansAtEnd returns the count of resources still tracked.
func (t *ResourceTracker) OrphansAtEnd() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.resources)
}
