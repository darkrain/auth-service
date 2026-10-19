package cache

import (
	"sync"
	"time"
)

// This window only avoids repeating the last_seen write throttle. It never
// stores session data or authorizes a request: GetSession still checks Redis.
// Expired entries are removed on access, or by a bounded sweep when full.
const maxLocalSessionSeen = 4096

type sessionSeenWindow struct {
	mu        sync.Mutex
	deadlines map[int64]time.Time
	nextSweep time.Time
}

func (w *sessionSeenWindow) contains(id int64, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	deadline, exists := w.deadlines[id]
	if exists && !now.Before(deadline) {
		delete(w.deadlines, id)
		return false
	}
	return exists
}

func (w *sessionSeenWindow) remember(id int64, deadline, now time.Time) {
	if !now.Before(deadline) {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if old, exists := w.deadlines[id]; exists {
		// A concurrent TTL observation must never extend a retained deadline.
		if deadline.Before(old) {
			w.deadlines[id] = deadline
		}
		return
	}
	if len(w.deadlines) >= maxLocalSessionSeen && !now.Before(w.nextSweep) {
		for key, until := range w.deadlines {
			if !now.Before(until) {
				delete(w.deadlines, key)
			}
		}
		w.nextSweep = now.Add(time.Second)
	}
	if len(w.deadlines) >= maxLocalSessionSeen {
		return // Redis remains the fallback; memory and sweep work stay bounded.
	}
	if w.deadlines == nil {
		w.deadlines = make(map[int64]time.Time)
	}
	w.deadlines[id] = deadline
}
