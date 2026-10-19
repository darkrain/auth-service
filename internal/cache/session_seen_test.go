package cache

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/darkrain/auth-service/internal/config"
	"github.com/redis/go-redis/v9"
)

func TestSessionSeenWindowDeadlineAndBound(t *testing.T) {
	var w sessionSeenWindow
	now := time.Now()
	for id := int64(1); id <= maxLocalSessionSeen+1; id++ {
		w.remember(id, now.Add(time.Minute), now)
	}
	if len(w.deadlines) != maxLocalSessionSeen || w.contains(maxLocalSessionSeen+1, now) {
		t.Fatal("window exceeded its bound")
	}
	w.remember(1, now.Add(2*time.Minute), now)
	if w.contains(1, now.Add(time.Minute)) {
		t.Fatal("a later observation extended the deadline")
	}
	w.remember(2, now.Add(time.Second), now)
	if w.contains(2, now.Add(time.Second)) {
		t.Fatal("an earlier observation did not shorten the deadline")
	}
	w.remember(1, now.Add(time.Minute), now)
	w.remember(2, now.Add(time.Minute), now)
	w.remember(5000, now.Add(2*time.Minute), now.Add(time.Minute))
	if len(w.deadlines) != 1 || !w.contains(5000, now.Add(time.Minute)) {
		t.Fatal("expired entries did not free the bounded window")
	}
	w.remember(5001, now, now)
	if w.contains(5001, now) {
		t.Fatal("an already expired observation was retained")
	}
}

func TestSessionSeenWindowConcurrent(t *testing.T) {
	var w sessionSeenWindow
	var workers sync.WaitGroup
	now := time.Now()
	for i := range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for n := range 1000 {
				id := int64((n + i) % 64)
				w.remember(id, now.Add(time.Minute), now)
				if !w.contains(id, now) {
					t.Error("live deadline disappeared")
				}
			}
		}()
	}
	workers.Wait()
}

type seenCommandCounter struct {
	sets, ttls, gets atomic.Int64
	failTTL          bool
}

func (h *seenCommandCounter) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *seenCommandCounter) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *seenCommandCounter) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		switch cmd.Name() {
		case "set", "setnx":
			h.sets.Add(1)
		case "pttl":
			h.ttls.Add(1)
			if h.failTTL {
				return errors.New("TTL observation unavailable")
			}
		case "get":
			h.gets.Add(1)
		}
		return next(ctx, cmd)
	}
}

// Use only the explicitly configured isolated Redis; never flush its database.
func TestSessionSeenRedisReuseExpiryAndRevocation(t *testing.T) {
	address, password := os.Getenv("REDIS_TEST_ADDR"), os.Getenv("REDIS_TEST_PASSWORD")
	if address == "" || password == "" {
		t.Skip("set REDIS_TEST_ADDR and REDIS_TEST_PASSWORD for isolated Redis")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{RedisDatabaseNetwork: "tcp", RedisDatabaseHost: host, RedisDatabasePort: port, RedisPassword: password}
	first, second := NewClient(cfg), NewClient(cfg)
	defer first.Close()
	defer second.Close()
	ctx := context.Background()
	id := time.Now().UnixNano()
	key := sessionSeenKey(id)
	token := "seen-test-" + key
	defer first.rdb.Del(ctx, key, sessionKey(token), sessionSeenKey(id+1), sessionSeenKey(id+2))
	counter := &seenCommandCounter{}
	first.rdb.AddHook(counter)
	update, err := first.MarkSessionSeen(ctx, id, time.Second)
	if err != nil || !update {
		t.Fatalf("first writer: %v %v", update, err)
	}
	for range 100 {
		if update, err := first.MarkSessionSeen(ctx, id, time.Second); err != nil || update {
			t.Fatalf("repeated writer: %v %v", update, err)
		}
	}
	if counter.sets.Load() != 1 || counter.ttls.Load() != 1 {
		t.Fatalf("hot calls reached Redis: SET=%d PTTL=%d", counter.sets.Load(), counter.ttls.Load())
	}

	// Another instance must use the remaining shared TTL, not a fresh interval.
	if err := first.rdb.PExpire(ctx, key, 80*time.Millisecond).Err(); err != nil {
		t.Fatal(err)
	}
	if update, err := second.MarkSessionSeen(ctx, id, time.Second); err != nil || update {
		t.Fatalf("second instance before shared expiry: %v %v", update, err)
	}
	time.Sleep(120 * time.Millisecond)
	if update, err := second.MarkSessionSeen(ctx, id, time.Second); err != nil || !update {
		t.Fatalf("second instance after shared expiry: %v %v", update, err)
	}

	if err := first.SetSession(ctx, token, &SessionData{SessionID: id, UserID: 7}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if data, err := first.GetSession(ctx, token); err != nil || data == nil {
		t.Fatal("session setup failed", err)
	}
	if err := first.DeleteSession(ctx, token); err != nil {
		t.Fatal(err)
	}
	if data, err := first.GetSession(ctx, token); err != nil || data != nil || counter.gets.Load() != 2 {
		t.Fatal("last_seen window interfered with fresh session lookup/revocation", data, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := first.MarkSessionSeen(canceled, id, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled context was ignored", err)
	}

	// Missing TTL information must not discard a successful write claim.
	counter.failTTL = true
	if update, err := first.MarkSessionSeen(ctx, id+1, time.Second); err != nil || !update || first.seen.contains(id+1, time.Now()) {
		t.Fatal("TTL observation failure changed claim or created a local window", update, err)
	}
	counter.failTTL = false
	if update, err := first.MarkSessionSeen(ctx, id+2, 0); err != nil || !update || first.seen.contains(id+2, time.Now()) {
		t.Fatal("a persistent Redis key received an invented local TTL", update, err)
	}
}
