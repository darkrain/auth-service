package broker

import (
	"errors"
	"sync"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

type fakeConnection struct {
	closed       bool
	channelError error
	channel      *amqp.Channel
}

func (f *fakeConnection) IsClosed() bool                  { return f.closed }
func (f *fakeConnection) Close() error                    { f.closed = true; return nil }
func (f *fakeConnection) Channel() (*amqp.Channel, error) { return f.channel, f.channelError }

func TestReconnectAfterStartupFailure(t *testing.T) {
	now := time.Now()
	failed := errors.New("broker unavailable")
	conn := &fakeConnection{channel: new(amqp.Channel)}
	dials := 0
	r := &Reconnecting{now: func() time.Time { return now }, dial: func() (connection, error) {
		dials++
		if dials == 1 {
			return nil, failed
		}
		return conn, nil
	}}
	if !errors.Is(r.Connect(), failed) {
		t.Fatal("startup must report failure")
	}
	if _, err := r.Channel(); !errors.Is(err, failed) || dials != 1 {
		t.Fatal("outage must be throttled")
	}
	now = now.Add(time.Second)
	if ch, err := r.Channel(); err != nil || ch != conn.channel || dials != 2 {
		t.Fatalf("recovery: channel=%p err=%v dials=%d", ch, err, dials)
	}
}

func TestReconnectAfterConnectionCloses(t *testing.T) {
	for _, duringOpen := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_channel", true: "during_channel"}[duringOpen], func(t *testing.T) {
			old := &fakeConnection{closed: !duringOpen, channelError: amqp.ErrClosed}
			next := &fakeConnection{channel: new(amqp.Channel)}
			dials := 0
			r := &Reconnecting{conn: old, now: time.Now, dial: func() (connection, error) { dials++; return next, nil }}
			ch, err := r.Channel()
			if err != nil || ch != next.channel || dials != 1 {
				t.Fatalf("channel=%p err=%v dials=%d", ch, err, dials)
			}
		})
	}
}

func TestConcurrentRecoveryUsesOneConnection(t *testing.T) {
	conn := &fakeConnection{channel: new(amqp.Channel)}
	dials := 0
	r := &Reconnecting{now: time.Now, dial: func() (connection, error) { dials++; return conn, nil }}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, err := r.Channel(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if dials != 1 {
		t.Fatalf("dialed %d times", dials)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Channel(); !errors.Is(err, amqp.ErrClosed) {
		t.Fatalf("shutdown: %v", err)
	}
	if dials != 1 {
		t.Fatal("reconnected after shutdown")
	}
}

func TestChannelErrorDoesNotReconnectHealthyConnection(t *testing.T) {
	want := errors.New("channel limit")
	r := &Reconnecting{conn: &fakeConnection{channelError: want}, now: time.Now, dial: func() (connection, error) { t.Fatal("unexpected dial"); return nil, nil }}
	if _, err := r.Channel(); !errors.Is(err, want) {
		t.Fatal(err)
	}
}
