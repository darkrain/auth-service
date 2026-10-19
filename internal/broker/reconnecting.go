package broker

import (
	"errors"
	"sync"
	"time"

	"github.com/darkrain/auth-service/internal/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

// ChannelProvider is shared by delivery and security event producers. Keeping
// the provider alive lets handlers recover even if RabbitMQ was down at boot.
type ChannelProvider interface {
	Channel() (*amqp.Channel, error)
}

type connection interface {
	ChannelProvider
	IsClosed() bool
	Close() error
}

// Reconnecting owns one connection. Reconnection happens before opening a
// channel, never after publishing: retrying an ambiguous publish can send twice.
type Reconnecting struct {
	mu        sync.Mutex
	conn      connection
	dial      func() (connection, error)
	now       func() time.Time
	retryAt   time.Time
	lastError error
	closed    bool
}

func NewReconnecting(cfg *config.Config) *Reconnecting {
	return &Reconnecting{dial: func() (connection, error) { return Connect(cfg) }, now: time.Now}
}

func (r *Reconnecting) connectLocked() error {
	if r.closed {
		return amqp.ErrClosed
	}
	if r.conn != nil && !r.conn.IsClosed() {
		return nil
	}
	if r.now().Before(r.retryAt) {
		return r.lastError
	}
	conn, err := r.dial()
	if err != nil {
		r.lastError = err
		r.retryAt = r.now().Add(time.Second)
		return err
	}
	r.conn, r.lastError, r.retryAt = conn, nil, time.Time{}
	return nil
}

func (r *Reconnecting) Connect() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.connectLocked()
}

func (r *Reconnecting) Channel() (*amqp.Channel, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.connectLocked(); err != nil {
		return nil, err
	}
	ch, err := r.conn.Channel()
	// The connection can close between IsClosed and Channel. Retry just this
	// channel open once; no message has been sent yet.
	if err != nil && (r.conn.IsClosed() || errors.Is(err, amqp.ErrClosed)) {
		_ = r.conn.Close()
		r.conn = nil
		if err := r.connectLocked(); err != nil {
			return nil, err
		}
		return r.conn.Channel()
	}
	return ch, err
}

func (r *Reconnecting) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.conn != nil {
		return r.conn.Close()
	}
	return nil
}
