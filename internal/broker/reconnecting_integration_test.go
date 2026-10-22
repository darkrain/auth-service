package broker

import (
	"errors"
	"os"
	"testing"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// Uses an existing local broker only; queues are exclusive and auto-deleted.
func TestReconnectPublishesAfterStartupFailureAndClosedConnection(t *testing.T) {
	url := os.Getenv("AUTH_RECONNECT_TEST_AMQP_URL")
	if url == "" {
		t.Skip("AUTH_RECONNECT_TEST_AMQP_URL is not set")
	}
	now := time.Now()
	var active *amqp.Connection
	dials := 0
	r := &Reconnecting{now: func() time.Time { return now }, dial: func() (connection, error) {
		dials++
		if dials == 1 {
			return nil, errors.New("startup outage")
		}
		var err error
		active, err = amqp.DialConfig(url, amqp.Config{Dial: amqp.DefaultDial(3 * time.Second)})
		return active, err
	}}
	t.Cleanup(func() { _ = r.Close() })
	if r.Connect() == nil {
		t.Fatal("expected startup outage")
	}
	now = now.Add(time.Second)
	for i := 0; i < 2; i++ {
		ch, err := r.Channel()
		if err != nil {
			t.Fatal(err)
		}
		q, err := ch.QueueDeclare("", false, true, true, false, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = ch.PublishWithContext(t.Context(), "", q.Name, false, false, amqp.Publishing{Body: []byte("recovery")}); err != nil {
			t.Fatal(err)
		}
		// A synchronous channel operation orders the subsequent Get after publish.
		msg, ok, err := ch.Get(q.Name, true)
		if err != nil || !ok || string(msg.Body) != "recovery" {
			t.Fatalf("message delivered=%v err=%v", ok, err)
		}
		_ = ch.Close()
		if err = active.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if dials != 3 {
		t.Fatalf("expected startup failure and two real connections, got %d", dials)
	}
}
