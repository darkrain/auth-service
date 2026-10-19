package broker

import (
	"fmt"
	"time"

	"github.com/darkrain/auth-service/internal/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

func Connect(cfg *config.Config) (*amqp.Connection, error) {
	url := fmt.Sprintf("amqp://%s:%s@%s/",
		cfg.MessageBroker.User,
		cfg.MessageBroker.Password,
		cfg.MessageBroker.Host,
	)

	conn, err := amqp.DialConfig(url, amqp.Config{Dial: amqp.DefaultDial(3 * time.Second)})
	if err != nil {
		// LOW: redact password from URL before logging — only log host
		return nil, fmt.Errorf("broker: dial %s: %w", cfg.MessageBroker.Host, err)
	}

	return conn, nil
}
