package broker

import (
	"fmt"

	"github.com/darkrain/auth-service/internal/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

func Connect(cfg *config.Config) (*amqp.Connection, error) {
	url := fmt.Sprintf("amqp://%s:%s@%s/",
		cfg.RmqUser,
		cfg.RmqPassword,
		cfg.RmqHost,
	)

	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, fmt.Errorf("broker: dial %s: %w", cfg.RmqHost, err)
	}

	return conn, nil
}
