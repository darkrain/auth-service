package broker

import (
	"fmt"
	"net/url"

	"github.com/darkrain/auth-service/internal/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

func Connect(cfg *config.Config) (*amqp.Connection, error) {
	brokerURL := url.URL{
		Scheme: "amqp",
		User:   url.UserPassword(cfg.MessageBroker.User, cfg.MessageBroker.Password),
		Host:   cfg.MessageBroker.Host,
		Path:   "/",
	}

	conn, err := amqp.Dial(brokerURL.String())
	if err != nil {
		return nil, fmt.Errorf("broker: dial %s: %w", cfg.MessageBroker.Host, err)
	}

	return conn, nil
}
