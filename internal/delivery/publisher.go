package delivery

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/darkrain/auth-service/internal/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	PublishModeRequired   = "required"
	PublishModeBestEffort = "best_effort"
	PublishModeDisabled   = "disabled"
)

// Publisher makes delivery testable without an AMQP broker.
type Publisher interface {
	PublishCode(context.Context, CodeRequest) error
}

type AMQPPublisher struct {
	connection *amqp.Connection
	config     *config.Config
}

func NewPublisher(connection *amqp.Connection, cfg *config.Config) *AMQPPublisher {
	return &AMQPPublisher{connection: connection, config: cfg}
}

func (p *AMQPPublisher) PublishCode(ctx context.Context, request CodeRequest) error {
	event, err := NewCodeEvent(p.config, request)
	if err != nil {
		return err
	}
	switch p.config.MessageBroker.PublishMode {
	case PublishModeDisabled:
		return nil
	case PublishModeBestEffort:
		if p.connection == nil {
			return nil
		}
	case PublishModeRequired:
		if p.connection == nil {
			return fmt.Errorf("delivery: broker is required but not connected")
		}
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("delivery: marshal event: %w", err)
	}
	channel, err := p.connection.Channel()
	if err != nil {
		return fmt.Errorf("delivery: open broker channel: %w", err)
	}
	defer channel.Close()
	if err := channel.ExchangeDeclare(p.config.MessageBroker.ExchangeName, p.config.MessageBroker.ExchangeKind, true, false, false, false, nil); err != nil {
		return fmt.Errorf("delivery: declare exchange: %w", err)
	}
	if err := channel.PublishWithContext(ctx, p.config.MessageBroker.ExchangeName, p.config.MessageBroker.RoutingKeys.DeliveryRequested, false, false, amqp.Publishing{ContentType: "application/json", DeliveryMode: amqp.Persistent, Body: payload}); err != nil {
		return fmt.Errorf("delivery: publish event: %w", err)
	}
	return nil
}
