package delivery

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/darkrain/auth-service/internal/broker"
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
	PublishNotice(context.Context, NoticeRequest) error
}

type AMQPPublisher struct {
	connection broker.ChannelProvider
	config     *config.Config
}

// NewEventPublisher builds the publisher the services send their events with.
// Tests replace it to record the events without a broker.
var NewEventPublisher = func(connection broker.ChannelProvider, cfg *config.Config) Publisher {
	return NewPublisher(connection, cfg)
}

func NewPublisher(connection broker.ChannelProvider, cfg *config.Config) *AMQPPublisher {
	return &AMQPPublisher{connection: connection, config: cfg}
}

func (p *AMQPPublisher) PublishCode(ctx context.Context, request CodeRequest) error {
	event, err := NewCodeEvent(p.config, request)
	if err != nil {
		return err
	}
	return p.publish(ctx, event)
}

func (p *AMQPPublisher) PublishNotice(ctx context.Context, request NoticeRequest) error {
	event, err := NewNoticeEvent(p.config, request)
	if err != nil {
		return err
	}
	return p.publish(ctx, event)
}

func (p *AMQPPublisher) publish(ctx context.Context, event *RequestEvent) error {
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
		if p.config.MessageBroker.PublishMode == PublishModeBestEffort {
			return nil
		}
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
