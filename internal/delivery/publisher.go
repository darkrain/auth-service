package delivery

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/darkrain/auth-service/internal/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

func PublishCode(ctx context.Context, conn *amqp.Connection, cfg *config.Config, req CodeRequest) error {
	event, err := NewCodeEvent(cfg, req)
	if err != nil {
		return err
	}
	return Publish(ctx, conn, cfg, event)
}

func Publish(ctx context.Context, conn *amqp.Connection, cfg *config.Config, event *RequestEvent) error {
	switch cfg.MessageBroker.PublishMode {
	case PublishModeDisabled:
		return nil
	case PublishModeBestEffort:
		if conn == nil {
			return nil
		}
	case PublishModeRequired:
		if conn == nil {
			return errorsRequiredBroker()
		}
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("delivery: marshal event: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		return fmt.Errorf("delivery: open broker channel: %w", err)
	}
	defer ch.Close()

	if err := ch.ExchangeDeclare(
		cfg.MessageBroker.ExchangeName,
		cfg.MessageBroker.ExchangeKind,
		true,
		false,
		false,
		false,
		nil,
	); err != nil {
		return fmt.Errorf("delivery: declare exchange: %w", err)
	}

	if err := ch.PublishWithContext(ctx,
		cfg.MessageBroker.ExchangeName,
		cfg.MessageBroker.RoutingKeys.DeliveryRequested,
		false,
		false,
		amqp.Publishing{
			ContentType:  "application/json",
			DeliveryMode: amqp.Persistent,
			Body:         payload,
		},
	); err != nil {
		return fmt.Errorf("delivery: publish event: %w", err)
	}

	return nil
}

func errorsRequiredBroker() error {
	return fmt.Errorf("delivery: broker is required but not connected")
}
