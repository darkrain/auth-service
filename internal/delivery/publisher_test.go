package delivery

import (
	"errors"
	"testing"

	"github.com/darkrain/auth-service/internal/config"
	amqp "github.com/rabbitmq/amqp091-go"
)

type unavailableChannelProvider struct{ calls int }

func (p *unavailableChannelProvider) Channel() (*amqp.Channel, error) {
	p.calls++
	return nil, amqp.ErrClosed
}

func TestPublishModesWithUnavailableProvider(t *testing.T) {
	for _, mode := range []string{PublishModeRequired, PublishModeBestEffort, PublishModeDisabled} {
		t.Run(mode, func(t *testing.T) {
			provider := new(unavailableChannelProvider)
			cfg := &config.Config{MessageBroker: config.MessageBrokerConfig{PublishMode: mode}, CodeDelivery: config.CodeDeliveryConfig{Email: config.CodeDeliveryEmailConfig{DefaultProvider: "email", AllowedProviders: []string{"email"}}}}
			err := NewPublisher(provider, cfg).PublishCode(t.Context(), CodeRequest{RecipientType: RecipientTypeEmail, Recipient: "test@example.com"})
			if mode == PublishModeRequired && !errors.Is(err, amqp.ErrClosed) {
				t.Fatalf("required must report unavailable broker: %v", err)
			}
			if mode != PublishModeRequired && err != nil {
				t.Fatal(err)
			}
			wantCalls := 1
			if mode == PublishModeDisabled {
				wantCalls = 0
			}
			if provider.calls != wantCalls {
				t.Fatalf("channel calls %d, want %d", provider.calls, wantCalls)
			}
		})
	}
}
