package delivery

import (
	"context"
	"testing"

	"github.com/darkrain/auth-service/internal/config"
)

func TestNewCodeEventBuildsPhoneDeliveryRequest(t *testing.T) {
	cfg := testConfig()

	event, err := NewCodeEvent(cfg, CodeRequest{
		Template:         TemplateAuthVerificationCode,
		Purpose:          PurposeVerification,
		RecipientType:    RecipientTypePhone,
		Recipient:        "+10000000000",
		Code:             "123456",
		TTLSec:           300,
		UserID:           42,
		DeviceUID:        "device-1",
		SelectedProvider: "telegram",
		AllowFallback:    true,
	})
	if err != nil {
		t.Fatalf("NewCodeEvent: %v", err)
	}
	if event.Type != EventTypeDeliveryRequested {
		t.Fatalf("type = %q", event.Type)
	}
	if event.Template != TemplateAuthVerificationCode || event.Purpose != PurposeVerification {
		t.Fatalf("template/purpose = %q/%q", event.Template, event.Purpose)
	}
	if event.RecipientType != RecipientTypePhone || event.Recipient != "+10000000000" {
		t.Fatalf("recipient = %q/%q", event.RecipientType, event.Recipient)
	}
	if event.Variables["code"] != "123456" || event.Variables["ttl_sec"] != "300" {
		t.Fatalf("variables = %#v", event.Variables)
	}
	if event.UserID != 42 || event.Metadata["device_uid"] != "device-1" {
		t.Fatalf("user/metadata = %d/%#v", event.UserID, event.Metadata)
	}
	if event.Delivery.SelectedProvider != "telegram" || !event.Delivery.AllowFallback {
		t.Fatalf("delivery = %#v", event.Delivery)
	}
	if len(event.Delivery.ProviderChain) != 2 || event.Delivery.ProviderChain[0] != "telegram" || event.Delivery.ProviderChain[1] != "sms" {
		t.Fatalf("provider chain = %#v", event.Delivery.ProviderChain)
	}
}

func TestPublishModesWithoutBroker(t *testing.T) {
	event, err := NewCodeEvent(testConfig(), CodeRequest{
		Template:      TemplateAuthVerificationCode,
		Purpose:       PurposeVerification,
		RecipientType: RecipientTypeEmail,
		Recipient:     "user@example.com",
		Code:          "123456",
		TTLSec:        300,
	})
	if err != nil {
		t.Fatalf("NewCodeEvent: %v", err)
	}

	cfg := testConfig()
	cfg.MessageBroker.PublishMode = PublishModeRequired
	if err := Publish(context.Background(), nil, cfg, event); err == nil {
		t.Fatal("required mode should fail without broker")
	}

	cfg.MessageBroker.PublishMode = PublishModeBestEffort
	if err := Publish(context.Background(), nil, cfg, event); err != nil {
		t.Fatalf("best_effort mode should ignore missing broker: %v", err)
	}

	cfg.MessageBroker.PublishMode = PublishModeDisabled
	if err := Publish(context.Background(), nil, cfg, event); err != nil {
		t.Fatalf("disabled mode should ignore missing broker: %v", err)
	}
}

func TestNewCodeEventRejectsDisallowedProvider(t *testing.T) {
	_, err := NewCodeEvent(testConfig(), CodeRequest{
		Template:         TemplateAuthVerificationCode,
		Purpose:          PurposeVerification,
		RecipientType:    RecipientTypePhone,
		Recipient:        "+10000000000",
		Code:             "123456",
		TTLSec:           300,
		SelectedProvider: "whatsapp",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func testConfig() *config.Config {
	return &config.Config{
		MessageBroker: config.MessageBrokerConfig{
			PublishMode:  PublishModeRequired,
			ExchangeName: "messages.events",
			ExchangeKind: "topic",
			RoutingKeys: config.MessageBrokerRoutingKeys{
				DeliveryRequested: EventTypeDeliveryRequested,
			},
		},
		CodeDelivery: config.CodeDeliveryConfig{
			Email: config.CodeDeliveryEmailConfig{
				DefaultProvider:  "email",
				AllowedProviders: []string{"email"},
			},
			Phone: config.CodeDeliveryPhoneConfig{
				DefaultProviderChain: []string{"telegram", "sms"},
				AllowedProviders:     []string{"telegram", "sms"},
			},
		},
	}
}
