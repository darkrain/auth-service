package delivery

import (
	"testing"

	"github.com/darkrain/auth-service/internal/config"
)

func TestNewCodeEventUsesConfiguredPhoneChain(t *testing.T) {
	cfg := &config.Config{CodeDelivery: config.CodeDeliveryConfig{Phone: config.CodeDeliveryPhoneConfig{DefaultProviderChain: []string{"telegram", "whatsapp", "sms"}, AllowedProviders: []string{"telegram", "whatsapp", "sms"}}}}
	event, err := NewCodeEvent(cfg, CodeRequest{Template: TemplateAuthVerificationCode, Purpose: PurposeVerification, RecipientType: RecipientTypePhone, Recipient: "+79312700684", Code: "123456", TTLSec: 300, SelectedProvider: "telegram", AllowFallback: false})
	if err != nil {
		t.Fatal(err)
	}
	if event.Type != EventTypeDeliveryRequested || event.Version != "v1" {
		t.Fatalf("unexpected event identity: %#v", event)
	}
	if event.Delivery.SelectedProvider != "telegram" || event.Delivery.AllowFallback {
		t.Fatalf("unexpected delivery policy: %#v", event.Delivery)
	}
	if len(event.Delivery.ProviderChain) != 3 || event.Variables["code"] != "123456" {
		t.Fatalf("unexpected event: %#v", event)
	}
}

func TestNewCodeEventRejectsUnknownProvider(t *testing.T) {
	cfg := &config.Config{CodeDelivery: config.CodeDeliveryConfig{Email: config.CodeDeliveryEmailConfig{DefaultProvider: "email", AllowedProviders: []string{"email"}}}}
	if _, err := NewCodeEvent(cfg, CodeRequest{RecipientType: RecipientTypeEmail, SelectedProvider: "telegram"}); err == nil {
		t.Fatal("expected provider validation error")
	}
}

func TestPublisherDisabledDoesNotRequireBroker(t *testing.T) {
	cfg := &config.Config{MessageBroker: config.MessageBrokerConfig{PublishMode: PublishModeDisabled}, CodeDelivery: config.CodeDeliveryConfig{Email: config.CodeDeliveryEmailConfig{DefaultProvider: "email", AllowedProviders: []string{"email"}}}}
	if err := NewPublisher(nil, cfg).PublishCode(t.Context(), CodeRequest{RecipientType: RecipientTypeEmail, Recipient: "test@example.com"}); err != nil {
		t.Fatal(err)
	}
}
