package service

import (
	"context"
	"testing"
	"time"

	"github.com/darkrain/auth-service/internal/broker"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/delivery"
)

type recordingPublisher struct{ codes []delivery.CodeRequest }

func (p *recordingPublisher) PublishCode(_ context.Context, request delivery.CodeRequest) error {
	p.codes = append(p.codes, request)
	return nil
}

func (p *recordingPublisher) PublishNotice(context.Context, delivery.NoticeRequest) error { return nil }

func recordCodes(t *testing.T) *recordingPublisher {
	t.Helper()
	recorder := new(recordingPublisher)
	previous := delivery.NewEventPublisher
	delivery.NewEventPublisher = func(broker.ChannelProvider, *config.Config) delivery.Publisher { return recorder }
	t.Cleanup(func() { delivery.NewEventPublisher = previous })
	return recorder
}

// The code senders that need no database pass the request's language on.
// Registration, contact change and password reset are covered end to end by
// tests/integration/locale_test.go.
func TestCodeSendersPassLocale(t *testing.T) {
	cfg := &config.Config{CodeDelivery: config.CodeDeliveryConfig{Email: config.CodeDeliveryEmailConfig{DefaultProvider: "email", AllowedProviders: []string{"email"}}}}
	recorder := recordCodes(t)
	if err := SendCode(t.Context(), nil, nil, cfg, "locale@example.com", "device", "", true, 0, "zh"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := PublishContactVerification(t.Context(), nil, cfg, &PreparedContactVerification{
		ContactVerificationRequest: ContactVerificationRequest{ContactType: "email", Recipient: "locale@example.com", Locale: "ru"},
		SentAt:                     now, ExpiresAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if len(recorder.codes) != 2 || recorder.codes[0].Locale != "zh" || recorder.codes[1].Locale != "ru" {
		t.Fatalf("unexpected code requests: %+v", recorder.codes)
	}
}
