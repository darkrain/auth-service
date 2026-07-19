package delivery

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/darkrain/auth-service/internal/config"
)

const (
	EventTypeDeliveryRequested = "message.delivery.requested"

	RecipientTypeEmail = "email"
	RecipientTypePhone = "phone"

	TemplateAuthVerificationCode = "auth_verification_code"
	TemplateAuthPasswordReset    = "auth_password_reset"

	PurposeRegistrationVerification = "registration_verification"
	PurposeVerification             = "verification"
	PurposePasswordReset            = "password_reset"

	PublishModeRequired   = "required"
	PublishModeBestEffort = "best_effort"
	PublishModeDisabled   = "disabled"
)

var ErrProviderNotAllowed = errors.New("delivery provider is not allowed")

type RequestEvent struct {
	Version       string            `json:"version"`
	EventID       string            `json:"event_id"`
	Type          string            `json:"type"`
	Source        string            `json:"source"`
	Template      string            `json:"template"`
	Purpose       string            `json:"purpose"`
	RecipientType string            `json:"recipient_type"`
	Recipient     string            `json:"recipient"`
	Variables     map[string]string `json:"variables"`
	UserID        int64             `json:"user_id"`
	CreatedAt     time.Time         `json:"created_at"`
	Delivery      DeliveryPolicy    `json:"delivery"`
	Metadata      map[string]string `json:"metadata"`
}

type DeliveryPolicy struct {
	SelectedProvider string   `json:"selected_provider,omitempty"`
	ProviderChain    []string `json:"provider_chain"`
	AllowFallback    bool     `json:"allow_fallback"`
}

type CodeRequest struct {
	Template         string
	Purpose          string
	RecipientType    string
	Recipient        string
	Code             string
	TTLSec           int
	UserID           int64
	DeviceUID        string
	SelectedProvider string
	AllowFallback    bool
}

func NewCodeEvent(cfg *config.Config, req CodeRequest) (*RequestEvent, error) {
	if req.RecipientType != RecipientTypeEmail && req.RecipientType != RecipientTypePhone {
		return nil, fmt.Errorf("delivery: unsupported recipient type %q", req.RecipientType)
	}
	if !cfg.IsAllowedCodeProvider(req.RecipientType, req.SelectedProvider) {
		return nil, fmt.Errorf("%w: %s", ErrProviderNotAllowed, req.SelectedProvider)
	}
	eventID, err := randomID()
	if err != nil {
		return nil, err
	}

	allowFallback := true
	if req.SelectedProvider != "" {
		allowFallback = req.AllowFallback
	}

	return &RequestEvent{
		Version:       "v1",
		EventID:       eventID,
		Type:          EventTypeDeliveryRequested,
		Source:        "auth-service",
		Template:      req.Template,
		Purpose:       req.Purpose,
		RecipientType: req.RecipientType,
		Recipient:     req.Recipient,
		Variables: map[string]string{
			"code":    req.Code,
			"ttl_sec": fmt.Sprintf("%d", req.TTLSec),
		},
		UserID:    req.UserID,
		CreatedAt: time.Now().UTC(),
		Delivery: DeliveryPolicy{
			SelectedProvider: req.SelectedProvider,
			ProviderChain:    cfg.CodeProviderChain(req.RecipientType),
			AllowFallback:    allowFallback,
		},
		Metadata: map[string]string{
			"device_uid": req.DeviceUID,
		},
	}, nil
}

func randomID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("delivery: event id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
