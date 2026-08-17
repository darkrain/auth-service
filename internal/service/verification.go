package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/delivery"
	"github.com/darkrain/auth-service/internal/validator"
	amqp "github.com/rabbitmq/amqp091-go"
)

// ErrTooManyRequests is returned when the rate limit is exceeded.
var ErrTooManyRequests = errors.New("too many requests")

// Err2FA is returned when 2FA is required after successful password check.
var Err2FA = errors.New("2fa required")

// ErrForbiddenRecipient is returned when the recipient does not belong to the authenticated user.
var ErrForbiddenRecipient = errors.New("recipient does not belong to authenticated user")

// SendCode generates a 6-digit verification code and publishes it to RabbitMQ.
// Rate-limited: if an existing code's TTL hasn't expired, returns ErrTooManyRequests.
// userID is the authenticated user's ID; recipient must match their email or phone.
func SendCode(ctx context.Context, pool *sql.DB, conn *amqp.Connection, cfg *config.Config, recipient, deviceUID, provider string, allowFallback bool, userID int64) error {
	recipient = strings.TrimSpace(recipient)
	if recipient == "" {
		return fmt.Errorf("%w: recipient is required", ErrValidation)
	}

	isEmail := strings.Contains(recipient, "@")

	// Validate format (IsValidEmail/IsValidPhone also enforce max length)
	if isEmail {
		if !validator.IsValidEmail(recipient) {
			return ErrInvalidEmail
		}
	} else {
		if !validator.IsValidPhone(recipient) {
			return ErrInvalidPhone
		}
	}
	recipientType := delivery.RecipientTypePhone
	if isEmail {
		recipientType = delivery.RecipientTypeEmail
	}
	if !cfg.IsAllowedCodeProvider(recipientType, provider) {
		return fmt.Errorf("%w: %s", delivery.ErrProviderNotAllowed, provider)
	}

	// HIGH-NEW-1: verify that the recipient belongs to the authenticated user
	if pool != nil && userID > 0 {
		var dbEmail, dbPhone sql.NullString
		err := pool.QueryRowContext(ctx, "SELECT email, phone FROM users WHERE id=$1", userID).Scan(&dbEmail, &dbPhone)
		if err != nil {
			return ErrForbidden
		}
		if isEmail {
			if !dbEmail.Valid || dbEmail.String != recipient {
				return ErrForbiddenRecipient
			}
		} else {
			if !dbPhone.Valid || dbPhone.String != recipient {
				return ErrForbiddenRecipient
			}
		}
	}

	// Find user_id by recipient (for RabbitMQ event payload)
	var recipientUserID int64
	if pool != nil {
		var query string
		if isEmail {
			query = `SELECT id FROM users WHERE email = $1 LIMIT 1`
		} else {
			query = `SELECT id FROM users WHERE phone = $1 LIMIT 1`
		}
		if err := pool.QueryRowContext(ctx, query, recipient).Scan(&recipientUserID); err != nil {
			// user not found — still proceed (don't leak existence)
			recipientUserID = 0
		}
	}

	// Check rate limit: if existing record has unexpired TTL, reject
	if pool != nil && cfg.RateLimit.Code.TTLSec > 0 {
		var oldSentTS time.Time
		err := pool.QueryRowContext(ctx,
			`SELECT sent_ts FROM confirm_codes WHERE device_uid=$1 AND recipient=$2 AND auth_type='verification' LIMIT 1`,
			deviceUID, recipient,
		).Scan(&oldSentTS)
		if err == nil {
			// Record exists — check TTL
			expiry := oldSentTS.Add(time.Duration(cfg.RateLimit.Code.TTLSec) * time.Second)
			if time.Now().Before(expiry) {
				return fmt.Errorf("%w: code already sent, please wait before requesting a new one", ErrTooManyRequests)
			}
		}
		// err != nil means no row → first time, fine
	}

	// Check if this is a test account
	testCode := ""
	for _, ta := range cfg.TestAccounts {
		if strings.EqualFold(ta.Login, recipient) {
			testCode = ta.Code
			break
		}
	}

	// Generate 6-digit code (or use fixed test code)
	var code string
	if testCode != "" {
		code = testCode
	} else {
		n, err := rand.Int(rand.Reader, big.NewInt(1000000))
		if err != nil {
			return fmt.Errorf("crypto/rand: %w", err)
		}
		code = fmt.Sprintf("%06d", n.Int64())
	}

	now := time.Now()

	// UPSERT into confirm_codes
	if pool != nil {
		_, upsertErr := pool.ExecContext(ctx,
			`INSERT INTO confirm_codes (device_uid, recipient, code, counter, sent_ts, auth_type)
			 VALUES ($1, $2, $3, 0, $4, 'verification')
			 ON CONFLICT (device_uid, recipient, auth_type) DO UPDATE
			 SET code = EXCLUDED.code, counter = 0, sent_ts = EXCLUDED.sent_ts`,
			deviceUID, recipient, code, now,
		)
		if upsertErr != nil {
			return fmt.Errorf("db: upsert confirm_codes: %w", upsertErr)
		}
	}

	if testCode != "" && !cfg.CodeDelivery.PublishTestAccountCodes {
		return nil
	}
	return delivery.NewPublisher(conn, cfg).PublishCode(ctx, delivery.CodeRequest{
		Template: delivery.TemplateAuthVerificationCode, Purpose: delivery.PurposeVerification,
		RecipientType: recipientType, Recipient: recipient, Code: code, TTLSec: cfg.RateLimit.Code.TTLSec,
		UserID: recipientUserID, DeviceUID: deviceUID, SelectedProvider: provider, AllowFallback: allowFallback,
	})
}
