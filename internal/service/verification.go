package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/validator"
	"github.com/jackc/pgx/v5/pgxpool"
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
func SendCode(ctx context.Context, pool *pgxpool.Pool, conn *amqp.Connection, cfg *config.Config, recipient, deviceUID string, userID int64) error {
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

	// HIGH-NEW-1: verify that the recipient belongs to the authenticated user
	if pool != nil && userID > 0 {
		var dbEmail, dbPhone sql.NullString
		err := pool.QueryRow(ctx, "SELECT email, phone FROM users WHERE id=$1", userID).Scan(&dbEmail, &dbPhone)
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
		if err := pool.QueryRow(ctx, query, recipient).Scan(&recipientUserID); err != nil {
			// user not found — still proceed (don't leak existence)
			recipientUserID = 0
		}
	}

	// Check rate limit: if existing record has unexpired TTL, reject
	if pool != nil && cfg.RateLimit.Code.TTLSec > 0 {
		var oldSentTS time.Time
		err := pool.QueryRow(ctx,
			`SELECT sent_ts FROM confirm_codes WHERE device_uid=$1 AND recipient=$2 LIMIT 1`,
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
		_, upsertErr := pool.Exec(ctx,
			`INSERT INTO confirm_codes (device_uid, recipient, code, counter, sent_ts)
			 VALUES ($1, $2, $3, 0, $4)
			 ON CONFLICT (device_uid, recipient) DO UPDATE
			 SET code = EXCLUDED.code, counter = 0, sent_ts = EXCLUDED.sent_ts`,
			deviceUID, recipient, code, now,
		)
		if upsertErr != nil {
			return fmt.Errorf("db: upsert confirm_codes: %w", upsertErr)
		}
	}

	// Skip RabbitMQ publish for test accounts
	if testCode != "" {
		return nil
	}

	// Publish event to RabbitMQ
	if conn != nil {
		eventType := "phone_verification"
		if isEmail {
			eventType = "email_verification"
		}

		type verificationEvent struct {
			Type      string `json:"type"`
			Recipient string `json:"recipient"`
			Code      string `json:"code"`
			UserID    int64  `json:"user_id"`
		}

		payload, err := json.Marshal(verificationEvent{
			Type:      eventType,
			Recipient: recipient,
			Code:      code,
			UserID:    recipientUserID,
		})
		if err != nil {
			return fmt.Errorf("json: marshal event: %w", err)
		}

		ch, err := conn.Channel()
		if err != nil {
			return fmt.Errorf("broker: open channel: %w", err)
		}
		defer ch.Close()

		if err := ch.ExchangeDeclare(
			cfg.RmqExchangeName,
			cfg.RmqExchangeKind,
			true,
			false,
			false,
			false,
			nil,
		); err != nil {
			return fmt.Errorf("broker: declare exchange: %w", err)
		}

		if err := ch.PublishWithContext(ctx,
			cfg.RmqExchangeName,
			cfg.RmqQueueMailName,
			false,
			false,
			amqp.Publishing{
				ContentType: "application/json",
				Body:        payload,
			},
		); err != nil {
			return fmt.Errorf("broker: publish: %w", err)
		}
	}

	return nil
}

// VerifyCode checks a verification code for the given recipient+deviceUID.
// verifyType must be "email" or "phone".
// userID is the authenticated user's ID; the recipient must match their email/phone.
// cacheClient is optional; used to purge registration session tokens from Redis.
func VerifyCode(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, cacheClient *cache.Client, recipient, code, deviceUID, verifyType string, userID int64) error {
	recipient = strings.TrimSpace(recipient)
	code = strings.TrimSpace(code)

	if pool == nil {
		return nil
	}

	// Validate recipient format
	isEmail := strings.Contains(recipient, "@")
	if isEmail {
		if !validator.IsValidEmail(recipient) {
			return ErrInvalidEmail
		}
	} else {
		if !validator.IsValidPhone(recipient) {
			return ErrInvalidPhone
		}
	}

	// Verify that the recipient belongs to the authenticated user (CRIT-2)
	if userID > 0 {
		var dbValue string
		var ownerQuery string
		if isEmail {
			ownerQuery = `SELECT COALESCE(email,'') FROM users WHERE id=$1 LIMIT 1`
		} else {
			ownerQuery = `SELECT COALESCE(phone,'') FROM users WHERE id=$1 LIMIT 1`
		}
		if err := pool.QueryRow(ctx, ownerQuery, userID).Scan(&dbValue); err != nil {
			return fmt.Errorf("%w: user not found", ErrNotFound)
		}
		if dbValue != recipient {
			return fmt.Errorf("%w: recipient does not match authenticated user", ErrForbidden)
		}
	}

	var storedCode string
	var counter int64
	var sentTS time.Time

	err := pool.QueryRow(ctx,
		`SELECT code, counter, sent_ts FROM confirm_codes WHERE device_uid=$1 AND recipient=$2 LIMIT 1`,
		deviceUID, recipient,
	).Scan(&storedCode, &counter, &sentTS)
	if err != nil {
		return fmt.Errorf("%w: verification code not found", ErrNotFound)
	}

	// Check TTL
	if cfg.RateLimit.Code.TTLSec > 0 {
		expiry := sentTS.Add(time.Duration(cfg.RateLimit.Code.TTLSec) * time.Second)
		if time.Now().After(expiry) {
			return fmt.Errorf("%w: verification code has expired", ErrValidation)
		}
	}

	// Check attempt counter
	if cfg.RateLimit.Code.MaxAttempts > 0 && counter >= int64(cfg.RateLimit.Code.MaxAttempts) {
		return fmt.Errorf("%w: Too many attempts. Request a new code.", ErrTooManyRequests)
	}

	// Compare code
	if code != storedCode {
		// Increment counter
		_, _ = pool.Exec(ctx,
			`UPDATE confirm_codes SET counter=counter+1 WHERE device_uid=$1 AND recipient=$2`,
			deviceUID, recipient,
		)
		return fmt.Errorf("%w: invalid verification code", ErrUnauthorized)
	}

	// Code is correct — update user and delete confirm record
	if verifyType == "email" {
		_, err = pool.Exec(ctx,
			`UPDATE users SET email_verified=true, verify_status='verified' WHERE email=$1`,
			recipient,
		)
	} else {
		_, err = pool.Exec(ctx,
			`UPDATE users SET phone_verified=true, verify_status='verified' WHERE phone=$1`,
			recipient,
		)
	}
	if err != nil {
		return fmt.Errorf("db: update user verified: %w", err)
	}

	_, err = pool.Exec(ctx,
		`DELETE FROM confirm_codes WHERE device_uid=$1 AND recipient=$2`,
		deviceUID, recipient,
	)
	if err != nil {
		return fmt.Errorf("db: delete confirm_codes: %w", err)
	}

	// Invalidate all registration tokens for this user
	if userID > 0 {
		// Fetch registration session tokens before blocking them (for cache invalidation)
		if cacheClient != nil {
			rows, qErr := pool.Query(ctx,
				`SELECT token FROM sessions WHERE user_id=$1 AND auth_type='registration' AND blocked=false`,
				userID,
			)
			if qErr == nil {
				defer rows.Close()
				for rows.Next() {
					var t string
					if rows.Scan(&t) == nil {
						_ = cacheClient.DeleteSession(ctx, t)
					}
				}
			}
		}
		_, _ = pool.Exec(ctx,
			`UPDATE sessions SET blocked=true WHERE user_id=$1 AND auth_type='registration'`,
			userID,
		)
	}

	return nil
}
