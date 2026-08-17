package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"database/sql"
	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/delivery"
	amqp "github.com/rabbitmq/amqp091-go"
	"golang.org/x/crypto/bcrypt"
)

// ErrInvalidCode is returned when the reset code does not match.
var ErrInvalidCode = errors.New("invalid reset code")

// ErrCodeExpired is returned when the reset code has expired.
var ErrCodeExpired = errors.New("reset code has expired")

// ErrWeakPassword is returned when the new password fails validation.
var ErrWeakPassword = errors.New("password does not meet requirements")

const authTypePasswordReset = "password_reset"

// RequestPasswordReset sends a password reset code to the user.
// Always returns nil regardless of whether the user exists (no enumeration).
// Rate-limited per IP and per login via Redis.
func RequestPasswordReset(
	ctx context.Context,
	pool *sql.DB,
	conn *amqp.Connection,
	cfg *config.Config,
	cacheClient *cache.Client,
	login, deviceUID, ip string,
) error {
	login = strings.TrimSpace(login)
	if login == "" {
		// Silently ignore — no enumeration
		return nil
	}

	// Rate limit by IP
	if cacheClient != nil && cfg.PasswordResetRateLimitPerHour > 0 && ip != "" {
		ipKey := fmt.Sprintf("rate:password_reset:%s", ip)
		count, err := cacheClient.SlidingWindowIncr(ctx, ipKey, 3600)
		if err == nil && count > int64(cfg.PasswordResetRateLimitPerHour) {
			// Exceeded — silently return nil (no enumeration for reset-request)
			return nil
		}
	}

	// Rate limit by login
	if cacheClient != nil && cfg.PasswordResetRateLimitPerHour > 0 && login != "" {
		loginKey := fmt.Sprintf("rate:password_reset:login:%s", strings.ToLower(login))
		count, err := cacheClient.SlidingWindowIncr(ctx, loginKey, 3600)
		if err == nil && count > int64(cfg.PasswordResetRateLimitPerHour) {
			return nil
		}
	}

	if pool == nil {
		return nil
	}

	// Look up user by email or phone (case-insensitive)
	isEmail := strings.Contains(login, "@")
	var userID int64
	var verifyStatus string

	var query string
	if isEmail {
		query = `SELECT id, verify_status FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1`
	} else {
		query = `SELECT id, verify_status FROM users WHERE phone = $1 LIMIT 1`
	}
	err := pool.QueryRowContext(ctx, query, login).Scan(&userID, &verifyStatus)
	if err != nil {
		// User not found — no enumeration, return nil
		return nil
	}

	// Only send code for verified users
	if verifyStatus != "verified" {
		return nil
	}

	// Check if this is a test account
	testCode := ""
	for _, ta := range cfg.TestAccounts {
		if strings.EqualFold(ta.Login, login) {
			testCode = ta.Code
			break
		}
	}

	// Generate or use fixed code
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
	ttlSec := cfg.PasswordResetCodeTTLMin * 60

	// UPSERT into confirm_codes with auth_type='password_reset'
	_, upsertErr := pool.ExecContext(ctx,
		`INSERT INTO confirm_codes (device_uid, recipient, code, counter, sent_ts, auth_type)
		 VALUES ($1, $2, $3, 0, $4, $5)
		 ON CONFLICT (device_uid, recipient, auth_type) DO UPDATE
		 SET code = EXCLUDED.code, counter = 0, sent_ts = EXCLUDED.sent_ts`,
		deviceUID, login, code, now, authTypePasswordReset,
	)
	if upsertErr != nil {
		return fmt.Errorf("db: upsert confirm_codes: %w", upsertErr)
	}

	if testCode != "" && !cfg.CodeDelivery.PublishTestAccountCodes {
		return nil
	}
	recipientType := delivery.RecipientTypePhone
	if isEmail {
		recipientType = delivery.RecipientTypeEmail
	}
	return delivery.NewPublisher(conn, cfg).PublishCode(ctx, delivery.CodeRequest{
		Template: delivery.TemplateAuthPasswordReset, Purpose: delivery.PurposePasswordReset,
		RecipientType: recipientType, Recipient: login, Code: code, TTLSec: ttlSec,
		UserID: userID, DeviceUID: deviceUID, AllowFallback: true,
	})
}

// ConfirmPasswordReset verifies the reset code, updates the password, and invalidates all sessions.
func ConfirmPasswordReset(
	ctx context.Context,
	pool *sql.DB,
	cfg *config.Config,
	cacheClient *cache.Client,
	login, code, deviceUID, newPassword string,
) error {
	login = strings.TrimSpace(login)
	code = strings.TrimSpace(code)
	newPassword = strings.TrimSpace(newPassword)

	if pool == nil {
		return nil
	}

	// Find user by login
	isEmail := strings.Contains(login, "@")
	var userID int64
	var findQuery string
	if isEmail {
		findQuery = `SELECT id FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1`
	} else {
		findQuery = `SELECT id FROM users WHERE phone = $1 LIMIT 1`
	}
	if err := pool.QueryRowContext(ctx, findQuery, login).Scan(&userID); err != nil {
		return fmt.Errorf("%w: user not found", ErrNotFound)
	}

	// Find reset code
	var storedCode string
	var counter int64
	var sentTS time.Time
	err := pool.QueryRowContext(ctx,
		`SELECT code, counter, sent_ts FROM confirm_codes
		 WHERE device_uid=$1 AND recipient=$2 AND auth_type=$3 LIMIT 1`,
		deviceUID, login, authTypePasswordReset,
	).Scan(&storedCode, &counter, &sentTS)
	if err != nil {
		return ErrInvalidCode
	}

	// Check TTL
	ttlSec := cfg.PasswordResetCodeTTLMin * 60
	if ttlSec > 0 {
		expiry := sentTS.Add(time.Duration(ttlSec) * time.Second)
		if time.Now().After(expiry) {
			return ErrCodeExpired
		}
	}

	// Compare code
	if subtle.ConstantTimeCompare([]byte(code), []byte(storedCode)) != 1 {
		// Increment counter
		_, _ = pool.ExecContext(ctx,
			`UPDATE confirm_codes SET counter=counter+1
			 WHERE device_uid=$1 AND recipient=$2 AND auth_type=$3`,
			deviceUID, login, authTypePasswordReset,
		)
		return ErrInvalidCode
	}

	// Validate new password
	if err := validatePassword(newPassword, cfg); err != nil {
		return fmt.Errorf("%w: %s", ErrWeakPassword, err.Error())
	}

	// Hash new password
	saltedPassword := cfg.PasswordSalt + newPassword
	hash, err := bcrypt.GenerateFromPassword([]byte(saltedPassword), 12)
	if err != nil {
		return fmt.Errorf("bcrypt: %w", err)
	}

	// Update password
	_, err = pool.ExecContext(ctx,
		`UPDATE users SET password=$1, password_updated_at=NOW(), update_date=NOW() WHERE id=$2`,
		string(hash), userID,
	)
	if err != nil {
		return fmt.Errorf("db: update password: %w", err)
	}

	// Delete the reset code
	_, _ = pool.ExecContext(ctx,
		`DELETE FROM confirm_codes WHERE device_uid=$1 AND recipient=$2 AND auth_type=$3`,
		deviceUID, login, authTypePasswordReset,
	)

	// Invalidate all active sessions for this user
	// First, collect session tokens for Redis cache invalidation
	if cacheClient != nil {
		rows, qErr := pool.QueryContext(ctx,
			`SELECT token FROM sessions WHERE user_id=$1 AND blocked=false`,
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

	// Mark all sessions as blocked in DB
	_, _ = pool.ExecContext(ctx,
		`UPDATE sessions SET blocked=true WHERE user_id=$1`,
		userID,
	)

	return nil
}
