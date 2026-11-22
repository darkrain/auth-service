package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"database/sql"
	"github.com/darkrain/auth-service/internal/broker"
	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/delivery"
	"golang.org/x/crypto/bcrypt"
)

// hashConfirmCode and confirmCodeMatches keep confirm_codes.code out of the
// database in readable form. A six-digit code is a credential: anyone who can
// read the table could finish a password reset for any account, which a
// password hash does not allow. Contact verifications already store a hash.
func hashConfirmCode(code string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash confirm code: %w", err)
	}
	return string(hash), nil
}

func confirmCodeMatches(storedHash, code string) bool {
	return bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(code)) == nil
}

// ErrInvalidCode is returned when the reset code does not match.
var ErrInvalidCode = errors.New("invalid reset code")

// ErrTooManyCodeAttempts is returned when a reset code has been guessed at too
// many times; the code must be requested again.
var ErrTooManyCodeAttempts = errors.New("too many reset code attempts")

// ErrCodeExpired is returned when the reset code has expired.
var ErrCodeExpired = errors.New("reset code has expired")

// ErrWeakPassword is returned when the new password fails validation.
var ErrWeakPassword = errors.New("password does not meet requirements")

const authTypePasswordReset = "password_reset"

// RequestPasswordReset sends a password reset code to the user.
// Always returns nil regardless of whether the user exists (no enumeration).
// Rate-limited per IP and per login via Redis. locale is the language of the
// message (delivery.RequestLocale), "" for message-delivery's default.
func RequestPasswordReset(
	ctx context.Context,
	pool *sql.DB,
	conn broker.ChannelProvider,
	cfg *config.Config,
	cacheClient *cache.Client,
	login, deviceUID, ip, locale string,
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
	if err := checkLoginRole(ctx, pool, cfg, userID); err != nil {
		return nil
	}

	// TestAccounts only shortcut login and contact verification. A reset code
	// replaces the password, so it is always random and always delivered: a
	// fixed code from the stand configuration would let anyone who knows it
	// take over the account.
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return fmt.Errorf("crypto/rand: %w", err)
	}
	code := fmt.Sprintf("%06d", n.Int64())

	now := time.Now()
	ttlSec := cfg.PasswordResetCodeTTLMin * 60

	// UPSERT into confirm_codes with auth_type='password_reset'
	storedCode, hashErr := hashConfirmCode(code)
	if hashErr != nil {
		return hashErr
	}
	_, upsertErr := pool.ExecContext(ctx,
		`INSERT INTO confirm_codes (device_uid, recipient, code, counter, sent_ts, auth_type)
		 VALUES ($1, $2, $3, 0, $4, $5)
		 ON CONFLICT (device_uid, recipient, auth_type) DO UPDATE
		 SET code = EXCLUDED.code, counter = 0, sent_ts = EXCLUDED.sent_ts`,
		deviceUID, login, storedCode, now, authTypePasswordReset,
	)
	if upsertErr != nil {
		return fmt.Errorf("db: upsert confirm_codes: %w", upsertErr)
	}

	recipientType := delivery.RecipientTypePhone
	if isEmail {
		recipientType = delivery.RecipientTypeEmail
	}
	return delivery.NewEventPublisher(conn, cfg).PublishCode(ctx, delivery.CodeRequest{
		Template: delivery.TemplateAuthPasswordReset, Purpose: delivery.PurposePasswordReset,
		RecipientType: recipientType, Recipient: login, Code: code, TTLSec: ttlSec,
		UserID: userID, DeviceUID: deviceUID, AllowFallback: true, Locale: locale,
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

	if err := checkLoginRole(ctx, pool, cfg, userID); err != nil {
		return err
	}

	// Reserve one attempt before the slow bcrypt comparison. Reading the
	// counter first and incrementing it after the comparison let parallel
	// requests all pass the limit check, so one code got far more guesses than
	// MaxAttempts. The conditional UPDATE serialises on the row: at most
	// MaxAttempts requests get a row back, every later one gets none.
	maxAttempts := cfg.RateLimit.Code.MaxAttempts
	var storedCode string
	var sentTS time.Time
	err := pool.QueryRowContext(ctx,
		`UPDATE confirm_codes SET counter = counter + 1
		 WHERE device_uid=$1 AND recipient=$2 AND auth_type=$3 AND ($4 <= 0 OR counter < $4)
		 RETURNING code, sent_ts`,
		deviceUID, login, authTypePasswordReset, maxAttempts,
	).Scan(&storedCode, &sentTS)
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		if existsErr := pool.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM confirm_codes WHERE device_uid=$1 AND recipient=$2 AND auth_type=$3)`,
			deviceUID, login, authTypePasswordReset,
		).Scan(&exists); existsErr == nil && exists {
			return ErrTooManyCodeAttempts
		}
		return ErrInvalidCode
	}
	if err != nil {
		return fmt.Errorf("db: reserve reset attempt: %w", err)
	}

	// Check TTL
	ttlSec := cfg.PasswordResetCodeTTLMin * 60
	if ttlSec > 0 {
		expiry := sentTS.Add(time.Duration(ttlSec) * time.Second)
		if time.Now().After(expiry) {
			return ErrCodeExpired
		}
	}

	if !confirmCodeMatches(storedCode, code) {
		return ErrInvalidCode
	}

	// Validate new password
	if err := ValidatePassword(newPassword, cfg); err != nil {
		return err
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

	// Invalidate all sessions of this user, including device-handoff codes
	// that are still waiting to be redeemed.
	if err := RevokeAllSessions(ctx, pool, cacheClient, userID); err != nil {
		return err
	}

	return nil
}
