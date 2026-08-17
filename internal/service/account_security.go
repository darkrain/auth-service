package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"database/sql"
	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const loginChallengeTTL = 5 * time.Minute

// StartLoginChallenge records a successful password check until the owner
// proves possession of the per-account TOTP factor.
func StartLoginChallenge(ctx context.Context, cacheClient *cache.Client, userID int64, deviceUID, ip string) (string, error) {
	if cacheClient == nil {
		return "", fmt.Errorf("two-factor login requires Redis")
	}
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate login challenge: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(bytes)
	if err := cacheClient.SetLoginChallenge(ctx, token, cache.LoginChallenge{UserID: userID, DeviceUID: deviceUID, IP: ip}, loginChallengeTTL); err != nil {
		return "", fmt.Errorf("store login challenge: %w", err)
	}
	return token, nil
}

// VerifyLoginTOTP completes a password-authenticated login challenge. The
// challenge is never derived from a login name, so a valid TOTP code alone
// cannot create a session.
func VerifyLoginTOTP(ctx context.Context, pool *sql.DB, cfg *config.Config, cacheClient *cache.Client, challengeToken, code, deviceUID, ip string) (*LoginResult, error) {
	challengeToken = strings.TrimSpace(challengeToken)
	code = strings.TrimSpace(code)
	if challengeToken == "" || code == "" {
		return nil, fmt.Errorf("%w: two-factor challenge and code are required", ErrValidation)
	}
	if cacheClient == nil {
		return nil, fmt.Errorf("two-factor login requires Redis")
	}
	challenge, err := cacheClient.GetLoginChallenge(ctx, challengeToken)
	if err != nil {
		return nil, fmt.Errorf("load login challenge: %w", err)
	}
	if challenge == nil || challenge.UserID <= 0 || challenge.DeviceUID != strings.TrimSpace(deviceUID) || challenge.IP != ip {
		return nil, fmt.Errorf("%w: login challenge is invalid or expired", ErrUnauthorized)
	}
	if pool == nil {
		return nil, fmt.Errorf("database is unavailable")
	}

	var status, encryptedSecret string
	var enabled bool
	if err := pool.QueryRowContext(ctx, `SELECT verify_status, two_factor_enabled, COALESCE(two_factor_secret_encrypted, '') FROM users WHERE id=$1`, challenge.UserID).Scan(&status, &enabled, &encryptedSecret); err != nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}
	if status != "verified" || !enabled {
		return nil, fmt.Errorf("%w: two-factor authentication is unavailable", ErrForbidden)
	}
	secret, err := decryptTwoFactorSecret(cfg, encryptedSecret)
	if err != nil {
		return nil, fmt.Errorf("two-factor configuration is invalid: %w", err)
	}
	valid, err := validateTOTP(secret, code)
	if err != nil {
		return nil, err
	}
	if !valid {
		attempts, incrementErr := cacheClient.IncrementLoginChallengeAttempts(ctx, challengeToken, loginChallengeTTL)
		if incrementErr == nil && cfg.RateLimit.Code.MaxAttempts > 0 && attempts >= int64(cfg.RateLimit.Code.MaxAttempts) {
			_ = cacheClient.DeleteLoginChallenge(ctx, challengeToken)
			return nil, fmt.Errorf("%w: too many two-factor attempts", ErrTooManyRequests)
		}
		return nil, fmt.Errorf("%w: invalid two-factor code", ErrUnauthorized)
	}
	if err := cacheClient.DeleteLoginChallenge(ctx, challengeToken); err != nil {
		return nil, fmt.Errorf("clear login challenge: %w", err)
	}
	return createSession(ctx, pool, cfg, challenge.UserID, deviceUID, ip)
}

func ConfigureTwoFactor(ctx context.Context, pool *sql.DB, cfg *config.Config, cacheClient *cache.Client, userID int64, currentToken string, enabled bool, secret, code string) (map[string]interface{}, error) {
	if cfg == nil || !cfg.TwoFactorEnabled {
		return nil, fmt.Errorf("%w: two-factor authentication is disabled", ErrForbidden)
	}
	if pool == nil {
		return nil, fmt.Errorf("database is unavailable")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, fmt.Errorf("%w: two-factor code is required", ErrValidation)
	}

	var storedSecret string
	var currentEnabled bool
	if err := pool.QueryRowContext(ctx, `SELECT two_factor_enabled, COALESCE(two_factor_secret_encrypted, '') FROM users WHERE id=$1`, userID).Scan(&currentEnabled, &storedSecret); err != nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}

	now := time.Now().UTC()
	if enabled {
		secret = normalizeTOTPSecret(secret)
		if secret == "" {
			return nil, fmt.Errorf("%w: two-factor secret is required", ErrValidation)
		}
		valid, err := validateTOTP(secret, code)
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, fmt.Errorf("%w: invalid two-factor code", ErrUnauthorized)
		}
		encrypted, err := encryptTwoFactorSecret(cfg, secret)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"two_factor_enabled":          true,
			"two_factor_secret_encrypted": encrypted,
			"two_factor_confirmed_at":     now.Format(time.RFC3339Nano),
		}, nil
	}

	if !currentEnabled || storedSecret == "" {
		return nil, fmt.Errorf("%w: two-factor authentication is not enabled", ErrValidation)
	}
	plain, err := decryptTwoFactorSecret(cfg, storedSecret)
	if err != nil {
		return nil, fmt.Errorf("two-factor configuration is invalid: %w", err)
	}
	valid, err := validateTOTP(plain, code)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, fmt.Errorf("%w: invalid two-factor code", ErrUnauthorized)
	}
	if err := RevokeOtherSessions(ctx, pool, cacheClient, userID, currentToken); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"two_factor_enabled":          false,
		"two_factor_secret_encrypted": nil,
		"two_factor_confirmed_at":     nil,
	}, nil
}

func ChangePassword(ctx context.Context, pool *sql.DB, cfg *config.Config, cacheClient *cache.Client, userID int64, currentToken, currentPassword, newPassword, confirmation, twoFactorCode string) (map[string]interface{}, error) {
	if newPassword != confirmation {
		return nil, fmt.Errorf("%w: password confirmation does not match", ErrValidation)
	}
	if err := validatePassword(newPassword, cfg); err != nil {
		return nil, err
	}
	if pool == nil {
		return nil, fmt.Errorf("database is unavailable")
	}

	var storedHash, encryptedSecret string
	var twoFactorEnabled bool
	if err := pool.QueryRowContext(ctx, `SELECT password, two_factor_enabled, COALESCE(two_factor_secret_encrypted, '') FROM users WHERE id=$1`, userID).Scan(&storedHash, &twoFactorEnabled, &encryptedSecret); err != nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(cfg.PasswordSalt+strings.TrimSpace(currentPassword))); err != nil {
		return nil, fmt.Errorf("%w: current password is invalid", ErrUnauthorized)
	}
	if twoFactorEnabled {
		secret, err := decryptTwoFactorSecret(cfg, encryptedSecret)
		if err != nil {
			return nil, fmt.Errorf("two-factor configuration is invalid: %w", err)
		}
		valid, err := validateTOTP(secret, strings.TrimSpace(twoFactorCode))
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, fmt.Errorf("%w: invalid two-factor code", ErrUnauthorized)
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.PasswordSalt+newPassword), 12)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	if err := RevokeOtherSessions(ctx, pool, cacheClient, userID, currentToken); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"password":            string(hash),
		"password_updated_at": time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func DeactivateAccount(ctx context.Context, pool *sql.DB, cfg *config.Config, cacheClient *cache.Client, userID int64, currentToken, currentPassword, confirmation, twoFactorCode string) (map[string]interface{}, error) {
	if confirmation != "DEACTIVATE" {
		return nil, fmt.Errorf("%w: deactivation confirmation does not match", ErrValidation)
	}
	if pool == nil {
		return nil, fmt.Errorf("database is unavailable")
	}
	var storedHash, encryptedSecret string
	var twoFactorEnabled bool
	if err := pool.QueryRowContext(ctx, `SELECT password, two_factor_enabled, COALESCE(two_factor_secret_encrypted, '') FROM users WHERE id=$1`, userID).Scan(&storedHash, &twoFactorEnabled, &encryptedSecret); err != nil {
		return nil, fmt.Errorf("%w: user not found", ErrNotFound)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(cfg.PasswordSalt+strings.TrimSpace(currentPassword))); err != nil {
		return nil, fmt.Errorf("%w: current password is invalid", ErrUnauthorized)
	}
	if twoFactorEnabled {
		secret, err := decryptTwoFactorSecret(cfg, encryptedSecret)
		if err != nil {
			return nil, fmt.Errorf("two-factor configuration is invalid: %w", err)
		}
		valid, err := validateTOTP(secret, strings.TrimSpace(twoFactorCode))
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, fmt.Errorf("%w: invalid two-factor code", ErrUnauthorized)
		}
	}
	if err := RevokeAllSessions(ctx, pool, cacheClient, userID); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"verify_status":  "deactivated",
		"deactivated_at": time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func RevokeOtherSessions(ctx context.Context, pool *sql.DB, cacheClient *cache.Client, userID int64, currentToken string) error {
	return revokeSessions(ctx, pool, cacheClient, userID, currentToken)
}

func RevokeAllSessions(ctx context.Context, pool *sql.DB, cacheClient *cache.Client, userID int64) error {
	return revokeSessions(ctx, pool, cacheClient, userID, "")
}

func revokeSessions(ctx context.Context, pool *sql.DB, cacheClient *cache.Client, userID int64, keepToken string) error {
	rows, err := pool.QueryContext(ctx, `SELECT token FROM sessions WHERE user_id=$1 AND blocked=false AND ($2='' OR token<>$2)`, userID, keepToken)
	if err != nil {
		return fmt.Errorf("list active sessions: %w", err)
	}
	defer rows.Close()
	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return fmt.Errorf("scan active session: %w", err)
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read active sessions: %w", err)
	}
	if _, err := pool.ExecContext(ctx, `UPDATE sessions SET blocked=true, update_date=NOW() WHERE user_id=$1 AND blocked=false AND ($2='' OR token<>$2)`, userID, keepToken); err != nil {
		return fmt.Errorf("revoke active sessions: %w", err)
	}
	if cacheClient != nil {
		for _, token := range tokens {
			_ = cacheClient.DeleteSession(ctx, token)
		}
	}
	return nil
}

func encryptTwoFactorSecret(cfg *config.Config, secret string) (string, error) {
	key, err := twoFactorEncryptionKey(cfg)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(secret), nil)
	return base64.RawStdEncoding.EncodeToString(append(nonce, ciphertext...)), nil
}

func decryptTwoFactorSecret(cfg *config.Config, encoded string) (string, error) {
	key, err := twoFactorEncryptionKey(cfg)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode encrypted secret: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("encrypted secret is malformed")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt encrypted secret: %w", err)
	}
	return string(plain), nil
}

func twoFactorEncryptionKey(cfg *config.Config) ([]byte, error) {
	if cfg == nil || strings.TrimSpace(cfg.TwoFactorEncryptionKey) == "" {
		return nil, fmt.Errorf("TwoFactorEncryptionKey is required for two-factor authentication")
	}
	key, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(cfg.TwoFactorEncryptionKey))
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(strings.TrimSpace(cfg.TwoFactorEncryptionKey))
	}
	if err != nil {
		return nil, fmt.Errorf("TwoFactorEncryptionKey must be base64 encoded")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("TwoFactorEncryptionKey must decode to 32 bytes")
	}
	return key, nil
}

func normalizeTOTPSecret(secret string) string {
	return strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(secret)))
}

func validateTOTP(secret, code string) (bool, error) {
	secret = normalizeTOTPSecret(secret)
	if secret == "" {
		return false, fmt.Errorf("%w: two-factor secret is required", ErrValidation)
	}
	valid, err := totp.ValidateCustom(strings.TrimSpace(code), secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return false, fmt.Errorf("%w: invalid two-factor code", ErrValidation)
	}
	return valid, nil
}
