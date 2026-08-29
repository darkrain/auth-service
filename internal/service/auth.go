package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"database/sql"
	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/delivery"
	"github.com/darkrain/auth-service/internal/validator"
	amqp "github.com/rabbitmq/amqp091-go"
	"golang.org/x/crypto/bcrypt"
)

// ErrValidation is returned when request data is invalid.
var ErrValidation = errors.New("validation error")

// ErrInvalidEmail is returned when the email format is invalid.
var ErrInvalidEmail = errors.New("invalid email format")

// ErrInvalidPhone is returned when the phone format is invalid.
var ErrInvalidPhone = errors.New("invalid phone format")

// ErrAlreadyExists is returned when email/phone is already taken.
var ErrAlreadyExists = errors.New("login already registered")

// ErrNotFound is returned when the user is not found.
var ErrNotFound = errors.New("not found")

// ErrUnauthorized is returned when credentials are invalid.
var ErrUnauthorized = errors.New("unauthorized")

// ErrForbidden is returned when access is denied due to account status.
var ErrForbidden = errors.New("forbidden")

// ErrAccountLocked is returned when the account is temporarily locked.
var ErrAccountLocked = errors.New("account locked")

// LoginResult holds the result of a successful login.
type LoginResult struct {
	Token          string
	ExpireDate     time.Time
	Requires2FA    bool
	ChallengeToken string
}

// Login2FARequest holds the request for 2FA login verification.
type Login2FARequest struct {
	ChallengeToken string
	Code           string
	DeviceUID      string
	IP             string
}

// Login validates credentials and creates a session. Accounts with enabled
// TOTP receive a short-lived challenge after their password has been checked.
// cacheClient is used for account lock checks; may be nil.
func Login(ctx context.Context, pool *sql.DB, cfg *config.Config, cacheClient *cache.Client, login, password, deviceUID, ip string) (*LoginResult, error) {
	login = strings.TrimSpace(login)
	password = strings.TrimSpace(password)

	if login == "" {
		return nil, fmt.Errorf("%w: login is required", ErrValidation)
	}
	if password == "" {
		return nil, fmt.Errorf("%w: password is required", ErrValidation)
	}

	isEmail := strings.Contains(login, "@")

	var userID int64
	var storedHash string
	var verifyStatus string
	var twoFactorEnabled bool

	if pool != nil {
		var query string
		if isEmail {
			query = `SELECT id, password, verify_status, two_factor_enabled FROM users WHERE email = $1 LIMIT 1`
		} else {
			query = `SELECT id, password, verify_status, two_factor_enabled FROM users WHERE phone = $1 LIMIT 1`
		}
		err := pool.QueryRowContext(ctx, query, login).Scan(&userID, &storedHash, &verifyStatus, &twoFactorEnabled)
		if err != nil {
			return nil, fmt.Errorf("%w: user not found", ErrNotFound)
		}
	}

	// Check verify_status
	switch verifyStatus {
	case "verified":
		// OK
	case "registered":
		return nil, fmt.Errorf("%w: Account not verified. Please verify your email or phone.", ErrForbidden)
	case "banned":
		return nil, fmt.Errorf("%w: Account is banned.", ErrForbidden)
	case "deleted":
		return nil, fmt.Errorf("%w: Account not found.", ErrForbidden)
	default:
		return nil, fmt.Errorf("%w: Account access denied.", ErrForbidden)
	}

	// Check account lock (before password verification)
	if cacheClient != nil {
		locked, err := cacheClient.IsAccountLocked(ctx, int(userID))
		if err == nil && locked {
			return nil, fmt.Errorf("%w: account is temporarily locked", ErrAccountLocked)
		}
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(cfg.PasswordSalt+password)); err != nil {
		// Increment failed login counter
		if cacheClient != nil {
			_ = cacheClient.IncrFailedLogin(ctx, int(userID), cfg.RateLimit.Account.MaxFailedLogins, cfg.RateLimit.Account.LockDurationSec)
		}
		return nil, fmt.Errorf("%w: invalid credentials", ErrUnauthorized)
	}

	// Reset failed login counter on successful password verification
	if cacheClient != nil {
		_ = cacheClient.ResetFailedLogin(ctx, int(userID))
	}

	if twoFactorEnabled {
		challenge, err := StartLoginChallenge(ctx, cacheClient, userID, strings.TrimSpace(deviceUID), ip)
		if err != nil {
			return nil, err
		}
		return &LoginResult{Requires2FA: true, ChallengeToken: challenge}, nil
	}

	return createSession(ctx, pool, cfg, userID, strings.TrimSpace(deviceUID), ip)
}

// createSession generates a token, inserts a session, and returns LoginResult.
func createSession(ctx context.Context, pool *sql.DB, cfg *config.Config, userID int64, deviceUID, ip string) (*LoginResult, error) {
	// Generate token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("token generation: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Calculate expiry
	ttlDays := cfg.SessionTTLDays
	if ttlDays <= 0 {
		ttlDays = 30
	}
	expireDate := time.Now().Add(time.Duration(ttlDays) * 24 * time.Hour)

	if pool != nil {
		_, err := pool.ExecContext(ctx,
			`INSERT INTO sessions (user_id, token, expire_date, auth_type, ip, device_uid, last_seen_at, blocked) VALUES ($1, $2, $3, $4, $5, $6, NOW(), false)`,
			userID, token, expireDate, "password", ip, deviceUID,
		)
		if err != nil {
			return nil, fmt.Errorf("db: insert session: %w", err)
		}
	}

	return &LoginResult{
		Token:      token,
		ExpireDate: expireDate,
	}, nil
}

// LoginVerify2FA completes a password-authenticated TOTP challenge.
func LoginVerify2FA(ctx context.Context, pool *sql.DB, cfg *config.Config, cacheClient *cache.Client, req Login2FARequest) (*LoginResult, error) {
	return VerifyLoginTOTP(ctx, pool, cfg, cacheClient, req.ChallengeToken, req.Code, req.DeviceUID, req.IP)
}

// Logout marks a session as blocked and invalidates the Redis cache.
func Logout(ctx context.Context, pool *sql.DB, cacheClient *cache.Client, token string) error {
	if pool == nil {
		return nil
	}
	_, err := pool.ExecContext(ctx, `UPDATE sessions SET blocked=true WHERE token=$1`, token)
	if err != nil {
		return fmt.Errorf("db: update session: %w", err)
	}
	if cacheClient != nil {
		_ = cacheClient.DeleteSession(ctx, token)
	}
	return nil
}

// RegisterRequest holds the registration input.
type RegisterRequest struct {
	Login         string
	Password      string
	Role          string
	DeviceUID     string
	Provider      string
	AllowFallback bool
}

// RegisterResult holds the result of a successful registration.
type RegisterResult struct {
	RegistrationToken string
	ExpiresIn         int
	VerificationID    int64
	ResendAfterSec    int
}

// Register validates, hashes password, inserts user and publishes a verification event.
// Returns a short-lived registration token the client can use to authenticate verify calls.
func Register(ctx context.Context, pool *sql.DB, conn *amqp.Connection, cfg *config.Config, req RegisterRequest) (*RegisterResult, error) {
	// 1. Basic field validation
	if strings.TrimSpace(req.Login) == "" {
		return nil, fmt.Errorf("%w: login (email or phone) is required", ErrValidation)
	}
	if strings.TrimSpace(req.Password) == "" {
		return nil, fmt.Errorf("%w: password is required", ErrValidation)
	}

	// 1b. Resolve role
	role := strings.TrimSpace(req.Role)
	if role == "" {
		if len(cfg.AllowedRoles) > 0 {
			role = cfg.AllowedRoles[0]
		} else {
			role = "user"
		}
	} else {
		if role == "admin" || role == "system" {
			return nil, fmt.Errorf("%w: cannot register with reserved role", ErrForbidden)
		}
		if !cfg.IsValidRole(role) {
			return nil, fmt.Errorf("%w: invalid role", ErrValidation)
		}
	}

	// Registration enforces only the configured minimum length. Complexity is a
	// client-side strength warning, not a reason to reject a usable account.
	if err := validateRegistrationPassword(req.Password, cfg); err != nil {
		return nil, err
	}

	// 3. Determine login type
	isEmail := strings.Contains(req.Login, "@")

	// 3a. Validate format
	if isEmail {
		if !validator.IsValidEmail(req.Login) {
			return nil, ErrInvalidEmail
		}
	} else {
		if !validator.IsValidPhone(req.Login) {
			return nil, ErrInvalidPhone
		}
	}

	// 4. Uniqueness check
	if pool != nil {
		var exists bool
		var query string
		if isEmail {
			query = `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`
		} else {
			query = `SELECT EXISTS(SELECT 1 FROM users WHERE phone = $1)`
		}
		if err := pool.QueryRowContext(ctx, query, req.Login).Scan(&exists); err != nil {
			return nil, fmt.Errorf("db: uniqueness check: %w", err)
		}
		if exists {
			return nil, ErrAlreadyExists
		}
	}

	// 5. Validate password max length
	if err := validator.ValidatePasswordLength(req.Password); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrValidation, err.Error())
	}

	// 5. Hash password: bcrypt(salt + password)
	saltedPassword := cfg.PasswordSalt + req.Password
	hash, err := bcrypt.GenerateFromPassword([]byte(saltedPassword), 12)
	if err != nil {
		return nil, fmt.Errorf("bcrypt: %w", err)
	}

	// 6. Insert user
	var userID int64
	if pool != nil {
		var insertQuery string
		if isEmail {
			insertQuery = `INSERT INTO users (email, password, role, verify_status) VALUES ($1, $2, $3, 'registered') RETURNING id`
		} else {
			insertQuery = `INSERT INTO users (phone, password, role, verify_status) VALUES ($1, $2, $3, 'registered') RETURNING id`
		}
		if err := pool.QueryRowContext(ctx, insertQuery, req.Login, string(hash), role).Scan(&userID); err != nil {
			return nil, fmt.Errorf("db: insert user: %w", err)
		}
	}

	// 6b. Generate registration token (short-lived session for email/phone verification)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("token generation: %w", err)
	}
	registrationToken := hex.EncodeToString(tokenBytes)
	if strings.TrimSpace(req.DeviceUID) == "" {
		// API clients that do not have a stable device identifier still receive a
		// token-scoped delivery request; browser clients always send device_uid.
		req.DeviceUID = "registration:" + registrationToken
	}

	ttlMin := cfg.RegistrationTokenTTLMin
	if ttlMin <= 0 {
		ttlMin = 30
	}
	expireDate := time.Now().Add(time.Duration(ttlMin) * time.Minute)
	expiresIn := ttlMin * 60

	if pool != nil {
		_, err := pool.ExecContext(ctx,
			`INSERT INTO sessions (user_id, token, expire_date, auth_type, ip, blocked) VALUES ($1, $2, $3, 'registration', '127.0.0.1', false)`,
			userID, registrationToken, expireDate,
		)
		if err != nil {
			return nil, fmt.Errorf("db: insert registration session: %w", err)
		}
	}

	contactType := "phone"
	if isEmail {
		contactType = "email"
	}
	verificationID, err := CreateContactVerification(ctx, pool, conn, cfg, ContactVerificationRequest{
		UserID: userID, ContactType: contactType, Recipient: req.Login,
		DeviceUID: req.DeviceUID, Provider: req.Provider, AllowFallback: req.AllowFallback,
		Purpose: delivery.PurposeRegistrationVerification,
	})
	if err != nil {
		return nil, fmt.Errorf("send registration verification code: %w", err)
	}

	return &RegisterResult{
		RegistrationToken: registrationToken,
		ExpiresIn:         expiresIn,
		VerificationID:    verificationID,
		ResendAfterSec:    cfg.RateLimit.Code.ResendCooldownSec,
	}, nil
}

func validateRegistrationPassword(password string, cfg *config.Config) error {
	if cfg.PasswordMinLength > 0 && len(password) < cfg.PasswordMinLength {
		return fmt.Errorf("%w: password must be at least %d characters", ErrValidation, cfg.PasswordMinLength)
	}
	return nil
}

// validatePassword checks password complexity against config rules.
func validatePassword(password string, cfg *config.Config) error {
	if cfg.PasswordMinLength > 0 && len(password) < cfg.PasswordMinLength {
		return fmt.Errorf("%w: password must be at least %d characters", ErrValidation, cfg.PasswordMinLength)
	}

	if cfg.PasswordRequireDigits {
		hasDigit := false
		for _, r := range password {
			if unicode.IsDigit(r) {
				hasDigit = true
				break
			}
		}
		if !hasDigit {
			return fmt.Errorf("%w: password must contain at least one digit", ErrValidation)
		}
	}

	if cfg.PasswordRequireSpecial {
		hasSpecial := false
		for _, r := range password {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
				hasSpecial = true
				break
			}
		}
		if !hasSpecial {
			return fmt.Errorf("%w: password must contain at least one special character", ErrValidation)
		}
	}

	return nil
}
