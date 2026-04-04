package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/darkrain/auth-service/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
	amqp "github.com/rabbitmq/amqp091-go"
	"golang.org/x/crypto/bcrypt"
)

// ErrValidation is returned when request data is invalid.
var ErrValidation = errors.New("validation error")

// ErrAlreadyExists is returned when email/phone is already taken.
var ErrAlreadyExists = errors.New("already exists")

// ErrNotFound is returned when the user is not found.
var ErrNotFound = errors.New("not found")

// ErrUnauthorized is returned when credentials are invalid.
var ErrUnauthorized = errors.New("unauthorized")

// ErrForbidden is returned when access is denied due to account status.
var ErrForbidden = errors.New("forbidden")

// LoginResult holds the result of a successful login.
type LoginResult struct {
	Token      string
	ExpireDate time.Time
}

// Login validates credentials, creates a session, and returns a token.
func Login(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, login, password, ip string) (*LoginResult, error) {
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

	if pool != nil {
		var query string
		if isEmail {
			query = `SELECT id, password, verify_status FROM users WHERE email = $1 LIMIT 1`
		} else {
			query = `SELECT id, password, verify_status FROM users WHERE phone = $1 LIMIT 1`
		}
		err := pool.QueryRow(ctx, query, login).Scan(&userID, &storedHash, &verifyStatus)
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

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(cfg.PasswordSalt+password)); err != nil {
		return nil, fmt.Errorf("%w: invalid credentials", ErrUnauthorized)
	}

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

	// Insert session
	if pool != nil {
		_, err := pool.Exec(ctx,
			`INSERT INTO sessions (user_id, token, expire_date, auth_type, ip, blocked) VALUES ($1, $2, $3, $4, $5, false)`,
			userID, token, expireDate, "password", ip,
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

// Logout marks a session as blocked.
func Logout(ctx context.Context, pool *pgxpool.Pool, token string) error {
	if pool == nil {
		return nil
	}
	_, err := pool.Exec(ctx, `UPDATE sessions SET blocked=true WHERE token=$1`, token)
	if err != nil {
		return fmt.Errorf("db: update session: %w", err)
	}
	return nil
}

// RegisterRequest holds the registration input.
type RegisterRequest struct {
	Login    string
	Password string
}

// Register validates, hashes password, inserts user and publishes a verification event.
func Register(ctx context.Context, pool *pgxpool.Pool, conn *amqp.Connection, cfg *config.Config, req RegisterRequest) error {
	// 1. Basic field validation
	if strings.TrimSpace(req.Login) == "" {
		return fmt.Errorf("%w: login (email or phone) is required", ErrValidation)
	}
	if strings.TrimSpace(req.Password) == "" {
		return fmt.Errorf("%w: password is required", ErrValidation)
	}

	// 2. Password complexity
	if err := validatePassword(req.Password, cfg); err != nil {
		return err
	}

	// 3. Determine login type
	isEmail := strings.Contains(req.Login, "@")

	// 4. Uniqueness check
	if pool != nil {
		var exists bool
		var query string
		if isEmail {
			query = `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`
		} else {
			query = `SELECT EXISTS(SELECT 1 FROM users WHERE phone = $1)`
		}
		if err := pool.QueryRow(ctx, query, req.Login).Scan(&exists); err != nil {
			return fmt.Errorf("db: uniqueness check: %w", err)
		}
		if exists {
			return fmt.Errorf("%w: %s is already registered", ErrAlreadyExists, req.Login)
		}
	}

	// 5. Hash password: bcrypt(salt + password)
	saltedPassword := cfg.PasswordSalt + req.Password
	hash, err := bcrypt.GenerateFromPassword([]byte(saltedPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt: %w", err)
	}

	// 6. Insert user
	var userID int64
	if pool != nil {
		var insertQuery string
		if isEmail {
			insertQuery = `INSERT INTO users (email, password, role, verify_status) VALUES ($1, $2, 'user', 'registered') RETURNING id`
		} else {
			insertQuery = `INSERT INTO users (phone, password, role, verify_status) VALUES ($1, $2, 'user', 'registered') RETURNING id`
		}
		if err := pool.QueryRow(ctx, insertQuery, req.Login, string(hash)).Scan(&userID); err != nil {
			return fmt.Errorf("db: insert user: %w", err)
		}
	}

	// 7. Publish verification event to RabbitMQ
	if conn != nil {
		eventType := "phone_verification"
		if isEmail {
			eventType = "email_verification"
		}

		type verificationEvent struct {
			Type      string `json:"type"`
			Recipient string `json:"recipient"`
			UserID    int64  `json:"user_id"`
		}

		payload, err := json.Marshal(verificationEvent{
			Type:      eventType,
			Recipient: req.Login,
			UserID:    userID,
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
			true,  // durable
			false, // auto-delete
			false, // internal
			false, // no-wait
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
