package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
