package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/delivery"
	"github.com/darkrain/auth-service/internal/validator"
	amqp "github.com/rabbitmq/amqp091-go"
	"golang.org/x/crypto/bcrypt"
)

// ContactVerificationRequest describes a code delivery request. It is shared
// by registration and the generator-backed account settings flow.
type ContactVerificationRequest struct {
	UserID        int64
	ContactType   string
	Recipient     string
	DeviceUID     string
	Provider      string
	AllowFallback bool
	Purpose       string
}

// PreparedContactVerification contains server-generated data that must never
// be supplied by a browser. Code is kept only until the delivery event is sent.
type PreparedContactVerification struct {
	ContactVerificationRequest
	Code      string
	CodeHash  string
	Status    string
	Counter   int
	SentAt    time.Time
	ExpiresAt time.Time
}

func PrepareContactVerification(ctx context.Context, pool *sql.DB, cfg *config.Config, request ContactVerificationRequest) (*PreparedContactVerification, error) {
	request.ContactType = strings.TrimSpace(request.ContactType)
	request.Recipient = strings.TrimSpace(request.Recipient)
	request.DeviceUID = strings.TrimSpace(request.DeviceUID)
	request.Provider = strings.TrimSpace(request.Provider)
	if request.UserID <= 0 {
		return nil, fmt.Errorf("%w: user is required", ErrValidation)
	}
	if request.DeviceUID == "" {
		return nil, fmt.Errorf("%w: device_uid is required", ErrValidation)
	}
	if request.Purpose == "" {
		request.Purpose = delivery.PurposeVerification
	}

	var recipientType string
	switch request.ContactType {
	case "email":
		if !validator.IsValidEmail(request.Recipient) {
			return nil, ErrInvalidEmail
		}
		recipientType = delivery.RecipientTypeEmail
	case "phone":
		if !validator.IsValidPhone(request.Recipient) {
			return nil, ErrInvalidPhone
		}
		recipientType = delivery.RecipientTypePhone
	default:
		return nil, fmt.Errorf("%w: contact_type must be email or phone", ErrValidation)
	}
	if !cfg.IsAllowedCodeProvider(recipientType, request.Provider) {
		return nil, fmt.Errorf("%w: %s", delivery.ErrProviderNotAllowed, request.Provider)
	}

	if pool != nil {
		var exists bool
		column := "email"
		if request.ContactType == "phone" {
			column = "phone"
		}
		query := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM users WHERE %s=$1 AND id<>$2)", column)
		if err := pool.QueryRowContext(ctx, query, request.Recipient, request.UserID).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check contact availability: %w", err)
		}
		if exists {
			return nil, fmt.Errorf("%w: contact is already in use", ErrAlreadyExists)
		}
	}

	code := testVerificationCode(cfg, request.Recipient)
	if code == "" {
		n, err := rand.Int(rand.Reader, big.NewInt(1000000))
		if err != nil {
			return nil, fmt.Errorf("generate verification code: %w", err)
		}
		code = fmt.Sprintf("%06d", n.Int64())
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash verification code: %w", err)
	}
	ttl := cfg.RateLimit.Code.TTLSec
	if ttl <= 0 {
		ttl = 300
	}
	now := time.Now().UTC()
	return &PreparedContactVerification{
		ContactVerificationRequest: request,
		Code:                       code,
		CodeHash:                   string(hash),
		Status:                     "pending",
		SentAt:                     now,
		ExpiresAt:                  now.Add(time.Duration(ttl) * time.Second),
	}, nil
}

func PublishContactVerification(ctx context.Context, conn *amqp.Connection, cfg *config.Config, verification *PreparedContactVerification) error {
	if verification == nil {
		return fmt.Errorf("%w: verification is required", ErrValidation)
	}
	if testVerificationCode(cfg, verification.Recipient) != "" && !cfg.CodeDelivery.PublishTestAccountCodes {
		return nil
	}
	recipientType := delivery.RecipientTypeEmail
	if verification.ContactType == "phone" {
		recipientType = delivery.RecipientTypePhone
	}
	return delivery.NewPublisher(conn, cfg).PublishCode(ctx, delivery.CodeRequest{
		Template:         delivery.TemplateAuthVerificationCode,
		Purpose:          verification.Purpose,
		RecipientType:    recipientType,
		Recipient:        verification.Recipient,
		Code:             verification.Code,
		TTLSec:           int(verification.ExpiresAt.Sub(verification.SentAt).Seconds()),
		UserID:           verification.UserID,
		DeviceUID:        verification.DeviceUID,
		SelectedProvider: verification.Provider,
		AllowFallback:    verification.AllowFallback,
	})
}

func CreateContactVerification(ctx context.Context, pool *sql.DB, conn *amqp.Connection, cfg *config.Config, request ContactVerificationRequest) (int64, error) {
	prepared, err := PrepareContactVerification(ctx, pool, cfg, request)
	if err != nil {
		return 0, err
	}
	var id int64
	if err := pool.QueryRowContext(ctx, `
		INSERT INTO contact_verifications
			(user_id, contact_type, recipient, device_uid, provider, allow_fallback, purpose, status, code_hash, counter, sent_ts, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id`,
		prepared.UserID, prepared.ContactType, prepared.Recipient, prepared.DeviceUID, prepared.Provider,
		prepared.AllowFallback, prepared.Purpose, prepared.Status, prepared.CodeHash, prepared.Counter,
		prepared.SentAt, prepared.ExpiresAt,
	).Scan(&id); err != nil {
		return 0, fmt.Errorf("create contact verification: %w", err)
	}
	if err := PublishContactVerification(ctx, conn, cfg, prepared); err != nil {
		return 0, err
	}
	return id, nil
}

// ConfirmContactVerification verifies a one-time code and applies the contact
// to the account in the same database transaction.
func ConfirmContactVerification(ctx context.Context, pool *sql.DB, cfg *config.Config, userID, verificationID int64, code string) error {
	code = strings.TrimSpace(code)
	if code == "" {
		return fmt.Errorf("%w: verification code is required", ErrValidation)
	}
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin contact verification: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var contactType, recipient, codeHash, status string
	var counter int
	var expiresAt time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT contact_type, recipient, code_hash, status, counter, expires_at
		FROM contact_verifications WHERE id=$1 AND user_id=$2 FOR UPDATE`, verificationID, userID,
	).Scan(&contactType, &recipient, &codeHash, &status, &counter, &expiresAt)
	if err == sql.ErrNoRows || status != "pending" {
		return fmt.Errorf("%w: verification request not found", ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("load contact verification: %w", err)
	}
	if time.Now().UTC().After(expiresAt) {
		_, _ = tx.ExecContext(ctx, "UPDATE contact_verifications SET status='expired', update_date=NOW() WHERE id=$1", verificationID)
		return fmt.Errorf("%w: verification code has expired", ErrValidation)
	}
	if cfg.RateLimit.Code.MaxAttempts > 0 && counter >= cfg.RateLimit.Code.MaxAttempts {
		return fmt.Errorf("%w: too many verification attempts", ErrTooManyRequests)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(codeHash), []byte(code)); err != nil {
		_, _ = tx.ExecContext(ctx, "UPDATE contact_verifications SET counter=counter+1, update_date=NOW() WHERE id=$1", verificationID)
		return fmt.Errorf("%w: invalid verification code", ErrUnauthorized)
	}

	var statement string
	switch contactType {
	case "email":
		statement = "UPDATE users SET email=$1, email_verified=true, verify_status='verified', update_date=NOW() WHERE id=$2"
	case "phone":
		statement = "UPDATE users SET phone=$1, phone_verified=true, verify_status='verified', update_date=NOW() WHERE id=$2"
	default:
		return fmt.Errorf("%w: unsupported contact type", ErrValidation)
	}
	if _, err = tx.ExecContext(ctx, statement, recipient, userID); err != nil {
		return fmt.Errorf("update verified contact: %w", err)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE contact_verifications SET status='confirmed', confirmed_at=NOW(), update_date=NOW() WHERE id=$1", verificationID); err != nil {
		return fmt.Errorf("complete contact verification: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit contact verification: %w", err)
	}
	return nil
}

func testVerificationCode(cfg *config.Config, recipient string) string {
	for _, account := range cfg.TestAccounts {
		if strings.EqualFold(account.Login, recipient) {
			return account.Code
		}
	}
	return ""
}
