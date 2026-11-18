package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/darkrain/auth-service/internal/broker"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/delivery"
	"github.com/darkrain/auth-service/internal/validator"
	"golang.org/x/crypto/bcrypt"
)

// ResendCooldownError tells a caller when a contact verification may be sent
// again. It wraps ErrTooManyRequests so existing error handling stays intact.
type ResendCooldownError struct {
	RetryAfterSec int
}

func (e *ResendCooldownError) Error() string {
	return fmt.Sprintf("%s: retry after %d seconds", ErrTooManyRequests, e.RetryAfterSec)
}

func (e *ResendCooldownError) Unwrap() error { return ErrTooManyRequests }

func ResendRetryAfter(err error) int {
	var cooldown *ResendCooldownError
	if errors.As(err, &cooldown) {
		return cooldown.RetryAfterSec
	}
	return 0
}

// RecipientLimitError reports that the account has already asked for codes to
// too many different addresses during the last day. Each code is an e-mail or
// a paid phone message to an address the caller chooses, so one cheap account
// must not be able to send them to arbitrary recipients.
type RecipientLimitError struct {
	Limit int
}

func (e *RecipientLimitError) Error() string {
	return fmt.Sprintf("%s: verification codes were sent to %d different contacts today", ErrTooManyRequests, e.Limit)
}

func (e *RecipientLimitError) Unwrap() error { return ErrTooManyRequests }

// StatusCode makes the generator answer 429 instead of its 400 fallback.
func (e *RecipientLimitError) StatusCode() int { return 429 }

// ContactRecipientsPerDaySetting is the «Системные настройки» key with the
// number of different contacts one account may receive codes for in 24 hours.
const (
	ContactRecipientsPerDaySetting = "auth.contact_recipients_per_day"
	DefaultContactRecipientsPerDay = 5
)

// ContactRecipientsPerDay reads the limit from the shared settings table. A
// missing row or table keeps the default; 0 switches the limit off.
func ContactRecipientsPerDay(ctx context.Context, pool *sql.DB) int {
	if pool == nil {
		return DefaultContactRecipientsPerDay
	}
	var raw string
	if err := pool.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=$1`, ContactRecipientsPerDaySetting).Scan(&raw); err != nil {
		return DefaultContactRecipientsPerDay
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 0 {
		return DefaultContactRecipientsPerDay
	}
	return value
}

// ContactChange describes a contact that ConfirmContactVerification wrote to
// the account, so the caller can end other sessions and warn the old contact.
type ContactChange struct {
	ContactType       string
	Recipient         string
	PreviousRecipient string
	Purpose           string
}

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

// RegistrationContactChangeResult contains the new verification request for
// an existing, not-yet-verified registration. The user ID and registration
// session stay unchanged, so changing a typo never creates a second account.
type RegistrationContactChangeResult struct {
	Login          string
	VerificationID int64
	ResendAfterSec int
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
	if retryAfter, err := contactVerificationRetryAfter(ctx, pool, cfg, request); err != nil {
		return nil, err
	} else if retryAfter > 0 {
		return nil, &ResendCooldownError{RetryAfterSec: retryAfter}
	}
	if err := checkContactRecipientLimit(ctx, pool, request); err != nil {
		return nil, err
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

func contactVerificationRetryAfter(ctx context.Context, pool *sql.DB, cfg *config.Config, request ContactVerificationRequest) (int, error) {
	if pool == nil || cfg.RateLimit.Code.ResendCooldownSec <= 0 {
		return 0, nil
	}
	var sentAt time.Time
	err := pool.QueryRowContext(ctx, `
		SELECT sent_ts
		FROM contact_verifications
		WHERE user_id=$1 AND contact_type=$2 AND recipient=$3 AND status='pending'
		ORDER BY sent_ts DESC
		LIMIT 1`, request.UserID, request.ContactType, request.Recipient).Scan(&sentAt)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("load verification cooldown: %w", err)
	}
	remaining := time.Until(sentAt.Add(time.Duration(cfg.RateLimit.Code.ResendCooldownSec) * time.Second))
	if remaining <= 0 {
		return 0, nil
	}
	return int(math.Ceil(remaining.Seconds())), nil
}

func checkContactRecipientLimit(ctx context.Context, pool *sql.DB, request ContactVerificationRequest) error {
	if pool == nil {
		return nil
	}
	limit := ContactRecipientsPerDay(ctx, pool)
	if limit <= 0 {
		return nil
	}
	var used int
	if err := pool.QueryRowContext(ctx, `
		SELECT COUNT(DISTINCT LOWER(recipient))
		FROM contact_verifications
		WHERE user_id=$1 AND sent_ts > NOW() - INTERVAL '24 hours' AND LOWER(recipient) <> LOWER($2)`,
		request.UserID, request.Recipient).Scan(&used); err != nil {
		return fmt.Errorf("count verification recipients: %w", err)
	}
	if used >= limit {
		return &RecipientLimitError{Limit: limit}
	}
	return nil
}

func PublishContactVerification(ctx context.Context, conn broker.ChannelProvider, cfg *config.Config, verification *PreparedContactVerification) error {
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

func CreateContactVerification(ctx context.Context, pool *sql.DB, conn broker.ChannelProvider, cfg *config.Config, request ContactVerificationRequest) (int64, error) {
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

// ChangeRegistrationContact replaces the login of an unfinished registration,
// expires every older registration code and creates a code for the new contact.
// The registration session remains valid and continues to belong to the same
// user. Updating the login immediately releases the mistyped contact instead of
// keeping it occupied until confirmation.
func ChangeRegistrationContact(ctx context.Context, pool *sql.DB, conn broker.ChannelProvider, cfg *config.Config, request ContactVerificationRequest) (*RegistrationContactChangeResult, error) {
	request.Purpose = delivery.PurposeRegistrationVerification
	prepared, err := PrepareContactVerification(ctx, pool, cfg, request)
	if err != nil {
		return nil, err
	}

	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin registration contact change: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var verifyStatus string
	if err = tx.QueryRowContext(ctx, `SELECT verify_status FROM users WHERE id=$1 FOR UPDATE`, request.UserID).Scan(&verifyStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: registration not found", ErrNotFound)
		}
		return nil, fmt.Errorf("load registration: %w", err)
	}
	if verifyStatus != "registered" {
		return nil, fmt.Errorf("%w: registration is already completed", ErrForbidden)
	}

	if _, err = tx.ExecContext(ctx, `
		UPDATE contact_verifications
		SET status='expired', update_date=NOW()
		WHERE user_id=$1 AND purpose=$2 AND status='pending'`, request.UserID, delivery.PurposeRegistrationVerification); err != nil {
		return nil, fmt.Errorf("expire previous registration codes: %w", err)
	}

	switch prepared.ContactType {
	case "email":
		_, err = tx.ExecContext(ctx, `
			UPDATE users
			SET email=$1, email_verified=false, phone=NULL, phone_verified=false, update_date=NOW()
			WHERE id=$2`, prepared.Recipient, prepared.UserID)
	case "phone":
		_, err = tx.ExecContext(ctx, `
			UPDATE users
			SET phone=$1, phone_verified=false, email=NULL, email_verified=false, update_date=NOW()
			WHERE id=$2`, prepared.Recipient, prepared.UserID)
	default:
		return nil, fmt.Errorf("%w: unsupported contact type", ErrValidation)
	}
	if err != nil {
		return nil, fmt.Errorf("update registration contact: %w", err)
	}

	var verificationID int64
	if err = tx.QueryRowContext(ctx, `
		INSERT INTO contact_verifications
			(user_id, contact_type, recipient, device_uid, provider, allow_fallback, purpose, status, code_hash, counter, sent_ts, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id`,
		prepared.UserID, prepared.ContactType, prepared.Recipient, prepared.DeviceUID, prepared.Provider,
		prepared.AllowFallback, prepared.Purpose, prepared.Status, prepared.CodeHash, prepared.Counter,
		prepared.SentAt, prepared.ExpiresAt,
	).Scan(&verificationID); err != nil {
		return nil, fmt.Errorf("create changed contact verification: %w", err)
	}

	if err = PublishContactVerification(ctx, conn, cfg, prepared); err != nil {
		return nil, fmt.Errorf("publish changed contact verification: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit registration contact change: %w", err)
	}

	return &RegistrationContactChangeResult{
		Login:          prepared.Recipient,
		VerificationID: verificationID,
		ResendAfterSec: cfg.RateLimit.Code.ResendCooldownSec,
	}, nil
}

// ConfirmContactVerification verifies a one-time code and applies the contact
// to the account in the same database transaction. A wrong code, an expired
// code and an exhausted attempt limit are committed before the error is
// returned: rolling them back left the counter at zero, so the limit never
// applied and a code could be guessed for its whole lifetime.
func ConfirmContactVerification(ctx context.Context, pool *sql.DB, cfg *config.Config, userID, verificationID int64, code string) (*ContactChange, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, fmt.Errorf("%w: verification code is required", ErrValidation)
	}
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin contact verification: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// failWith persists the state change of a rejected attempt and returns
	// the rejection.
	failWith := func(rejection error, statement string, args ...interface{}) (*ContactChange, error) {
		if _, err := tx.ExecContext(ctx, statement, args...); err != nil {
			return nil, fmt.Errorf("record verification attempt: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("record verification attempt: %w", err)
		}
		return nil, rejection
	}

	var contactType, recipient, codeHash, status, purpose string
	var counter int
	var expiresAt time.Time
	err = tx.QueryRowContext(ctx, `
		SELECT contact_type, recipient, code_hash, status, counter, expires_at, COALESCE(purpose, '')
		FROM contact_verifications WHERE id=$1 AND user_id=$2 FOR UPDATE`, verificationID, userID,
	).Scan(&contactType, &recipient, &codeHash, &status, &counter, &expiresAt, &purpose)
	if err == sql.ErrNoRows || (err == nil && status != "pending") {
		return nil, fmt.Errorf("%w: verification request not found", ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("load contact verification: %w", err)
	}
	if time.Now().UTC().After(expiresAt) {
		return failWith(fmt.Errorf("%w: verification code has expired", ErrValidation),
			`UPDATE contact_verifications SET status='expired', update_date=NOW() WHERE id=$1`, verificationID)
	}
	if cfg.RateLimit.Code.MaxAttempts > 0 && counter >= cfg.RateLimit.Code.MaxAttempts {
		return failWith(fmt.Errorf("%w: too many verification attempts", ErrTooManyRequests),
			`UPDATE contact_verifications SET status='expired', update_date=NOW() WHERE id=$1`, verificationID)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(codeHash), []byte(code)); err != nil {
		rejection := fmt.Errorf("%w: invalid verification code", ErrUnauthorized)
		if cfg.RateLimit.Code.MaxAttempts > 0 && counter+1 >= cfg.RateLimit.Code.MaxAttempts {
			rejection = fmt.Errorf("%w: too many verification attempts", ErrTooManyRequests)
		}
		return failWith(rejection, `UPDATE contact_verifications
			SET counter = counter + 1,
			    status = CASE WHEN $2 > 0 AND counter + 1 >= $2 THEN 'expired' ELSE status END,
			    update_date = NOW()
			WHERE id = $1`, verificationID, cfg.RateLimit.Code.MaxAttempts)
	}

	var previous string
	var statement string
	switch contactType {
	case "email":
		statement = "UPDATE users SET email=$1, email_verified=true, verify_status='verified', update_date=NOW() WHERE id=$2"
		err = tx.QueryRowContext(ctx, "SELECT COALESCE(email, '') FROM users WHERE id=$1 FOR UPDATE", userID).Scan(&previous)
	case "phone":
		statement = "UPDATE users SET phone=$1, phone_verified=true, verify_status='verified', update_date=NOW() WHERE id=$2"
		err = tx.QueryRowContext(ctx, "SELECT COALESCE(phone, '') FROM users WHERE id=$1 FOR UPDATE", userID).Scan(&previous)
	default:
		return nil, fmt.Errorf("%w: unsupported contact type", ErrValidation)
	}
	if err != nil {
		return nil, fmt.Errorf("load current contact: %w", err)
	}
	if _, err = tx.ExecContext(ctx, statement, recipient, userID); err != nil {
		return nil, fmt.Errorf("update verified contact: %w", err)
	}
	if _, err = tx.ExecContext(ctx, "UPDATE contact_verifications SET status='confirmed', confirmed_at=NOW(), update_date=NOW() WHERE id=$1", verificationID); err != nil {
		return nil, fmt.Errorf("complete contact verification: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit contact verification: %w", err)
	}
	return &ContactChange{ContactType: contactType, Recipient: recipient, PreviousRecipient: previous, Purpose: purpose}, nil
}

func testVerificationCode(cfg *config.Config, recipient string) string {
	for _, account := range cfg.TestAccounts {
		if strings.EqualFold(account.Login, recipient) {
			return account.Code
		}
	}
	return ""
}

// ContactChangeNotice builds the warning for the contact that a confirmed
// change replaced. Only an e-mail is warned: the phone channel delivers
// verification codes only. It returns false when there is nobody to warn:
// the contact was empty, did not change, or the change finished a
// registration.
func ContactChangeNotice(userID int64, change *ContactChange) (delivery.NoticeRequest, bool) {
	if change == nil || change.Purpose == delivery.PurposeRegistrationVerification || change.ContactType != "email" {
		return delivery.NoticeRequest{}, false
	}
	previous := strings.TrimSpace(change.PreviousRecipient)
	if previous == "" || strings.EqualFold(previous, strings.TrimSpace(change.Recipient)) {
		return delivery.NoticeRequest{}, false
	}
	return delivery.NoticeRequest{
		Template: delivery.TemplateAuthContactChanged, Purpose: delivery.PurposeSecurityNotice,
		RecipientType: delivery.RecipientTypeEmail, Recipient: previous, UserID: userID,
		Variables: map[string]string{"contact_type": change.ContactType, "new_contact": MaskContact(change.Recipient)},
	}, true
}

// PublishContactChangeNotice sends the warning built by ContactChangeNotice.
func PublishContactChangeNotice(ctx context.Context, conn broker.ChannelProvider, cfg *config.Config, notice delivery.NoticeRequest) error {
	return delivery.NewPublisher(conn, cfg).PublishNotice(ctx, notice)
}

// MaskContact keeps enough of an address to recognise it and hides the rest:
// "jo***@example.com", "+7999***45".
func MaskContact(value string) string {
	value = strings.TrimSpace(value)
	if at := strings.LastIndex(value, "@"); at > 0 {
		local, domain := value[:at], value[at:]
		keep := 2
		if len(local) <= 2 {
			keep = 1
		}
		return local[:keep] + "***" + domain
	}
	if len(value) <= 6 {
		return "***"
	}
	return value[:5] + "***" + value[len(value)-2:]
}
