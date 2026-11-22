package service

import (
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/validator"
)

// Password policy rules a refused password breaks (PasswordPolicyError.Rule).
const (
	PasswordRuleTooShort       = "too_short"
	PasswordRuleTooLong        = "too_long"
	PasswordRuleRequireDigit   = "require_digit"
	PasswordRuleRequireSpecial = "require_special"
)

// PasswordPolicyError is the refusal of a new password by ValidatePassword. It
// matches both ErrValidation and ErrWeakPassword, and its message is a plain
// sentence ("password must be at least 8 characters").
type PasswordPolicyError struct {
	Rule    string
	Message string
}

func (e *PasswordPolicyError) Error() string { return e.Message }

func (e *PasswordPolicyError) Unwrap() []error { return []error{ErrValidation, ErrWeakPassword} }

// ValidatePassword is the one password policy of every place that sets a
// password: registration, password change and password reset. A password is
// therefore accepted or refused everywhere alike. It checks the maximum length
// (validator.MaxPasswordLength bytes), the configured minimum length in
// characters (PasswordMinLength), and, only when configured, a digit
// (PasswordRequireDigits) and a character that is neither a letter nor a digit
// (PasswordRequireSpecial). The password is checked as stored, so callers
// trim it first, as sign-in does. Stored passwords are never re-checked:
// an account whose password predates the policy still signs in.
func ValidatePassword(password string, cfg *config.Config) error {
	if validator.ValidatePasswordLength(password) != nil {
		return &PasswordPolicyError{Rule: PasswordRuleTooLong,
			Message: fmt.Sprintf("password must be at most %d characters", validator.MaxPasswordLength)}
	}
	if cfg.PasswordMinLength > 0 && utf8.RuneCountInString(password) < cfg.PasswordMinLength {
		return &PasswordPolicyError{Rule: PasswordRuleTooShort,
			Message: fmt.Sprintf("password must be at least %d characters", cfg.PasswordMinLength)}
	}
	if cfg.PasswordRequireDigits && !containsRune(password, unicode.IsDigit) {
		return &PasswordPolicyError{Rule: PasswordRuleRequireDigit, Message: "password must contain at least one digit"}
	}
	if cfg.PasswordRequireSpecial && !containsRune(password, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		return &PasswordPolicyError{Rule: PasswordRuleRequireSpecial, Message: "password must contain at least one special character"}
	}
	return nil
}

// PasswordPolicyRule returns the rule err broke, or "" when err is not a
// password policy refusal.
func PasswordPolicyRule(err error) string {
	var policy *PasswordPolicyError
	if errors.As(err, &policy) {
		return policy.Rule
	}
	return ""
}

func containsRune(s string, match func(rune) bool) bool {
	for _, r := range s {
		if match(r) {
			return true
		}
	}
	return false
}
