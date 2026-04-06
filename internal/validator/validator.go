package validator

import (
	"errors"
	"regexp"
)

// MaxPasswordLength is the maximum allowed password length.
const MaxPasswordLength = 128

// MaxEmailLength is the maximum allowed email length (RFC 5321).
const MaxEmailLength = 254

// MaxPhoneLength is the maximum allowed phone length (E.164 max = 15 digits + '+').
const MaxPhoneLength = 16

var (
	// emailRegex matches RFC 5322 subset: user@domain.tld
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	// phoneRegex matches E.164: starts with +, then 6-14 digits (total 7-15 chars)
	phoneRegex = regexp.MustCompile(`^\+[1-9]\d{6,14}$`)
)

// IsValidEmail returns true if s is a valid email address (RFC 5322 subset).
func IsValidEmail(s string) bool {
	if len(s) > MaxEmailLength {
		return false
	}
	return emailRegex.MatchString(s)
}

// IsValidPhone returns true if s is a valid phone number in E.164 format (+79991234567).
func IsValidPhone(s string) bool {
	if len(s) > MaxPhoneLength {
		return false
	}
	return phoneRegex.MatchString(s)
}

// ValidatePasswordLength returns an error if the password exceeds MaxPasswordLength.
func ValidatePasswordLength(s string) error {
	if len(s) > MaxPasswordLength {
		return errors.New("password too long (max 128 characters)")
	}
	return nil
}
