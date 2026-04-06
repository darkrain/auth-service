package validator

import "regexp"

var (
	// emailRegex matches RFC 5322 subset: user@domain.tld
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	// phoneRegex matches E.164: starts with +, then 6-14 digits (total 7-15 chars)
	phoneRegex = regexp.MustCompile(`^\+[1-9]\d{6,14}$`)
)

// IsValidEmail returns true if s is a valid email address (RFC 5322 subset).
func IsValidEmail(s string) bool {
	return emailRegex.MatchString(s)
}

// IsValidPhone returns true if s is a valid phone number in E.164 format (+79991234567).
func IsValidPhone(s string) bool {
	return phoneRegex.MatchString(s)
}
