package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/darkrain/auth-service/internal/config"
)

func TestValidatePassword(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		minLength                     int
		requireDigits, requireSpecial bool
		password, wantRule            string
	}{
		{name: "length only accepts letters", minLength: 8, password: "lettersonly"},
		{name: "exact minimum", minLength: 8, password: "abcdefgh"},
		{name: "too short", minLength: 8, password: "abc1!xy", wantRule: PasswordRuleTooShort},
		{name: "minimum counts characters not bytes", minLength: 8, password: "пароль1", wantRule: PasswordRuleTooShort},
		{name: "cyrillic at minimum", minLength: 8, password: "парольпа"},
		{name: "no minimum configured", password: "a"},
		{name: "too long", minLength: 8, password: strings.Repeat("a", 129), wantRule: PasswordRuleTooLong},
		{name: "maximum length", minLength: 8, password: strings.Repeat("a", 128)},
		{name: "digit flag refuses", minLength: 8, requireDigits: true, password: "Password!", wantRule: PasswordRuleRequireDigit},
		{name: "digit flag accepts", minLength: 8, requireDigits: true, password: "Password1"},
		{name: "special flag refuses", minLength: 8, requireSpecial: true, password: "Password1", wantRule: PasswordRuleRequireSpecial},
		{name: "special flag accepts", minLength: 8, requireSpecial: true, password: "Password!"},
		{name: "length is checked first", minLength: 8, requireDigits: true, requireSpecial: true, password: "abc", wantRule: PasswordRuleTooShort},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{PasswordMinLength: tc.minLength, PasswordRequireDigits: tc.requireDigits, PasswordRequireSpecial: tc.requireSpecial}
			err := ValidatePassword(tc.password, cfg)
			if got := PasswordPolicyRule(err); got != tc.wantRule {
				t.Fatalf("ValidatePassword(%q) = %v, want rule %q", tc.password, err, tc.wantRule)
			}
			if tc.wantRule != "" && (!errors.Is(err, ErrValidation) || !errors.Is(err, ErrWeakPassword)) {
				t.Fatalf("policy refusal must match ErrValidation and ErrWeakPassword: %v", err)
			}
		})
	}
}

func TestValidatePasswordMessage(t *testing.T) {
	err := ValidatePassword("short", &config.Config{PasswordMinLength: 8})
	if err == nil || err.Error() != "password must be at least 8 characters" {
		t.Fatalf("unexpected message: %v", err)
	}
	if PasswordPolicyRule(errors.New("other")) != "" || PasswordPolicyRule(nil) != "" {
		t.Fatal("only policy refusals have a rule")
	}
}

// Registration, change and reset share ValidatePassword; registration and
// change reach it before any database access, so the same password is refused
// by both even without a database.
func TestRegistrationAndChangeUseTheSamePolicy(t *testing.T) {
	cfg := &config.Config{PasswordMinLength: 8, PasswordRequireSpecial: true}
	_, registerErr := Register(t.Context(), nil, nil, cfg, RegisterRequest{Login: "policy@example.com", Password: "Password1"})
	_, changeErr := ChangePassword(t.Context(), nil, cfg, nil, 1, "", "Current1!", "Password1", "Password1", "")
	if PasswordPolicyRule(registerErr) != PasswordRuleRequireSpecial || PasswordPolicyRule(changeErr) != PasswordRuleRequireSpecial {
		t.Fatalf("register: %v; change: %v", registerErr, changeErr)
	}
	cfg.PasswordRequireSpecial = false
	_, registerErr = Register(t.Context(), nil, nil, cfg, RegisterRequest{Login: "policy@example.com", Password: "short"})
	_, changeErr = ChangePassword(t.Context(), nil, cfg, nil, 1, "", "Current1!", "short", "short", "")
	if PasswordPolicyRule(registerErr) != PasswordRuleTooShort || PasswordPolicyRule(changeErr) != PasswordRuleTooShort {
		t.Fatalf("register: %v; change: %v", registerErr, changeErr)
	}
}
