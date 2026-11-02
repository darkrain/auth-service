package config

import "testing"

func TestLoginPolicyAllowsExistingNonRegistrationRoles(t *testing.T) {
	cfg := &Config{PasswordSalt: "fixture", PostgreSqlHost: "localhost", PostgreSqlDatabase: "fixture", RegistrationBrand: "iamfree", AllowedRoles: []string{"model"}, AllowedLoginRoles: []string{"model", "sudo", "admin", "system"}}
	cfg.PasswordResetCodeTTLMin = 5
	cfg.PasswordResetRateLimitPerHour = 5
	cfg.setMessageDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.IsValidRole("sudo") {
		t.Fatal("login policy must not enable sudo registration")
	}
	cfg.AllowedLoginRoles = []string{" "}
	if cfg.Validate() == nil {
		t.Fatal("accepted blank login role")
	}
}
