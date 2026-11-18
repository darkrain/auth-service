package config

import "testing"

func TestValidateRejectsStaffRolesInAllowedRoles(t *testing.T) {
	for _, role := range []string{"support", "staff", "sudo", "admin", "system", " Support "} {
		cfg := &Config{PasswordSalt: "fixture", PostgreSqlHost: "localhost", PostgreSqlDatabase: "fixture",
			AllowedRoles: []string{"model", "client", role}}
		cfg.PasswordResetCodeTTLMin = 5
		cfg.PasswordResetRateLimitPerHour = 5
		cfg.setMessageDefaults()
		if err := cfg.Validate(); err == nil {
			t.Fatalf("AllowedRoles with %q passed validation", role)
		}
	}
}

func TestValidateAcceptsPublicRoles(t *testing.T) {
	cfg := &Config{PasswordSalt: "fixture", PostgreSqlHost: "localhost", PostgreSqlDatabase: "fixture",
		AllowedRoles: []string{"model", "agency", "manager", "client"}}
	cfg.PasswordResetCodeTTLMin = 5
	cfg.PasswordResetRateLimitPerHour = 5
	cfg.setMessageDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.IsValidRole("support") {
		t.Fatal("support must not be registrable")
	}
}
