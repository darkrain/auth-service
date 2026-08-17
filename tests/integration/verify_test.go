package integration

import (
	"net/http"
	"testing"
)

func TestRegistrationTokenCannotAccessAccountData(t *testing.T) {
	truncateTables(t)

	registrationToken := registerUser(t, "registration-token@example.com", "Password1")
	w := doRequest("GET", "/auth/me", nil, registrationToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for registration token on /auth/me, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegistrationTokenIsRevokedAfterGeneratorVerification(t *testing.T) {
	truncateTables(t)

	login := "registration-revoked@example.com"
	registrationToken := registerUser(t, login, "Password1")
	verifyUser(t, login, "registration-device", registrationToken)

	w := doRequest("GET", "/auth/me", nil, registrationToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected revoked registration token to return 403, got %d: %s", w.Code, w.Body.String())
	}
}
