package integration

import (
	"net/http"
	"testing"
)

func TestMe_Authenticated(t *testing.T) {
	truncateTables(t)

	login := "me@example.com"
	password := "Password1"
	deviceUID := "device-me"

	registerUser(t, login, password)
	verifyUser(t, login, deviceUID)
	token := loginUser(t, login, password)

	w := doRequest("GET", "/auth/me", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := parseJSON(w)
	if body["email"] == nil {
		t.Errorf("expected email field in response")
	}
	if body["role"] == nil {
		t.Errorf("expected role field in response")
	}
	if body["id"] == nil {
		t.Errorf("expected id field in response")
	}
	if body["verify_status"] == nil {
		t.Errorf("expected verify_status field in response")
	}

	// Verify email matches
	if email, ok := body["email"].(string); !ok || email != login {
		t.Errorf("expected email=%s, got %v", login, body["email"])
	}
}

func TestMe_NoToken(t *testing.T) {
	truncateTables(t)

	w := doRequest("GET", "/auth/me", nil, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMe_InvalidToken(t *testing.T) {
	truncateTables(t)

	w := doRequest("GET", "/auth/me", nil, "invalid-token-abc123")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with invalid token, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMe_SystemUser(t *testing.T) {
	truncateTables(t)

	token := loginSystemUser(t)

	w := doRequest("GET", "/auth/me", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for system user, got %d: %s", w.Code, w.Body.String())
	}

	body := parseJSON(w)
	if role, ok := body["role"].(string); !ok || role != "system" {
		t.Errorf("expected role=system, got %v", body["role"])
	}
}
